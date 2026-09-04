//! A read-only filesystem server (D-047).
//!
//! The first process that is both a client and a server: it calls the block
//! driver below it and answers file requests from above. It holds no device
//! capability, no interrupt, and no idea what a virtqueue is, only a
//! send-only endpoint to the driver and a receive-only endpoint of its own.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use rt::abi::{MessageInfo, ObjectType, PAGE_SIZE, bootinfo, rights};
use rt::fsformat as fmt;
use rt::{block, entry, fs, println, spawn, sys, vm};

entry!(main);

/// What this task writes to the page its parent gave it.
pub const MAGIC: u64 = 0xf115_0000_0000_0001;

/// The frame the driver fills for us, remembered so we can offer it again if
/// the driver is restarted underneath us (D-048).
static DISK_FRAME: AtomicU64 = AtomicU64::new(0);

/// One block, filled by the driver on our behalf.
const DISK_VADDR: usize = 0x1200_0000;
/// Where a client's frame gets mapped while we are copying into it.
const CLIENT_VADDR: usize = 0x1201_0000;

fn main() {
    println!("  fs server     : running as thread {}, a client and a server", sys::thread_id());
    spawn::say_hello(MAGIC);

    let vspace = bootinfo::slot::VSPACE;
    let mut alloc = vm::Alloc::new(spawn::UNTYPED, spawn::FIRST_FREE);

    // Our own block buffer. It stays connected to the driver for the whole run:
    // the driver holds one client frame, and we are its one client.
    let disk = alloc.object(ObjectType::Frame, 0).expect("disk frame");
    let rw = rights::READ | rights::WRITE;
    vm::map(&mut alloc, vspace, disk, DISK_VADDR, rw, false).expect("map disk frame");

    DISK_FRAME.store(disk, Ordering::Relaxed);
    let connect = connect_to_driver();
    if connect != block::OK {
        println!("    driver        : refused our buffer");
        report(0);
        return;
    }

    let files = match mount() {
        Some(n) => n,
        None => {
            println!("    mount         : no filesystem on this disk");
            report(0);
            return;
        }
    };

    // Tell our parent we are up *before* waiting on anyone: it is the parent
    // that spawns the client we are about to wait for (D-046).
    report(files);
    serve(&mut alloc, vspace);

    // We are the driver's only client, so its shutdown is ours to send.
    sys::call(spawn::UPSTREAM, MessageInfo::new(block::SHUTDOWN, 0, false), [0; 4]);
    println!("    fs server     : told the driver to stop, and stopping");
}

/// Read the superblock and check it is one.
fn mount() -> Option<u32> {
    read_block(fmt::SUPER_BLOCK)?;
    // SAFETY: our own frame, mapped read-write, which the driver has just had
    // the device fill.
    let sb = unsafe { core::slice::from_raw_parts(DISK_VADDR as *const u8, fmt::BLOCK_SIZE) };
    if !fmt::super_is_valid(sb) {
        return None;
    }
    let files = fmt::super_files(sb);
    println!("    mounted       : {files} files, {} blocks reserved", fmt::FS_BLOCKS);
    Some(files)
}

/// Offer the driver our block buffer. Done once at startup, and again if a
/// restarted driver turns out never to have heard of us.
fn connect_to_driver() -> usize {
    let frame = DISK_FRAME.load(Ordering::Relaxed);
    let reply =
        sys::call_cap(spawn::UPSTREAM, MessageInfo::new(block::CONNECT, 0, true), [0; 4], frame);
    reply.words[0]
}

/// Ask the driver for one block. It lands in our own frame, which the driver
/// never maps and we never share.
///
/// A `NO_BUFFER` means the driver on the other end is not the one we connected
/// to: it was rebuilt while we were working, and kept no state across the
/// crash. Saying who we are again is the whole of our recovery (D-048).
fn read_block(n: u32) -> Option<()> {
    let ask = MessageInfo::new(block::READ, 1, false);
    for attempt in 0..2 {
        let reply = sys::call(spawn::UPSTREAM, ask, [n as usize, 0, 0, 0]);
        match reply.words[0] {
            block::OK => return Some(()),
            block::NO_BUFFER if attempt == 0 => {
                println!("    reconnecting  : the driver below us was restarted");
                if connect_to_driver() != block::OK {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

/// The bytes of the block we last read.
fn disk_bytes() -> &'static [u8] {
    // SAFETY: our own frame, mapped read-write for the life of the process.
    unsafe { core::slice::from_raw_parts(DISK_VADDR as *const u8, fmt::BLOCK_SIZE) }
}

/// Answer file requests until a client says stop.
fn serve(alloc: &mut vm::Alloc, vspace: u64) {
    let first = sys::recv_cap(spawn::SERVICE, spawn::CLIENT_FRAME);
    // Three words: a status, and room for an inode and a size.
    let answer = MessageInfo::new(0, 3, false);
    if first.info.label() != fs::CONNECT {
        let _ = sys::reply(answer, [fs::NO_BUFFER, 0, 0, 0]);
        return;
    }

    // Unlike the driver, we *do* map our client's frame. A filesystem assembles
    // bytes out of blocks, so it has to touch them; a driver never does, which
    // is why the driver only ever learns a physical address (D-047).
    let rw = rights::READ | rights::WRITE;
    if vm::map(alloc, vspace, spawn::CLIENT_FRAME, CLIENT_VADDR, rw, false).is_err() {
        let _ = sys::reply(answer, [fs::FAILED, 0, 0, 0]);
        return;
    }
    println!("    connected     : a client's frame, mapped here at {CLIENT_VADDR:#x}");

    let mut msg = sys::reply_recv(spawn::SERVICE, answer, [fs::OK, 0, 0, 0]);
    loop {
        let words = match msg.info.label() {
            fs::OPEN => open(&fs::unpack_name(&msg.words)),
            fs::READ => read_file(msg.words[0], msg.words[1], msg.words[2]),
            fs::SHUTDOWN => {
                let _ = sys::reply(answer, [fs::OK, 0, 0, 0]);
                return;
            }
            _ => [fs::FAILED, 0, 0, 0],
        };
        msg = sys::reply_recv(spawn::SERVICE, answer, words);
    }
}

/// Look a name up in the flat table and answer with its inode and size.
fn open(want: &[u8; fmt::NAME_LEN]) -> [usize; 4] {
    if read_block(fmt::NAME_BLOCK).is_none() {
        return [fs::FAILED, 0, 0, 0];
    }
    let mut found = None;
    for i in 0..fmt::MAX_FILES {
        if fmt::name_matches(disk_bytes(), i, want) {
            found = Some(fmt::name_inode(disk_bytes(), i) as usize);
            break;
        }
    }
    let Some(inode) = found else { return [fs::NO_SUCH_FILE, 0, 0, 0] };

    if read_block(fmt::INODE_BLOCK).is_none() {
        return [fs::FAILED, 0, 0, 0];
    }
    [fs::OK, inode, fmt::inode_size(disk_bytes(), inode) as usize, 0]
}

/// Copy `len` bytes from `offset` of `inode` into the client's frame.
/// This is the part that makes it a filesystem rather than a block device: a
/// byte range is assembled out of whichever direct blocks hold it.
fn read_file(inode: usize, len: usize, offset: usize) -> [usize; 4] {
    if inode >= fmt::MAX_FILES {
        return [fs::NO_SUCH_FILE, 0, 0, 0];
    }
    if read_block(fmt::INODE_BLOCK).is_none() {
        return [fs::FAILED, 0, 0, 0];
    }

    // The inode is copied out before any data block is read, because reading
    // one overwrites the buffer the inode is sitting in.
    let mut direct = [0u32; fmt::DIRECT];
    for (k, d) in direct.iter_mut().enumerate() {
        *d = fmt::inode_direct(disk_bytes(), inode, k);
    }
    let size = fmt::inode_size(disk_bytes(), inode) as usize;

    let end = (offset + len).min(size).min(offset + PAGE_SIZE);
    let mut pos = offset;
    let mut written = 0usize;
    while pos < end {
        let which = pos / fmt::BLOCK_SIZE;
        if which >= fmt::DIRECT || direct[which] == 0 {
            break;
        }
        if read_block(direct[which]).is_none() {
            return [fs::FAILED, written, 0, 0];
        }
        let within = pos % fmt::BLOCK_SIZE;
        let n = (fmt::BLOCK_SIZE - within).min(end - pos);
        // SAFETY: our own block buffer, and a client frame we mapped read-write
        // above; `n` stays inside both by construction.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (DISK_VADDR + within) as *const u8,
                (CLIENT_VADDR + written) as *mut u8,
                n,
            );
        }
        pos += n;
        written += n;
    }
    [fs::OK, written, 0, 0]
}

fn report(files: u32) {
    sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::READY, 1, false),
        [files as usize, 0, 0, 0],
    );
}
