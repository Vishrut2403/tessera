//! A client of the filesystem service (D-046, D-047).
//!
//! It holds a CSpace, an address space, a TCB, an endpoint to its parent, one
//! untyped region, and a **send-only** capability to a filesystem server it did
//! not create and cannot receive on. It has no device capability, no interrupt,
//! no block-level access, and no idea what a virtqueue is.

#![no_std]
#![no_main]

use rt::abi::{MessageInfo, ObjectType, bootinfo, rights};
use rt::{entry, fs, println, spawn, sys, vm};

entry!(main);

/// What this task writes to the page its parent gave it, distinct from every
/// other task's word at the same address.
pub const MAGIC: u64 = 0xc11e_0000_0000_0001;

/// Where the buffer the server fills is mapped, in our address space.
const BUFFER_VADDR: usize = 0x1200_0000;

/// A read that starts inside one block and ends inside the next, so a server
/// that only ever follows the first direct pointer cannot pass.
const SPAN_OFFSET: usize = 500;
const SPAN_LEN: usize = 200;

fn main() {
    println!("  fs client     : running as thread {}, send-only to the server", sys::thread_id());
    spawn::say_hello(MAGIC);

    let vspace = bootinfo::slot::VSPACE;
    let mut alloc = vm::Alloc::new(spawn::UNTYPED, spawn::FIRST_FREE);

    let buffer = alloc.object(ObjectType::Frame, 0).expect("buffer frame");
    vm::map(&mut alloc, vspace, buffer, BUFFER_VADDR, rights::READ | rights::WRITE, false)
        .expect("map buffer");

    // One capability, once. Everything after this is four registers each way.
    let connect =
        sys::call_cap(spawn::UPSTREAM, MessageInfo::new(fs::CONNECT, 0, true), [0; 4], buffer);
    if connect.words[0] != fs::OK {
        println!("    connect       : refused, {}", connect.words[0]);
        report(0);
        return;
    }
    println!("    connected     : gave the server one frame of ours to fill");

    let mut checks = 0usize;
    checks += print_a_file("motd") as usize;
    checks += read_across_a_block("spans.bin") as usize;
    checks += a_missing_file_is_refused("nope.txt") as usize;
    // Once more, at the end. If the disk subsystem was torn down and rebuilt
    // underneath us while we worked, this is where we would find out (D-048).
    checks += read_across_a_block("spans.bin") as usize;

    sys::call(spawn::UPSTREAM, MessageInfo::new(fs::SHUTDOWN, 0, false), [0; 4]);
    println!("    shutdown      : told the server to stop");
    report(checks);
}

/// Open a file, read all of it, and print it. Nothing about this asks where the
/// bytes are: the client never sees a block number.
fn print_a_file(name: &str) -> bool {
    let Some((inode, size)) = open(name) else { return false };
    if size == 0 {
        println!("    {name:<10}    : the server says it is empty");
        return false;
    }
    let got = read(inode, size, 0);
    if got != size {
        println!("    {name:<10}    : wanted {size} bytes, got {got}");
        return false;
    }
    // SAFETY: our own frame, mapped read-write, which the server has just
    // copied `got` bytes into.
    let bytes = unsafe { core::slice::from_raw_parts(BUFFER_VADDR as *const u8, got) };
    println!("    {name:<10}    : {size} bytes:");
    for line in bytes.split(|b| *b == b'\n') {
        if !line.is_empty() {
            println!("      | {}", core::str::from_utf8(line).unwrap_or("<not utf-8>"));
        }
    }
    true
}

/// Read a range that starts in one block and ends in the next, and check every
/// byte against the pattern `kernel/build.rs` wrote.
fn read_across_a_block(name: &str) -> bool {
    let Some((inode, size)) = open(name) else { return false };
    if size <= SPAN_OFFSET + SPAN_LEN {
        println!("    {name:<10}    : only {size} bytes, too small to span a block");
        return false;
    }
    let got = read(inode, SPAN_LEN, SPAN_OFFSET);
    if got != SPAN_LEN {
        println!("    {name:<10}    : wanted {SPAN_LEN} bytes at {SPAN_OFFSET}, got {got}");
        return false;
    }
    // SAFETY: as above.
    let bytes = unsafe { core::slice::from_raw_parts(BUFFER_VADDR as *const u8, got) };
    for (i, b) in bytes.iter().enumerate() {
        let want = ((SPAN_OFFSET + i) % 251) as u8;
        if *b != want {
            println!("    {name:<10}    : byte {} is {b}, not {want}", SPAN_OFFSET + i);
            return false;
        }
    }
    println!(
        "    {name:<10}    : {size} bytes; {SPAN_LEN} of them from {SPAN_OFFSET} span two blocks"
    );
    true
}

fn a_missing_file_is_refused(name: &str) -> bool {
    let words = fs::pack_name(name);
    let reply = sys::call(spawn::UPSTREAM, MessageInfo::new(fs::OPEN, 3, false), words);
    let refused = reply.words[0] == fs::NO_SUCH_FILE;
    let said = if refused { "no such file, as it must be" } else { "found, which it must not be" };
    println!("    {name:<10}    : {said}");
    refused
}

/// A name is 24 bytes, which is exactly three registers, so a whole filename
/// fits in one message and nothing has to be shared to ask a question (D-047).
fn open(name: &str) -> Option<(usize, usize)> {
    let ask = MessageInfo::new(fs::OPEN, 3, false);
    let reply = sys::call(spawn::UPSTREAM, ask, fs::pack_name(name));
    if reply.words[0] != fs::OK {
        println!("    {name:<10}    : open refused, {}", reply.words[0]);
        return None;
    }
    Some((reply.words[1], reply.words[2]))
}

fn read(inode: usize, len: usize, offset: usize) -> usize {
    // SAFETY: our own frame. Cleared so a read that never happened cannot pass
    // for one that did.
    unsafe { core::ptr::write_bytes(BUFFER_VADDR as *mut u8, 0, len) };
    let reply =
        sys::call(spawn::UPSTREAM, MessageInfo::new(fs::READ, 3, false), [inode, len, offset, 0]);
    if reply.words[0] == fs::OK { reply.words[1] } else { 0 }
}

fn report(checks: usize) {
    sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::READY, 1, false),
        [checks, 0, 0, 0],
    );
}
