//! A client of the block service (D-046).
//!
//! It holds a CSpace, an address space, a TCB, an endpoint to its parent, one
//! untyped region, and a **send-only** capability to a driver it did not create
//! and cannot receive on. It has no device capability, no interrupt, and no
//! idea what a virtqueue is.

#![no_std]
#![no_main]

use rt::abi::{MessageInfo, ObjectType, bootinfo, rights};
use rt::{block, entry, println, spawn, sys, vm};

entry!(main);

/// What this task writes to the page its parent gave it, distinct from both the
/// parent's word and the driver's.
pub const MAGIC: u64 = 0xc11e_0000_0000_0001;

/// Where the buffer the driver fills is mapped, in our address space only.
const BUFFER_VADDR: usize = 0x1200_0000;

/// The first block, one in the middle, and the last. `kernel/build.rs` writes
/// each block's own number into both ends of it.
const WANTED: [u64; 3] = [0, 5, 2047];

fn main() {
    println!("  blk client    : running as thread {}, send-only to the driver", sys::thread_id());
    spawn::say_hello(MAGIC);

    let vspace = bootinfo::slot::VSPACE;
    let mut alloc = vm::Alloc::new(spawn::UNTYPED, spawn::FIRST_FREE);

    let buffer = alloc.object(ObjectType::Frame, 0).expect("buffer frame");
    vm::map(&mut alloc, vspace, buffer, BUFFER_VADDR, rights::READ | rights::WRITE, false)
        .expect("map buffer");

    // One capability, once. A 512-byte block will never fit in four registers,
    // so the connect hands over the *authority* to a page and every request
    // after it is a block number (D-046).
    let connect = sys::call_cap(
        spawn::SERVICE,
        MessageInfo::new(block::CONNECT, 0, true),
        [0; 4],
        buffer,
    );
    if connect.words[0] != block::OK {
        println!("    connect       : refused, {}", connect.words[0]);
        report(0);
        return;
    }
    println!("    connected     : gave the driver one frame of ours to fill");

    let mut verified = 0usize;
    for sector in WANTED {
        // Something the driver must overwrite, so a read that never happened
        // cannot pass for one that did.
        // SAFETY: our own frame, mapped read-write just above.
        unsafe { (BUFFER_VADDR as *mut u64).write_volatile(0) };

        let reply = sys::call(
            spawn::SERVICE,
            MessageInfo::new(block::READ, 1, false),
            [sector as usize, 0, 0, 0],
        );

        // SAFETY: as above. The driver never mapped this page -- the device
        // wrote it directly, from a physical address the driver was told.
        let (first, last) = unsafe {
            (
                (BUFFER_VADDR as *const u64).read_volatile(),
                ((BUFFER_VADDR + block::BLOCK - 8) as *const u64).read_volatile(),
            )
        };

        let want = 0x07e5_5e7a_0000_0000 | sector;
        if reply.words[0] == block::OK && first == want && last == sector {
            verified += 1;
            println!("    block {sector:<4}     : {first:#x}, and {last} at the far end");
        } else {
            let status = reply.words[0];
            println!("    block {sector:<4}     : status {status} -- {first:#x} / {last}");
        }
    }

    // A server loop needs an end, or the run queue never empties.
    sys::call(spawn::SERVICE, MessageInfo::new(block::SHUTDOWN, 0, false), [0; 4]);
    println!("    shutdown      : told the driver to stop serving");

    report(verified);
}

fn report(verified: usize) {
    sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::READY, 2, false),
        [verified, 0, 0, 0],
    );
}
