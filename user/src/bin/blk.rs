//! The block driver, as a process of its own (D-043).
//!
//! M7e-1 is the process, not yet the driver: it proves that a boot module the
//! root task loaded runs in its own address space, holding nothing but the
//! four capabilities it was minted.

#![no_std]
#![no_main]

use rt::abi::{MessageInfo, bootinfo, rights};
use rt::{entry, println, spawn, sys};

entry!(main);

/// What the driver writes to the page its parent gave it. Distinct from the
/// parent's own word at the same address, which is the whole point.
pub const MAGIC: u64 = 0xb10c_0000_0000_0001;

fn main() {
    let id = sys::thread_id();
    println!("  blk driver    : running as thread {id}, in an address space of its own");

    // The shared page, at an address the parent also has a page at -- a
    // different page, which is what makes the two spaces separate.
    // SAFETY: the parent mapped a frame here read-write before resuming us.
    let seen = unsafe {
        let p = spawn::SHARED_VADDR as *mut u64;
        p.write_volatile(MAGIC);
        p.read_volatile()
    };
    println!("    wrote         : {MAGIC:#x} at {:#x}, read back {seen:#x}", spawn::SHARED_VADDR);

    // We hold the endpoint with `WRITE` and nothing else, which is exactly
    // what `call` needs: the reply arrives through the Reply capability the
    // kernel mints, never back through the endpoint (D-042).
    let reply = sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::HELLO, 3, false),
        [id, seen as usize, spawn::SHARED_VADDR, 0],
    );
    println!("    parent said   : {:#x}", reply.words[0]);

    // Four slots is the whole of our authority: everything else is empty, and
    // an empty slot names nothing that can be copied out of it.
    assert!(sys::mint(bootinfo::slot::CNODE, bootinfo::slot::NULL, 32, rights::ALL, 0).is_err());
    assert!(sys::mint(bootinfo::slot::CNODE, bootinfo::slot::IRQ_CONTROL, 32, rights::ALL, 0)
        .is_err());
    println!("    refused       : copying out of the empty slots, as it must be");
}
