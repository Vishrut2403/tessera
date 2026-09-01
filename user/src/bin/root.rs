//! The root task: the first program, and the last thing the kernel creates.
//!
//! Everything it has arrived in its CSpace before it ran. It has no ambient
//! authority beyond `PUTC`, no allocator, and no way to ask the kernel for
//! memory: what it can build is bounded by the untypeds the boot info names.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

use rt::abi::{BootInfo, ObjectType, bootinfo, rights};
use rt::{entry, println, sys, thread_entry};

entry!(main);

/// Written by the child thread, read by the root task. In `.bss`, which the
/// kernel's loader zeroed, and shared because both threads run in one address
/// space.
static CHILD_RAN: AtomicUsize = AtomicUsize::new(0);

/// Written to the scratch page when the root task has finished successfully.
pub const DONE: u64 = 0xd02e_0000_0000_0000;

fn main() {
    // SAFETY: the kernel mapped a `BootInfo` here read-only before we ran, and
    // the magic and version are checked before anything else is believed.
    let bi = unsafe { &*(bootinfo::VADDR as *const BootInfo) };
    assert!(bi.is_valid(), "boot info page is not a boot info page");

    println!();
    println!("root task: hello from userspace, thread {}", sys::thread_id());
    println!("  image         : {:#x}..{:#x}", bi.image_start, bi.image_end);
    println!("  stack         : {:#x}..{:#x}", bi.stack_bottom, bi.stack_top);
    println!("  boot info     : {:#x}", bi.bootinfo_vaddr);
    println!("  free from     : {:#x}", bi.free_vaddr);
    println!("  cspace        : {} slots, radix {}", bi.cnode_slots, bi.cnode_radix);
    println!("  free slots    : {}..{}", bi.first_free_slot, bi.cnode_slots);

    let mut total = 0u64;
    for u in bi.untypeds() {
        total += u.bytes();
    }
    println!("  untyped       : {} regions, {} KiB total", bi.untyped_count, total / 1024);
    for (i, u) in bi.untypeds().iter().enumerate() {
        println!(
            "    slot {:<3}    : {:#012x}  2^{} = {} KiB{}",
            bi.untyped_slot(i),
            u.paddr,
            u.size_bits,
            u.bytes() / 1024,
            if u.is_device != 0 { "  (device)" } else { "" }
        );
    }

    // The biggest region; everything below comes out of it.
    let (best, _) = bi
        .untypeds()
        .iter()
        .enumerate()
        .max_by_key(|(_, u)| u.size_bits)
        .expect("no untyped memory");
    let ut = bi.untyped_slot(best);

    // Slots we allocate ourselves, starting where the kernel stopped.
    let f = bi.first_free_slot;
    let (l1, l0, scratch, child_stack, child_tcb) = (f, f + 1, f + 2, f + 3, f + 4);

    sys::retype(ut, ObjectType::PageTable, 0, l1, 2).expect("retype page tables");
    sys::retype(ut, ObjectType::Frame, 0, scratch, 2).expect("retype frames");
    sys::retype(ut, ObjectType::Tcb, 0, child_tcb, 1).expect("retype tcb");
    println!();
    println!("  retyped       : 2 page tables, 2 frames, 1 thread out of slot {ut}");

    // Nothing maps `base` yet, and the two intermediate levels do not exist
    // either -- the kernel will not create them, so we do (D-035).
    let base = bi.free_vaddr as usize;
    let vspace = bootinfo::slot::VSPACE;
    sys::map_table(l1, vspace, base, 2).expect("map l1");
    sys::map_table(l0, vspace, base, 1).expect("map l0");
    sys::map_frame(scratch, vspace, base, rights::READ | rights::WRITE, false).expect("map frame");

    // SAFETY: a frame we retyped and just mapped read-write at `base`.
    unsafe {
        let p = base as *mut u64;
        p.write_volatile(0x7e55e7a);
        assert_eq!(p.read_volatile(), 0x7e55e7a);
    }
    println!("  mapped        : {base:#x} rw, wrote and read back a word");

    // A second thread in this address space: its own stack, our CSpace, our
    // page tables, and an entry point in the text we are running out of.
    let stack = base + 0x1000;
    sys::map_frame(child_stack, vspace, stack, rights::READ | rights::WRITE, false)
        .expect("map child stack");
    sys::tcb_configure(child_tcb, bootinfo::slot::CNODE, vspace, 0).expect("configure");
    sys::tcb_write_registers(child_tcb, child_start as *const () as usize, stack + 0x1000)
        .expect("write registers");
    sys::tcb_resume(child_tcb).expect("resume");
    println!("  spawned       : a thread at {:#x} on a stack at {:#x}", child_start as *const () as usize, stack);

    // Bounded: a child that never runs must fail the run, not hang it. One
    // hung test hangs the whole suite, because a test file is one QEMU boot.
    let mut spins = 0;
    while CHILD_RAN.load(Ordering::Acquire) == 0 && spins < 1000 {
        sys::yield_now();
        spins += 1;
    }
    let child_id = CHILD_RAN.load(Ordering::Acquire);
    if child_id == 0 {
        println!("  child said    : nothing, after {spins} yields");
    } else {
        println!("  child said    : {child_id}");
    }

    // The finish line, in memory the kernel can read once we are done: reaching
    // here means every step above succeeded, and a panic would have exited
    // before writing it.
    // SAFETY: the scratch frame is still mapped read-write at `base`.
    unsafe { (base as *mut u64).add(1).write_volatile(DONE | child_id as u64) };

    println!();
    println!("root task: done.");
}

thread_entry!(child_start => child);

extern "C" fn child() {
    println!("  child thread  : running as thread {}", sys::thread_id());
    CHILD_RAN.store(sys::thread_id(), Ordering::Release);
}
