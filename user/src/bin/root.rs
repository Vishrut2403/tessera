//! The root task: the first program, and the last thing the kernel creates.
//!
//! Everything it has arrived in its CSpace before it ran. It has no ambient
//! authority beyond `PUTC`, no allocator, and no way to ask the kernel for
//! memory: what it can build is bounded by the untypeds the boot info names.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

use rt::abi::{BootInfo, ObjectType, bootinfo, rights};
use rt::{entry, print, println, sys, thread_entry};

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

    // The biggest region that is actually memory. The PCI ECAM window is a
    // 256 MiB device untyped and would win on size, and retyping it into a page
    // table is exactly what `DeviceUntyped` refuses.
    let (best, _) = bi
        .untypeds()
        .iter()
        .enumerate()
        .filter(|(_, u)| u.is_device == 0)
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
    let phys = sys::get_address(scratch).expect("get_address");
    println!("  physically at : {phys:#x}  (what a virtqueue descriptor needs)");

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

    check_device_untyped(bi, vspace, f + 8, base + 0x10000, ut);

    println!();
    println!("root task: done.");
}

/// Check what a device untyped is and is not allowed to become, from the
/// outside — the same checks the kernel's tests make, made by a user program
/// holding nothing but capabilities (D-040).
///
/// Deliberately no MMIO *reads*: identifying a device by reading it is not
/// safe. QEMU's CLINT and fw-cfg both raise a load access fault on a plain
/// 32-bit read of offset 0, and with no fault endpoint attached that kills the
/// root task outright. Knowing which region is a virtio transport is the device
/// tree's job, not a scan's.
fn check_device_untyped(bi: &BootInfo, vspace: u64, first_slot: u64, at: usize, ram: u64) {
    println!();
    println!("  device untyped:");

    let (i, u) = bi
        .untypeds()
        .iter()
        .enumerate()
        .find(|(_, u)| u.is_device != 0)
        .expect("no device regions");
    let dev = bi.untyped_slot(i);
    let (frame, spare, weak) = (first_slot, first_slot + 1, first_slot + 2);

    // A device region becomes a frame, and nothing else. A page table there
    // would put the kernel's own bookkeeping in device registers.
    sys::retype(dev, ObjectType::Frame, 0, frame, 1).expect("device untyped -> frame");
    assert!(
        sys::retype(dev, ObjectType::PageTable, 0, spare, 1).is_err(),
        "a page table was carved out of device registers"
    );
    assert!(
        sys::retype(dev, ObjectType::Tcb, 0, spare, 1).is_err(),
        "a thread was carved out of device registers"
    );
    // And RAM cannot claim to be a device: that is the lie the type prevents.
    assert!(
        sys::retype(ram, ObjectType::DeviceUntyped, 12, spare, 1).is_err(),
        "ordinary memory was relabelled as device registers"
    );
    println!("    slot {dev:<3}      : {:#012x}, 2^{}", u.paddr, u.size_bits);
    println!("    retype        : frame yes; page table, thread, and RAM->device all refused");

    // The capability says where the frame is; the boot info said where the
    // region is. Both have to agree, or one of them is lying.
    sys::map_frame(frame, vspace, at, rights::READ | rights::WRITE, false).expect("map device");
    let phys = sys::get_address(frame).expect("get_address");
    assert_eq!(phys as u64, u.paddr, "a device frame is not where its untyped said");
    println!("    mapped at     : {at:#x} -> {phys:#012x}, which the boot info agrees with");

    // `GetAddress` needs WRITE. A read-only copy of the same frame is a
    // capability you can map and read, but not locate — which is the point,
    // because locating is most of the way to aiming a bus master at it.
    sys::mint(bootinfo::slot::CNODE, frame, weak, rights::READ, 0).expect("mint");
    assert!(sys::get_address(weak).is_err(), "a read-only frame gave up its address");
    println!("    read-only copy: refused GetAddress, as it must");

    // SAFETY: the scratch frame is mapped read-write at `at - 0x10000`.
    unsafe { ((at - 0x10000) as *mut u64).add(2).write_volatile(u.paddr) };
}

thread_entry!(child_start => child);

extern "C" fn child() {
    println!("  child thread  : running as thread {}", sys::thread_id());
    CHILD_RAN.store(sys::thread_id(), Ordering::Release);
}
