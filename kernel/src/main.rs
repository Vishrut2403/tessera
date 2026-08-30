//! The kernel binary; everything real lives in the library.

#![no_std]
#![no_main]

use kernel::csr::{sstatus, sstatus_bits};
use kernel::mm::{self, PhysAddr};
use kernel::{kernel_entry, layout, println, qemu, trap};

kernel_entry!(kmain);

/// First Rust code to run in the high half.
#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();

    println!();
    println!("tessera :: M2 -- higher half, Sv39");
    println!("  hart          : {}", hartid);
    println!("  device tree   : {:#x}", dtb_pa);
    println!("  sp            : {:#018x}", kernel::stack_pointer());
    println!(
        "  sstatus       : {:#018x} (SIE={})",
        sstatus::read(),
        (sstatus::read() & sstatus_bits::SIE != 0) as u8
    );
    println!();
    println!("memory layout:");
    println!(
        "  .text         : {:#012x}..{:#012x}  ({} B)",
        layout::text_start(),
        layout::text_end(),
        layout::text_end() - layout::text_start()
    );
    println!(
        "  .rodata       : {:#012x}..{:#012x}  ({} B)",
        layout::rodata_start(),
        layout::rodata_end(),
        layout::rodata_end() - layout::rodata_start()
    );
    println!(
        "  .data         : {:#012x}..{:#012x}  ({} B)",
        layout::data_start(),
        layout::data_end(),
        layout::data_end() - layout::data_start()
    );
    println!(
        "  .bss          : {:#012x}..{:#012x}  ({} B)",
        layout::bss_start(),
        layout::bss_end(),
        layout::bss_end() - layout::bss_start()
    );
    println!(
        "  boot stack    : {:#012x}..{:#012x}  ({} B)",
        layout::boot_stack_bottom(),
        layout::boot_stack_top(),
        layout::boot_stack_top() - layout::boot_stack_bottom()
    );
    println!(
        "  kernel image  : {:#012x}..{:#012x}  ({} KiB)",
        layout::kernel_start(),
        layout::kernel_end(),
        (layout::kernel_end() - layout::kernel_start()) / 1024
    );

    // ---- M2a: what physical memory is there?
    let dtb = PhysAddr::new(dtb_pa);
    let map = match mm::init(dtb, layout::kernel_phys_range()) {
        Ok(map) => map,
        Err(e) => panic!("could not read the memory map: {:?}", e),
    };

    println!();
    println!("physical memory:");
    println!("  RAM reported by the device tree:");
    for r in map.ram.iter() {
        println!("    {:?}", r);
    }
    println!("  reserved (firmware, kernel image, DTB):");
    for r in map.reserved.iter() {
        println!("    {:?}", r);
    }
    println!("  free:");
    for r in map.free.iter() {
        println!("    {:?}  = {} frames", r, r.frame_count());
    }
    // Read the numbers out and release the lock *before* printing.
    let usable = mm::FRAMES.lock().bytes_remaining();
    println!(
        "  usable: {} KiB in {} frames across {} region(s)",
        usable / 1024,
        usable / kernel::mm::PAGE_SIZE,
        map.free.len()
    );

    // Prove the allocator works and that frames come back zeroed.
    let a = mm::alloc_frame().expect("no free frames");
    let b = mm::alloc_frame().expect("no free frames");
    println!("  test alloc: {} then {} (delta {} B)", a, b, b.as_usize() - a.as_usize());

    // --- M2c: build and activate the real kernel address space ---
    let kspace = {
        // Scoped so the allocator lock is released before any printing (D-008).
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("could not build kernel space")
    };

    println!();
    println!("kernel address space (root at {}):", kspace.root());
    for s in mm::kernel_space::sections() {
        let (pa, flags, level) = kspace
            .translate(s.start)
            .unwrap_or_else(|| panic!("{} is not mapped", s.name));
        println!(
            "  {:<12} {} -> {}  {:?}  {} KiB in {} B pages",
            s.name,
            s.start,
            pa,
            flags,
            s.len() / 1024,
            kernel::mm::page_table::page_size(level)
        );
    }
    for (name, pa) in mm::kernel_space::DEVICES {
        let va = kernel::mm::VirtAddr::new(kernel::mm::KERNEL_VMA + pa);
        let (got, flags, _) = kspace.translate(va).expect("device not mapped");
        println!("  {:<12} {} -> {}  {:?}", name, va, got, flags);
    }

    // The identity mapping the bootstrap table provided is simply absent here.
    assert!(
        kspace.translate(kernel::mm::VirtAddr::new(0x8020_0000)).is_none(),
        "the low identity mapping survived into the kernel table"
    );

    // SAFETY: `kspace` maps .text, .data/.bss and the boot stack at the addresses we run at.
    unsafe { mm::kernel_space::activate(&kspace) };

    println!();
    println!("switched to the kernel page table.");
    println!("  identity map : gone (low half is unmapped)");
    println!("  .text        : {:?}", kspace.translate(
        kernel::mm::VirtAddr::new(layout::text_start())).unwrap().1);
    println!("  direct map   : {} covering {} MiB",
        kernel::mm::VirtAddr::new(kernel::mm::KERNEL_VMA),
        map.ram.total_bytes() / (1024 * 1024));

    // Prove the direct map works: allocate a frame, write through it, read it back.
    let probe = mm::alloc_frame().expect("no free frames");
    let ptr = mm::phys_to_virt(probe).as_mut_ptr::<u64>();
    // SAFETY: `probe` is a frame we own, reachable through the direct map.
    unsafe {
        core::ptr::write_volatile(ptr, 0x7e55e7a_u64);
        assert_eq!(core::ptr::read_volatile(ptr), 0x7e55e7a);
    }
    println!("  direct map rw: verified at {}", mm::phys_to_virt(probe));

    // --- M2d: a user address space over the shared kernel half ---
    let uspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::AddressSpace::new(&kspace, &mut *alloc).expect("could not build a user space")
    };
    let text = kernel::mm::VirtAddr::new(layout::text_start());
    println!();
    println!("user address space (root at {}):", uspace.root());
    println!("  satp         : {:#018x}  asid {}", uspace.satp(), uspace.asid().as_u16());
    println!("  kernel half  : shared, .text -> {}", uspace.translate(text).unwrap().0);
    println!("  user half    : empty ({:?} at 0x1000)", uspace.translate(
        kernel::mm::VirtAddr::new(0x1000)));

    // Prove the trap path end to end.
    println!();
    println!("trap test: executing ebreak...");
    let before = trap::BREAKPOINTS.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: `ebreak` raises a breakpoint, which `dispatch` handles by skipping it.
    unsafe { core::arch::asm!("ebreak") };
    let after = trap::BREAKPOINTS.load(core::sync::atomic::Ordering::Relaxed);
    println!("  returned from trap; breakpoints handled: {} -> {}", before, after);
    assert_eq!(after, before + 1, "breakpoint handler did not run");

    println!();
    println!("M2 complete. Parking. (Ctrl-A x to exit QEMU)");
    qemu::park()
}
