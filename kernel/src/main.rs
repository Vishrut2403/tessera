//! The kernel binary; everything real lives in the library.

#![no_std]
#![no_main]

use kernel::csr::{sstatus, sstatus_bits};
use kernel::mm::{self, PhysAddr};
use kernel::cap::asid::AsidPool;
use kernel::cap::cspace::bootstrap;
use kernel::cap::rights::{ALL, GRANT, READ, WRITE};
use kernel::cap::object::SLOT_BITS;
use kernel::cap::vspace::vspace_cap;
use kernel::cap::{ObjectType, RawCap};
use kernel::mm::{AddressSpace, PAGE_SIZE, PteFlags, VirtAddr};
use kernel::uprog::{self, A7, ECALL, Prog, li};
use kernel::{kernel_entry, layout, println, qemu, sched, time, trap};

kernel_entry!(kmain);

/// First Rust code to run in the high half.
#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();

    println!();
    println!("tessera :: M7 -- userspace drivers: ELF, device memory, interrupts");
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
    println!("  devices (not RAM, handed out as device untyped):");
    for r in map.devices.iter() {
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

    // --- M3: threads ---
    time::init(PhysAddr::new(dtb_pa));
    println!();
    println!("timer:");
    println!("  timebase      : {} Hz (from the device tree)", time::timebase_hz());
    println!("  sstc          : {}", if time::has_sstc() { "yes" } else { "no, using SBI" });
    println!("  timeslice     : {} ms", time::TIMESLICE_MS);

    // A thread that branches to itself, queued *first*, then three that each
    // print a letter and exit.
    let spinner = user_space(&kspace, &[uprog::SPIN]);
    sched::spawn(&spinner, VirtAddr::new(USER_TEXT), VirtAddr::new(USER_STACK + PAGE_SIZE))
        .expect("spawn failed");
    core::mem::forget(spinner);
    for letter in [b'a', b'b', b'c'] {
        let space = user_space(&kspace, &greeter(letter));
        sched::spawn(&space, VirtAddr::new(USER_TEXT), VirtAddr::new(USER_STACK + PAGE_SIZE))
            .expect("spawn failed");
        core::mem::forget(space);
    }

    println!();
    println!("scheduling {} threads; the first one never yields:", sched::ready_count());
    kernel::print!("  output        : ");

    time::enable();
    time::arm_next_tick();
    // SAFETY: the trap path is installed and the dispatcher handles timer interrupts.
    unsafe { sstatus::set(sstatus_bits::SIE) };

    // Each greeter exits, so this returns three times; the spinner never does.
    for _ in 0..3 {
        sched::run_until_exit();
    }

    // SAFETY: leaving interrupts masked while we print the summary.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    println!();
    println!("  spawned       : {}", sched::spawned());
    println!("  exited        : {}", sched::exited());
    println!("  still ready   : {} (the spinner, preempted and requeued)", sched::ready_count());
    println!("  timer ticks   : {}", time::TICKS.load(core::sync::atomic::Ordering::Relaxed));

    // --- M4: capabilities ---
    // One 2 MiB region of untyped memory, and a capability space rooted in a
    // CNode carved out of it.
    let region = {
        let mut alloc = mm::FRAMES.lock();
        let mut first = alloc.alloc_frame().expect("no frames");
        while first.as_usize() & (2 * 1024 * 1024 - 1) != 0 {
            first = alloc.alloc_frame().expect("no frames");
        }
        for _ in 1..512 {
            alloc.alloc_frame().expect("no frames");
        }
        RawCap::untyped(first, 21, ALL)
    };

    let mut cs = bootstrap(region, 6 + SLOT_BITS).expect("could not bootstrap a capability space");
    println!();
    println!("capability space (root CNode at {}):", cs.root().paddr);
    println!("  untyped       : {} .. {:#012x}", region.paddr, region.end());
    println!("  root slots    : {}", cs.root_slots());

    let mut made = [RawCap::NULL; 4];
    cs.retype((0, 6), ObjectType::Frame, 0, (8, 6), &mut made).expect("retype");
    cs.retype((0, 6), ObjectType::Endpoint, 0, (12, 6), &mut made[..1]).expect("retype");
    println!(
        "  retyped       : 4 frames + 1 endpoint, watermark now {} KiB",
        cs.read(0, 6).unwrap().watermark / 1024
    );

    // Delegate the endpoint twice, weaker each time.
    cs.mint((12, 6), (13, 6), READ | GRANT, 0x51de).expect("mint");
    cs.mint((13, 6), (14, 6), READ, 0xfeed).expect("mint");
    for slot in [12u64, 13, 14] {
        let c = cs.read(slot, 6).unwrap();
        println!(
            "  slot {slot:<2}       : {} rights={} badge={:#x}",
            c.kind.name(),
            kernel::cap::rights::name(c.rights),
            c.badge
        );
    }
    println!("  descendants   : {} under slot 12", cs.descendants(12, 6).unwrap());

    // A capability without GRANT cannot be delegated further.
    match cs.mint((14, 6), (15, 6), READ, 0) {
        Err(e) => println!("  re-delegating slot 14 : refused ({e:?})"),
        Ok(()) => panic!("a capability without GRANT was delegated"),
    }

    let gone = cs.revoke(12, 6).expect("revoke");
    println!("  revoke slot 12: {gone} capabilities destroyed, slot 12 {}",
        if cs.read(12, 6).unwrap().is_null() { "empty" } else { "intact" });

    // --- M4e: ASIDs (D-022) ---
    let bits = kernel::cap::asid::init();
    let mut pool = AsidPool::new(bits);
    println!();
    println!("asid pool:");
    println!("  hart supports : {bits} bits ({} usable ids)", pool.capacity());
    let mut demo_space = {
        let mut alloc = mm::FRAMES.lock();
        AddressSpace::new(&kspace, &mut *alloc).expect("address space")
    };
    println!("  before assign : satp {:#018x}", demo_space.satp());
    let asid = pool.assign(&mut demo_space).expect("assign");
    println!("  after  assign : satp {:#018x} (asid {})", demo_space.satp(), asid.as_u16());
    println!("  switching to it no longer needs a full TLB flush");

    // --- M6: a page fault handled by a userspace pager ---
    // The spinner from the M3 demo is still runnable and never exits, so it has
    // to go or the run below would never come back.
    let left = sched::kill_all();
    println!();
    println!("demand paging:");
    println!("  cleaned up    : {left} thread(s) left over from the scheduling demo");
    demand_paging_demo(&kspace);

    // --- M7b: the root task ---
    // The last thing the kernel creates.
    println!();
    println!("root task:");
        if let Some(plic) = map.plic {
        kernel::plic::init(plic);
        kernel::irq::enable();
        println!(
            "  interrupts    : plic at {} ({} sources, hart context {}), sie.SEIE on",
            plic.region.start, plic.ndev, plic.context
        );
    }
    let rt = kernel::root::load(&kspace, &map).expect("could not load the root task");
    println!("  image         : {} KiB of ELF embedded in .rodata", kernel::root::IMAGE.len() / 1024);
    println!("  entry         : {:#x}  (image {:#x}..{:#x})", rt.entry, rt.image.0, rt.image.1);
    println!("  address space : root {} (asid {})", rt.space.root(), rt.space.asid().as_u16());
    println!("  cspace        : {} slots at {}", 1usize << rt.cnode.size_bits.saturating_sub(7), rt.cnode.paddr);
    println!(
        "  untyped       : {} regions, {} KiB of RAM handed over",
        rt.untypeds - rt.devices,
        rt.untyped_bytes / 1024
    );
    println!("  device untyped: {} regions, one per device tree `reg`", rt.devices);
    println!(
        "  boot modules  : {} mapped read-only at {:#x}, for the root task to load",
        rt.modules,
        abi::bootinfo::MODULE_VADDR
    );
    println!("  thread        : {}", rt.id);

    let before = sched::exited();
    time::enable();
    time::arm_next_tick();
    // SAFETY: the trap path is installed and the dispatcher handles timers.
    unsafe { sstatus::set(sstatus_bits::SIE) };
    sched::run();
    // SAFETY: masking again before the summary is printed.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    time::disarm();

    println!();
    println!("  threads exited: {}", sched::exited() - before);
    println!();
    println!("M7e-3 complete. Parking. (Ctrl-A x to exit QEMU)");
    qemu::park()
}

const USER_TEXT: usize = 0x1000_0000;
const USER_STACK: usize = 0x2000_0000;

/// `putc(letter); exit()` — the smallest program that proves a thread ran.
fn greeter(letter: u8) -> [u32; 5] {
    [
        li(uprog::A0, letter as u32),
        li(A7, sched::syscall::PUTC as u32),
        ECALL,
        li(A7, sched::syscall::EXIT as u32),
        ECALL,
    ]
}

/// An address space with one page of user text and one page of user stack.
fn user_space(kernel: &mm::Mapper, words: &[u32]) -> AddressSpace {
    let text = mm::alloc_frame().expect("no frames");
    let stack = mm::alloc_frame().expect("no frames");
    // SAFETY: both frames came from the allocator, so nothing else owns them.
    unsafe { uprog::write_to_frame(text, words) };

    let mut alloc = mm::FRAMES.lock();
    let mut space = AddressSpace::new(kernel, &mut *alloc).expect("address space");
    space
        .map(VirtAddr::new(USER_TEXT), text, 0, PteFlags::USER_RX, &mut *alloc)
        .expect("map text");
    space
        .map(VirtAddr::new(USER_STACK), stack, 0, PteFlags::USER_RW, &mut *alloc)
        .expect("map stack");
    space
}

/// The address a client touches that nothing maps up front.
const LAZY: usize = 0x4000_0000;

/// Spawn a client that stores to an unmapped page and a pager that maps it.
fn demand_paging_demo(kernel: &mm::Mapper) {
    const FAULT_EP: u64 = 8;
    const VSPACE: u64 = 9;
    const L1: u64 = 10;
    const L0: u64 = 11;
    const FRAME: u64 = 12;
    const D: u8 = 6;

    let region = |bits: u8| {
        let size = 1usize << bits;
        let mut first = mm::alloc_frame().expect("no frames");
        while first.as_usize() & (size - 1) != 0 {
            first = mm::alloc_frame().expect("no frames");
        }
        for _ in 1..(size / PAGE_SIZE) {
            mm::alloc_frame().expect("no frames");
        }
        RawCap::untyped(first, bits, ALL)
    };

    let mut ep_cs = bootstrap(region(18), D + SLOT_BITS).expect("bootstrap");
    let mut made = [RawCap::NULL; 1];
    ep_cs.retype((0, D), ObjectType::Endpoint, 0, (16, D), &mut made).expect("endpoint");
    let ep = made[0];

    // The client stores 0x5a5a at LAZY, which nothing maps.
    let client_prog = Prog::<32>::new()
        .li(9, (LAZY >> 12) as u32)
        .raw(uprog::slli(9, 9, 12))
        .li(uprog::A0, 0x5a5a)
        .raw(uprog::sd(9, uprog::A0, 0))
        .exit();
    let client = user_space(kernel, client_prog.as_slice());

    // The pager installs both intermediate tables and a frame, then replies.
    let map4 = kernel::ipc::MessageInfo::new(kernel::sched::label::MAP, 4, false).bits() as u32;
    let mut pager_prog = Prog::<64>::new()
        .li(uprog::A0, FAULT_EP as u32)
        .syscall(sched::syscall::RECV)
        .raw(uprog::srli(9, uprog::A0 + 2, 12))
        .raw(uprog::slli(9, 9, 12));
    for (slot, level, rights) in [(L1, 2u32, 0u32), (L0, 1, 0), (FRAME, 0, (READ | WRITE) as u32)] {
        pager_prog = pager_prog
            .li(uprog::A0, slot as u32)
            .li(uprog::A0 + 1, map4)
            .li(uprog::A0 + 2, VSPACE as u32)
            .raw(uprog::mv(uprog::A0 + 3, 9))
            .li(uprog::A0 + 4, rights)
            .li(uprog::A0 + 5, level)
            .syscall(sched::syscall::CALL);
    }
    let pager_prog = pager_prog
        .li(uprog::A0 + 1, kernel::ipc::MessageInfo::new(0, 0, false).bits() as u32)
        .syscall(sched::syscall::REPLY)
        .exit();
    let pager = user_space(kernel, pager_prog.as_slice());

    let mut pager_cs = bootstrap(region(19), D + SLOT_BITS).expect("bootstrap");
    pager_cs.insert(FAULT_EP, D, ep, None).expect("fault ep");
    pager_cs.insert(VSPACE, D, vspace_cap(client.root()), None).expect("vspace");
    pager_cs.retype((0, D), ObjectType::PageTable, 0, (L1, D), &mut made).expect("l1");
    pager_cs.retype((0, D), ObjectType::PageTable, 0, (L0, D), &mut made).expect("l0");
    pager_cs.retype((0, D), ObjectType::Frame, 0, (FRAME, D), &mut made).expect("frame");
    let client_cs = bootstrap(region(18), D + SLOT_BITS).expect("bootstrap");

    println!("  client        : stores to {:#x}, which nothing maps", LAZY);
    println!("  pager         : holds a fault endpoint, a vspace cap and 3 objects");
    assert!(client.translate(VirtAddr::new(LAZY)).is_none());

    sched::spawn_with_cspace(
        &pager,
        VirtAddr::new(USER_TEXT),
        VirtAddr::new(USER_STACK + PAGE_SIZE),
        *pager_cs.root(),
    )
    .expect("spawn pager");
    sched::spawn_full(
        &client,
        VirtAddr::new(USER_TEXT),
        VirtAddr::new(USER_STACK + PAGE_SIZE),
        *client_cs.root(),
        ep,
    )
    .expect("spawn client");

    time::enable();
    time::arm_next_tick();
    // SAFETY: the trap path is installed and the dispatcher handles timers.
    unsafe { sstatus::set(sstatus_bits::SIE) };
    sched::run();
    // SAFETY: masking again before the summary is printed.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    time::disarm();

    match client.translate(VirtAddr::new(LAZY)) {
        Some((pa, flags, _)) => {
            // SAFETY: a frame the pager mapped, reachable through the direct map.
            let v = unsafe { core::ptr::read_volatile(mm::phys_to_virt(pa).as_ptr::<u64>()) };
            println!("  after fault   : {:#x} -> {}  {:?}", LAZY, pa, flags);
            println!("  client's store: {v:#x} (it retried the instruction and it worked)");
        }
        None => println!("  after fault   : still unmapped -- the pager did not run"),
    }
    core::mem::forget((ep_cs, pager_cs, client_cs));
}
