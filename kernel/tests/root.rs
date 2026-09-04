//! The root task: the ELF loader, the untyped split, and the whole boot path
//! from an embedded image to a compiled Rust program spawning a thread (D-039).

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::csr::{sstatus, sstatus_bits};
use kernel::elf::{Elf, ElfError};
use kernel::mm::{self, PAGE_SIZE, PhysAddr, Region, VirtAddr};
use kernel::root;
use kernel::{kernel_entry, layout, qemu, sched, time};

kernel_entry!(test_main_entry);

static mut MAP: Option<mm::MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("discovery");
    // SAFETY: single hart, before any test runs.
    unsafe { (&raw mut MAP).write(Some(map)) };
    time::init(PhysAddr::new(dtb_pa));

    let kspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    // SAFETY: `kspace` maps this code, this stack and `gp` where they are.
    unsafe { mm::kernel_space::activate(&kspace) };

    // The root task takes a real interrupt, so this image needs the controller
    // driven and `sie.SEIE` on, exactly as the kernel binary does.
    if let Some(plic) = map.plic {
        kernel::plic::init(plic);
        kernel::irq::enable();
    }

    test_main();
    qemu::exit_success()
}

fn memory_map() -> mm::MemoryMap {
    // SAFETY: written once during boot, read-only thereafter.
    unsafe { (&raw const MAP).read() }.expect("no memory map")
}

fn kernel_mapper() -> mm::Mapper {
    let map = memory_map();
    let mut alloc = mm::FRAMES.lock();
    mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
}

/// A 64-byte ELF header copied out of the real image, for corrupting.
fn header() -> [u8; 64] {
    let mut h = [0u8; 64];
    h.copy_from_slice(&root::IMAGE[..64]);
    h
}

// --- The loader ---

#[test_case]
fn the_embedded_image_is_a_riscv_executable() {
    let elf = Elf::parse(root::IMAGE).expect("the embedded root task does not parse");
    let (lo, hi) = elf.image_range().expect("no loadable segments");
    assert!(lo <= elf.entry() && elf.entry() < hi, "entry {:#x} outside {lo:#x}..{hi:#x}", elf.entry());
    assert!(lo >= PAGE_SIZE, "the image starts in the null page");
}

#[test_case]
fn no_segment_is_both_writable_and_executable() {
    let elf = Elf::parse(root::IMAGE).unwrap();
    for seg in elf.segments() {
        let seg = seg.expect("bad segment");
        assert!(
            !(seg.writable() && seg.executable()),
            "segment at {:#x} is W+X",
            seg.vaddr
        );
    }
}

#[test_case]
fn segments_never_share_a_page() {
    // What `map_one` refuses at load time, checked against the linker script:
    // two segments in one page would mean mapping one over the other.
    let elf = Elf::parse(root::IMAGE).unwrap();
    let mut prev_end = 0usize;
    for seg in elf.segments() {
        let seg = seg.unwrap();
        assert!(seg.vaddr >= prev_end, "segment at {:#x} overlaps the last page", seg.vaddr);
        prev_end = (seg.vaddr + seg.mem_size).next_multiple_of(PAGE_SIZE);
    }
}

#[test_case]
fn a_bss_tail_is_described_by_memsz_exceeding_filesz() {
    // The root task has statics, so at least one segment must ask for more
    // memory than the file provides -- the bytes the loader leaves zero.
    let elf = Elf::parse(root::IMAGE).unwrap();
    assert!(
        elf.segments().any(|s| { let s = s.unwrap(); s.mem_size > s.data.len() }),
        "no segment has a .bss tail; the loader's zeroing path is untested"
    );
}

#[test_case]
fn garbage_is_not_an_elf() {
    assert_eq!(Elf::parse(&[]).err(), Some(ElfError::TooSmall));
    assert_eq!(Elf::parse(&[0u8; 128]).err(), Some(ElfError::BadMagic));
}

#[test_case]
fn a_32_bit_or_big_endian_image_is_refused() {
    let mut h = header();
    h[4] = 1;
    assert_eq!(Elf::parse(&h).err(), Some(ElfError::WrongFormat));
    let mut h = header();
    h[5] = 2;
    assert_eq!(Elf::parse(&h).err(), Some(ElfError::WrongFormat));
}

#[test_case]
fn a_foreign_architecture_is_refused() {
    let mut h = header();
    // x86-64, which would otherwise parse perfectly well.
    h[18] = 62;
    h[19] = 0;
    assert_eq!(Elf::parse(&h).err(), Some(ElfError::WrongFormat));
}

#[test_case]
fn a_shared_object_is_refused() {
    let mut h = header();
    // ET_DYN: it would need relocations, and nothing here applies them.
    h[16] = 3;
    assert_eq!(Elf::parse(&h).err(), Some(ElfError::NotExecutable));
}

#[test_case]
fn a_program_header_table_past_the_end_is_refused() {
    // The header alone, so the table it points at is not there.
    assert_eq!(Elf::parse(&header()).err(), Some(ElfError::Truncated));
}

// --- Splitting free memory into untypeds ---

#[test_case]
fn a_split_tiles_its_region_exactly() {
    let start = 0x8080_0000;
    let region = Region::new(PhysAddr::new(start), PhysAddr::new(start + 0x1_5000));
    let mut at = start;
    for desc in root::split(region, false) {
        let size = 1usize << desc.size_bits;
        assert_eq!(desc.paddr as usize, at, "a gap at {at:#x}");
        assert_eq!(at & (size - 1), 0, "block at {at:#x} is not {size}-aligned");
        at += size;
    }
    assert_eq!(at, region.end.as_usize(), "the split did not reach the end");
}

#[test_case]
fn a_split_starts_with_what_alignment_allows_not_what_size_allows() {
    // 4 KiB into a 2 MiB boundary with megabytes to spare: the first block is
    // bounded by the address, not by how much memory is left.
    let start = 0x8000_1000;
    let region = Region::new(PhysAddr::new(start), PhysAddr::new(start + 0x40_0000));
    let first = root::split(region, false).next().expect("no blocks");
    assert_eq!(first.size_bits, 12);
    assert_eq!(first.paddr as usize, start);
}

#[test_case]
fn a_sub_page_region_yields_nothing() {
    let region = Region::new(PhysAddr::new(0x8000_0000), PhysAddr::new(0x8000_0800));
    assert_eq!(root::split(region, false).count(), 0);
}

// --- The whole path ---

#[test_case]
fn the_root_task_runs_and_starts_a_thread_of_its_own() {
    // The only test in this image that may call `load`: each call admits
    // another root task to the run queue, and two of them race for the clock.
    let kspace = kernel_mapper();
    let rt = root::load(&kspace, &memory_map()).expect("the root task did not load");

    assert_eq!(rt.entry, Elf::parse(root::IMAGE).unwrap().entry());
    assert!(rt.untypeds > 0, "no untyped memory was handed over");
    assert!(rt.devices > 0, "no device regions were handed over");
    assert!(rt.untypeds > rt.devices, "nothing but devices was handed over");
    assert!(rt.space.asid().as_u16() != 0, "the root task's space has no ASID");

    // The boot modules the kernel carried in but did not load: mapped read-only
    // for the root task to load itself (D-043).
    assert_eq!(rt.modules, root::MODULES.len());
    let (module_pa, flags, _) = rt
        .space
        .translate(VirtAddr::new(abi::bootinfo::MODULE_VADDR))
        .expect("no boot module is mapped");
    assert!(flags.contains(kernel::mm::PteFlags::U), "a module is not user-reachable");
    assert!(flags.contains(kernel::mm::PteFlags::R), "a module is not readable");
    assert!(!flags.contains(kernel::mm::PteFlags::W), "a module is writable");
    assert!(!flags.contains(kernel::mm::PteFlags::X), "a module is executable in place");
    assert_ne!(
        module_pa,
        PhysAddr::new(root::MODULES[0].1.as_ptr() as usize),
        "the module was mapped in place rather than copied"
    );
    let seen = mm::phys_to_virt(module_pa).as_ptr::<u8>();
    for (i, byte) in root::MODULES[0].1.iter().take(64).enumerate() {
        // SAFETY: a frame the kernel filled, read back through the direct map.
        assert_eq!(unsafe { seen.add(i).read_volatile() }, *byte, "module byte {i} differs");
    }

    // And the boot info names each one, so the root task can ask for it.
    let (info_pa, _, _) =
        rt.space.translate(VirtAddr::new(abi::bootinfo::VADDR)).expect("no boot info page");
    // SAFETY: the page the kernel just wrote a `BootInfo` into.
    let bi = unsafe { &*mm::phys_to_virt(info_pa).as_ptr::<abi::BootInfo>() };
    assert_eq!(bi.modules().len(), root::MODULES.len());
    for (name, bytes) in root::MODULES {
        let m = bi.module(name).unwrap_or_else(|| panic!("no module called {name}"));
        assert_eq!(m.size, bytes.len() as u64);
        assert!(rt.space.translate(VirtAddr::new(m.vaddr as usize)).is_some());
    }
    assert!(bi.module("nothing-by-this-name").is_none());

    // Nothing maps the scratch region yet: the root task builds the two
    // intermediate page tables and the mapping itself (D-035).
    let scratch = VirtAddr::new(root::FREE_VADDR);
    assert!(rt.space.translate(scratch).is_none());

    let before = sched::exited();
    time::enable();
    time::arm_next_tick();
    // SAFETY: the trap path is installed and the dispatcher handles timers.
    unsafe { sstatus::set(sstatus_bits::SIE) };
    sched::run();
    // SAFETY: masking again now that the run queue is empty.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    time::disarm();

    let (pa, flags, _) = rt.space.translate(scratch).expect("the root task mapped nothing");
    assert!(flags.contains(kernel::mm::PteFlags::U), "the scratch page is not user-reachable");

    let p = mm::phys_to_virt(pa).as_ptr::<u64>();
    // SAFETY: a frame the root task retyped and mapped, read through the direct map.
    let (probe, done) = unsafe { (p.read_volatile(), p.add(1).read_volatile()) };
    assert_eq!(probe, 0x7e55e7a, "the root task's own write is missing");
    assert_eq!(done >> 48, 0xd02e, "the root task did not reach the end: {done:#x}");
    assert!(done & 0xffff != 0, "no child thread id was recorded");

    // The root task wrote the physical address `GetAddress` gave it for a
    // device frame; it must be a region the device tree called a device.
    // SAFETY: the same scratch page, one word further on.
    let device_pa = unsafe { p.add(2).read_volatile() } as usize;
    assert!(
        memory_map().devices.iter().any(|d| d.contains(PhysAddr::new(device_pa))),
        "{device_pa:#x} is not a device region the kernel discovered"
    );

    // And the interrupt it took: the low half is the notification word it was
    // woken with, the high half the source the device tree named.
    // SAFETY: the same scratch page, one word further on.
    let irq_word = unsafe { p.add(3).read_volatile() };
    assert_eq!(irq_word & 0xffff_ffff, 1, "the root task was not woken by its own badge");
    let irq = (irq_word >> 32) as usize;
    assert!(irq > 0 && irq < kernel::irq::MAX_IRQ, "source {irq} is not a real interrupt");
    assert!(kernel::irq::is_claimed(irq), "source {irq} was never claimed");

    // The task it loaded out of a boot module, in an address space of its own,
    // answered -- and its own page at the address the root task also has a page
    // at held something else (D-043).
    // SAFETY: the same scratch page, one word further on.
    let spawned = unsafe { p.add(4).read_volatile() };
    assert_eq!(spawned >> 48, 0x5b1c, "the root task spawned nothing: {spawned:#x}");
    assert!(spawned & 0xffff != 0, "the spawned task reported no thread id");

    // And it brought a real device up: probe, feature negotiation, a queue and
    // `DRIVER_OK`, all from an unprivileged process (D-044). The capacity is
    // the image `kernel/build.rs` writes, so this is end to end -- the driver
    // read it out of the device's own configuration space.
    // SAFETY: the same scratch page, one word further on.
    let disk = unsafe { p.add(5).read_volatile() };
    let (sectors, verified) = (disk & 0xffff_ffff, disk >> 32);
    assert_eq!(sectors, 2048, "the driver reported {sectors} sectors, not the disk image's 2048");

    // Then it moved bytes: two sectors, far apart, each carrying its own number
    // at both ends, fetched over a virtqueue and completed by an interrupt the
    // driver blocked for (D-045).
    assert_eq!(verified, 2, "the driver read back {verified} of 2 sectors correctly");

    // And then it served them, through a filesystem server that is itself only
    // a client of the driver, to a task holding nothing but a send-only
    // endpoint and a filename: it printed a file, read a byte range spanning
    // two blocks, and was refused a name that does not exist (D-046, D-047).
    // SAFETY: the same scratch page, one word further on.
    let checks = unsafe { p.add(6).read_volatile() };
    assert_eq!(checks, 3, "the client passed {checks} of 3 checks against the filesystem");

    // The root task, the thread it made, and the three processes it loaded.
    assert_eq!(sched::exited() - before, 5);
}

// --- Boot modules (D-043) ---

#[test_case]
fn every_boot_module_is_a_riscv_executable() {
    assert!(!root::MODULES.is_empty(), "no boot modules were embedded");
    for (name, bytes) in root::MODULES {
        let elf =
            Elf::parse(bytes).unwrap_or_else(|e| panic!("module {name} does not parse: {e:?}"));
        let (lo, hi) = elf.image_range().expect("no loadable segments");
        assert!(lo <= elf.entry() && elf.entry() < hi, "module {name}: entry outside its image");
    }
}

