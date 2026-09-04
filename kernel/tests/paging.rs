//! The kernel address space: W^X, the direct map, and no identity mapping.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::mm::kernel_space;
use kernel::mm::{
    self, KERNEL_VMA, MemoryMap, Mapper, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr,
};
use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

static mut MAP: Option<MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range())
        .expect("memory discovery failed");
    // SAFETY: single hart, before any test runs.
    unsafe { (&raw mut MAP).write(Some(map)) };
    test_main();
    qemu::exit_success()
}

fn memory_map() -> MemoryMap {
    // SAFETY: written once during boot, read-only thereafter.
    unsafe { (&raw const MAP).read() }.expect("memory map missing")
}

fn build() -> Mapper {
    let map = memory_map();
    let mut alloc = mm::FRAMES.lock();
    kernel_space::build(&map, &mut *alloc).expect("could not build kernel space")
}

// --- W^X ---

#[test_case]
fn kernel_text_is_executable_and_not_writable() {
    let m = build();
    let (_, flags, _) = m.translate(VirtAddr::new(layout::text_start())).expect(".text unmapped");
    assert!(flags.contains(PteFlags::X), ".text is not executable");
    assert!(!flags.contains(PteFlags::W), ".text is WRITABLE, so W^X is broken");
}

#[test_case]
fn rodata_is_neither_writable_nor_executable() {
    let m = build();
    let (_, flags, _) =
        m.translate(VirtAddr::new(layout::rodata_start())).expect(".rodata unmapped");
    assert!(!flags.contains(PteFlags::W), ".rodata is writable");
    assert!(!flags.contains(PteFlags::X), ".rodata is executable");
}

#[test_case]
fn data_is_writable_and_not_executable() {
    let m = build();
    let (_, flags, _) = m.translate(VirtAddr::new(layout::data_start())).expect(".data unmapped");
    assert!(flags.contains(PteFlags::W), ".data is not writable");
    assert!(!flags.contains(PteFlags::X), ".data is EXECUTABLE");
}

#[test_case]
fn the_whole_of_text_is_covered_and_none_of_it_is_writable() {
    // Not just the first page: catches a map_range that stopped early.
    let m = build();
    let start = layout::text_start();
    let end = layout::text_end();
    let mut va = start;
    while va < end {
        let (_, flags, _) =
            m.translate(VirtAddr::new(va)).unwrap_or_else(|| panic!("{va:#x} unmapped"));
        assert!(flags.contains(PteFlags::X), "{va:#x} in .text is not executable");
        assert!(!flags.contains(PteFlags::W), "{va:#x} in .text is writable");
        va += PAGE_SIZE;
    }
}

#[test_case]
fn there_is_no_writable_alias_of_kernel_text() {
    // The entire argument for D-013.
    let m = build();
    let text_phys = layout::text_start() - KERNEL_VMA;
    let via_direct_map = VirtAddr::new(KERNEL_VMA + text_phys);
    let (pa, flags, _) = m.translate(via_direct_map).expect("unmapped");
    assert_eq!(pa, PhysAddr::new(text_phys));
    assert!(!flags.contains(PteFlags::W), "kernel text has a writable alias");
}

// --- The direct map ---

#[test_case]
fn direct_map_covers_free_memory_read_write() {
    let m = build();
    let map = memory_map();
    let frame = map.free.iter().next().expect("no free memory").start;
    let (pa, flags, _) =
        m.translate(VirtAddr::new(KERNEL_VMA + frame.as_usize())).expect("frame unmapped");
    assert_eq!(pa, frame);
    assert!(flags.contains(PteFlags::W), "direct map is not writable");
    assert!(!flags.contains(PteFlags::X), "direct map is EXECUTABLE");
}

#[test_case]
fn direct_map_agrees_with_phys_to_virt() {
    // phys_to_virt is the promise; the page table is whether we kept it.
    let m = build();
    let map = memory_map();
    let frame = map.free.iter().next().expect("no free memory").start;
    let (pa, _, _) = m.translate(mm::phys_to_virt(frame)).expect("unmapped");
    assert_eq!(pa, frame);
}

#[test_case]
fn direct_map_spans_every_ram_region() {
    let m = build();
    let map = memory_map();
    for region in map.ram.iter() {
        // Sample the first and last page of each RAM bank.
        for pa in [region.start, PhysAddr::new(region.end.as_usize() - PAGE_SIZE)] {
            let va = VirtAddr::new(KERNEL_VMA + pa.as_usize());
            assert!(m.translate(va).is_some(), "{pa} is not in the direct map");
        }
    }
}

// --- What must not be mapped ---

#[test_case]
fn the_low_half_is_empty() {
    // The bootstrap identity mappings must not survive into the kernel table.
    let m = build();
    for va in [0x8020_0000usize, 0x8000_0000, 0x1000_0000, 0x0010_0000, 0x87e0_0000] {
        assert!(
            m.translate(VirtAddr::new(va)).is_none(),
            "{va:#x} is still identity-mapped in the kernel table"
        );
    }
}

#[test_case]
fn nothing_in_the_kernel_space_is_user_reachable() {
    // A single U bit anywhere here would hand userspace the kernel.
    let m = build();
    let probes = [
        layout::text_start(),
        layout::rodata_start(),
        layout::data_start(),
        KERNEL_VMA + kernel::uart::UART0_PHYS,
    ];
    for va in probes {
        let (_, flags, _) = m.translate(VirtAddr::new(va)).expect("unmapped");
        assert!(!flags.contains(PteFlags::U), "{va:#x} is user-reachable");
    }
}

#[test_case]
fn kernel_mappings_are_global() {
    // G means the translation survives an ASID switch.
    let m = build();
    for va in [layout::text_start(), layout::data_start()] {
        let (_, flags, _) = m.translate(VirtAddr::new(va)).expect("unmapped");
        assert!(flags.contains(PteFlags::G), "{va:#x} is not global");
    }
}

// --- Devices ---

#[test_case]
fn devices_are_mapped_read_write_and_not_executable() {
    let m = build();
    for (name, pa) in kernel_space::DEVICES {
        let va = VirtAddr::new(KERNEL_VMA + pa);
        let (got, flags, _) = m.translate(va).unwrap_or_else(|| panic!("{name} unmapped"));
        assert_eq!(got, PhysAddr::new(pa), "{name} maps to the wrong frame");
        assert!(flags.contains(PteFlags::W), "{name} is not writable");
        assert!(!flags.contains(PteFlags::X), "{name} is executable");
    }
}

#[test_case]
fn the_live_table_is_the_one_we_are_running_on() {
    // satp holds a root; kernel_space::root() remembers which one we installed.
    let satp = kernel::csr::satp::read();
    assert_eq!(satp >> 60, 8, "not in Sv39 mode");
    let root_from_satp = (satp & ((1 << 44) - 1)) << 12;
    match kernel_space::root() {
        // Tests never activate, so the live table is still the bootstrap one.
        None => assert_ne!(root_from_satp, 0, "satp points at nothing"),
        Some(root) => assert_eq!(root.as_usize(), root_from_satp),
    }
}
