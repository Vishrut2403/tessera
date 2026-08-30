//! User address spaces: a shared kernel half, a private user half, and the wall between.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::mm::address_space::{KERNEL_ROOT_FIRST, kernel_half_fingerprint};
use kernel::mm::page_table::{ENTRIES, MAX_LEVEL, page_size};
use kernel::mm::{
    self, AddressSpace, AddressSpaceError, Asid, KERNEL_VMA, MapError, Mapper, MemoryMap,
    PAGE_SIZE, PhysAddr, PteFlags, VirtAddr,
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

fn kernel_mapper() -> Mapper {
    // SAFETY: written once during boot, read-only thereafter.
    let map = unsafe { (&raw const MAP).read() }.expect("memory map missing");
    let mut alloc = mm::FRAMES.lock();
    mm::kernel_space::build(&map, &mut *alloc).expect("could not build kernel space")
}

fn space(kernel: &Mapper) -> AddressSpace {
    let mut alloc = mm::FRAMES.lock();
    AddressSpace::new(kernel, &mut *alloc).expect("could not build address space")
}

/// A user virtual address well clear of the kernel half.
const USER_VA: usize = 0x2000_0000;

// --- The kernel half ---

#[test_case]
fn kernel_half_starts_at_the_middle_of_the_root_table() {
    assert_eq!(KERNEL_ROOT_FIRST, 256);
    assert_eq!(KERNEL_ROOT_FIRST, ENTRIES / 2);
    assert_eq!(VirtAddr::new(KERNEL_VMA).vpn(MAX_LEVEL), KERNEL_ROOT_FIRST);
}

#[test_case]
fn a_new_space_can_reach_the_kernel() {
    let kernel = kernel_mapper();
    let space = space(&kernel);

    for section in mm::kernel_space::sections() {
        let want = kernel.translate(section.start).expect("kernel section unmapped");
        let got = space.translate(section.start).expect("section missing from user space");
        assert_eq!(want, got, "{} does not match the kernel table", section.name);
    }
}

#[test_case]
fn the_direct_map_is_shared_too() {
    let kernel = kernel_mapper();
    let space = space(&kernel);
    let va = VirtAddr::new(KERNEL_VMA + 0x8000_0000);

    assert_eq!(kernel.translate(va), space.translate(va));
}

#[test_case]
fn the_user_half_starts_empty() {
    let kernel = kernel_mapper();
    let space = space(&kernel);

    for va in [0usize, 0x1000, USER_VA, 0x10_0000_0000] {
        assert!(space.translate(VirtAddr::new(va)).is_none(), "{va:#x} is mapped in a fresh space");
    }
}

#[test_case]
fn distinct_spaces_have_distinct_roots() {
    let kernel = kernel_mapper();
    let a = space(&kernel);
    let b = space(&kernel);

    assert_ne!(a.root(), b.root());
    assert_ne!(a.root(), kernel.root());
}

// --- The wall ---

#[test_case]
fn mapping_into_the_kernel_half_is_refused() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let mut alloc = mm::FRAMES.lock();

    for va in [KERNEL_VMA, KERNEL_VMA + 0x8000_0000, usize::MAX & !(PAGE_SIZE - 1)] {
        assert_eq!(
            space.map(VirtAddr::new(va), frame, 0, PteFlags::USER_RW, &mut *alloc),
            Err(AddressSpaceError::KernelHalf),
            "{va:#x} was accepted"
        );
    }
}

#[test_case]
fn a_range_that_runs_into_the_kernel_half_is_refused() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let mut alloc = mm::FRAMES.lock();

    // Starts in the user half, ends past the top of it.
    let va = VirtAddr::new((KERNEL_ROOT_FIRST - 1) * page_size(MAX_LEVEL));
    assert_eq!(
        space.map_range(va, frame, 2 * page_size(MAX_LEVEL), PteFlags::USER_RW, &mut *alloc),
        Err(AddressSpaceError::KernelHalf)
    );
}

#[test_case]
fn a_mapping_without_the_user_bit_is_refused() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let mut alloc = mm::FRAMES.lock();

    assert_eq!(
        space.map(VirtAddr::new(USER_VA), frame, 0, PteFlags::KERNEL_RW, &mut *alloc),
        Err(AddressSpaceError::NotUserAccessible)
    );
}

#[test_case]
fn unmapping_the_kernel_half_is_refused() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);

    assert_eq!(
        space.unmap(VirtAddr::new(layout::text_start())),
        Err(AddressSpaceError::KernelHalf)
    );
}

// --- User mappings ---

#[test_case]
fn a_user_mapping_round_trips() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let va = VirtAddr::new(USER_VA);

    {
        let mut alloc = mm::FRAMES.lock();
        space.map(va, frame, 0, PteFlags::USER_RW, &mut *alloc).expect("map failed");
    }

    let (pa, flags, level) = space.translate(va).expect("mapping vanished");
    assert_eq!(pa, frame);
    assert_eq!(level, 0);
    assert!(flags.contains(PteFlags::U), "the user bit did not survive");
    assert!(!flags.contains(PteFlags::G), "a user mapping must not be Global");
    assert_eq!(space.unmap(va), Ok(frame));
    assert!(space.translate(va).is_none(), "the mapping outlived unmap");
}

#[test_case]
fn user_mappings_are_private_to_their_space() {
    let kernel = kernel_mapper();
    let mut a = space(&kernel);
    let b = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let va = VirtAddr::new(USER_VA);

    {
        let mut alloc = mm::FRAMES.lock();
        a.map(va, frame, 0, PteFlags::USER_RW, &mut *alloc).expect("map failed");
    }

    assert!(a.translate(va).is_some());
    assert!(b.translate(va).is_none(), "a user mapping leaked into another space");
}

#[test_case]
fn user_mappings_do_not_disturb_the_kernel_half() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let text = VirtAddr::new(layout::text_start());
    let before = kernel.translate(text);

    {
        let mut alloc = mm::FRAMES.lock();
        space
            .map(VirtAddr::new(USER_VA), frame, 0, PteFlags::USER_RW, &mut *alloc)
            .expect("map failed");
    }

    assert_eq!(kernel.translate(text), before, "the kernel table was modified");
    assert_eq!(space.translate(text), before);
    assert!(!space.kernel_half_is_stale(&kernel), "the kernel half drifted");
}

#[test_case]
fn a_changed_kernel_half_is_detected() {
    let mut kernel = kernel_mapper();
    let space = space(&kernel);
    assert!(!space.kernel_half_is_stale(&kernel));

    // A new kernel root entry is exactly what a copied half cannot see (D-021).
    let frame = mm::alloc_frame().expect("no free frames");
    {
        let mut alloc = mm::FRAMES.lock();
        // Root entry 300: inside the kernel half, and nothing maps it today.
        let va = VirtAddr::new(KERNEL_VMA + 44 * page_size(MAX_LEVEL));
        kernel
            .map(va, frame, 0, PteFlags::KERNEL_RW, &mut *alloc)
            .expect("kernel map failed");
    }

    assert_ne!(kernel_half_fingerprint(&kernel), 0);
    assert!(space.kernel_half_is_stale(&kernel), "a new kernel entry went unnoticed");
}

// --- satp ---

#[test_case]
fn a_fresh_space_has_no_asid() {
    let kernel = kernel_mapper();
    let space = space(&kernel);

    assert_eq!(space.asid(), Asid::UNASSIGNED);
    assert_eq!((space.satp() >> 44) & 0xffff, 0);
}

#[test_case]
fn satp_encodes_sv39_and_the_root() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);

    assert_eq!(space.satp() >> 60, 8, "satp MODE is not Sv39");
    assert_eq!(space.satp() & ((1 << 44) - 1), space.root().page_number());

    space.set_asid(Asid::new(0x2a));
    assert_eq!(space.asid().as_u16(), 0x2a);
    assert_eq!((space.satp() >> 44) & 0xffff, 0x2a);
    assert_eq!(space.satp() >> 60, 8, "setting an ASID disturbed MODE");
}

#[test_case]
fn a_non_canonical_address_is_rejected_before_anything_else() {
    let kernel = kernel_mapper();
    let mut space = space(&kernel);
    let frame = mm::alloc_frame().expect("no free frames");
    let mut alloc = mm::FRAMES.lock();

    // Bits 63:39 do not replicate bit 38.
    let va = VirtAddr::new(0x0000_0080_0000_0000);
    assert!(!va.is_canonical());
    assert_eq!(
        space.map(va, frame, 0, PteFlags::USER_RW, &mut *alloc),
        Err(AddressSpaceError::Map(MapError::NonCanonical))
    );
}
