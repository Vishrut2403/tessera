//! Sv39 page tables, exercised with the MMU still off.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::mm::page_table::{MAX_LEVEL, page_size};
use kernel::mm::{
    self, MapError, Mapper, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr,
};
use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range())
        .expect("memory discovery failed");
    test_main();
    qemu::exit_success()
}

/// A fresh, empty address space plus the allocator that feeds it.
macro_rules! with_mapper {
    (|$m:ident, $alloc:ident| $body:block) => {{
        let mut guard = mm::FRAMES.lock();
        let $alloc = &mut *guard;
        // Some tests only call translate(), which takes &self.
        #[allow(unused_mut)]
        let mut $m = Mapper::new($alloc).expect("no frames for a root table");
        $body
    }};
}

const KVA: usize = 0xFFFF_FFD0_0000_0000;

// --- Flag encoding ---

#[test_case]
fn flags_distinguish_leaf_from_branch() {
    assert!(PteFlags::KERNEL_RX.is_leaf());
    assert!(PteFlags::KERNEL_RW.is_leaf());
    // V alone is a branch: no R, W or X.
    assert!(!PteFlags::V.is_leaf());
}

#[test_case]
fn write_without_read_is_rejected() {
    // Reserved encoding in the spec, not write-only memory.
    let bad = PteFlags::V | PteFlags::W;
    assert!(!bad.is_valid_combination());
    assert!(PteFlags::KERNEL_RW.is_valid_combination());
}

#[test_case]
fn kernel_flags_are_never_user_reachable() {
    for f in [PteFlags::KERNEL_RX, PteFlags::KERNEL_RO, PteFlags::KERNEL_RW] {
        assert!(!f.contains(PteFlags::U), "kernel mapping is user-reachable");
    }
}

#[test_case]
fn kernel_text_is_never_writable() {
    assert!(!PteFlags::KERNEL_RX.contains(PteFlags::W));
    assert!(!PteFlags::KERNEL_RO.contains(PteFlags::W));
}

#[test_case]
fn entry_round_trips_address_and_flags() {
    let pa = PhysAddr::new(0x8123_4000);
    let pte = kernel::mm::Pte::leaf(pa, PteFlags::KERNEL_RW);
    assert_eq!(pte.phys_addr(), pa, "PPN field did not round trip");
    assert!(pte.is_leaf());
    assert!(!pte.is_branch());
    assert!(pte.flags().contains(PteFlags::V));
}

#[test_case]
fn branch_entry_has_no_permission_bits() {
    // The spec requires R/W/X and A/D/U to be zero in a non-leaf.
    let pte = kernel::mm::Pte::branch(PhysAddr::new(0x8100_0000));
    assert!(pte.is_branch());
    assert!(!pte.is_leaf());
    assert!(!pte.flags().intersects(PteFlags::R | PteFlags::W | PteFlags::X));
    assert!(!pte.flags().intersects(PteFlags::A | PteFlags::D | PteFlags::U));
}

// --- Mapping and translation ---

#[test_case]
fn map_then_translate_a_4k_page() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        let pa = PhysAddr::new(0x8100_0000);
        m.map(va, pa, 0, PteFlags::KERNEL_RW, alloc).unwrap();

        let (got, flags, level) = m.translate(va).expect("translation failed");
        assert_eq!(got, pa);
        assert_eq!(level, 0);
        assert!(flags.contains(PteFlags::W));
    });
}

#[test_case]
fn translation_carries_the_offset_within_the_page() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        let pa = PhysAddr::new(0x8100_0000);
        m.map(va, pa, 0, PteFlags::KERNEL_RW, alloc).unwrap();

        let (got, _, _) = m.translate(va.offset(0x321)).unwrap();
        assert_eq!(got, pa.offset(0x321));
    });
}

#[test_case]
fn megapage_maps_two_megabytes() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        let pa = PhysAddr::new(0x8020_0000);
        m.map(va, pa, 1, PteFlags::KERNEL_RW, alloc).unwrap();

        let (_, _, level) = m.translate(va).unwrap();
        assert_eq!(level, 1, "expected a level-1 leaf");

        // The offset mask must come from the level, not from PAGE_SIZE.
        let last = page_size(1) - 1;
        let (got, _, _) = m.translate(va.offset(last)).unwrap();
        assert_eq!(got, pa.offset(last));
    });
}

#[test_case]
fn gigapage_lives_in_the_root_table() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        let pa = PhysAddr::new(0x8000_0000);
        // A 1 GiB leaf sits in the root itself, so this must consume no intermediate tables at all.
        let before = alloc.frames_allocated();
        m.map(va, pa, MAX_LEVEL, PteFlags::KERNEL_RW, alloc).unwrap();
        assert_eq!(alloc.frames_allocated(), before, "a gigapage allocated a table");

        let (got, _, level) = m.translate(va).unwrap();
        assert_eq!(level, MAX_LEVEL);
        assert_eq!(got, pa);
    });
}

#[test_case]
fn a_fresh_4k_mapping_costs_two_tables() {
    with_mapper!(|m, alloc| {
        let before = alloc.frames_allocated();
        m.map(VirtAddr::new(KVA), PhysAddr::new(0x8100_0000), 0, PteFlags::KERNEL_RW, alloc)
            .unwrap();
        // Levels 1 and 0; the root already existed.
        assert_eq!(alloc.frames_allocated() - before, 2);
    });
}

#[test_case]
fn a_second_mapping_nearby_reuses_the_tables() {
    with_mapper!(|m, alloc| {
        m.map(VirtAddr::new(KVA), PhysAddr::new(0x8100_0000), 0, PteFlags::KERNEL_RW, alloc)
            .unwrap();
        let before = alloc.frames_allocated();
        m.map(
            VirtAddr::new(KVA + PAGE_SIZE),
            PhysAddr::new(0x8100_1000),
            0,
            PteFlags::KERNEL_RW,
            alloc,
        )
        .unwrap();
        assert_eq!(alloc.frames_allocated(), before, "adjacent page allocated new tables");
    });
}

#[test_case]
fn unmapped_addresses_do_not_translate() {
    with_mapper!(|m, alloc| {
        let _ = alloc;
        assert!(m.translate(VirtAddr::new(KVA)).is_none());
    });
}

#[test_case]
fn unmap_removes_the_translation() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        let pa = PhysAddr::new(0x8100_0000);
        m.map(va, pa, 0, PteFlags::KERNEL_RW, alloc).unwrap();
        assert_eq!(m.unmap(va).unwrap(), pa);
        assert!(m.translate(va).is_none());
    });
}

#[test_case]
fn unmapping_nothing_is_an_error() {
    with_mapper!(|m, alloc| {
        let _ = alloc;
        assert_eq!(m.unmap(VirtAddr::new(KVA)), Err(MapError::NotMapped));
    });
}

// --- Rejections ---

#[test_case]
fn double_mapping_is_rejected() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        m.map(va, PhysAddr::new(0x8100_0000), 0, PteFlags::KERNEL_RW, alloc).unwrap();
        assert_eq!(
            m.map(va, PhysAddr::new(0x8200_0000), 0, PteFlags::KERNEL_RW, alloc),
            Err(MapError::AlreadyMapped)
        );
    });
}

#[test_case]
fn misaligned_superpage_is_rejected() {
    with_mapper!(|m, alloc| {
        // A 2 MiB leaf whose physical address is only 4 KiB aligned.
        assert_eq!(
            m.map(
                VirtAddr::new(KVA),
                PhysAddr::new(0x8000_1000),
                1,
                PteFlags::KERNEL_RW,
                alloc
            ),
            Err(MapError::MisalignedPhys)
        );
        assert_eq!(
            m.map(
                VirtAddr::new(KVA + PAGE_SIZE),
                PhysAddr::new(0x8020_0000),
                1,
                PteFlags::KERNEL_RW,
                alloc
            ),
            Err(MapError::MisalignedVirt)
        );
    });
}

#[test_case]
fn non_canonical_addresses_are_rejected() {
    with_mapper!(|m, alloc| {
        // Bit 39 set, bits above it clear: not a sign extension of bit 38.
        let bad = VirtAddr::new(1 << 39);
        assert!(!bad.is_canonical());
        assert_eq!(
            m.map(bad, PhysAddr::new(0x8100_0000), 0, PteFlags::KERNEL_RW, alloc),
            Err(MapError::NonCanonical)
        );
        assert!(m.translate(bad).is_none());
    });
}

#[test_case]
fn branch_flags_are_not_a_valid_leaf() {
    with_mapper!(|m, alloc| {
        assert_eq!(
            m.map(VirtAddr::new(KVA), PhysAddr::new(0x8100_0000), 0, PteFlags::V, alloc),
            Err(MapError::BadFlags)
        );
    });
}

#[test_case]
fn write_only_mapping_is_refused() {
    with_mapper!(|m, alloc| {
        assert_eq!(
            m.map(
                VirtAddr::new(KVA),
                PhysAddr::new(0x8100_0000),
                0,
                PteFlags::V | PteFlags::W,
                alloc
            ),
            Err(MapError::BadFlags)
        );
    });
}

#[test_case]
fn mapping_inside_a_superpage_is_refused() {
    with_mapper!(|m, alloc| {
        let base = VirtAddr::new(KVA);
        m.map(base, PhysAddr::new(0x8000_0000), 1, PteFlags::KERNEL_RW, alloc).unwrap();
        // Splitting a live superpage is unimplemented; say so rather than corrupt the tree.
        assert_eq!(
            m.map(
                base.offset(PAGE_SIZE),
                PhysAddr::new(0x8100_0000),
                0,
                PteFlags::KERNEL_RW,
                alloc
            ),
            Err(MapError::CoveredBySuperpage)
        );
    });
}

#[test_case]
fn bad_level_is_rejected() {
    with_mapper!(|m, alloc| {
        assert_eq!(
            m.map(VirtAddr::new(KVA), PhysAddr::new(0x8000_0000), 3, PteFlags::KERNEL_RW, alloc),
            Err(MapError::BadLevel)
        );
    });
}

// --- map_range and superpage selection ---

#[test_case]
fn map_range_uses_a_gigapage_when_it_can() {
    with_mapper!(|m, alloc| {
        let before = alloc.frames_allocated();
        m.map_range(
            VirtAddr::new(KVA),
            PhysAddr::new(0x8000_0000),
            page_size(MAX_LEVEL),
            PteFlags::KERNEL_RW,
            alloc,
        )
        .unwrap();
        // One 1 GiB leaf in the root: no tables at all.
        assert_eq!(alloc.frames_allocated(), before);
        assert_eq!(m.translate(VirtAddr::new(KVA)).unwrap().2, MAX_LEVEL);
    });
}

#[test_case]
fn map_range_falls_back_to_smaller_pages() {
    with_mapper!(|m, alloc| {
        // 4 KiB past a gigapage boundary, so the mapper must step down to level 0.
        let va = VirtAddr::new(KVA + PAGE_SIZE);
        m.map_range(va, PhysAddr::new(0x8000_1000), PAGE_SIZE * 4, PteFlags::KERNEL_RW, alloc)
            .unwrap();
        for i in 0..4 {
            let (pa, _, level) = m.translate(va.offset(i * PAGE_SIZE)).unwrap();
            assert_eq!(level, 0);
            assert_eq!(pa, PhysAddr::new(0x8000_1000 + i * PAGE_SIZE));
        }
    });
}

#[test_case]
fn map_range_covers_every_byte_it_promised() {
    with_mapper!(|m, alloc| {
        let va = VirtAddr::new(KVA);
        let pa = PhysAddr::new(0x8020_0000);
        let size = 6 * PAGE_SIZE;
        m.map_range(va, pa, size, PteFlags::KERNEL_RW, alloc).unwrap();
        // Every page in the range, and nothing past the end.
        for i in 0..6 {
            assert!(m.translate(va.offset(i * PAGE_SIZE)).is_some(), "page {i} missing");
        }
        assert!(m.translate(va.offset(size)).is_none(), "mapped past the end");
    });
}

#[test_case]
fn independent_address_spaces_do_not_share_mappings() {
    let mut guard = mm::FRAMES.lock();
    let alloc = &mut *guard;
    let mut a = Mapper::new(alloc).unwrap();
    let mut b = Mapper::new(alloc).unwrap();
    assert_ne!(a.root(), b.root());

    let va = VirtAddr::new(KVA);
    a.map(va, PhysAddr::new(0x8100_0000), 0, PteFlags::KERNEL_RW, alloc).unwrap();
    assert!(a.translate(va).is_some());
    assert!(b.translate(va).is_none(), "mapping leaked between address spaces");

    b.map(va, PhysAddr::new(0x8200_0000), 0, PteFlags::KERNEL_RW, alloc).unwrap();
    assert_eq!(a.translate(va).unwrap().0, PhysAddr::new(0x8100_0000));
    assert_eq!(b.translate(va).unwrap().0, PhysAddr::new(0x8200_0000));
}
