//! Capability spaces: resolving addresses, deriving copies, and revoking them.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::asid::{AsidError, AsidPool};
use kernel::cap::cspace::{CSpace, ResolveError, bootstrap};
use kernel::cap::rights::{ALL, GRANT, READ, WRITE};
use kernel::cap::{CapError, ObjectType, RawCap, kind};
use kernel::mm::{self, PhysAddr};
use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("memory discovery");
    test_main();
    qemu::exit_success()
}

/// A 2 MiB untyped region, aligned to its own size.
fn region(bits: u8) -> RawCap {
    let size = 1usize << bits;
    let mut first = mm::alloc_frame().expect("no frames");
    while first.as_usize() & (size - 1) != 0 {
        first = mm::alloc_frame().expect("no frames");
    }
    for _ in 1..(size / mm::PAGE_SIZE) {
        mm::alloc_frame().expect("no frames");
    }
    RawCap {
        kind: ObjectType::Untyped,
        rights: ALL,
        size_bits: bits,
        paddr: first,
        watermark: 0,
        badge: 0,
    }
}

/// A capability space rooted in a 64-slot CNode, so the root radix is 6.
const D: u8 = 6;

fn space() -> CSpace {
    bootstrap(region(21), D + 6).expect("bootstrap failed")
}

// --- Bootstrap and resolution ---

#[test_case]
fn a_bootstrapped_space_holds_its_own_untyped_and_cnode() {
    let cs = space();
    assert_eq!(cs.root_slots(), 64);

    let untyped = cs.read(0, D).unwrap();
    assert_eq!(untyped.kind, ObjectType::Untyped);
    assert_eq!(untyped.rights, ALL);

    let cnode = cs.read(1, D).unwrap();
    assert_eq!(cnode.kind, ObjectType::CNode);
    assert_eq!(cnode.paddr, cs.root().paddr, "slot 1 is not the root CNode itself");
}

#[test_case]
fn empty_slots_resolve_but_hold_nothing() {
    let cs = space();
    for i in 2..64u64 {
        assert!(cs.read(i, D).unwrap().is_null(), "slot {i} was not empty");
    }
}

#[test_case]
fn the_wrong_depth_does_not_resolve() {
    let cs = space();
    // The root consumes 6 bits; asking for 5 stops partway into it.
    assert_eq!(cs.resolve(0, 5), Err(ResolveError::DepthMismatch));
    // And 7 bits would need a second level that slot 0 is not.
    assert_eq!(cs.resolve(0, 7), Err(ResolveError::NotACNode));
    assert_eq!(cs.resolve(0, 65), Err(ResolveError::TooDeep));
}

#[test_case]
fn a_cnode_in_a_slot_becomes_a_second_level() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    // A 64-slot CNode in slot 2, so (2 << 6) | n at depth 12 addresses it.
    cs.retype((0, D), ObjectType::CNode, D + 6, (2, D), &mut made).expect("retype");

    let inner = cs.read(2, D).unwrap();
    assert_eq!(inner.kind, ObjectType::CNode);

    // Every slot of the inner CNode is reachable, and empty.
    for i in 0..64u64 {
        let cap = cs.read((2 << 6) | i, 12).expect("inner slot unreachable");
        assert!(cap.is_null());
    }
    // A capability put in the inner CNode is found through the two-level path.
    cs.retype((0, D), ObjectType::Frame, 0, ((2 << 6) | 5, 12), &mut made).expect("retype");
    assert_eq!(cs.read((2 << 6) | 5, 12).unwrap().kind, ObjectType::Frame);
}

// --- Retyping through a space ---

#[test_case]
fn retyping_installs_objects_as_children_of_the_untyped() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 4];
    cs.retype((0, D), ObjectType::Frame, 0, (8, D), &mut made).expect("retype");

    for i in 0..4u64 {
        assert_eq!(cs.read(8 + i, D).unwrap().kind, ObjectType::Frame);
    }
    // The CNode from bootstrap, plus the four frames.
    assert_eq!(cs.descendants(0, D).unwrap(), 5);
}

#[test_case]
fn retyping_moves_the_watermark() {
    let mut cs = space();
    let before = cs.read(0, D).unwrap().watermark;
    let mut made = [RawCap::NULL; 2];
    cs.retype((0, D), ObjectType::Frame, 0, (8, D), &mut made).expect("retype");

    let after = cs.read(0, D).unwrap().watermark;
    assert!(after > before, "the watermark did not move");
    assert_eq!(after - before, 2 * mm::PAGE_SIZE);
}

#[test_case]
fn retyping_into_an_occupied_slot_is_refused_and_changes_nothing() {
    let mut cs = space();
    let watermark = cs.read(0, D).unwrap().watermark;

    let mut made = [RawCap::NULL; 1];
    // Slot 1 already holds the root CNode.
    assert_eq!(
        cs.retype((0, D), ObjectType::Frame, 0, (1, D), &mut made),
        Err(CapError::SlotOccupied)
    );
    assert_eq!(cs.read(0, D).unwrap().watermark, watermark, "the region was touched anyway");
}

#[test_case]
fn retyping_needs_write_on_the_untyped() {
    let mut cs = space();
    // Hand a read-only copy of the untyped to slot 3, then try to retype it.
    cs.mint((0, D), (3, D), READ, 0).expect("mint");

    let mut made = [RawCap::NULL; 1];
    assert_eq!(
        cs.retype((3, D), ObjectType::Frame, 0, (8, D), &mut made),
        Err(CapError::MissingRights { wanted: WRITE, held: READ })
    );
}

// --- Derivation ---

#[test_case]
fn a_minted_copy_is_a_child_with_no_more_rights_than_the_original() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");

    cs.mint((8, D), (9, D), READ, 0x1234).expect("mint");
    let copy = cs.read(9, D).unwrap();

    assert_eq!(copy.kind, ObjectType::Endpoint);
    assert_eq!(copy.paddr, made[0].paddr, "the copy names a different object");
    assert_eq!(copy.rights, READ);
    assert_eq!(copy.badge, 0x1234);
    assert_eq!(cs.descendants(8, D).unwrap(), 1);
}

#[test_case]
fn minting_cannot_widen_rights() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");

    // Weaken to READ|GRANT, then try to mint ALL back out of it.
    cs.mint((8, D), (9, D), READ | GRANT, 0).expect("mint");
    cs.mint((9, D), (10, D), ALL, 0).expect("mint");

    assert_eq!(cs.read(10, D).unwrap().rights, READ | GRANT, "rights were widened");
}

#[test_case]
fn minting_needs_grant_on_the_original() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");

    // A copy without GRANT cannot be copied again.
    cs.mint((8, D), (9, D), READ | WRITE, 0).expect("mint");
    assert_eq!(
        cs.mint((9, D), (10, D), READ, 0),
        Err(CapError::MissingRights { wanted: GRANT, held: READ | WRITE })
    );
}

#[test_case]
fn derivation_nests() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");

    cs.mint((8, D), (9, D), ALL, 1).expect("mint");
    cs.mint((9, D), (10, D), ALL, 2).expect("mint");
    cs.mint((10, D), (11, D), ALL, 3).expect("mint");

    // A chain three deep, all descended from slot 8.
    assert_eq!(cs.descendants(8, D).unwrap(), 3);
    assert_eq!(cs.descendants(9, D).unwrap(), 2);
    assert_eq!(cs.descendants(11, D).unwrap(), 0);
}

// --- Revocation ---

#[test_case]
fn revoking_removes_descendants_and_leaves_the_original() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");
    cs.mint((8, D), (9, D), ALL, 1).expect("mint");
    cs.mint((9, D), (10, D), ALL, 2).expect("mint");

    assert_eq!(cs.revoke(8, D).unwrap(), 2);

    assert_eq!(cs.read(8, D).unwrap().kind, ObjectType::Endpoint, "the original went too");
    assert!(cs.read(9, D).unwrap().is_null(), "a child survived");
    assert!(cs.read(10, D).unwrap().is_null(), "a grandchild survived");
    assert_eq!(cs.descendants(8, D).unwrap(), 0);
}

#[test_case]
fn revoking_walks_a_wide_tree_as_well_as_a_deep_one() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");

    // Four children of slot 8, each with two children of its own.
    for (i, child) in (16..20u64).enumerate() {
        cs.mint((8, D), (child, D), ALL, i as u64).expect("mint");
        cs.mint((child, D), (24 + (i as u64 * 2), D), ALL, 0).expect("mint");
        cs.mint((child, D), (25 + (i as u64 * 2), D), ALL, 0).expect("mint");
    }
    assert_eq!(cs.descendants(8, D).unwrap(), 12);

    assert_eq!(cs.revoke(8, D).unwrap(), 12);
    for i in 16..32u64 {
        assert!(cs.read(i, D).unwrap().is_null(), "slot {i} survived revocation");
    }
    assert_eq!(cs.read(8, D).unwrap().kind, ObjectType::Endpoint);
}

#[test_case]
fn deleting_takes_the_capability_itself_too() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");
    cs.mint((8, D), (9, D), ALL, 0).expect("mint");

    assert_eq!(cs.delete(8, D).unwrap(), 2);
    assert!(cs.read(8, D).unwrap().is_null());
    assert!(cs.read(9, D).unwrap().is_null());
}

#[test_case]
fn revoking_an_untyped_lets_its_memory_be_used_again() {
    let mut cs = space();

    // A *second*, independent region, put in slot 4 with no parent. Revoking
    // the region the CSpace itself was carved from would destroy the CNode we
    // are standing on -- correct behaviour, and the reason a real init task
    // does not keep that original untyped inside the space it roots.
    cs.insert(4, D, region(20), None).expect("insert spare region");

    let mut made = [RawCap::NULL; 4];
    cs.retype((4, D), ObjectType::Frame, 0, (8, D), &mut made).expect("retype");
    let first_time = made;
    assert!(cs.read(4, D).unwrap().watermark > 0);

    assert_eq!(cs.revoke(4, D).unwrap(), 4, "the four frames should have gone");
    assert_eq!(cs.read(4, D).unwrap().watermark, 0, "the watermark was not reset");
    for i in 8..12u64 {
        assert!(cs.read(i, D).unwrap().is_null(), "slot {i} survived");
    }

    // The same addresses come back, which is the whole point: revocation is
    // the only way memory is ever reused, because there is no free list.
    let mut again = [RawCap::NULL; 4];
    cs.retype((4, D), ObjectType::Frame, 0, (8, D), &mut again).expect("retype");
    for i in 0..4 {
        assert_eq!(again[i].paddr, first_time[i].paddr, "memory was not reused");
    }
}

#[test_case]
fn revoking_something_with_no_children_is_not_an_error() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (8, D), &mut made).expect("retype");
    assert_eq!(cs.revoke(8, D).unwrap(), 0);
    assert_eq!(cs.read(8, D).unwrap().kind, ObjectType::Endpoint);
}

// --- Typed lookup through a space ---

#[test_case]
fn lookup_proves_kind_and_rights_in_one_step() {
    let mut cs = space();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Frame, 0, (8, D), &mut made).expect("retype");

    // The right kind with rights it holds.
    assert!(cs.lookup::<kind::Frame, { READ | WRITE }>(8, D).is_ok());
    // The wrong kind.
    assert!(cs.lookup::<kind::Tcb, READ>(8, D).is_err());

    // Rights it does not hold, after weakening.
    cs.mint((8, D), (9, D), READ, 0).expect("mint");
    assert_eq!(
        cs.lookup::<kind::Frame, WRITE>(9, D).unwrap_err(),
        CapError::MissingRights { wanted: WRITE, held: READ }
    );
}

// --- ASIDs (M4e, closing out D-022) ---

#[test_case]
fn the_hart_implements_asid_bits() {
    let bits = kernel::cap::asid::init();
    assert!(bits > 0, "no ASID bits: tagging is unavailable on this hart");
    assert!(bits <= 16, "satp.ASID is 16 bits on RV64, got {bits}");
}

#[test_case]
fn a_pool_hands_out_distinct_nonzero_asids() {
    let mut pool = AsidPool::new(kernel::cap::asid::init());
    let a = pool.allocate().expect("allocate");
    let b = pool.allocate().expect("allocate");

    assert_ne!(a, b);
    assert_ne!(a.as_u16(), 0, "ASID 0 is reserved for unassigned spaces");
    assert_ne!(b.as_u16(), 0);
    assert_eq!(pool.in_use(), 2);
}

#[test_case]
fn a_released_asid_comes_back() {
    let mut pool = AsidPool::new(kernel::cap::asid::init());
    let a = pool.allocate().unwrap();
    pool.release(a);
    assert_eq!(pool.in_use(), 0);
    assert_eq!(pool.allocate().unwrap(), a, "the freed ASID was not reused");
}

#[test_case]
fn a_pool_runs_out_rather_than_repeating_itself() {
    let mut pool = AsidPool::new(2);
    // 2 bits is 4 values, minus the reserved zero.
    assert_eq!(pool.capacity(), 3);
    let mut seen = [0u16; 3];
    for s in seen.iter_mut() {
        *s = pool.allocate().unwrap().as_u16();
    }
    assert_eq!(pool.allocate(), Err(AsidError::Exhausted));

    seen.sort_unstable();
    assert_eq!(seen, [1, 2, 3], "the pool repeated or skipped an ASID");
}

#[test_case]
fn a_hart_with_no_asid_bits_refuses_rather_than_handing_out_zero() {
    let mut pool = AsidPool::new(0);
    assert_eq!(pool.allocate(), Err(AsidError::NotSupported));
}
