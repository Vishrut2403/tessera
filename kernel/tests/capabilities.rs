//! Capabilities: rights enforced by the compiler, and untyped memory retyped.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::object::SLOT_BITS;
use kernel::cap::rights::{ALL, GRANT, READ, WRITE};
use kernel::cap::untyped::carve;
use kernel::cap::{Cap, CapError, ObjectType, RawCap, kind};
use kernel::mm::{self, PAGE_SIZE, PhysAddr, phys_to_virt};
use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("memory discovery");
    test_main();
    qemu::exit_success()
}

/// An untyped capability over `1 << bits` bytes of real, owned memory.
fn untyped(bits: u8) -> RawCap {
    let size = 1usize << bits;
    let count = 1usize << (bits.saturating_sub(12));

    let mut first = mm::alloc_frame().expect("no frames");
    while first.as_usize() & (size - 1) != 0 {
        first = mm::alloc_frame().expect("no frames");
    }
    for _ in 1..count {
        mm::alloc_frame().expect("no frames");
    }
    RawCap::untyped(first, bits, ALL)
}

// --- Rights, at runtime ---

#[test_case]
fn a_lookup_that_needs_a_right_the_slot_lacks_fails() {
    let raw = untyped(12).with_rights(READ);

    // Asking for exactly what is held succeeds.
    assert!(Cap::<kind::Untyped, READ>::from_raw(raw).is_ok());

    // Asking for more does not.
    let err = Cap::<kind::Untyped, { READ | WRITE }>::from_raw(raw).unwrap_err();
    assert_eq!(err, CapError::MissingRights { wanted: READ | WRITE, held: READ });
}

#[test_case]
fn a_lookup_of_the_wrong_kind_fails() {
    let mut raw = untyped(12);
    raw.kind = ObjectType::Frame;
    let err = Cap::<kind::Untyped, ALL>::from_raw(raw).unwrap_err();
    assert_eq!(err, CapError::WrongType { wanted: ObjectType::Untyped, found: ObjectType::Frame });
}

#[test_case]
fn a_null_slot_is_not_a_capability() {
    assert_eq!(Cap::<kind::Frame, 0>::from_raw(RawCap::NULL).unwrap_err(), CapError::Null);
}

// --- Rights, at compile time ---

#[test_case]
fn reducing_rights_narrows_what_is_stored() {
    let cap = Cap::<kind::Untyped, ALL>::from_raw(untyped(12)).unwrap();
    assert_eq!(cap.raw().rights, ALL);

    let weaker = cap.reduce::<READ>();
    assert_eq!(weaker.raw().rights, READ, "reduce did not narrow the stored rights");

    // And the weakened capability can no longer be re-widened:
    // `reduce::<ALL>()` on it does not compile, because Mask<READ>:
    // Subset<READ, ALL> has no impl.
    let weaker_still = weaker.reduce::<0>();
    assert_eq!(weaker_still.raw().rights, 0);
}

#[test_case]
fn grant_is_what_makes_a_capability_delegatable() {
    // An endpoint, because a badge names a holder to a server and only an
    // endpoint or a notification has one on the other end (D-050).
    let ep = RawCap::new(ObjectType::Endpoint, GRANT | WRITE, SLOT_BITS, untyped(12).paddr);
    let cap = Cap::<kind::Endpoint, { GRANT | WRITE }>::from_raw(ep).unwrap();
    let handed_over = cap.delegate(0xbad_9e);

    assert_eq!(handed_over.badge(), 0xbad_9e, "the badge did not survive delegation");
    assert_eq!(handed_over.paddr, cap.paddr(), "delegation moved the object");
    assert_eq!(handed_over.rights, cap.raw().rights);

    // `cap.reduce::<WRITE>().delegate(..)` does not compile: `delegate` is only
    // defined where Mask<R>: HasGrant, and WRITE alone does not implement it.
}

#[test_case]
fn only_an_endpoint_or_a_notification_carries_a_badge() {
    // A frame spends both payload words on where it is mapped, so a badge has
    // nowhere to live and must not silently land on top of one (D-050).
    let mut frame = untyped(12);
    frame.kind = ObjectType::Frame;
    frame.set_mapping(PhysAddr::new(0x8000_0000), 0x1234_0000);

    assert_eq!(frame.badge(), 0, "a frame reported a badge");
    assert_eq!(
        frame.mapping(),
        Some((PhysAddr::new(0x8000_0000), 0x1234_0000)),
        "the mapping did not survive being read as a badge"
    );
    assert_eq!(untyped(12).badge(), 0, "untyped memory reported a badge");
}

// --- Carving ---

#[test_case]
fn an_unaligned_region_is_refused() {
    // 0x8000_1000 is page-aligned but not 64 KiB aligned, so it cannot be a 64
    // KiB region: objects placed at aligned offsets inside it would not be
    // aligned addresses.
    assert_eq!(
        carve(PhysAddr::new(0x8000_1000), 16, 0, 12).unwrap_err(),
        CapError::Misaligned
    );
    assert!(carve(PhysAddr::new(0x8001_0000), 16, 0, 12).is_ok());
}

#[test_case]
fn objects_are_aligned_to_their_own_size() {
    let base = PhysAddr::new(0x8000_0000);
    // A 4 KiB object after 1 byte has been used must start at 4096, not at 1.
    let c = carve(base, 20, 1, 12).unwrap();
    assert_eq!(c.paddr.as_usize(), 0x8000_1000);
    assert_eq!(c.watermark, 0x2000);
}

#[test_case]
fn carving_past_the_end_of_a_region_fails() {
    let base = PhysAddr::new(0x8000_0000);
    // A 4 KiB region holds exactly one 4 KiB object.
    assert!(carve(base, 12, 0, 12).is_ok());
    assert_eq!(carve(base, 12, 4096, 12).unwrap_err(), CapError::NotEnoughSpace);
    // And nothing larger than the region itself fits at all.
    assert_eq!(carve(base, 12, 0, 13).unwrap_err(), CapError::NotEnoughSpace);
}

// --- Retyping ---

#[test_case]
fn retyping_produces_objects_inside_the_region() {
    let raw = untyped(15);
    let cap = Cap::<kind::Untyped, ALL>::from_raw(raw).unwrap();

    let mut out = [RawCap::NULL; 4];
    let watermark = cap.retype(ObjectType::Frame, 0, &mut out).expect("retype failed");

    assert_eq!(watermark, 4 * PAGE_SIZE);
    for (i, obj) in out.iter().enumerate() {
        assert_eq!(obj.kind, ObjectType::Frame);
        assert_eq!(obj.size_bits, 12);
        assert_eq!(obj.paddr.as_usize(), raw.paddr.as_usize() + i * PAGE_SIZE);
        assert!(raw.covers(obj), "object {i} escaped the region it was carved from");
    }
}

#[test_case]
fn a_fresh_object_arrives_with_every_right() {
    let cap = Cap::<kind::Untyped, ALL>::from_raw(untyped(14)).unwrap();
    let mut out = [RawCap::NULL; 1];
    cap.retype(ObjectType::Tcb, 0, &mut out).unwrap();
    assert_eq!(out[0].rights, ALL);
}

#[test_case]
fn retyped_memory_is_zeroed() {
    let raw = untyped(14);

    // Dirty the region first, the way a previous owner would have.
    let ptr = phys_to_virt(raw.paddr).as_mut_ptr::<u8>();
    // SAFETY: `raw` names frames we just took from the allocator.
    unsafe { core::ptr::write_bytes(ptr, 0xa5, 1 << 14) };
    // SAFETY: as above.
    assert_eq!(unsafe { core::ptr::read_volatile(ptr) }, 0xa5);

    let cap = Cap::<kind::Untyped, ALL>::from_raw(raw).unwrap();
    let mut out = [RawCap::NULL; 1];
    cap.retype(ObjectType::Frame, 0, &mut out).unwrap();

    let obj = phys_to_virt(out[0].paddr).as_ptr::<u8>();
    for i in 0..PAGE_SIZE {
        // SAFETY: inside the object we just created.
        assert_eq!(unsafe { core::ptr::read_volatile(obj.add(i)) }, 0, "byte {i} was not zeroed");
    }
}

#[test_case]
fn a_failed_retype_changes_nothing() {
    let raw = untyped(12);
    let cap = Cap::<kind::Untyped, ALL>::from_raw(raw).unwrap();

    // Two frames do not fit in a 4 KiB region.
    let mut out = [RawCap::NULL; 2];
    assert_eq!(cap.retype(ObjectType::Frame, 0, &mut out), Err(CapError::NotEnoughSpace));
    assert_eq!(cap.raw().watermark(), 0, "a failed retype consumed part of the region");
}

#[test_case]
fn a_cnode_must_be_big_enough_to_hold_a_slot() {
    let cap = Cap::<kind::Untyped, ALL>::from_raw(untyped(14)).unwrap();
    let mut out = [RawCap::NULL; 1];

    // Smaller than one slot, and exactly one slot, are both refused: a CNode
    // must consume at least one address bit or resolution would not terminate.
    assert_eq!(cap.retype(ObjectType::CNode, 4, &mut out), Err(CapError::BadSize));
    assert_eq!(cap.retype(ObjectType::CNode, SLOT_BITS, &mut out), Err(CapError::BadSize));

    assert!(cap.retype(ObjectType::CNode, 12, &mut out).is_ok());
    assert_eq!(
        out[0].kind.slots(out[0].size_bits),
        Some(1 << (12 - SLOT_BITS)),
        "a 4 KiB CNode holds one slot per 2^SLOT_BITS bytes"
    );
}

#[test_case]
fn null_is_not_something_you_can_retype_into() {
    let cap = Cap::<kind::Untyped, ALL>::from_raw(untyped(13)).unwrap();
    let mut out = [RawCap::NULL; 1];
    assert_eq!(cap.retype(ObjectType::Null, 0, &mut out), Err(CapError::BadObjectType));
}

#[test_case]
fn a_fixed_size_object_ignores_the_size_it_is_asked_for() {
    let cap = Cap::<kind::Untyped, ALL>::from_raw(untyped(15)).unwrap();
    let mut out = [RawCap::NULL; 1];
    // 20 would be a megabyte; a Frame is a page whatever the caller says.
    cap.retype(ObjectType::Frame, 20, &mut out).unwrap();
    assert_eq!(out[0].size_bits, 12);
}
