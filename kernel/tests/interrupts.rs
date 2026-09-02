//! Interrupts as capabilities: the controller, the per-source table, and the
//! notification an interrupt turns into (D-041).
//!
//! The whole path — device tree to a userspace thread woken by real hardware —
//! is exercised by the root task in `tests/root.rs`. What is here is the parts,
//! and the refusals that path never triggers.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::irq::{self, IrqError};
use kernel::mm::{self, PhysAddr};
use kernel::notify::Notification;
use kernel::{kernel_entry, layout, plic, qemu};

kernel_entry!(test_main_entry);

static mut MAP: Option<mm::MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("discovery");
    // SAFETY: single hart, before any test runs.
    unsafe { (&raw mut MAP).write(Some(map)) };

    let kspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    // SAFETY: `kspace` maps this code, this stack and `gp` where they are.
    unsafe { mm::kernel_space::activate(&kspace) };

    if let Some(info) = map.plic {
        plic::init(info);
    }

    test_main();
    qemu::exit_success()
}

fn map() -> mm::MemoryMap {
    // SAFETY: written once during boot, read-only thereafter.
    unsafe { (&raw const MAP).read() }.expect("no memory map")
}

/// A source no other test in this file uses, so claims do not collide.
fn spare(n: usize) -> usize {
    40 + n
}

// --- The controller, as the device tree describes it ---

#[test_case]
fn the_device_tree_names_an_interrupt_controller() {
    let info = map().plic.expect("no interrupt controller was found");
    assert!(info.ndev > 0, "a controller with no sources");
    assert_eq!(info.region.len() % mm::PAGE_SIZE, 0);
}

#[test_case]
fn the_supervisor_context_is_read_not_assumed() {
    // QEMU virt lists hart 0's machine context first and its supervisor context
    // second, so this is 1 -- but it is found by looking for cause 9 in
    // `interrupts-extended`, which is what makes it right on a board that
    // orders them differently.
    let info = map().plic.expect("no controller");
    assert_eq!(info.context, 1);
}

#[test_case]
fn the_controller_is_never_handed_out_as_a_device() {
    // Two owners programming one interrupt controller is a race, not a design.
    let m = map();
    let plic = m.plic.expect("no controller");
    assert!(
        !m.devices.iter().any(|d| d.overlaps(&plic.region)),
        "the interrupt controller was handed out as device untyped"
    );
}

#[test_case]
fn the_table_has_room_for_every_source_the_platform_has() {
    let info = map().plic.expect("no controller");
    assert!(
        info.ndev < irq::MAX_IRQ,
        "the platform has {} sources but the table holds {}",
        info.ndev,
        irq::MAX_IRQ
    );
}

// --- Masking ---

#[test_case]
fn every_source_starts_masked() {
    // `init` leaves each source at a deliverable priority but disabled, so
    // turning on `sie.SEIE` on its own delivers nothing.
    for irq in [1, 8, 11, 30] {
        assert!(!plic::is_enabled(irq), "source {irq} was enabled before anyone claimed it");
    }
}

#[test_case]
fn enabling_and_masking_a_source_round_trips() {
    let irq = spare(0);
    plic::enable(irq);
    assert!(plic::is_enabled(irq));
    plic::disable(irq);
    assert!(!plic::is_enabled(irq));
}

#[test_case]
fn masking_one_source_leaves_its_neighbours_alone() {
    // The enable bits are packed 32 to a word, so a read-modify-write that got
    // the mask wrong would silently take out a whole block of sources.
    let (a, b) = (spare(1), spare(1) + 1);
    plic::enable(a);
    plic::enable(b);
    plic::disable(a);
    assert!(!plic::is_enabled(a));
    assert!(plic::is_enabled(b), "masking {a} also masked {b}");
    plic::disable(b);
}

// --- Who is allowed to receive a source ---

#[test_case]
fn source_zero_cannot_be_claimed() {
    // The controller returns 0 from a claim to mean "nothing pending", so it is
    // not a source and a capability for it would name nothing.
    assert_eq!(irq::claim(0), Err(IrqError::OutOfRange));
    assert_eq!(irq::claim(irq::MAX_IRQ), Err(IrqError::OutOfRange));
}

#[test_case]
fn a_source_can_only_be_claimed_once() {
    let irq = spare(4);
    assert_eq!(irq::claim(irq), Ok(()));
    assert_eq!(irq::claim(irq), Err(IrqError::AlreadyClaimed));
    assert!(irq::is_claimed(irq));
}

#[test_case]
fn an_unclaimed_source_cannot_be_bound() {
    // Binding is what an `IrqHandler` capability authorises, and there is no
    // handler for a source nobody claimed.
    let frame = mm::alloc_frame().expect("no frames");
    assert_eq!(irq::bind(spare(5), frame, 1), Err(IrqError::NotClaimed));
}

#[test_case]
fn binding_records_the_target_and_unmasks_the_source() {
    let irq = spare(6);
    let frame = mm::alloc_frame().expect("no frames");
    irq::claim(irq).expect("claim");
    assert!(!plic::is_enabled(irq));

    irq::bind(irq, frame, 0x40).expect("bind");
    assert_eq!(irq::target(irq), Some((frame, 0x40)));
    assert!(plic::is_enabled(irq), "binding left the source masked");

    irq::unbind(irq).expect("unbind");
    assert_eq!(irq::target(irq), None);
    assert!(!plic::is_enabled(irq), "unbinding left the source live");
}

#[test_case]
fn the_scheduler_can_tell_whether_hardware_could_still_wake_anyone() {
    // An empty run queue means "finished" only when nothing outside it can make
    // a thread runnable. This is the question the idle loop asks.
    irq::reset();
    assert!(!irq::any_bound());

    let irq = spare(7);
    let frame = mm::alloc_frame().expect("no frames");
    irq::claim(irq).expect("claim");
    irq::bind(irq, frame, 1).expect("bind");
    assert!(irq::any_bound());

    irq::unbind(irq).expect("unbind");
    assert!(!irq::any_bound());
}

// --- What a notification holds ---

#[test_case]
fn a_fresh_notification_holds_nothing() {
    let mut n = Notification::EMPTY;
    assert!(n.is_empty());
    assert_eq!(n.take(), None);
}

#[test_case]
fn signals_between_waits_collapse_into_one() {
    // OR'd, not counted: a device interrupting faster than its driver runs must
    // not make the kernel accumulate anything.
    let mut n = Notification::EMPTY;
    n.post(0b001);
    n.post(0b100);
    n.post(0b001);
    assert_eq!(n.take(), Some(0b101));
    assert_eq!(n.take(), None, "the word was not cleared by taking it");
}

#[test_case]
fn an_unbadged_signal_still_wakes_a_later_waiter() {
    // The reason `pending` exists separately from `word`: testing `word != 0`
    // would silently lose every signal whose badge is zero, and a lost wake-up
    // is a driver that never runs again.
    let mut n = Notification::EMPTY;
    n.post(0);
    assert_eq!(n.take(), Some(0));
    assert_eq!(n.take(), None);
}
