//! The timer: is it discovered from the device tree, and does it actually fire?

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use core::sync::atomic::Ordering;

use kernel::csr::{interrupt_bits, sie, sstatus, sstatus_bits};
use kernel::mm::PhysAddr;
use kernel::{kernel_entry, qemu, time};

kernel_entry!(test_main_entry);

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    time::init(PhysAddr::new(dtb_pa));
    test_main();
    qemu::exit_success()
}

/// Spin until `f` holds or we run out of patience, in `time` units.
fn wait_until(limit_ticks: u64, f: impl Fn() -> bool) -> bool {
    let deadline = time::now() + limit_ticks;
    while time::now() < deadline {
        if f() {
            return true;
        }
    }
    f()
}

// --- Discovery ---

#[test_case]
fn timebase_comes_from_the_device_tree() {
    // QEMU virt reports 10 MHz; the point is that we read it rather than assume it.
    assert_eq!(time::timebase_hz(), 10_000_000);
}

#[test_case]
fn sstc_is_detected() {
    // O-004: QEMU's boot hart lists sstc among riscv,isa-extensions.
    assert!(time::has_sstc(), "sstc was not found in the device tree");
}

#[test_case]
fn a_timeslice_is_the_advertised_length() {
    assert_eq!(time::ms_to_ticks(1000), time::timebase_hz());
    assert_eq!(time::ms_to_ticks(time::TIMESLICE_MS), time::timebase_hz() / 100);
}

// --- The counter ---

#[test_case]
fn the_time_counter_advances() {
    let start = time::now();
    assert!(wait_until(time::ms_to_ticks(50), || time::now() > start), "rdtime is frozen");
}

#[test_case]
fn the_counter_advances_at_roughly_the_advertised_rate() {
    // Measure one millisecond against itself: a sanity check on the units, not the clock.
    let start = time::now();
    let target = start + time::ms_to_ticks(1);
    while time::now() < target {}
    let elapsed = time::now() - start;
    assert!(elapsed >= time::ms_to_ticks(1), "spun for less than we waited for");
    assert!(elapsed < time::ms_to_ticks(50), "1 ms took more than 50 ms: units are wrong");
}

// --- The interrupt ---

#[test_case]
fn the_timer_interrupt_is_masked_until_we_ask() {
    assert_eq!(sie::read() & interrupt_bits::STIE, 0, "STIE is set before init");
    assert_eq!(sstatus::read() & sstatus_bits::SIE, 0, "interrupts are enabled at boot");
}

#[test_case]
fn arming_the_timer_produces_an_interrupt() {
    let before = time::TICKS.load(Ordering::Relaxed);

    time::enable();
    time::arm(time::now() + time::ms_to_ticks(1));
    // SAFETY: the dispatcher handles timer interrupts; nothing here holds a lock.
    unsafe { sstatus::set(sstatus_bits::SIE) };

    let fired = wait_until(time::ms_to_ticks(200), || {
        time::TICKS.load(Ordering::Relaxed) > before
    });

    // SAFETY: restoring the masked state the rest of the suite expects.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    unsafe { sie::clear(interrupt_bits::STIE) };
    time::disarm();

    assert!(fired, "no timer interrupt within 200 ms");
}

#[test_case]
fn the_handler_rearms_so_ticks_keep_coming() {
    time::enable();
    time::arm(time::now() + time::ms_to_ticks(1));
    // SAFETY: as above.
    unsafe { sstatus::set(sstatus_bits::SIE) };

    let start = time::TICKS.load(Ordering::Relaxed);
    let got_three = wait_until(time::ms_to_ticks(500), || {
        time::TICKS.load(Ordering::Relaxed) >= start + 3
    });

    // SAFETY: as above.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    unsafe { sie::clear(interrupt_bits::STIE) };
    time::disarm();

    assert!(got_three, "the handler did not rearm: ticks stopped after the first");
}

#[test_case]
fn a_masked_timer_does_not_interrupt() {
    // STIE clear, so an expired deadline must stay pending and never reach us.
    time::arm(time::now() + time::ms_to_ticks(1));
    // SAFETY: SIE alone, with STIE masked, must not admit a timer interrupt.
    unsafe { sstatus::set(sstatus_bits::SIE) };

    let before = time::TICKS.load(Ordering::Relaxed);
    let fired = wait_until(time::ms_to_ticks(50), || {
        time::TICKS.load(Ordering::Relaxed) > before
    });

    // SAFETY: as above.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    time::disarm();

    assert!(!fired, "a masked timer interrupt was taken anyway");
}
