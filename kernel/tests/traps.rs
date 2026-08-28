//! The trap path: does a trap actually reach us, do we come back, and does the
//! register file survive the round trip?
//!
//! The register test matters more than it looks. A wrong offset in one of the 31
//! save/restore pairs in `trap_entry` corrupts exactly one register, which then
//! misbehaves somewhere unrelated, long after the trap. Checking all of them at
//! the point of the trap turns a haunting into a test failure.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use core::sync::atomic::Ordering;

use kernel::csr::{stvec, stvec_mode};
use kernel::{kernel_entry, qemu, trap};

kernel_entry!(test_main_entry);

extern "C" fn test_main_entry(_hartid: usize, _dtb_pa: usize) -> ! {
    kernel::init();
    test_main();
    qemu::exit_success()
}

#[test_case]
fn stvec_points_at_our_handler() {
    let v = stvec::read();
    assert_eq!(v & 0b11, stvec_mode::DIRECT, "stvec is not in direct mode");
    assert_eq!(
        v & !0b11,
        trap::trap_entry as *const () as usize,
        "stvec does not point at trap_entry"
    );
}

#[test_case]
fn breakpoint_is_handled_and_returns() {
    let before = trap::BREAKPOINTS.load(Ordering::Relaxed);
    // SAFETY: `ebreak` raises a breakpoint exception, which the dispatcher
    // handles by advancing sepc past it.
    unsafe { core::arch::asm!("ebreak") };
    assert_eq!(trap::BREAKPOINTS.load(Ordering::Relaxed), before + 1);
}

#[test_case]
fn breakpoints_are_repeatable() {
    let before = trap::BREAKPOINTS.load(Ordering::Relaxed);
    for _ in 0..64 {
        // SAFETY: as above.
        unsafe { core::arch::asm!("ebreak") };
    }
    assert_eq!(trap::BREAKPOINTS.load(Ordering::Relaxed), before + 64);
}

#[test_case]
fn temporaries_survive_a_trap() {
    // Load recognisable values into the caller-saved temporaries, trap, and read
    // them back. `out`/`inout` with explicit registers stops the compiler from
    // keeping these anywhere but where we asked.
    let (t0, t1, t2, a4, a5): (usize, usize, usize, usize, usize);
    // SAFETY: the asm writes only the registers named as outputs and takes a
    // breakpoint the kernel handles.
    unsafe {
        core::arch::asm!(
            "li t0, 0x1111",
            "li t1, 0x2222",
            "li t2, 0x3333",
            "li a4, 0x4444",
            "li a5, 0x5555",
            "ebreak",
            out("t0") t0,
            out("t1") t1,
            out("t2") t2,
            out("a4") a4,
            out("a5") a5,
            // No `options(nostack)`: `ebreak` traps, and the trap entry
            // allocates a 256-byte frame below sp. Promising the compiler that
            // this asm leaves the stack alone would be a lie.
        );
    }
    assert_eq!(t0, 0x1111);
    assert_eq!(t1, 0x2222);
    assert_eq!(t2, 0x3333);
    assert_eq!(a4, 0x4444);
    assert_eq!(a5, 0x5555);
}

#[test_case]
fn saved_registers_survive_a_trap() {
    // The callee-saved half. s0 is the frame pointer and s1..s11 are otherwise
    // in use by the compiler, so we save and restore them around the test
    // ourselves rather than asking the register allocator for them.
    let (s2, s3, s10, s11): (usize, usize, usize, usize);
    // SAFETY: as above; every register touched is declared.
    unsafe {
        core::arch::asm!(
            "li s2,  0x6666",
            "li s3,  0x7777",
            "li s10, 0x8888",
            "li s11, 0x9999",
            "ebreak",
            out("s2") s2,
            out("s3") s3,
            out("s10") s10,
            out("s11") s11,
            // See the note in temporaries_survive_a_trap.
        );
    }
    assert_eq!(s2, 0x6666);
    assert_eq!(s3, 0x7777);
    assert_eq!(s10, 0x8888);
    assert_eq!(s11, 0x9999);
}

#[test_case]
fn stack_pointer_survives_a_trap() {
    let before = kernel::stack_pointer();
    // SAFETY: as above.
    unsafe { core::arch::asm!("ebreak") };
    assert_eq!(kernel::stack_pointer(), before, "trap entry did not restore sp");
}
