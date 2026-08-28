//! Terminating QEMU from inside the guest, via the SiFive test device (D-011).
//!
//! QEMU's `virt` machine always has this device at 0x10_0000, so no extra
//! `-device` flag is needed. Writing a 32-bit status word to it makes the QEMU
//! *process* exit: `0x5555` means exit(0), `0x3333 | (code << 16)` means
//! exit(code). The success case producing a literal 0 is why this is nicer than
//! x86's `isa-debug-exit`, which cannot, and forces the test harness to remap
//! exit codes.

const SIFIVE_TEST: *mut u32 = 0x0010_0000 as *mut u32;

const FINISH_FAIL: u32 = 0x3333;
const FINISH_PASS: u32 = 0x5555;

/// Exit QEMU with status 0.
pub fn exit_success() -> ! {
    // SAFETY: 0x10_0000 is the SiFive test device on QEMU virt, MMIO, always
    // mapped while the MMU is off. Volatile so it is never elided or reordered.
    unsafe { core::ptr::write_volatile(SIFIVE_TEST, FINISH_PASS) };
    park()
}

/// Exit QEMU with status `code` (must be non-zero to be distinguishable).
pub fn exit_failure(code: u16) -> ! {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(SIFIVE_TEST, FINISH_FAIL | ((code as u32) << 16)) };
    park()
}

/// Stop this hart forever. Reached only if the test device is absent — on real
/// hardware, where these functions are meaningless.
pub fn park() -> ! {
    loop {
        // SAFETY: `wfi` is a hint; with interrupts masked it is a no-op, without
        // them it idles until one arrives. Either way it cannot fault.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
