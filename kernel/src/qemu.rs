//! Terminating QEMU from inside the guest, via the SiFive test device (D-011).

/// Physical address of the device; resolved through `phys_to_virt` per use.
pub const SIFIVE_TEST_PHYS: usize = 0x0010_0000;

const FINISH_FAIL: u32 = 0x3333;
const FINISH_PASS: u32 = 0x5555;

fn test_device() -> *mut u32 {
    crate::mm::phys_to_virt(crate::mm::PhysAddr::new(SIFIVE_TEST_PHYS)).as_mut_ptr()
}

/// Exit QEMU with status 0.
pub fn exit_success() -> ! {
    // SAFETY: 0x10_0000 is the SiFive test device MMIO on QEMU virt, always mapped.
    unsafe { core::ptr::write_volatile(test_device(), FINISH_PASS) };
    park()
}

/// Exit QEMU with status `code` (must be non-zero to be distinguishable).
pub fn exit_failure(code: u16) -> ! {
    // SAFETY: as above.
    unsafe {
        core::ptr::write_volatile(test_device(), FINISH_FAIL | ((code as u32) << 16))
    };
    park()
}

/// Stop this hart forever.
pub fn park() -> ! {
    loop {
        // SAFETY: `wfi` is a hint; with interrupts masked it is a no-op.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
