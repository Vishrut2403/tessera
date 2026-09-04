//! tessera: a capability-based microkernel for RV64.

#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test::runner)]
#![reexport_test_harness_main = "test_main"]

pub mod boot;
pub mod cap;
pub mod csr;
pub mod elf;
pub mod fdt;
pub mod ipc;
pub mod irq;
pub mod mm;
pub mod notify;
pub mod plic;
pub mod qemu;
pub mod root;
pub mod sbi;
pub mod sched;
pub mod sync;
pub mod test;
pub mod thread;
pub mod time;
pub mod trap;
pub mod uart;
pub mod uprog;

/// Where the linker put us.
pub mod layout {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
        static __text_start: u8;
        static __text_end: u8;
        static __rodata_start: u8;
        static __rodata_end: u8;
        static __data_start: u8;
        static __data_end: u8;
        static __bss_start: u8;
        static __bss_end: u8;
        static __boot_stack_bottom: u8;
        static __boot_stack_top: u8;
    }

    macro_rules! sym_addr {
        ($(#[$doc:meta])* $vis:vis fn $f:ident() = $sym:ident) => {
            $(#[$doc])*
            $vis fn $f() -> usize {
                // `&raw const` forms an address without an access, so no unsafe is needed.
                &raw const $sym as usize
            }
        };
    }

    sym_addr!(pub fn kernel_start() = __kernel_start);
    sym_addr!(pub fn kernel_end() = __kernel_end);
    sym_addr!(pub fn text_start() = __text_start);
    sym_addr!(pub fn text_end() = __text_end);
    sym_addr!(pub fn rodata_start() = __rodata_start);
    sym_addr!(pub fn rodata_end() = __rodata_end);
    sym_addr!(pub fn data_start() = __data_start);
    sym_addr!(pub fn data_end() = __data_end);
    sym_addr!(pub fn bss_start() = __bss_start);
    sym_addr!(pub fn bss_end() = __bss_end);
    sym_addr!(pub fn boot_stack_bottom() = __boot_stack_bottom);
    sym_addr!(pub fn boot_stack_top() = __boot_stack_top);

    /// The kernel image as a physical region.
    pub fn kernel_phys_range() -> crate::mm::Region {
        crate::mm::Region::new(
            crate::mm::PhysAddr::new(kernel_start() - crate::mm::KERNEL_VMA),
            crate::mm::PhysAddr::new(kernel_end() - crate::mm::KERNEL_VMA),
        )
    }
}

/// Bring the kernel to a state where `println!` works and traps are handled.
pub fn init() {
    uart::init();
    trap::init();
    trap::use_default_kernel_stack();
}

/// Read the current stack pointer.
#[inline(always)]
pub fn stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reading a register into a local cannot fault or alias anything.
    unsafe { core::arch::asm!("mv {sp}, sp", sp = out(reg) sp, options(nomem, nostack)) };
    sp
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Bypasses the UART lock: the panicking code may still hold it (D-009).
    crate::println_unlocked!();
    crate::println_unlocked!("=== KERNEL PANIC ===");
    if let Some(loc) = info.location() {
        crate::println_unlocked!("at {}:{}:{}", loc.file(), loc.line(), loc.column());
    }
    crate::println_unlocked!("{}", info.message());
    qemu::exit_failure(1)
}

// --- Unit-test image ---

#[cfg(test)]
crate::kernel_entry!(test_kmain);

#[cfg(test)]
extern "C" fn test_kmain(_hartid: usize, _dtb_pa: usize) -> ! {
    init();
    test_main();
    qemu::exit_success()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn trivial() {
        assert_eq!(1 + 1, 2);
    }

    #[test_case]
    fn layout_is_ordered() {
        assert!(layout::kernel_start() <= layout::text_start());
        assert!(layout::text_start() < layout::text_end());
        assert!(layout::text_end() <= layout::rodata_start());
        assert!(layout::rodata_end() <= layout::data_start());
        assert!(layout::data_end() <= layout::bss_start());
        assert!(layout::bss_start() < layout::bss_end());
        assert!(layout::bss_end() <= layout::kernel_end());
    }

    #[test_case]
    fn loaded_low_and_linked_high() {
        // The two halves of D-002, pinned together.
        assert_eq!(layout::kernel_phys_range().start.as_usize(), 0x8020_0000);
        assert_eq!(layout::kernel_start(), mm::KERNEL_VMA + 0x8020_0000);
        assert_eq!(
            layout::kernel_start() - layout::kernel_phys_range().start.as_usize(),
            mm::KERNEL_VMA
        );
    }

    #[test_case]
    fn we_are_executing_in_the_high_half() {
        // Not a tautology: a failed jump would still run, just at physical addresses.
        let sp = stack_pointer();
        assert!(sp > mm::KERNEL_VMA, "sp {sp:#x} is not a high-half address");
        assert_eq!(mm::phys_offset(), mm::KERNEL_VMA);
    }
}
