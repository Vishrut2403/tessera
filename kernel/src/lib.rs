//! tessera — a capability-based microkernel for RV64.
//!
//! Milestone 1: boot under OpenSBI, establish a Rust-shaped machine state, print
//! to the UART, and take a trap.
//!
//! The kernel is a library so that integration tests can link it; the binary in
//! `main.rs` is a shim (D-005).

#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test::runner)]
#![reexport_test_harness_main = "test_main"]

pub mod boot;
pub mod csr;
pub mod fdt;
pub mod mm;
pub mod qemu;
pub mod sync;
pub mod test;
pub mod trap;
pub mod uart;

/// Where the linker put us.
///
/// These symbols have no storage — only addresses — which is why every accessor
/// takes the address of the symbol rather than reading it. Reading one would
/// load whatever byte happens to live at the boundary.
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
                // No `unsafe` needed: `&raw const` forms an address without
                // performing an access, which is the whole reason it exists.
                // Reading one of these statics *would* be unsafe, and would also
                // be meaningless -- it would load whatever byte happens to sit
                // at the section boundary.
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

    /// The kernel image as a physical region, for reserving it during memory
    /// discovery.
    ///
    /// Correct only while the linker's addresses *are* physical addresses,
    /// which is true until M2c sets `KERNEL_VMA`. At that point this becomes
    /// `linked address - KERNEL_VMA` and the subtraction must be added here.
    pub fn kernel_phys_range() -> crate::mm::Region {
        crate::mm::Region::new(
            crate::mm::PhysAddr::new(kernel_start()),
            crate::mm::PhysAddr::new(kernel_end()),
        )
    }
}

/// Bring the kernel to a state where `println!` works and traps are handled.
///
/// Order matters: the trap vector is installed second so that a fault during
/// UART setup still hits OpenSBI's default handler, which at least prints
/// something, rather than jumping through an `stvec` pointing at uninitialised
/// memory.
pub fn init() {
    uart::init();
    trap::init();
}

/// Read the current stack pointer. Used by tests to prove `_start` installed the
/// boot stack, and by dumps.
#[inline(always)]
pub fn stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reading a register into a local cannot fault or alias anything.
    unsafe { core::arch::asm!("mv {sp}, sp", sp = out(reg) sp, options(nomem, nostack)) };
    sp
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Deliberately bypasses the UART lock (D-009): the panicking code may be
    // holding it, and a panic handler that deadlocks prints nothing at all.
    crate::println_unlocked!();
    crate::println_unlocked!("=== KERNEL PANIC ===");
    if let Some(loc) = info.location() {
        crate::println_unlocked!("at {}:{}:{}", loc.file(), loc.line(), loc.column());
    }
    crate::println_unlocked!("{}", info.message());
    qemu::exit_failure(1)
}

// ---------------------------------------------------------------------------
// Unit-test image: `cargo test` builds the library as its own bootable kernel.
// ---------------------------------------------------------------------------

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
    fn linked_where_opensbi_expects_us() {
        assert_eq!(layout::kernel_start(), 0x8020_0000);
    }
}
