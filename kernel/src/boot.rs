//! The entry point.
//!
//! OpenSBI enters us in S-mode with the MMU off, `a0 = hartid`, and
//! `a1 = physical address of the device tree blob`. Everything a Rust function
//! is entitled to assume — a stack, zeroed statics, a valid `gp` — is false at
//! that instant, so establishing those is exactly this file's job, and it has to
//! be done in assembly because a Rust function would be relying on the very
//! invariants it is creating (D-012).
//!
//! The entry lives in a macro rather than in this library because a `_start`
//! sitting unreferenced in an rlib is at the mercy of the linker's decision to
//! pull it in (D-005). Each bootable image — the kernel binary and every
//! integration test — invokes `kernel_entry!` exactly once, and the assembly is
//! still written in exactly one place.

/// Emit the kernel entry point, which hands control to `$main`.
///
/// `$main` must be `extern "C" fn(hartid: usize, dtb_pa: usize) -> !`.
///
/// ```ignore
/// kernel_entry!(kmain);
/// extern "C" fn kmain(hartid: usize, dtb: usize) -> ! { ... }
/// ```
#[macro_export]
macro_rules! kernel_entry {
    ($main:path) => {
        /// Kernel entry. Called by OpenSBI, never by Rust.
        ///
        /// Naked: the compiler must emit *no* prologue here. A normal function
        /// would spill callee-saved registers to a stack that does not exist
        /// yet, and would be free to touch statics before `.bss` is zeroed.
        /// A naked function is a guarantee that the bytes in this file are the
        /// bytes that execute, in order, starting at the ELF entry point.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".text.boot")]
        pub unsafe extern "C" fn _start() -> ! {
            ::core::arch::naked_asm!(
                // Live on entry: a0 = hartid, a1 = DTB physical address.
                // Nothing below may clobber a0 or a1 — they are the arguments
                // to $main, which we tail-jump to.
                //
                // There is no "park the other harts" loop here on purpose.
                // OpenSBI brings up exactly one hart into S-mode; the rest are
                // left in the SBI HSM STOPPED state and never execute a byte of
                // our code until we call sbi_hart_start. A parking loop keyed on
                // `hartid != 0` would be dead code that also happens to be wrong
                // if the boot hart is ever not hart 0.

                // 1. gp — the global pointer.
                //
                // The linker relaxes some absolute global accesses into
                // gp-relative ones, so `gp` must be correct before any compiled
                // Rust runs. `.option norelax` around this is not a style
                // choice: without it the linker would relax `la gp,
                // __global_pointer$` into an access relative to gp itself,
                // which is the register we are in the middle of computing.
                ".option push",
                ".option norelax",
                "la    gp, __global_pointer$",
                ".option pop",

                // 2. Zero .bss.
                //
                // Rust assumes every static that is not explicitly initialized
                // reads as zero; the ELF marks .bss NOBITS, so nothing has put
                // zeroes there. This loop deliberately uses no stack — the boot
                // stack itself lives inside the range being cleared.
                "la    t0, __bss_start",
                "la    t1, __bss_end",
                "bgeu  t0, t1, 2f",
                "1:",
                "sd    zero, 0(t0)",
                "addi  t0, t0, 8",
                "bltu  t0, t1, 1b",
                "2:",

                // 3. The stack. Grows down from the top of the reserved region.
                "la    sp, __boot_stack_top",

                // 4. Terminate the frame-pointer chain and the return-address
                //    chain, so a backtrace that walks off the top of kmain stops
                //    instead of chasing whatever OpenSBI left in these
                //    registers.
                "mv    s0, zero",
                "mv    ra, zero",

                // 5. Into Rust. A tail-jump, not a call: $main is `-> !`, so
                //    there is nowhere to return to and leaving `ra` zeroed is
                //    more honest than pointing it here.
                //
                //    `tail` rather than `j`: `j` is a J-type branch with a
                //    +/-1 MiB range. It works today and would become a link
                //    error the first time the kernel's .text grows past that,
                //    with an error message that has nothing to do with this
                //    line. `tail` expands to auipc+jr, reaching +/-2 GiB, and
                //    clobbers t1 -- which we are done with.
                "tail  {kmain}",

                kmain = sym $main,
            )
        }
    };
}
