//! Thin wrappers over the S-mode control and status registers.
//!
//! Hand-written rather than pulled from the `riscv` crate, on purpose: the point
//! of the project is to know the privileged spec, and a CSR wrapper is four
//! instructions of surface area. What we get in exchange for typing it out is
//! that every CSR access in the kernel is greppable and every bit constant has a
//! name we chose.
//!
//! Convention: **reads are safe, writes are `unsafe`.** Reading any CSR here is
//! side-effect free. Writing one can redirect traps (`stvec`), change the
//! address space (`satp`, from M2), or re-enable interrupts in the middle of a
//! critical section (`sstatus`) — all of which can violate invariants the safe
//! Rust above depends on.
//!
//! None of the `asm!` blocks below is marked `nomem`. A CSR write is not a
//! memory operation in the obvious sense, but `satp` and `sstatus.SUM` change
//! what memory *means*, and marking those `nomem` would license the compiler to
//! move loads and stores across them. Uniformity here is worth more than the
//! handful of cycles.

/// Generate a module of accessors for one CSR.
macro_rules! csr_rw {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub mod $name {
            /// Read the CSR.
            #[inline(always)]
            pub fn read() -> usize {
                let v: usize;
                // SAFETY: `csrr` on an S-mode CSR from S-mode has no side
                // effects and cannot fault.
                unsafe {
                    core::arch::asm!(
                        concat!("csrr {v}, ", stringify!($name)),
                        v = out(reg) v,
                        options(nostack),
                    );
                }
                v
            }

            /// Write the CSR.
            ///
            /// # Safety
            /// The caller must uphold whatever invariant this register carries;
            /// see the module docs for the specific hazards.
            #[inline(always)]
            pub unsafe fn write(v: usize) {
                unsafe {
                    core::arch::asm!(
                        concat!("csrw ", stringify!($name), ", {v}"),
                        v = in(reg) v,
                        options(nostack),
                    );
                }
            }

            /// Atomically set the bits in `mask` (`csrs`), returning the old value.
            ///
            /// # Safety
            /// As [`write`].
            #[inline(always)]
            pub unsafe fn set(mask: usize) -> usize {
                let old: usize;
                unsafe {
                    core::arch::asm!(
                        concat!("csrrs {old}, ", stringify!($name), ", {mask}"),
                        old = out(reg) old,
                        mask = in(reg) mask,
                        options(nostack),
                    );
                }
                old
            }

            /// Atomically clear the bits in `mask` (`csrc`), returning the old value.
            ///
            /// # Safety
            /// As [`write`].
            #[inline(always)]
            pub unsafe fn clear(mask: usize) -> usize {
                let old: usize;
                unsafe {
                    core::arch::asm!(
                        concat!("csrrc {old}, ", stringify!($name), ", {mask}"),
                        old = out(reg) old,
                        mask = in(reg) mask,
                        options(nostack),
                    );
                }
                old
            }
        }
    };
}

csr_rw!(
    /// Supervisor status: interrupt enable, previous privilege, MMU access bits.
    sstatus
);
csr_rw!(
    /// Supervisor interrupt *enable* mask (which interrupts we accept).
    sie
);
csr_rw!(
    /// Supervisor interrupt *pending* bits (which are asserted right now).
    sip
);
csr_rw!(
    /// Trap vector base address, plus a 2-bit mode field. See [`stvec_mode`].
    stvec
);
csr_rw!(
    /// PC at the instruction that trapped. `sret` returns here.
    sepc
);
csr_rw!(
    /// Why we trapped: bit 63 distinguishes interrupt from exception, the low
    /// bits are the cause code.
    scause
);
csr_rw!(
    /// Trap value: the faulting address for page faults, the instruction bits
    /// for illegal-instruction, zero for most others.
    stval
);
csr_rw!(
    /// A scratch word the hardware never touches. From M3 this holds the
    /// per-hart kernel stack pointer and the trap entry swaps it with `sp`
    /// (D-007).
    sscratch
);

/// `sstatus` bit positions we actually use.
pub mod sstatus_bits {
    /// Supervisor Interrupt Enable: the global "accept interrupts in S-mode" switch.
    pub const SIE: usize = 1 << 1;
    /// Supervisor Previous Interrupt Enable: what SIE was before the trap.
    pub const SPIE: usize = 1 << 5;
    /// Supervisor Previous Privilege: 0 = trap came from U-mode, 1 = from S-mode.
    pub const SPP: usize = 1 << 8;
    /// Permit Supervisor User Memory access. Needed from M2 to touch user pages.
    pub const SUM: usize = 1 << 18;
    /// Make eXecutable Readable. We keep this off: it weakens W^X.
    pub const MXR: usize = 1 << 19;
}

/// `sie` / `sip` bit positions.
pub mod interrupt_bits {
    /// Supervisor software interrupt (IPIs, from another hart via SBI).
    pub const SSIE: usize = 1 << 1;
    /// Supervisor timer interrupt. M3 turns this on.
    pub const STIE: usize = 1 << 5;
    /// Supervisor external interrupt (the PLIC). M7 turns this on.
    pub const SEIE: usize = 1 << 9;
}

/// `stvec` mode field, held in the low two bits of the register.
pub mod stvec_mode {
    /// All traps enter at BASE. What we use (D-006).
    pub const DIRECT: usize = 0;
    /// Interrupts enter at BASE + 4 * cause; exceptions still at BASE.
    pub const VECTORED: usize = 1;
}
