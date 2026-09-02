//! Thin wrappers over the S-mode control and status registers.

/// Generate a module of accessors for one CSR.
macro_rules! csr_rw {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub mod $name {
            /// Read the CSR.
            #[inline(always)]
            pub fn read() -> usize {
                let v: usize;
                // SAFETY: `csrr` on an S-mode CSR from S-mode has no side effects and cannot fault.
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
            /// The caller must uphold whatever invariant this register carries.
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

            /// Atomically set the bits in `mask` (`csrs`), returning the old
            /// value.
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

            /// Atomically clear the bits in `mask` (`csrc`), returning the old
            /// value.
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

/// As [`csr_rw`], but for a CSR the `riscv64gc` assembler has no name for.
macro_rules! csr_num {
    ($(#[$doc:meta])* $name:ident = $num:literal) => {
        $(#[$doc])*
        pub mod $name {
            #[inline(always)]
            pub fn read() -> usize {
                let v: usize;
                // SAFETY: reading an S-mode CSR from S-mode has no side effects.
                unsafe {
                    core::arch::asm!(
                        concat!("csrr {v}, ", $num),
                        v = out(reg) v,
                        options(nostack),
                    );
                }
                v
            }

            /// # Safety
            /// The caller must uphold whatever invariant this register carries.
            #[inline(always)]
            pub unsafe fn write(v: usize) {
                unsafe {
                    core::arch::asm!(
                        concat!("csrw ", $num, ", {v}"),
                        v = in(reg) v,
                        options(nostack),
                    );
                }
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
    /// Trap cause: bit 63 selects interrupt vs exception.
    scause
);
csr_rw!(
    /// Trap value: the faulting address for page faults.
    stval
);
csr_rw!(
    /// Translation control: MODE, ASID, root page table PPN.
    satp
);
csr_rw!(
    /// Scratch word the hardware never touches; holds the kernel sp from M3.
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

csr_num!(
    /// Supervisor timer compare (`sstc`). Not in `riscv64gc`, so it goes by number.
    stimecmp = "0x14d"
);
