//! Hand-encoded user programs: scaffolding until there is an ELF loader.
//!
//! M3 needs code running in U-mode before anything can load code from anywhere,
//! so these are RV64I words written out by hand. M7's filesystem server is what
//! eventually replaces them.

use crate::mm::{PAGE_SIZE, PhysAddr, phys_to_virt};

pub const ECALL: u32 = 0x0000_0073;
/// `jal x0, 0` — branch to itself. Only a timer gets a thread out of this.
pub const SPIN: u32 = 0x0000_006f;
/// `fmv.d.x f0, zero`. The instruction word O-008 saw in `stval`.
pub const USE_FP: u32 = 0xf200_0053;

/// `addi rd, zero, imm` — the `li` of a small constant.
pub const fn li(rd: usize, imm: u32) -> u32 {
    ((imm & 0xfff) << 20) | ((rd as u32) << 7) | 0x13
}

pub const A0: usize = 10;
pub const A7: usize = 17;

/// `li a7, n; ecall`, the two words every system call here starts from.
pub const fn syscall(n: usize) -> [u32; 2] {
    [li(A7, n as u32), ECALL]
}

/// Copy `words` into `frame` through the direct map, ready to be mapped as user text.
///
/// # Safety
/// `frame` must be a frame we own, and `words` must fit in a page.
pub unsafe fn write_to_frame(frame: PhysAddr, words: &[u32]) {
    assert!(words.len() * 4 <= PAGE_SIZE, "program does not fit in a page");
    let dst = phys_to_virt(frame).as_mut_ptr::<u32>();
    // SAFETY: the caller owns the frame and it is reachable through the direct map.
    unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), dst, words.len()) };
}
