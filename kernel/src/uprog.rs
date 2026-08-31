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

/// `lui rd, imm20` — the upper 20 bits of a constant.
pub const fn lui(rd: usize, imm20: u32) -> u32 {
    ((imm20 & 0xf_ffff) << 12) | ((rd as u32) << 7) | 0x37
}

/// `addi rd, rs1, imm`.
pub const fn addi(rd: usize, rs1: usize, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | ((rs1 as u32) << 15) | ((rd as u32) << 7) | 0x13
}

/// `jal rd, offset` — offset in bytes from this instruction.
pub const fn jal(rd: usize, offset: i32) -> u32 {
    let imm = offset as u32;
    ((imm & 0x10_0000) << 11)
        | ((imm & 0x7fe) << 20)
        | ((imm & 0x800) << 9)
        | (imm & 0xf_f000)
        | ((rd as u32) << 7)
        | 0x6f
}

/// `bne rs1, rs2, offset` — offset in bytes from this instruction.
pub const fn bne(rs1: usize, rs2: usize, offset: i32) -> u32 {
    let imm = offset as u32;
    ((imm & 0x1000) << 19)
        | ((imm & 0x7e0) << 20)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (0b001 << 12)
        | ((imm & 0x1e) << 7)
        | ((imm & 0x800) >> 4)
        | 0x63
}

/// `slli rd, rs1, shamt`.
pub const fn slli(rd: usize, rs1: usize, shamt: u32) -> u32 {
    ((shamt & 0x3f) << 20) | ((rs1 as u32) << 15) | (0b001 << 12) | ((rd as u32) << 7) | 0x13
}

/// `srli rd, rs1, shamt`.
pub const fn srli(rd: usize, rs1: usize, shamt: u32) -> u32 {
    ((shamt & 0x3f) << 20) | ((rs1 as u32) << 15) | (0b101 << 12) | ((rd as u32) << 7) | 0x13
}

/// `mv rd, rs` — `addi rd, rs, 0`.
pub const fn mv(rd: usize, rs: usize) -> u32 {
    addi(rd, rs, 0)
}

/// `sd rs2, offset(rs1)`.
pub const fn sd(rs1: usize, rs2: usize, offset: i32) -> u32 {
    let imm = offset as u32;
    ((imm & 0xfe0) << 20)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (0b011 << 12)
        | ((imm & 0x1f) << 7)
        | 0x23
}

/// `ld rd, offset(rs1)`.
pub const fn ld(rd: usize, rs1: usize, offset: i32) -> u32 {
    (((offset as u32) & 0xfff) << 20) | ((rs1 as u32) << 15) | (0b011 << 12) | ((rd as u32) << 7) | 0x03
}

/// A small program, assembled into a fixed buffer.
///
/// `li` only reaches 12 bits, and a packed message header does not fit, so
/// anything wider needs `lui` + `addi`. A builder keeps the tests readable
/// instead of a wall of hand-encoded words.
pub struct Prog<const N: usize> {
    words: [u32; N],
    len: usize,
}

impl<const N: usize> Prog<N> {
    pub const fn new() -> Self {
        Self { words: [0; N], len: 0 }
    }

    pub const fn raw(mut self, word: u32) -> Self {
        self.words[self.len] = word;
        self.len += 1;
        self
    }

    /// Load any 32-bit constant into `rd`.
    pub const fn li(self, rd: usize, value: u32) -> Self {
        if value < 0x800 {
            return self.raw(li(rd, value));
        }
        // The `addi` immediate is sign-extended, so bias the upper half.
        let hi = (value.wrapping_add(0x800)) >> 12;
        let lo = value.wrapping_sub(hi << 12);
        self.raw(lui(rd, hi)).raw(li_add(rd, lo))
    }

    pub const fn ecall(self) -> Self {
        self.raw(ECALL)
    }

    /// The index of the next word, to branch back to.
    pub const fn here(&self) -> usize {
        self.len
    }

    /// `bne rs, zero, <word `target`>` — the backward edge of a loop.
    pub const fn bne_back(self, rs: usize, target: usize) -> Self {
        let offset = (target as i32 - self.len as i32) * 4;
        self.raw(bne(rs, 0, offset))
    }

    /// `jal zero, <word `target`>`.
    pub const fn jump_back(self, target: usize) -> Self {
        let offset = (target as i32 - self.len as i32) * 4;
        self.raw(jal(0, offset))
    }

    /// `addi rd, rd, imm`.
    pub const fn addi(self, rd: usize, imm: i32) -> Self {
        self.raw(addi(rd, rd, imm))
    }

    /// `li a7, n; ecall`.
    pub const fn syscall(self, n: usize) -> Self {
        self.li(A7, n as u32).ecall()
    }

    pub const fn exit(self) -> Self {
        self.syscall(1)
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.words[..self.len]
    }
}

impl<const N: usize> Default for Prog<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// `addi rd, rd, imm` — the low half of a wide constant.
const fn li_add(rd: usize, imm: u32) -> u32 {
    ((imm & 0xfff) << 20) | ((rd as u32) << 15) | ((rd as u32) << 7) | 0x13
}

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

/// A client that calls `ep_slot` `trips` times, then exits.
///
/// The counter lives in `a6`, which is neither `a0`/`a1` nor one of the message
/// registers `a2..a5`, so it survives every transfer.
pub fn ipc_client(ep_slot: u32, msginfo: u32, call: usize, exit: usize, trips: u32) -> Prog<32> {
    const COUNTER: usize = 16;
    let head = Prog::<32>::new().li(COUNTER, trips);
    let top = head.here();
    head.li(A0, ep_slot)
        .li(A0 + 1, msginfo)
        .li(A7, call as u32)
        .ecall()
        .addi(COUNTER, -1)
        .bne_back(COUNTER, top)
        .syscall(exit)
}

/// A server that receives once and then replies-and-receives forever.
pub fn ipc_server(ep_slot: u32, msginfo: u32, recv: usize, reply_recv: usize) -> Prog<32> {
    let head = Prog::<32>::new().li(A0, ep_slot).syscall(recv);
    let top = head.here();
    head.li(A0, ep_slot)
        .li(A0 + 1, msginfo)
        .li(A7, reply_recv as u32)
        .ecall()
        .jump_back(top)
}
