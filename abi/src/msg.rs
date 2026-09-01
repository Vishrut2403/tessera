//! Message headers.

/// Message words carried in registers. Four is what the fast path can move
/// without touching memory, and what seL4 settled on for the same reason.
pub const MSG_REGS: usize = 4;

/// The header of a message: what it means, how long it is, and whether a
/// capability rides along.
///
/// Packed into one register so the fast path never has to read memory to find
/// out how much to copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct MessageInfo(u64);

impl MessageInfo {
    const LENGTH_BITS: u64 = 0x7;
    const CAP_BIT: u64 = 1 << 3;
    const LABEL_SHIFT: u32 = 12;

    pub const fn new(label: u64, length: usize, carries_cap: bool) -> Self {
        let len = if length > MSG_REGS { MSG_REGS } else { length } as u64;
        Self((label << Self::LABEL_SHIFT) | len | if carries_cap { Self::CAP_BIT } else { 0 })
    }

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    /// What the message means. The kernel reads this for its own objects; for
    /// an endpoint it is untouched application data.
    pub const fn label(self) -> u64 {
        self.0 >> Self::LABEL_SHIFT
    }

    pub const fn length(self) -> usize {
        (self.0 & Self::LENGTH_BITS) as usize
    }

    pub const fn carries_cap(self) -> bool {
        self.0 & Self::CAP_BIT != 0
    }
}
