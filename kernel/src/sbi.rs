//! Our side of the SBI: the calls we make into OpenSBI.

/// What every SBI call returns: an error code and a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SbiRet {
    pub error: isize,
    pub value: usize,
}

impl SbiRet {
    pub const fn is_ok(self) -> bool {
        self.error == 0
    }
}

/// Extension IDs.
pub mod eid {
    pub const BASE: usize = 0x10;
    pub const TIME: usize = 0x5449_4D45;
}

/// Invoke an SBI function.
///
/// The SBI spec makes the implementation preserve everything but `a0` and `a1`,
/// and OpenSBI runs on its own M-mode stack, so there is nothing to clobber.
#[inline]
pub fn call(eid: usize, fid: usize, arg0: usize, arg1: usize) -> SbiRet {
    let (error, value);
    // SAFETY: `ecall` from S-mode traps to OpenSBI, which honours this convention.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            inlateout("a1") arg1 => value,
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    SbiRet { error, value }
}

/// Arm the timer for an absolute `time` value. The fallback when `sstc` is absent.
pub fn set_timer(deadline: u64) -> SbiRet {
    call(eid::TIME, 0, deadline as usize, 0)
}

/// Whether OpenSBI implements an extension at all.
pub fn probe_extension(id: usize) -> bool {
    let ret = call(eid::BASE, 3, id, 0);
    ret.is_ok() && ret.value != 0
}
