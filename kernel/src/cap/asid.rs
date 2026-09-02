//! The ASID pool: what D-022 deferred until there was an object model.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mm::address_space::{AddressSpace, Asid};
use crate::sync::SpinLock;

/// ASIDs the pool hands out.
pub const MAX_ASIDS: usize = 64;

/// ASID 0 is what every address space uses before it is assigned one, so the
/// pool never hands it out: two spaces sharing it would be indistinguishable to
/// the TLB, which is the exact bug ASIDs exist to prevent.
const FIRST_ASID: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsidError {
    /// Every ASID in the pool is assigned.
    Exhausted,
    /// The hart implements no ASID bits, so tagging is not available.
    NotSupported,
}

/// A pool of address space identifiers.
pub struct AsidPool {
    /// One bit per ASID; bit `n` set means `FIRST_ASID + n` is in use.
    used: u64,
    bits: u8,
}

impl AsidPool {
    pub const fn new(bits: u8) -> Self {
        Self { used: 0, bits }
    }

    /// How many ASID bits this hart actually implements.
    pub fn probe_bits() -> u8 {
        let original = crate::csr::satp::read();
        const ASID_MASK: usize = 0xffff << 44;

        // SAFETY: satp is restored before returning, and no translation happens
        // in between -- writing the ASID field alone does not change the root
        // page table, and this hart is not using ASIDs yet.
        let readback = unsafe {
            crate::csr::satp::write(original | ASID_MASK);
            let v = crate::csr::satp::read();
            crate::csr::satp::write(original);
            v
        };
        crate::mm::flush_tlb_all();

        (((readback & ASID_MASK) >> 44) as u16).count_ones() as u8
    }

    /// Re-open the pool at the hart's real ASID width, forgetting every
    /// assignment.
    pub fn reset(&mut self, bits: u8) {
        self.used = 0;
        self.bits = bits;
    }

    pub const fn capacity(&self) -> usize {
        let n = 1usize << self.bits;
        // Minus one for the reserved ASID 0, capped by the bitmap's width.
        let usable = if n > 0 { n - 1 } else { 0 };
        if usable > MAX_ASIDS { MAX_ASIDS } else { usable }
    }

    pub const fn in_use(&self) -> u32 {
        self.used.count_ones()
    }

    /// Take an unused ASID.
    pub fn allocate(&mut self) -> Result<Asid, AsidError> {
        if self.bits == 0 {
            return Err(AsidError::NotSupported);
        }
        let capacity = self.capacity();
        for i in 0..capacity {
            if self.used & (1 << i) == 0 {
                self.used |= 1 << i;
                return Ok(Asid::new(FIRST_ASID + i as u16));
            }
        }
        Err(AsidError::Exhausted)
    }

    /// Give an ASID back.
    /// Stale TLB entries go first: the next holder must not see them.
    pub fn release(&mut self, asid: Asid) {
        let Some(index) = asid.as_u16().checked_sub(FIRST_ASID) else { return };
        if (index as usize) < self.capacity() {
            flush_asid(asid);
            self.used &= !(1u64 << index);
        }
    }

    /// Bind an ASID to an address space, so switching to it stops needing a
    /// full TLB flush (D-022).
    pub fn assign(&mut self, space: &mut AddressSpace) -> Result<Asid, AsidError> {
        let asid = self.allocate()?;
        flush_asid(asid);
        space.set_asid(asid);
        Ok(asid)
    }
}

/// Invalidate every translation tagged with `asid`, on this hart.
pub fn flush_asid(asid: Asid) {
    // SAFETY: `sfence.vma zero, rs2` invalidates the entries for one ASID and
    // has no effect beyond the TLB.
    unsafe {
        core::arch::asm!(
            "sfence.vma zero, {asid}",
            asid = in(reg) asid.as_u16() as usize,
            options(nostack),
        );
    }
}

/// Number of ASID bits this hart implements, probed once at boot.
static ASID_BITS: AtomicU64 = AtomicU64::new(u64::MAX);

/// Probe and remember the ASID width. Safe to call more than once.
pub fn init() -> u8 {
    if ASID_BITS.load(Ordering::Relaxed) == u64::MAX {
        ASID_BITS.store(AsidPool::probe_bits() as u64, Ordering::Relaxed);
    }
    ASID_BITS.load(Ordering::Relaxed) as u8
}

pub fn bits() -> u8 {
    match ASID_BITS.load(Ordering::Relaxed) {
        u64::MAX => 0,
        n => n as u8,
    }
}

/// The kernel-global pool userspace draws from.
static POOL: SpinLock<AsidPool> = SpinLock::new(AsidPool::new(0));

static POOL_READY: AtomicBool = AtomicBool::new(false);

/// Probe the hart's ASID width and open the global pool.
pub fn init_pool() -> u8 {
    let bits = init();
    if !POOL_READY.swap(true, Ordering::Relaxed) {
        POOL.lock().reset(bits);
    }
    bits
}

/// Take an ASID from the global pool.
pub fn assign_global() -> Result<Asid, AsidError> {
    init_pool();
    POOL.lock().allocate()
}

/// Give one back.
pub fn release_global(asid: Asid) {
    POOL.lock().release(asid);
}

/// How many ASIDs the global pool has handed out.
pub fn global_in_use() -> u32 {
    POOL.lock().in_use()
}
