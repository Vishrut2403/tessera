//! Untyped memory and retyping: where every kernel object comes from.

use super::{Cap, CapError, HasWrite, Mask, ObjectType, RawCap, kind};
use crate::mm::{PhysAddr, phys_to_virt};

/// Where one object landed, and what is left of the region afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carved {
    pub paddr: PhysAddr,
    /// Bytes of the region consumed once this object is accounted for.
    pub watermark: usize,
}

/// Place one object of `size_bits` inside a region starting at `base`.
///
/// Objects are aligned to their own size, so the watermark is rounded up first;
/// the skipped bytes are lost, which is why a caller retyping many objects
/// should ask for them in one call rather than one at a time.
///
/// The alignment is applied to the *offset*, which only yields aligned objects
/// because a region is required to be aligned to its own size. That requirement
/// is checked here rather than assumed: an unaligned region would quietly
/// produce page tables the hardware will not accept.
pub const fn carve(
    base: PhysAddr,
    region_bits: u8,
    watermark: usize,
    size_bits: u8,
) -> Result<Carved, CapError> {
    if base.as_usize() & ((1usize << region_bits) - 1) != 0 {
        return Err(CapError::Misaligned);
    }
    if size_bits > region_bits {
        return Err(CapError::NotEnoughSpace);
    }
    let size = 1usize << size_bits;
    let aligned = (watermark + size - 1) & !(size - 1);
    if aligned + size > (1usize << region_bits) {
        return Err(CapError::NotEnoughSpace);
    }
    Ok(Carved { paddr: PhysAddr::new(base.as_usize() + aligned), watermark: aligned + size })
}

/// Zero a freshly carved object.
///
/// Retyping hands userspace a view of memory that may have held anything,
/// including another process's secrets, so this is not tidiness.
///
/// # Safety
/// `paddr` must name `1 << size_bits` bytes we own, reachable through the
/// direct map, with no live reference to them.
unsafe fn zero(paddr: PhysAddr, size_bits: u8) {
    let ptr = phys_to_virt(paddr).as_mut_ptr::<u8>();
    // SAFETY: the caller promised exclusive ownership of a mapped region.
    unsafe { core::ptr::write_bytes(ptr, 0, 1usize << size_bits) };
}

/// Retyping needs [`super::rights::WRITE`] on the untyped capability.
impl<const R: u8> Cap<kind::Untyped, R>
where
    Mask<R>: HasWrite,
{
    /// Carve `out.len()` objects of `kind` out of this region.
    ///
    /// Returns the new watermark. The caller owns writing it back to the slot,
    /// and owns installing the resulting capabilities; nothing is committed to
    /// the region unless every object fits, so a failure changes nothing.
    pub fn retype(
        &self,
        target: ObjectType,
        size_bits: u8,
        out: &mut [RawCap],
    ) -> Result<usize, CapError> {
        if matches!(target, ObjectType::Null) {
            return Err(CapError::BadObjectType);
        }
        let bits = match target.size_bits(size_bits) {
            Some(b) => b,
            None => return Err(CapError::BadObjectType),
        };
        // A CNode must consume at least one address bit, so it needs at least
        // two slots. A one-slot CNode would have radix 0, and a walk through it
        // would never shorten the remaining depth -- resolution would not
        // terminate. Refusing it here is what lets `CSpace::resolve` have no
        // iteration limit (D-029).
        if matches!(target, ObjectType::CNode) && bits <= super::object::SLOT_BITS {
            return Err(CapError::BadSize);
        }

        // Plan the whole batch before touching anything.
        let mut watermark = self.raw.watermark;
        for slot in out.iter_mut() {
            let carved = carve(self.raw.paddr, self.raw.size_bits, watermark, bits)?;
            watermark = carved.watermark;
            *slot = RawCap {
                kind: target,
                // A fresh object is held with every right; reduction is the
                // holder's business from here on.
                rights: super::rights::ALL,
                size_bits: bits,
                paddr: carved.paddr,
                ..RawCap::NULL
            };
        }

        for slot in out.iter() {
            // SAFETY: `carve` placed each object inside a region this
            // capability owns, and nothing else refers to it yet.
            unsafe { zero(slot.paddr, slot.size_bits) };
        }

        Ok(watermark)
    }

    /// Bytes of this region not yet handed out.
    pub const fn free_bytes(&self) -> usize {
        self.raw.size() - self.raw.watermark
    }
}
