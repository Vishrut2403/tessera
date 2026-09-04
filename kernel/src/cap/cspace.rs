//! CSpace: a radix tree of CNodes, resolved by consuming address bits (D-029).

use core::ptr::NonNull;

use super::object::SLOT_BITS;
use super::slot::{self, Slot};
use super::{Cap, CapError, ObjectKind, ObjectType, RawCap};
use crate::mm::{PhysAddr, phys_to_virt};

/// Where a capability address stopped resolving, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// The root, or a slot the walk descended into, is not a CNode.
    NotACNode,
    /// The remaining depth is smaller than the next CNode's radix.
    DepthMismatch,
    /// More than 64 bits of address were asked for.
    TooDeep,
    /// The walk reached an empty slot with bits still to consume.
    EmptySlot,
}

impl From<ResolveError> for CapError {
    fn from(e: ResolveError) -> Self {
        CapError::Resolve(e)
    }
}

/// Borrow a CNode's slots.
///
/// # Safety
/// `cap` must be a live CNode capability, and the caller must have exclusive
/// access to it for the lifetime of the returned slice.
unsafe fn slots<'a>(cap: &RawCap) -> &'a mut [Slot] {
    let ptr = phys_to_virt(cap.paddr).as_mut_ptr::<Slot>();
    let len = 1usize << (cap.size_bits - SLOT_BITS);
    // SAFETY: the caller promised exclusive access to a live CNode, whose size
    // is what `retype` recorded when it made it.
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }
}

/// A capability space: the root CNode, and everything reachable from it.
pub struct CSpace {
    root: RawCap,
}

impl CSpace {
    /// Wrap a CNode as the root of a capability space.
    pub fn new(root: RawCap) -> Result<Self, CapError> {
        if root.kind != ObjectType::CNode {
            return Err(CapError::Resolve(ResolveError::NotACNode));
        }
        Ok(Self { root })
    }

    pub const fn root(&self) -> &RawCap {
        &self.root
    }

    /// Bits of a capability address the root CNode consumes: its radix.
    pub const fn root_depth(&self) -> u8 {
        self.root.size_bits - SLOT_BITS
    }

    /// Slots in the root CNode.
    pub const fn root_slots(&self) -> usize {
        1usize << (self.root.size_bits - SLOT_BITS)
    }

    /// Walk `cptr` to the slot it names.
    pub fn resolve(&self, cptr: u64, depth: u8) -> Result<NonNull<Slot>, ResolveError> {
        if depth > 64 {
            return Err(ResolveError::TooDeep);
        }

        let mut node = self.root;
        let mut remaining = depth;

        loop {
            if node.kind != ObjectType::CNode {
                return Err(ResolveError::NotACNode);
            }
            let radix = node.size_bits - SLOT_BITS;
            // `retype` refuses a CNode with radix 0, so `remaining` always
            // shrinks and this loop always terminates.
            if radix > remaining {
                return Err(ResolveError::DepthMismatch);
            }
            remaining -= radix;

            let index = ((cptr >> remaining) & ((1u64 << radix) - 1)) as usize;
            // SAFETY: `node` is a CNode capability the kernel owns, and `index`
            // is masked to its radix so it is in bounds.
            let entry = unsafe { &mut slots(&node)[index] };

            if remaining == 0 {
                return Ok(NonNull::from(entry));
            }
            if entry.is_empty() {
                return Err(ResolveError::EmptySlot);
            }
            node = entry.cap;
        }
    }

    /// The capability stored at `cptr`, without checking kind or rights.
    pub fn read(&self, cptr: u64, depth: u8) -> Result<RawCap, CapError> {
        let slot = self.resolve(cptr, depth)?;
        // SAFETY: `resolve` returned a live slot in a CNode we own.
        Ok(unsafe { slot.as_ref().cap })
    }

    /// Resolve `cptr` and prove, once, that it names a `T` carrying `R`.
    pub fn lookup<T: ObjectKind, const R: u8>(
        &self,
        cptr: u64,
        depth: u8,
    ) -> Result<Cap<T, R>, CapError> {
        Cap::from_raw(self.read(cptr, depth)?)
    }

    /// Put `cap` in an empty slot, derived from `parent` if one is given.
    pub fn insert(
        &mut self,
        cptr: u64,
        depth: u8,
        cap: RawCap,
        parent: Option<NonNull<Slot>>,
    ) -> Result<(), CapError> {
        let mut target = self.resolve(cptr, depth)?;
        // SAFETY: a live slot in a CNode we hold exclusively via `&mut self`.
        unsafe {
            if !target.as_ref().is_empty() {
                return Err(CapError::SlotOccupied);
            }
            target.as_mut().cap = cap;
            if let Some(p) = parent {
                slot::link(p, target);
            }
        }
        Ok(())
    }

    /// The copy `mint` would make, and the slot it descends from.
    /// Rights are intersected, never widened.
    fn prepare_mint(
        &self,
        src: (u64, u8),
        rights: u8,
        badge: u64,
    ) -> Result<(RawCap, NonNull<Slot>), CapError> {
        let source = self.resolve(src.0, src.1)?;
        // SAFETY: a live slot we hold exclusively.
        let original = unsafe { source.as_ref().cap };
        if original.is_null() {
            return Err(CapError::Null);
        }
        if original.rights & super::rights::GRANT == 0 {
            return Err(CapError::MissingRights {
                wanted: super::rights::GRANT,
                held: original.rights,
            });
        }
        // A copy is not the mapping the original made. seL4 gives every page
        // capability its own mapping slot for the same reason: without this a
        // receiver could not map a frame it was handed, and revoking a copy
        // would tear down the *original's* mapping (D-047).
        let mut copy = RawCap { rights: original.rights & rights, badge, ..original };
        copy.clear_mapping();
        Ok((copy, source))
    }

    /// Copy the capability at `src` into the empty slot at `dst`, weakened to
    /// `rights` and carrying `badge`.
    pub fn mint(
        &mut self,
        src: (u64, u8),
        dst: (u64, u8),
        rights: u8,
        badge: u64,
    ) -> Result<(), CapError> {
        let (copy, source) = self.prepare_mint(src, rights, badge)?;
        self.insert(dst.0, dst.1, copy, Some(source))
    }

    /// `mint`, but into a slot of some *other* capability space. This is how a parent
    /// endows a child it is building (D-043). The copy is still a derivative of
    /// the source, so revoking the original reclaims it across the boundary.
    pub fn mint_into(
        &self,
        into: &mut CSpace,
        src: (u64, u8),
        dst: (u64, u8),
        rights: u8,
        badge: u64,
    ) -> Result<(), CapError> {
        let (copy, source) = self.prepare_mint(src, rights, badge)?;
        into.insert(dst.0, dst.1, copy, Some(source))
    }

    /// Carve `count` objects out of the untyped at `src` and install them in
    /// consecutive slots starting at `dst`, as children of the untyped.
    pub fn retype(
        &mut self,
        src: (u64, u8),
        target: ObjectType,
        size_bits: u8,
        dst: (u64, u8),
        out: &mut [RawCap],
    ) -> Result<(), CapError> {
        let mut source = self.resolve(src.0, src.1)?;
        // SAFETY: a live slot we hold exclusively via `&mut self`.
        let untyped = unsafe { source.as_ref().cap };

        // Every destination slot must be free before the region is touched.
        for i in 0..out.len() {
            let s = self.resolve(dst.0 + i as u64, dst.1)?;
            // SAFETY: as above.
            if !unsafe { s.as_ref().is_empty() } {
                return Err(CapError::SlotOccupied);
            }
        }

        // Which retype runs is decided by the source's kind, and the two have
        // different rules about what they may become and whether the bytes are
        // zeroed (D-040).
        let watermark = if untyped.kind == ObjectType::DeviceUntyped {
            Cap::<super::kind::DeviceUntyped, { super::rights::WRITE }>::from_raw(untyped)?
                .retype(target, size_bits, out)?
        } else {
            Cap::<super::kind::Untyped, { super::rights::WRITE }>::from_raw(untyped)?
                .retype(target, size_bits, out)?
        };

        for (i, made) in out.iter().enumerate() {
            if made.kind == ObjectType::Endpoint {
                // SAFETY: just carved out of the untyped, so nothing refers to
                // it yet. Zeroed memory happens to be `Endpoint::EMPTY`, but
                // relying on that would make the enum's discriminant
                // load-bearing.
                unsafe { crate::ipc::init_endpoint(made.paddr) };
            }
            if made.kind == ObjectType::Notification {
                // SAFETY: just carved out of the untyped, so nothing refers to
                // it yet. Zeroed memory happens to be `Notification::EMPTY`,
                // but relying on that would make the layout load-bearing.
                unsafe { crate::notify::init(made.paddr) };
            }
            if made.kind == ObjectType::Tcb {
                // SAFETY: just carved out of the untyped, so nothing refers to
                // it yet. It comes out inactive: no address space, no CSpace,
                // no entry point, and `Resume` refuses it until it has them.
                unsafe { crate::thread::Tcb::init_inactive(made.paddr) };
            }
            if made.kind == ObjectType::CNode {
                // SAFETY: just carved out of the untyped, so nothing refers to
                // it yet. `zero` already made every slot empty (an all-zero
                // `Slot` is `Slot::EMPTY`), but relying on that silently would
                // make the layout of `SlotRef` load-bearing.
                unsafe { init_cnode(made.paddr, made.size_bits) };
            }
            self.insert(dst.0 + i as u64, dst.1, *made, Some(source))?;
        }

        // SAFETY: the source slot is live and only we are writing it.
        unsafe { source.as_mut().cap.watermark = watermark };
        Ok(())
    }

    /// Destroy everything derived from `cptr`, leaving the capability itself.
    pub fn revoke(&mut self, cptr: u64, depth: u8) -> Result<usize, CapError> {
        let target = self.resolve(cptr, depth)?;
        // SAFETY: `&mut self` is exclusive access to this whole capability space.
        Ok(unsafe { slot::revoke(target) })
    }

    /// Revoke everything under `cptr`, then empty the slot itself.
    pub fn delete(&mut self, cptr: u64, depth: u8) -> Result<usize, CapError> {
        let target = self.resolve(cptr, depth)?;
        // SAFETY: as above.
        Ok(unsafe { slot::delete(target) })
    }

    /// How many capabilities descend from `cptr`.
    pub fn descendants(&self, cptr: u64, depth: u8) -> Result<usize, CapError> {
        let target = self.resolve(cptr, depth)?;
        // SAFETY: a live slot; `&self` means nothing is mutating the tree.
        Ok(unsafe { target.as_ref().descendants() })
    }
}

/// Lay an empty CNode out over memory that was just retyped into one.
///
/// # Safety
/// `paddr` must be a CNode object of `size_bits` bytes that we own and that
/// nothing else refers to yet.
pub unsafe fn init_cnode(paddr: PhysAddr, size_bits: u8) {
    let count = 1usize << (size_bits - SLOT_BITS);
    let ptr = phys_to_virt(paddr).as_mut_ptr::<Slot>();
    for i in 0..count {
        // SAFETY: inside the object the caller promised, written once before
        // anything can observe it.
        unsafe { ptr.add(i).write(Slot::EMPTY) };
    }
}

/// Build the first capability space out of a region of untyped memory.
pub fn bootstrap(mut region: RawCap, cnode_bits: u8) -> Result<CSpace, CapError> {
    let cap = Cap::<super::kind::Untyped, { super::rights::WRITE }>::from_raw(region)?;

    let mut made = [RawCap::NULL; 1];
    region.watermark = cap.retype(ObjectType::CNode, cnode_bits, &mut made)?;
    let cnode = made[0];

    // SAFETY: freshly carved from the untyped, so nothing else refers to it.
    unsafe { init_cnode(cnode.paddr, cnode.size_bits) };

    let mut space = CSpace::new(cnode)?;
    let depth = cnode_bits - SLOT_BITS;
    space.insert(0, depth, region, None)?;

    let root_slot = space.resolve(0, depth)?;
    space.insert(1, depth, cnode, Some(root_slot))?;
    Ok(space)
}
