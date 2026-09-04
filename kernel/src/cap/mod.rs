//! Capabilities: unforgeable authority, with rights checked by the compiler.

pub mod asid;
pub mod cspace;
pub mod object;
pub mod rights;
pub mod slot;
pub mod tcb;
pub mod untyped;
pub mod vspace;

use core::marker::PhantomData;

use crate::mm::PhysAddr;
pub use object::{ObjectKind, ObjectType, kind};
pub use rights::{HasGrant, HasRead, HasWrite, Mask, Subset};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The slot is empty.
    Null,
    /// The slot holds a different kind of object than the caller asked for.
    WrongType { wanted: ObjectType, found: ObjectType },
    /// The stored capability does not carry every right the caller needs.
    MissingRights { wanted: u8, held: u8 },
    /// The untyped region has no room left for another object of that size.
    NotEnoughSpace,
    /// A size was given for a fixed-size object, or omitted for a variable one.
    BadSize,
    /// A CNode smaller than one slot, or an object smaller than its type allows.
    BadObjectType,
    /// The capability address did not name a slot.
    Resolve(cspace::ResolveError),
    /// The destination slot already holds a capability.
    SlotOccupied,
    /// A badge was asked for on something that has no server on the other end
    /// (D-050).
    CannotBadge,
    /// Untyped memory cannot be copied, only moved: a copy would carry a
    /// second watermark over the same region (D-049).
    CannotCopy,
    /// The capability already records a mapping; unmap it first.
    AlreadyMapped,
    /// The page table refused the mapping.
    Map(crate::mm::page_table::MapError),
    /// The page table already has an ASID; assigning twice would strand one.
    AlreadyAssigned,
    /// The ASID pool refused.
    Asid(asid::AsidError),
    /// The kernel's own root table is not published yet, so there is no kernel
    /// half to copy.
    NoKernelSpace,
    /// A thread invoked its own TCB capability.
    SelfInvocation,
    /// The thread is not in a state where this invocation is allowed.
    NotInactive,
    /// The root page table has no ASID, so it is not an address space yet.
    NotAssigned,
    /// An untyped region not aligned to its own size.
    Misaligned,
}

/// A capability as it is stored: rights and identity known only at runtime.
/// `repr(C)`: [`slot::Slot`] must come out at exactly 128 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RawCap {
    pub kind: ObjectType,
    pub rights: u8,
    /// Log2 of the object's size in bytes.
    pub size_bits: u8,
    /// Root page tables only: the ASID `Assign` bound to this address space, or
    /// zero.
    pub asid: u16,
    /// `IrqHandler` only: the interrupt source this capability speaks for.
    pub irq: u16,
    /// The object itself. Physical, because a capability outlives any mapping.
    pub paddr: PhysAddr,
    /// Two payload words whose meaning `kind` decides. No object needs more
    /// than two, and none needs two different meanings at once, so they are
    /// shared rather than laid out side by side (D-050):
    ///
    /// | kind | `w0` | `w1` |
    /// |---|---|---|
    /// | untyped, device untyped | watermark | unused |
    /// | frame, page table | mapped root | mapped vaddr |
    /// | endpoint, notification | unused | badge |
    /// | everything else | unused | unused |
    ///
    /// Private, so that table is enforced by the accessors below instead of
    /// being remembered at every use.
    w0: usize,
    w1: usize,
}

impl RawCap {
    pub const NULL: RawCap = RawCap {
        kind: ObjectType::Null,
        rights: 0,
        size_bits: 0,
        asid: 0,
        irq: 0,
        paddr: PhysAddr::new(0),
        w0: 0,
        w1: 0,
    };

    pub const fn is_null(&self) -> bool {
        matches!(self.kind, ObjectType::Null)
    }

    /// A capability over an object, with no payload set. Callers outside this
    /// module build capabilities through this rather than by struct update,
    /// which is what keeps the payload words private (D-050).
    pub const fn new(kind: ObjectType, rights: u8, size_bits: u8, paddr: PhysAddr) -> RawCap {
        RawCap { kind, rights, size_bits, paddr, ..RawCap::NULL }
    }

    /// The same capability held with fewer rights. Rights are only ever
    /// narrowed, never widened, which `mint` and `reduce` both rely on.
    pub const fn with_rights(mut self, rights: u8) -> RawCap {
        self.rights &= rights;
        self
    }

    /// An untyped capability over a region. The one shape callers build by hand.
    pub const fn untyped(paddr: PhysAddr, size_bits: u8, rights: u8) -> RawCap {
        RawCap { kind: ObjectType::Untyped, rights, size_bits, paddr, ..RawCap::NULL }
    }

    /// Untyped memory over device registers rather than RAM (D-040).
    pub const fn device_untyped(paddr: PhysAddr, size_bits: u8, rights: u8) -> RawCap {
        RawCap { kind: ObjectType::DeviceUntyped, rights, size_bits, paddr, ..RawCap::NULL }
    }

    /// How much of an untyped region has already been handed out. Zero for
    /// anything that is not untyped, which has no watermark to speak of.
    pub const fn watermark(&self) -> usize {
        if self.kind.is_untyped() { self.w0 } else { 0 }
    }

    pub const fn set_watermark(&mut self, to: usize) {
        debug_assert!(self.kind.is_untyped(), "only untyped memory has a watermark");
        self.w0 = to;
    }

    /// The badge a holder was minted with, to identify it to a server. Zero on
    /// anything a badge cannot mean something on, so a frame's mapped address
    /// can never be read back as one.
    pub const fn badge(&self) -> u64 {
        if self.kind.is_badgeable() { self.w1 as u64 } else { 0 }
    }

    pub const fn set_badge(&mut self, to: u64) {
        debug_assert!(self.kind.is_badgeable(), "only endpoints and notifications carry a badge");
        self.w1 = to as usize;
    }

    /// Where this capability is mapped, if anywhere.
    pub const fn mapping(&self) -> Option<(PhysAddr, usize)> {
        if !self.kind.is_mappable() {
            return None;
        }
        match self.w0 {
            0 => None,
            root => Some((PhysAddr::new(root), self.w1)),
        }
    }

    pub const fn set_mapping(&mut self, root: PhysAddr, vaddr: usize) {
        debug_assert!(self.kind.is_mappable(), "only frames and page tables are mapped");
        self.w0 = root.as_usize();
        self.w1 = vaddr;
    }

    /// A copy of this capability carrying nothing that belonged to the previous
    /// holder: no badge, and no mapping of its own (D-047, D-050).
    pub const fn fresh_copy(&self) -> RawCap {
        let mut copy = *self;
        copy.w1 = 0;
        if copy.kind.is_mappable() {
            copy.w0 = 0;
        }
        copy
    }

    /// Whether an ASID has been bound, which is what makes a root page table
    /// usable as an address space.
    pub const fn is_assigned(&self) -> bool {
        self.asid != 0
    }

    pub const fn clear_mapping(&mut self) {
        if self.kind.is_mappable() {
            self.w0 = 0;
            self.w1 = 0;
        }
    }

    /// Size of the object in bytes.
    pub const fn size(&self) -> usize {
        1usize << self.size_bits
    }

    /// One past the last byte of the object.
    pub const fn end(&self) -> usize {
        self.paddr.as_usize() + self.size()
    }

    /// Whether `other` names memory inside this region.
    pub const fn covers(&self, other: &RawCap) -> bool {
        other.paddr.as_usize() >= self.paddr.as_usize() && other.end() <= self.end()
    }
}

/// A capability whose object kind and rights are both known to the compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap<T, const R: u8> {
    raw: RawCap,
    _kind: PhantomData<T>,
}

impl<T: ObjectKind, const R: u8> Cap<T, R> {
    /// Wrap a raw capability, checking the kind and the rights once.
    pub fn from_raw(raw: RawCap) -> Result<Self, CapError> {
        if raw.is_null() {
            return Err(CapError::Null);
        }
        if raw.kind != T::TYPE {
            return Err(CapError::WrongType { wanted: T::TYPE, found: raw.kind });
        }
        if raw.rights & R != R {
            return Err(CapError::MissingRights { wanted: R, held: raw.rights });
        }
        Ok(Self { raw, _kind: PhantomData })
    }

    pub const fn raw(&self) -> &RawCap {
        &self.raw
    }

    pub const fn paddr(&self) -> PhysAddr {
        self.raw.paddr
    }

    pub const fn size(&self) -> usize {
        self.raw.size()
    }

    pub const fn badge(&self) -> u64 {
        self.raw.badge()
    }

    /// Weaken this capability to a smaller set of rights.
    pub fn reduce<const M: u8>(self) -> Cap<T, M>
    where
        Mask<R>: Subset<R, M>,
    {
        Cap { raw: RawCap { rights: self.raw.rights & M, ..self.raw }, _kind: PhantomData }
    }
}

/// Operations that need [`rights::GRANT`].
impl<T: ObjectKind, const R: u8> Cap<T, R>
where
    Mask<R>: HasGrant,
{
    /// A copy to hand to someone else, carrying `badge` so a server can tell
    /// holders apart.
    pub fn delegate(&self, badge: u64) -> RawCap {
        let mut copy = self.raw.fresh_copy();
        if badge != 0 && copy.kind.is_badgeable() {
            copy.set_badge(badge);
        }
        copy
    }
}
