//! Capabilities: unforgeable authority, with rights checked by the compiler.

pub mod asid;
pub mod cspace;
pub mod object;
pub mod rights;
pub mod slot;
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
    /// The capability already records a mapping; unmap it first.
    AlreadyMapped,
    /// The page table refused the mapping.
    Map(crate::mm::page_table::MapError),
    /// An untyped region not aligned to its own size. Objects are placed at
    /// aligned offsets, so an unaligned region would yield unaligned objects --
    /// and a page table that is not 4 KiB aligned is not a page table.
    Misaligned,
}

/// A capability as it is stored: rights and identity known only at runtime.
///
/// `repr(C)` because [`slot::Slot`] must come out at exactly 64 bytes, which is
/// what makes a CNode of 2^n slots occupy 2^(n+6) bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RawCap {
    pub kind: ObjectType,
    pub rights: u8,
    /// Log2 of the object's size in bytes.
    pub size_bits: u8,
    /// The object itself. Physical, because a capability outlives any mapping.
    pub paddr: PhysAddr,
    /// Untyped only: how much of the region has already been handed out.
    pub watermark: usize,
    /// Set when a capability is minted, to identify the holder to a server (M5).
    pub badge: u64,
    /// Frames and page tables: the root of the address space this is mapped
    /// into, or zero. Recorded so revocation can find the mapping (D-034).
    pub mapped_root: PhysAddr,
    /// Where in that address space, valid only when `mapped_root` is non-zero.
    pub mapped_vaddr: usize,
}

impl RawCap {
    pub const NULL: RawCap = RawCap {
        kind: ObjectType::Null,
        rights: 0,
        size_bits: 0,
        paddr: PhysAddr::new(0),
        watermark: 0,
        badge: 0,
        mapped_root: PhysAddr::new(0),
        mapped_vaddr: 0,
    };

    pub const fn is_null(&self) -> bool {
        matches!(self.kind, ObjectType::Null)
    }

    /// An untyped capability over a region. The one shape callers build by hand.
    pub const fn untyped(paddr: PhysAddr, size_bits: u8, rights: u8) -> RawCap {
        RawCap { kind: ObjectType::Untyped, rights, size_bits, paddr, ..RawCap::NULL }
    }

    /// Where this capability is mapped, if anywhere.
    pub const fn mapping(&self) -> Option<(PhysAddr, usize)> {
        match self.mapped_root.as_usize() {
            0 => None,
            root => Some((PhysAddr::new(root), self.mapped_vaddr)),
        }
    }

    pub const fn clear_mapping(&mut self) {
        self.mapped_root = PhysAddr::new(0);
        self.mapped_vaddr = 0;
    }

    /// Size of the object in bytes.
    pub const fn size(&self) -> usize {
        1usize << self.size_bits
    }

    /// One past the last byte of the object.
    pub const fn end(&self) -> usize {
        self.paddr.as_usize() + self.size()
    }

    /// Whether `other` names memory inside this region. What makes an object a
    /// descendant of the untyped it was carved from.
    pub const fn covers(&self, other: &RawCap) -> bool {
        other.paddr.as_usize() >= self.paddr.as_usize() && other.end() <= self.end()
    }
}

/// A capability whose object kind and rights are both known to the compiler.
///
/// `R` is a mask of [`rights`]. An operation needing a right is only defined for
/// masks that contain it, so calling it without one is a missing method rather
/// than a check that might be forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap<T, const R: u8> {
    raw: RawCap,
    _kind: PhantomData<T>,
}

impl<T: ObjectKind, const R: u8> Cap<T, R> {
    /// Wrap a raw capability, checking the kind and the rights once.
    ///
    /// This is the only way a `Cap` is made, and the single runtime check that
    /// the rest of the type system is built on.
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
        self.raw.badge
    }

    /// Weaken this capability to a smaller set of rights.
    ///
    /// `Mask<R>: Subset<R, M>` is what makes this a reduction: a target mask
    /// that is not a subset does not implement it, so escalation does not
    /// compile. The rights actually stored are narrowed to match.
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
    /// holders apart. Requires GRANT, by construction.
    pub fn delegate(&self, badge: u64) -> RawCap {
        RawCap { badge, ..self.raw }
    }
}
