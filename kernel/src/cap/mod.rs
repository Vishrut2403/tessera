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
    /// Untyped only: how much of the region has already been handed out.
    pub watermark: usize,
    /// Set when a capability is minted, to identify the holder to a server (M5).
    pub badge: u64,
    /// Frames and page tables: the root of the address space this is mapped
    /// into, or zero.
    pub mapped_root: PhysAddr,
    /// Where in that address space, valid only when `mapped_root` is non-zero.
    pub mapped_vaddr: usize,
}

impl RawCap {
    pub const NULL: RawCap = RawCap {
        kind: ObjectType::Null,
        rights: 0,
        size_bits: 0,
        asid: 0,
        irq: 0,
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

    /// Untyped memory over device registers rather than RAM (D-040).
    pub const fn device_untyped(paddr: PhysAddr, size_bits: u8, rights: u8) -> RawCap {
        RawCap { kind: ObjectType::DeviceUntyped, rights, size_bits, paddr, ..RawCap::NULL }
    }

    /// Where this capability is mapped, if anywhere.
    pub const fn mapping(&self) -> Option<(PhysAddr, usize)> {
        match self.mapped_root.as_usize() {
            0 => None,
            root => Some((PhysAddr::new(root), self.mapped_vaddr)),
        }
    }

    /// Whether an ASID has been bound, which is what makes a root page table
    /// usable as an address space.
    pub const fn is_assigned(&self) -> bool {
        self.asid != 0
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
        self.raw.badge
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
        RawCap { badge, ..self.raw }
    }
}
