//! The object model: what untyped memory can become.

use crate::mm::PAGE_SHIFT;

/// A capability slot is 128 bytes, so a CNode of 2^n slots is 2^(n+7) bytes.
///
/// It grew from 64 in M6: a frame capability has to record *where* it is
/// mapped, or revoking it cannot remove the mapping and revocation does not
/// actually revoke (D-034). Overlaying those fields onto ones only other kinds
/// use would have kept 64 bytes and made the capability a union by convention,
/// which is what seL4 does and what is hardest to read there.
pub const SLOT_BITS: u8 = 7;

/// Every kind of object the kernel knows how to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    /// An empty slot. Not an object.
    Null,
    /// Physical memory with no type yet. The only thing that can become anything.
    Untyped,
    /// A table of capability slots. Also a level of a CSpace.
    CNode,
    /// A page of memory userspace can map.
    Frame,
    /// One level of an Sv39 page table.
    PageTable,
    /// A thread.
    Tcb,
    /// An IPC rendezvous point.
    Endpoint,
    /// A one-shot right to reply to a caller. Only the kernel mints these, on
    /// `call`, so it is deliberately absent from everything `retype` accepts.
    Reply,
}

impl ObjectType {
    /// Whether the object's size is fixed, or chosen when it is made.
    pub const fn is_variable_size(self) -> bool {
        matches!(self, ObjectType::Untyped | ObjectType::CNode)
    }

    /// Log2 of the object's size in bytes.
    ///
    /// `size_bits` is only consulted for the variable-size kinds; for the rest
    /// it is the type that decides, which is why passing one is an error.
    pub const fn size_bits(self, requested: u8) -> Option<u8> {
        match self {
            ObjectType::Null => None,
            ObjectType::Untyped | ObjectType::CNode => Some(requested),
            ObjectType::Frame | ObjectType::PageTable | ObjectType::Tcb => {
                Some(PAGE_SHIFT as u8)
            }
            ObjectType::Endpoint => Some(SLOT_BITS),
            // Never retyped into: minted by the kernel, pointing at a TCB.
            ObjectType::Reply => None,
        }
    }

    /// Slots in a CNode of this size, if it is one.
    pub const fn slots(self, size_bits: u8) -> Option<usize> {
        match self {
            ObjectType::CNode if size_bits >= SLOT_BITS => {
                Some(1usize << (size_bits - SLOT_BITS))
            }
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            ObjectType::Null => "null",
            ObjectType::Untyped => "untyped",
            ObjectType::CNode => "cnode",
            ObjectType::Frame => "frame",
            ObjectType::PageTable => "page-table",
            ObjectType::Tcb => "tcb",
            ObjectType::Endpoint => "endpoint",
            ObjectType::Reply => "reply",
        }
    }
}

/// Zero-sized markers naming an object kind in a capability's type.
pub mod kind {
    macro_rules! kinds {
        ($($name:ident => $ty:ident),* $(,)?) => { $(
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $name;
            impl super::ObjectKind for $name {
                const TYPE: super::ObjectType = super::ObjectType::$ty;
            }
        )* };
    }

    kinds! {
        Untyped => Untyped,
        CNode => CNode,
        Frame => Frame,
        PageTable => PageTable,
        Tcb => Tcb,
        Endpoint => Endpoint,
        Reply => Reply,
    }
}

/// Ties a marker type to the runtime tag it must match on lookup.
pub trait ObjectKind {
    const TYPE: ObjectType;
}
