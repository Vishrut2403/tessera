//! What untyped memory can become.

use crate::PAGE_SHIFT;

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
    /// Untyped memory over a region that is not RAM: device registers (D-040).
    ///
    /// It becomes frames, or smaller device untypeds, and nothing else. A CNode
    /// or a TCB is memory the *kernel* reads and writes, and putting one over
    /// MMIO would make the kernel's own bookkeeping a sequence of device
    /// accesses. It is also never zeroed, because zeroing MMIO is a burst of
    /// stores to live hardware.
    DeviceUntyped,
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
        matches!(self, ObjectType::Untyped | ObjectType::DeviceUntyped | ObjectType::CNode)
    }

    /// Whether this is memory waiting to be given a type.
    pub const fn is_untyped(self) -> bool {
        matches!(self, ObjectType::Untyped | ObjectType::DeviceUntyped)
    }

    /// Whether retyping it must skip zeroing, because the bytes are registers.
    pub const fn is_device(self) -> bool {
        matches!(self, ObjectType::DeviceUntyped)
    }

    /// Log2 of the object's size in bytes.
    ///
    /// `size_bits` is only consulted for the variable-size kinds; for the rest
    /// it is the type that decides, which is why passing one is an error.
    pub const fn size_bits(self, requested: u8) -> Option<u8> {
        match self {
            ObjectType::Null => None,
            ObjectType::Untyped | ObjectType::DeviceUntyped | ObjectType::CNode => {
                Some(requested)
            }
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

    /// Decode the wire value userspace puts in a `Retype` message.
    ///
    /// The one place the discriminants are written down twice, and it sits
    /// beside the enum so the two cannot drift into separate crates.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => ObjectType::Null,
            1 => ObjectType::Untyped,
            2 => ObjectType::DeviceUntyped,
            3 => ObjectType::CNode,
            4 => ObjectType::Frame,
            5 => ObjectType::PageTable,
            6 => ObjectType::Tcb,
            7 => ObjectType::Endpoint,
            8 => ObjectType::Reply,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            ObjectType::Null => "null",
            ObjectType::Untyped => "untyped",
            ObjectType::DeviceUntyped => "device-untyped",
            ObjectType::CNode => "cnode",
            ObjectType::Frame => "frame",
            ObjectType::PageTable => "page-table",
            ObjectType::Tcb => "tcb",
            ObjectType::Endpoint => "endpoint",
            ObjectType::Reply => "reply",
        }
    }
}
