//! What untyped memory can become.

use crate::PAGE_SHIFT;

/// A capability slot is 128 bytes, so a CNode of 2^n slots is 2^(n+7) bytes.
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
    /// An asynchronous wake-up: a word of badges, and whoever is waiting for
    /// it.
    Notification,
    /// A one-shot right to reply to a caller.
    Reply,
    /// The right to claim interrupt sources.
    IrqControl,
    /// The right to receive, and to acknowledge, one interrupt source.
    IrqHandler,
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
    pub const fn size_bits(self, requested: u8) -> Option<u8> {
        match self {
            ObjectType::Null => None,
            ObjectType::Untyped | ObjectType::DeviceUntyped | ObjectType::CNode => {
                Some(requested)
            }
            ObjectType::Frame | ObjectType::PageTable | ObjectType::Tcb => {
                Some(PAGE_SHIFT as u8)
            }
            ObjectType::Endpoint | ObjectType::Notification => Some(SLOT_BITS),
            // Never retyped into.
            ObjectType::Reply | ObjectType::IrqControl | ObjectType::IrqHandler => None,
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
            8 => ObjectType::Notification,
            9 => ObjectType::Reply,
            10 => ObjectType::IrqControl,
            11 => ObjectType::IrqHandler,
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
            ObjectType::Notification => "notification",
            ObjectType::Reply => "reply",
            ObjectType::IrqControl => "irq-control",
            ObjectType::IrqHandler => "irq-handler",
        }
    }
}
