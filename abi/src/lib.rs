//! The tessera system-call interface: everything the kernel and userspace must
//! agree on, and nothing else (D-038).

#![no_std]

pub mod bootinfo;
pub mod msg;
pub mod object;
pub mod rights;

pub use bootinfo::BootInfo;
pub use msg::{MSG_REGS, MessageInfo};
pub use object::{ObjectType, SLOT_BITS};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// The system call numbers.
pub mod syscall {
    pub const YIELD: usize = 0;
    pub const EXIT: usize = 1;
    pub const PUTC: usize = 2;
    pub const GET_ID: usize = 3;
    /// Send and block until taken; no reply expected.
    pub const SEND: usize = 4;
    /// Block until a message arrives.
    pub const RECV: usize = 5;
    /// Send and block until replied to. The fast path.
    pub const CALL: usize = 6;
    /// Answer the caller whose reply capability we hold.
    pub const REPLY: usize = 7;
    /// Reply, then wait for the next message. What a server loop runs.
    pub const REPLY_RECV: usize = 8;
}

/// Labels selecting an operation on a kernel object (D-032).
pub mod label {
    /// Untyped: carve objects out of a region.
    pub const RETYPE: u64 = 1;
    /// CNode: copy a capability with reduced rights.
    pub const MINT: u64 = 2;
    /// CNode: destroy everything derived from a capability.
    pub const REVOKE: u64 = 3;
    /// CNode: destroy a capability and its derivatives.
    pub const DELETE: u64 = 4;
    /// Frame or PageTable: install into an address space.
    pub const MAP: u64 = 5;
    /// Frame or PageTable: remove whatever mapping it records.
    pub const UNMAP: u64 = 6;
    /// TCB: attach a fault endpoint.
    pub const SET_FAULT_EP: u64 = 7;
    /// TCB: give a thread its address space, CSpace and pager.
    pub const CONFIGURE: u64 = 8;
    /// TCB: set the entry point and stack pointer.
    pub const WRITE_REGISTERS: u64 = 9;
    /// TCB: make a configured thread runnable.
    pub const RESUME: u64 = 10;
    /// TCB: take a runnable thread off the run queue.
    pub const SUSPEND: u64 = 11;
    /// PageTable: install the kernel half and bind an ASID (D-037).
    pub const ASSIGN: u64 = 12;
    /// IrqControl: mint an `IrqHandler` for one source (D-041).
    pub const IRQ_GET: u64 = 14;
    /// IrqHandler: deliver this source to a notification from now on.
    pub const IRQ_SET_NOTIFICATION: u64 = 15;
    /// IrqHandler: the device is quiet again; unmask the source.
    pub const IRQ_ACK: u64 = 16;

    /// Frame: where it physically is, for a device that does not walk page
    /// tables.
    /// Needs `WRITE`: a physical address aims a bus master (D-040).
    pub const GET_ADDRESS: u64 = 13;

    /// What the kernel sends a pager when a thread faults (D-034).
    pub const FAULT_VM: u64 = 0x100;

    /// The first label the kernel does not interpret.
    pub const APP_BASE: u64 = 0x1000;
}

/// What a syscall returns in `a0`.
pub mod result {
    pub const OK: usize = 0;
    pub const ERR_BAD_CAP: usize = usize::MAX;
    pub const ERR_BAD_LABEL: usize = usize::MAX - 1;
    pub const ERR_NO_REPLY: usize = usize::MAX - 2;
    pub const ERR_NO_CSPACE: usize = usize::MAX - 3;
    pub const ERR_MAP: usize = usize::MAX - 4;
    /// The thread is not in a state that allows the invocation, or a thread
    /// invoked its own TCB.
    pub const ERR_STATE: usize = usize::MAX - 5;
    /// The address space has no ASID, or the pool had none left.
    pub const ERR_ASID: usize = usize::MAX - 6;

    /// Whether `a0` came back as one of the error codes above.
    pub const fn is_err(a0: usize) -> bool {
        a0 >= ERR_ASID
    }
}
