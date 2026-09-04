//! The system calls, and the capability invocations built on them.

use core::arch::asm;

use abi::{MSG_REGS, MessageInfo, ObjectType, label, result, syscall};

/// A syscall that came back with one of the kernel's error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub usize);

pub type Result<T = ()> = core::result::Result<T, Error>;

impl Error {
    /// Whether this is the one mapping failure a caller can fix, by retyping
    /// an intermediate page table and trying again (D-035).
    pub const fn is_missing_table(self) -> bool {
        self.0 == result::ERR_NO_TABLE
    }

    pub const fn name(self) -> &'static str {
        match self.0 {
            result::ERR_BAD_CAP => "bad capability",
            result::ERR_BAD_LABEL => "bad label",
            result::ERR_NO_REPLY => "no reply capability",
            result::ERR_NO_CSPACE => "no capability space",
            result::ERR_MAP => "mapping failed",
            result::ERR_STATE => "wrong thread state",
            result::ERR_ASID => "asid",
            result::ERR_NO_TABLE => "no intermediate page table",
            _ => "unknown",
        }
    }
}

const fn check(a0: usize) -> Result {
    if result::is_err(a0) { Err(Error(a0)) } else { Ok(()) }
}

// --- The bare syscalls ---

pub fn yield_now() {
    // SAFETY: `ecall` traps to the kernel, which restores every register.
    unsafe { asm!("ecall", in("a7") syscall::YIELD, options(nostack)) }
}

pub fn exit() -> ! {
    // SAFETY: the kernel never returns from `EXIT`.
    unsafe { asm!("ecall", in("a7") syscall::EXIT, options(nostack, noreturn)) }
}

pub fn putc(c: u8) {
    // SAFETY: as above; `a0` is written by the kernel and declared out.
    unsafe { asm!("ecall", inout("a0") c as usize => _, in("a7") syscall::PUTC, options(nostack)) }
}

pub fn thread_id() -> usize {
    let id;
    // SAFETY: as above.
    unsafe { asm!("ecall", out("a0") id, in("a7") syscall::GET_ID, options(nostack)) };
    id
}

/// What a `recv` or the reply to a `call` on an endpoint came back with.
#[derive(Debug, Clone, Copy, Default)]
pub struct Message {
    /// The badge of the capability the sender used, or zero.
    pub badge: u64,
    pub info: MessageInfo,
    pub words: [usize; MSG_REGS],
}

impl Message {
    /// `a0` again, under the name it has when the thing invoked was a kernel
    /// object rather than an endpoint.
    pub const fn status(&self) -> usize {
        self.badge as usize
    }
}

/// The one place `ecall` is written with a full message in and out.
fn ecall(number: usize, cptr: u64, info: MessageInfo, words: [usize; MSG_REGS], cap: u64)
-> Message {
    let mut a0 = cptr as usize;
    let mut a1 = info.bits() as usize;
    let [mut a2, mut a3, mut a4, mut a5] = words;
    // SAFETY: `ecall` traps to the kernel, which restores every register other
    // than the ones declared `inout` here.
    unsafe {
        asm!(
            "ecall",
            inout("a0") a0,
            inout("a1") a1,
            inout("a2") a2,
            inout("a3") a3,
            inout("a4") a4,
            inout("a5") a5,
            in("a6") cap as usize,
            in("a7") number,
            options(nostack),
        );
    }
    Message { badge: a0 as u64, info: MessageInfo::from_bits(a1 as u64), words: [a2, a3, a4, a5] }
}

/// Invoke a kernel object. `a0` comes back as a status, not a badge.
fn invoke(cptr: u64, l: u64, words: [usize; MSG_REGS], used: usize) -> Result {
    let info = MessageInfo::new(l, used, false);
    check(ecall(syscall::CALL, cptr, info, words, 0).status())
}

// --- Endpoints ---

pub fn send(ep: u64, info: MessageInfo, words: [usize; MSG_REGS]) -> Result {
    check(ecall(syscall::SEND, ep, info, words, 0).status())
}

pub fn call(ep: u64, info: MessageInfo, words: [usize; MSG_REGS]) -> Message {
    ecall(syscall::CALL, ep, info, words, 0)
}

/// Call, granting the capability in `slot` to the receiver (D-036). The
/// receiver names where it lands, so nobody is handed authority unasked.
pub fn call_cap(ep: u64, info: MessageInfo, words: [usize; MSG_REGS], slot: u64) -> Message {
    ecall(syscall::CALL, ep, info, words, slot)
}

pub fn recv(ep: u64) -> Message {
    ecall(syscall::RECV, ep, MessageInfo::default(), [0; MSG_REGS], 0)
}

/// Receive, taking any capability the sender grants into `slot`.
pub fn recv_cap(ep: u64, slot: u64) -> Message {
    ecall(syscall::RECV, ep, MessageInfo::default(), [0; MSG_REGS], slot)
}

pub fn reply(info: MessageInfo, words: [usize; MSG_REGS]) -> Result {
    check(ecall(syscall::REPLY, 0, info, words, 0).status())
}

/// Answer the current caller and wait for the next. What a server loop runs.
pub fn reply_recv(ep: u64, info: MessageInfo, words: [usize; MSG_REGS]) -> Message {
    ecall(syscall::REPLY_RECV, ep, info, words, 0)
}

// --- Invocations on kernel objects ---

/// Carve `count` objects out of `untyped` into consecutive slots from `dst`.
pub fn retype(untyped: u64, kind: ObjectType, size_bits: u8, dst: u64, count: usize) -> Result {
    invoke(untyped, label::RETYPE, [kind as usize, size_bits as usize, dst as usize, count], 4)
}

/// Copy `src` to `dst` with `rights` and a badge.
pub fn mint(cnode: u64, src: u64, dst: u64, rights: u8, badge: u64) -> Result {
    invoke(cnode, label::MINT, [src as usize, dst as usize, rights as usize, badge as usize], 4)
}

pub fn revoke(cnode: u64, src: u64) -> Result {
    invoke(cnode, label::REVOKE, [src as usize, 0, 0, 0], 4)
}

pub fn delete(cnode: u64, src: u64) -> Result {
    invoke(cnode, label::DELETE, [src as usize, 0, 0, 0], 4)
}

/// Install the kernel half and bind an ASID: what turns a retyped page table
/// into an address space (D-037).
pub fn assign(vspace: u64) -> Result {
    invoke(vspace, label::ASSIGN, [0; MSG_REGS], 4)
}

pub fn map_frame(frame: u64, vspace: u64, vaddr: usize, rights: u8, exec: bool) -> Result {
    invoke(frame, label::MAP, [vspace as usize, vaddr, rights as usize, exec as usize], 4)
}

/// Install an intermediate page table at `level` (2 is the outermost).
pub fn map_table(table: u64, vspace: u64, vaddr: usize, level: usize) -> Result {
    invoke(table, label::MAP, [vspace as usize, vaddr, 0, level], 4)
}

pub fn unmap(obj: u64) -> Result {
    invoke(obj, label::UNMAP, [0; MSG_REGS], 4)
}

/// Where a frame physically is, for a device that does not walk page tables.
/// Needs `WRITE` on the frame (D-040).
pub fn get_address(frame: u64) -> core::result::Result<usize, Error> {
    let info = MessageInfo::new(label::GET_ADDRESS, 0, false);
    let a0 = ecall(syscall::CALL, frame, info, [0; MSG_REGS], 0).status();
    if result::is_err(a0) { Err(Error(a0)) } else { Ok(a0) }
}

// --- Notifications and interrupts (D-041) ---

/// Signal a notification: OR this capability's badge into its word and wake
/// whoever is waiting.
pub fn signal(notification: u64) -> Result {
    send(notification, MessageInfo::default(), [0; MSG_REGS])
}

/// Wait for a notification, and take the badges that have accumulated.
pub fn wait(notification: u64) -> u64 {
    ecall(syscall::RECV, notification, MessageInfo::default(), [0; MSG_REGS], 0).badge
}

/// Claim one interrupt source, minting an `IrqHandler` for it into `dst`.
pub fn irq_get(control: u64, irq: usize, dst: u64) -> Result {
    invoke(control, label::IRQ_GET, [irq, dst as usize, 0, 0], 2)
}

/// Deliver this source to `notification` from now on, and unmask it.
pub fn irq_set_notification(handler: u64, notification: u64) -> Result {
    invoke(handler, label::IRQ_SET_NOTIFICATION, [notification as usize, 0, 0, 0], 1)
}

/// The device is quiet again: unmask the source.
pub fn irq_ack(handler: u64) -> Result {
    invoke(handler, label::IRQ_ACK, [0; MSG_REGS], 0)
}

// --- Invocations on threads ---

pub fn tcb_configure(tcb: u64, cspace: u64, vspace: u64, fault_ep: u64) -> Result {
    invoke(tcb, label::CONFIGURE, [cspace as usize, vspace as usize, fault_ep as usize, 0], 3)
}

pub fn tcb_set_fault_ep(tcb: u64, fault_ep: u64) -> Result {
    invoke(tcb, label::SET_FAULT_EP, [fault_ep as usize, 0, 0, 0], 1)
}

pub fn tcb_write_registers(tcb: u64, entry: usize, stack_top: usize) -> Result {
    invoke(tcb, label::WRITE_REGISTERS, [entry, stack_top, 0, 0], 2)
}

pub fn tcb_resume(tcb: u64) -> Result {
    invoke(tcb, label::RESUME, [0; MSG_REGS], 0)
}

pub fn tcb_suspend(tcb: u64) -> Result {
    invoke(tcb, label::SUSPEND, [0; MSG_REGS], 0)
}
