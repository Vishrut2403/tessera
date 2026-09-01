//! The system calls, and the capability invocations built on them.
//!
//! Register layout, which is the whole ABI: `a0` is the capability being
//! invoked, `a1` the message header, `a2..a5` the four message words, `a6` a
//! capability slot when one rides along, `a7` the syscall number. The kernel
//! restores every register it did not deliberately write, so nothing here needs
//! a clobber list.

use core::arch::asm;

use abi::{MSG_REGS, MessageInfo, ObjectType, label, result, syscall};

/// A syscall that came back with one of the kernel's error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub usize);

pub type Result<T = ()> = core::result::Result<T, Error>;

impl Error {
    pub const fn name(self) -> &'static str {
        match self.0 {
            result::ERR_BAD_CAP => "bad capability",
            result::ERR_BAD_LABEL => "bad label",
            result::ERR_NO_REPLY => "no reply capability",
            result::ERR_NO_CSPACE => "no capability space",
            result::ERR_MAP => "mapping failed",
            result::ERR_STATE => "wrong thread state",
            result::ERR_ASID => "asid",
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
///
/// `cap` is the slot a capability is taken from or delivered into; it is only
/// read when the header says one is riding along.
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

/// Copy `src` to `dst` with `rights` and a badge. Both name slots in the
/// caller's own CSpace; `cnode` only has to be a CNode capability.
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
