//! Synchronous IPC: endpoints, messages, and the direct switch (D-031).

use core::ptr::NonNull;

use crate::cap::{ObjectType, RawCap};
use crate::mm::{PhysAddr, phys_to_virt};
use crate::thread::{Tcb, ThreadState};
use crate::trap::reg;

pub use abi::msg::{MSG_REGS, MessageInfo};

/// Registers `a2..a5` carry the message; `a0` and `a1` carry the header.
const MR_BASE: usize = reg::A0 + 2;

/// What an endpoint is doing. It never has senders and receivers queued at the
/// same time: whichever arrives second is matched immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointState {
    Idle,
    /// Threads are queued with messages to hand over.
    Sending,
    /// Threads are queued waiting for one.
    Receiving,
}

/// The rendezvous point itself, living in the endpoint object's memory.
#[repr(C)]
pub struct Endpoint {
    pub state: EndpointState,
    head: Option<NonNull<Tcb>>,
    tail: Option<NonNull<Tcb>>,
}

const _: () = assert!(size_of::<Endpoint>() <= 1 << crate::cap::object::SLOT_BITS);

impl Endpoint {
    pub const EMPTY: Endpoint = Endpoint { state: EndpointState::Idle, head: None, tail: None };

    pub const fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Put `tcb` at the back of the queue, and record what the queue is for.
    ///
    /// # Safety
    /// `tcb` must be a live TCB not already on any endpoint queue.
    pub unsafe fn enqueue(&mut self, mut tcb: NonNull<Tcb>, state: EndpointState) {
        // SAFETY: the caller promised a live TCB only we are touching.
        unsafe { tcb.as_mut().ipc_next = None };
        match self.tail {
            // SAFETY: as above.
            Some(mut t) => unsafe { t.as_mut().ipc_next = Some(tcb) },
            None => self.head = Some(tcb),
        }
        self.tail = Some(tcb);
        self.state = state;
    }

    /// Take the thread at the front, if the queue is for `wanted`.
    ///
    /// # Safety
    /// The queue must contain only live TCBs.
    pub unsafe fn dequeue(&mut self, wanted: EndpointState) -> Option<NonNull<Tcb>> {
        if self.state != wanted {
            return None;
        }
        let mut head = self.head?;
        // SAFETY: the caller promised live TCBs.
        let next = unsafe { head.as_mut().ipc_next.take() };
        self.head = next;
        if next.is_none() {
            self.tail = None;
            self.state = EndpointState::Idle;
        }
        Some(head)
    }

    /// Whether anyone is queued for `wanted`, without disturbing the order.
    ///
    /// `reply_recv` needs to know whether a sender is already waiting before it
    /// decides who gets the hart. Answering that by dequeuing and re-enqueuing
    /// would move the head to the tail and quietly break FIFO delivery.
    pub fn has_waiting(&self, wanted: EndpointState) -> bool {
        self.state == wanted && self.head.is_some()
    }

    /// Remove `tcb` from this queue wherever it is. Needed when a blocked
    /// thread is destroyed rather than woken.
    ///
    /// # Safety
    /// As [`dequeue`].
    pub unsafe fn remove(&mut self, tcb: NonNull<Tcb>) -> bool {
        let mut prev: Option<NonNull<Tcb>> = None;
        let mut cursor = self.head;

        while let Some(mut cur) = cursor {
            // SAFETY: the caller promised live TCBs.
            let next = unsafe { cur.as_ref().ipc_next };
            if cur == tcb {
                match prev {
                    // SAFETY: as above.
                    Some(mut p) => unsafe { p.as_mut().ipc_next = next },
                    None => self.head = next,
                }
                if self.tail == Some(cur) {
                    self.tail = prev;
                }
                // SAFETY: as above.
                unsafe { cur.as_mut().ipc_next = None };
                if self.head.is_none() {
                    self.state = EndpointState::Idle;
                }
                return true;
            }
            prev = Some(cur);
            cursor = next;
        }
        false
    }
}

/// Borrow the endpoint living in an object's memory.
///
/// # Safety
/// `paddr` must be a live endpoint object, and the caller must hold exclusive
/// access to it.
pub unsafe fn endpoint_at<'a>(paddr: PhysAddr) -> &'a mut Endpoint {
    // SAFETY: the caller promised a live endpoint reachable through the direct map.
    unsafe { &mut *phys_to_virt(paddr).as_mut_ptr::<Endpoint>() }
}

/// Lay out a freshly retyped endpoint.
///
/// # Safety
/// `paddr` must be an endpoint object nothing refers to yet.
pub unsafe fn init_endpoint(paddr: PhysAddr) {
    // SAFETY: the caller promised an untouched object.
    unsafe { phys_to_virt(paddr).as_mut_ptr::<Endpoint>().write(Endpoint::EMPTY) };
}

/// Copy the message registers from one thread's frame to another's.
///
/// This is the whole of the fast path's data movement: four words, register to
/// register, with no buffer to bound-check and no memory the sender can change
/// after the header has been read.
#[inline(always)]
pub fn transfer(from: &Tcb, to: &mut Tcb, info: MessageInfo, badge: u64) {
    for i in 0..info.length() {
        to.frame.x[MR_BASE + i] = from.frame.x[MR_BASE + i];
    }
    to.frame.x[reg::A0] = badge as usize;
    to.frame.x[reg::A1] = info.bits() as usize;
    to.badge = badge;
}

/// Read the message a thread is sending, out of its trap frame.
#[inline(always)]
pub fn message_of(tcb: &Tcb) -> MessageInfo {
    MessageInfo::from_bits(tcb.frame.x[reg::A1] as u64)
}

/// A one-shot capability naming the thread waiting for a reply.
///
/// The `paddr` is the caller's TCB, which is how `reply` finds it without a
/// lookup. Rights are READ only: a reply is used, not delegated onward with
/// more authority than it arrived with.
pub fn reply_cap(caller: PhysAddr) -> RawCap {
    RawCap {
        kind: ObjectType::Reply,
        rights: crate::cap::rights::READ,
        size_bits: 0,
        paddr: caller,
        ..RawCap::NULL
    }
}

/// Whether a thread is parked on an endpoint and can be woken with a message.
pub fn is_waiting(tcb: &Tcb) -> bool {
    matches!(tcb.state, ThreadState::BlockedOnRecv | ThreadState::BlockedOnSend)
}
