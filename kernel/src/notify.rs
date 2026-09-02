//! Notifications: the asynchronous half of IPC (D-041).
//!
//! An endpoint is a rendezvous — both ends block until the other arrives. That
//! is exactly wrong for an interrupt, which has no thread behind it and cannot
//! wait for anyone. A notification is the other shape: signalling never blocks,
//! and what it leaves behind is a word of badges rather than a message.
//!
//! Signals between two waits collapse into one wake, because the word is OR'd
//! rather than counted. A device that interrupts faster than its driver runs
//! therefore accumulates nothing in the kernel — and for a level-triggered
//! device "how many" was never the question anyway: the driver re-reads the
//! status register to find out what happened.

use core::ptr::NonNull;

use crate::mm::{PhysAddr, phys_to_virt};
use crate::thread::Tcb;

/// The rendezvous-free wake-up, living in the notification object's memory.
#[repr(C)]
pub struct Notification {
    /// Badges of every signal since the last wait, OR'd together.
    pub word: u64,
    /// Whether anything has been signalled at all. Separate from `word` so an
    /// unbadged signal still wakes a later waiter: testing `word != 0` would
    /// silently lose every signal carrying a badge of zero.
    pub pending: bool,
    head: Option<NonNull<Tcb>>,
    tail: Option<NonNull<Tcb>>,
}

const _: () = assert!(size_of::<Notification>() <= 1 << crate::cap::object::SLOT_BITS);

impl Notification {
    pub const EMPTY: Notification =
        Notification { word: 0, pending: false, head: None, tail: None };

    pub const fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Record a signal that nobody was waiting for.
    ///
    /// OR'd rather than counted, so signals between two waits collapse into one
    /// wake and the kernel accumulates nothing unbounded.
    pub const fn post(&mut self, badge: u64) {
        self.word |= badge;
        self.pending = true;
    }

    /// Take everything posted since the last take, if anything was.
    pub const fn take(&mut self) -> Option<u64> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        let word = self.word;
        self.word = 0;
        Some(word)
    }

    /// Park `tcb` until someone signals.
    ///
    /// # Safety
    /// `tcb` must be a live TCB not already on any endpoint or notification
    /// queue: both use `ipc_next`, so being on two at once corrupts both.
    pub unsafe fn enqueue(&mut self, mut tcb: NonNull<Tcb>) {
        // SAFETY: the caller promised a live TCB only we are touching.
        unsafe { tcb.as_mut().ipc_next = None };
        match self.tail {
            // SAFETY: as above.
            Some(mut t) => unsafe { t.as_mut().ipc_next = Some(tcb) },
            None => self.head = Some(tcb),
        }
        self.tail = Some(tcb);
    }

    /// Take the thread that has been waiting longest, if any.
    ///
    /// # Safety
    /// The queue must contain only live TCBs.
    pub unsafe fn dequeue(&mut self) -> Option<NonNull<Tcb>> {
        let mut head = self.head?;
        // SAFETY: the caller promised live TCBs.
        let next = unsafe { head.as_mut().ipc_next.take() };
        self.head = next;
        if next.is_none() {
            self.tail = None;
        }
        Some(head)
    }

    /// Take `tcb` off the queue wherever it sits, and say whether it was there.
    ///
    /// # Safety
    /// The queue must contain only live TCBs.
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
                return true;
            }
            prev = Some(cur);
            cursor = next;
        }
        false
    }
}

/// Borrow the notification living at `paddr`.
///
/// # Safety
/// `paddr` must name a live notification object, and the caller must have
/// exclusive access to it for the lifetime of the reference.
pub unsafe fn at<'a>(paddr: PhysAddr) -> &'a mut Notification {
    // SAFETY: the caller promised a live notification reachable through the
    // direct map, which is where every kernel object lives.
    unsafe { &mut *phys_to_virt(paddr).as_mut_ptr::<Notification>() }
}

/// Lay an empty notification over memory that was just retyped into one.
///
/// # Safety
/// `paddr` must be a notification object we own that nothing refers to yet.
pub unsafe fn init(paddr: PhysAddr) {
    // SAFETY: the caller promised untouched memory of the right size.
    unsafe { phys_to_virt(paddr).as_mut_ptr::<Notification>().write(Notification::EMPTY) };
}
