//! Notifications: the asynchronous half of IPC (D-041).

use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::{PhysAddr, phys_to_virt};
use crate::thread::{BlockedOn, Tcb};

/// The rendezvous-free wake-up, living in the notification object's memory.
#[repr(C)]
pub struct Notification {
    /// Badges of every signal since the last wait, OR'd together.
    pub word: u64,
    /// Whether anything has been signalled at all.
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
    pub unsafe fn enqueue(&mut self, mut tcb: NonNull<Tcb>, at: PhysAddr) {
        // SAFETY: the caller promised a live TCB only we are touching.
        unsafe {
            tcb.as_mut().ipc_next = None;
            // Which queue, so the thread can be taken off it again (D-048).
            tcb.as_mut().blocked_on = BlockedOn::Notification(at);
        }
        WAITERS.fetch_add(1, Ordering::Relaxed);
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
        let next = unsafe {
            head.as_mut().blocked_on = BlockedOn::Nothing;
            head.as_mut().ipc_next.take()
        };
        self.head = next;
        if next.is_none() {
            self.tail = None;
        }
        WAITERS.fetch_sub(1, Ordering::Relaxed);
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
                unsafe {
                    cur.as_mut().ipc_next = None;
                    cur.as_mut().blocked_on = BlockedOn::Nothing;
                }
                WAITERS.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
            prev = Some(cur);
            cursor = next;
        }
        false
    }
}

/// How many threads are parked on notifications. The scheduler idles only
/// while one of these exists: an interrupt can wake a waiter, and once the run
/// queue is empty nothing else can wake anyone at all (D-048).
static WAITERS: AtomicUsize = AtomicUsize::new(0);

pub fn waiters() -> usize {
    WAITERS.load(Ordering::Relaxed)
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
