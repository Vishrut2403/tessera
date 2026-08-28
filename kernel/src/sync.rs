//! A spin lock that also masks S-mode interrupts while held (D-008).
//!
//! The problem it solves: `println!` takes a lock on the UART. If a timer
//! interrupt lands while that lock is held and the handler also prints, the hart
//! spins forever waiting for a lock that only it can release. That is a
//! self-deadlock on a single hart, and it is miserable to diagnose because the
//! machine simply stops.
//!
//! The fix is xv6's `push_off`/`pop_off` expressed as `Drop`: acquiring clears
//! `sstatus.SIE` and the guard remembers whether it had been set, so nested
//! locks restore the *saved* state rather than unconditionally re-enabling
//! interrupts on the inner unlock.
//!
//! The cost is that interrupts are off for the length of every critical section,
//! so a lock held across something slow is a direct hit to interrupt latency.
//! Rule for later milestones: no lock is held across an IPC or a page-table walk.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::csr::{sstatus, sstatus_bits};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: the lock is what serialises access to `data`, so `&SpinLock<T>` may
// cross harts as long as the T itself can. T: Send (not Sync) is the right
// bound: only one hart ever holds a reference to the interior at a time.
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self { locked: AtomicBool::new(false), data: UnsafeCell::new(data) }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        // Mask interrupts *before* taking the lock. The other order has a window
        // in which we hold the lock with interrupts still enabled.
        let was_enabled = unsafe { sstatus::clear(sstatus_bits::SIE) } & sstatus_bits::SIE != 0;

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // `wfi` would be wrong here: with interrupts masked nothing would
            // wake us. `spin_loop` lowers to the Zihintpause `pause` hint where
            // available and to nothing where it is not.
            core::hint::spin_loop();
        }

        SpinGuard { lock: self, restore_sie: was_enabled }
    }

    /// Reach inside without locking.
    ///
    /// # Safety
    /// The caller must know that no one else can be holding the lock, or must
    /// have decided that consistency no longer matters. The panic handler is the
    /// one legitimate user: taking a lock while unwinding a dead kernel turns a
    /// diagnosable crash into a hang (D-009).
    pub unsafe fn force_get(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
    restore_sie: bool,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard means we hold the lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` proves uniqueness on this hart.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        // Release ordering pairs with the Acquire in `lock`: everything written
        // inside the critical section is visible to the next holder.
        self.lock.locked.store(false, Ordering::Release);
        if self.restore_sie {
            // SAFETY: we are restoring the exact interrupt state that existed
            // before this guard was created.
            unsafe { sstatus::set(sstatus_bits::SIE) };
        }
    }
}
