//! A spin lock that also masks S-mode interrupts while held (D-008).

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::csr::{sstatus, sstatus_bits};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: the lock serialises access to `data`, so `&SpinLock<T>` may cross harts if T can.
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self { locked: AtomicBool::new(false), data: UnsafeCell::new(data) }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        // Mask interrupts *before* taking the lock.
        let was_enabled = unsafe { sstatus::clear(sstatus_bits::SIE) } & sstatus_bits::SIE != 0;

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // `wfi` would be wrong here: with interrupts masked nothing would wake us.
            core::hint::spin_loop();
        }

        SpinGuard { lock: self, restore_sie: was_enabled }
    }

    /// Reach inside without locking.
    ///
    /// # Safety
    /// The caller must know no one else holds the lock; only the panic handler qualifies (D-009).
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
        // Release pairs with the Acquire in `lock`.
        self.lock.locked.store(false, Ordering::Release);
        if self.restore_sie {
            // SAFETY: restoring the exact interrupt state that existed before this guard.
            unsafe { sstatus::set(sstatus_bits::SIE) };
        }
    }
}
