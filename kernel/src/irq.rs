//! Which notification an interrupt source wakes, and who is allowed to say so
//! (D-041).

use crate::mm::PhysAddr;
use crate::sync::SpinLock;

/// Sources the table has room for.
pub const MAX_IRQ: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqError {
    /// Source 0 does not exist: the controller uses it to mean "none".
    OutOfRange,
    /// An `IrqHandler` capability for this source already exists.
    AlreadyClaimed,
    /// No `IrqHandler` capability has been minted for this source.
    NotClaimed,
}

#[derive(Clone, Copy)]
struct Entry {
    /// The notification to signal, or zero if none is bound yet.
    notification: PhysAddr,
    badge: u64,
    /// Whether an `IrqHandler` capability for this source has been handed out.
    claimed: bool,
}

impl Entry {
    const NONE: Entry = Entry { notification: PhysAddr::new(0), badge: 0, claimed: false };
}

static TABLE: SpinLock<[Entry; MAX_IRQ]> = SpinLock::new([Entry::NONE; MAX_IRQ]);

/// Unmask external interrupts on this hart.
pub fn enable() {
    // SAFETY: `sie.SEIE` only unmasks an interrupt the dispatcher handles.
    unsafe { crate::csr::sie::set(crate::csr::interrupt_bits::SEIE) };
}

/// Reset every source. Boot and tests only.
pub fn reset() {
    *TABLE.lock() = [Entry::NONE; MAX_IRQ];
}

/// Hand out the right to receive one source, if nobody holds it already.
pub fn claim(irq: usize) -> Result<(), IrqError> {
    if irq == 0 || irq >= MAX_IRQ {
        return Err(IrqError::OutOfRange);
    }
    let mut table = TABLE.lock();
    if table[irq].claimed {
        return Err(IrqError::AlreadyClaimed);
    }
    table[irq].claimed = true;
    Ok(())
}

/// Deliver `irq` to this notification from now on, and unmask it.
pub fn bind(irq: usize, notification: PhysAddr, badge: u64) -> Result<(), IrqError> {
    if irq == 0 || irq >= MAX_IRQ {
        return Err(IrqError::OutOfRange);
    }
    {
        let mut table = TABLE.lock();
        if !table[irq].claimed {
            return Err(IrqError::NotClaimed);
        }
        table[irq].notification = notification;
        table[irq].badge = badge;
    }
    // The lock is released first: the controller is a device, and holding a
    // kernel lock across a device write is how deadlocks start.
    crate::plic::enable(irq);
    Ok(())
}

/// Stop delivering `irq` anywhere, and mask it.
pub fn unbind(irq: usize) -> Result<(), IrqError> {
    if irq == 0 || irq >= MAX_IRQ {
        return Err(IrqError::OutOfRange);
    }
    TABLE.lock()[irq].notification = PhysAddr::new(0);
    crate::plic::disable(irq);
    Ok(())
}

/// Where `irq` should be delivered, if anywhere.
pub fn target(irq: usize) -> Option<(PhysAddr, u64)> {
    if irq == 0 || irq >= MAX_IRQ {
        return None;
    }
    let entry = TABLE.lock()[irq];
    match entry.notification.as_usize() {
        0 => None,
        _ => Some((entry.notification, entry.badge)),
    }
}

/// Whether any source is bound to a notification.
pub fn any_bound() -> bool {
    TABLE.lock().iter().any(|e| e.notification.as_usize() != 0)
}

pub fn is_claimed(irq: usize) -> bool {
    irq < MAX_IRQ && TABLE.lock()[irq].claimed
}
