//! Thread invocations: what makes a thread an object rather than a kernel
//! privilege (D-037).
//!
//! A TCB comes out of `retype` inactive — no address space, no CSpace, no entry
//! point — and the three of those arrive through invocations on the capability.
//! Until M7 the kernel built threads itself in `sched::spawn`, which meant the
//! kernel decided who could make one. Now the answer is "whoever holds untyped
//! memory and a slot to put the capability in", which is the answer the whole
//! architecture wanted.

use core::ptr::NonNull;

use super::{Cap, CapError, ObjectType, RawCap, kind, rights};
use crate::mm::{Asid, VirtAddr, phys_to_virt, satp_for};
use crate::thread::{Tcb, ThreadState};

/// Mutating a thread is a write to it, so every invocation here needs `WRITE`.
type TcbCap = Cap<kind::Tcb, { rights::WRITE }>;

/// Borrow the thread a TCB capability names.
///
/// # Safety
/// `cap` must be a live TCB capability, and the caller must not already hold a
/// reference to the same thread — which is why [`check`] refuses a thread
/// invoking its own capability.
pub unsafe fn tcb_at<'a>(cap: &RawCap) -> &'a mut Tcb {
    // SAFETY: the caller promised a live TCB object, reachable through the
    // direct map because every object the kernel makes is.
    unsafe { &mut *phys_to_virt(cap.paddr).as_mut_ptr::<Tcb>() }
}

/// The pointer form, for putting a thread on the run queue.
///
/// # Safety
/// As [`tcb_at`].
pub unsafe fn tcb_ptr(cap: &RawCap) -> NonNull<Tcb> {
    // SAFETY: as above; the object address is never zero.
    unsafe { NonNull::new_unchecked(phys_to_virt(cap.paddr).as_mut_ptr::<Tcb>()) }
}

/// The one runtime check every invocation shares: right kind, right rights, and
/// not the caller's own thread.
///
/// Self-invocation is refused rather than special-cased. The caller is already
/// borrowed as `&mut Tcb` by the trap path, so reaching it a second time
/// through its own capability would be two live mutable references to one
/// thread. Suspending yourself is a reasonable thing to want and is simply not
/// offered yet.
pub fn check(cap: RawCap, caller: &Tcb) -> Result<TcbCap, CapError> {
    let typed = TcbCap::from_raw(cap)?;
    if cap.paddr == caller.self_paddr {
        return Err(CapError::SelfInvocation);
    }
    Ok(typed)
}

/// Give a thread an address space, a capability space, and a pager.
///
/// Only an inactive thread can be configured. That is not caution: an inactive
/// thread is on no run queue and no endpoint queue and is not current on any
/// hart, so it is the one state in which rewriting its `satp` cannot pull the
/// ground out from under a thread that is running or about to be resumed.
pub fn configure(
    target: &mut Tcb,
    cspace: RawCap,
    vspace: RawCap,
    fault_ep: RawCap,
) -> Result<(), CapError> {
    if target.state != ThreadState::Inactive {
        return Err(CapError::NotInactive);
    }
    if cspace.kind != ObjectType::CNode {
        return Err(CapError::WrongType { wanted: ObjectType::CNode, found: cspace.kind });
    }
    if vspace.kind != ObjectType::PageTable {
        return Err(CapError::WrongType { wanted: ObjectType::PageTable, found: vspace.kind });
    }
    // An unassigned root has no ASID *and* no kernel half, so the thread's
    // first trap would take the handler through a table that does not map it.
    if !vspace.is_assigned() {
        return Err(CapError::NotAssigned);
    }
    if !fault_ep.is_null() && fault_ep.kind != ObjectType::Endpoint {
        return Err(CapError::WrongType { wanted: ObjectType::Endpoint, found: fault_ep.kind });
    }

    target.cspace = cspace;
    target.fault_ep = fault_ep;
    target.satp = satp_for(vspace.paddr, Asid::new(vspace.asid));
    Ok(())
}

/// Attach a pager on its own, leaving everything else alone.
pub fn set_fault_ep(target: &mut Tcb, fault_ep: RawCap) -> Result<(), CapError> {
    if !fault_ep.is_null() && fault_ep.kind != ObjectType::Endpoint {
        return Err(CapError::WrongType { wanted: ObjectType::Endpoint, found: fault_ep.kind });
    }
    target.fault_ep = fault_ep;
    Ok(())
}

/// Set where the thread starts and what stack it starts on.
///
/// Refused while the thread is blocked: its registers are the message it is
/// waiting to send or the reply it is waiting to receive, and rewriting them
/// would corrupt an IPC in flight.
pub fn write_registers(
    target: &mut Tcb,
    entry: VirtAddr,
    stack_top: VirtAddr,
) -> Result<(), CapError> {
    if target.state.is_blocked() {
        return Err(CapError::NotInactive);
    }
    target.set_registers(entry, stack_top);
    Ok(())
}
