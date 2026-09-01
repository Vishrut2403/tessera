//! Round-robin scheduling over a single kernel stack per hart (D-024).

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::cap::cspace::CSpace;
use crate::cap::{Cap, CapError, ObjectType, RawCap, kind, rights};
use crate::ipc::{self, EndpointState, MessageInfo};
use crate::mm::{AddressSpace, VirtAddr};
use crate::sync::SpinLock;
use crate::thread::{Tcb, ThreadId, ThreadState};
use crate::trap::{Cause, TrapFrame, reg, return_to_user};

pub use abi::{label, result, syscall};

/// Callee-saved state of the kernel context that called [`run`].
#[repr(C)]
#[derive(Default)]
struct KernelContext {
    ra: usize,
    sp: usize,
    s: [usize; 12],
}

struct RunQueue {
    head: Option<NonNull<Tcb>>,
    tail: Option<NonNull<Tcb>>,
    ready: usize,
}

// SAFETY: the pointers are to TCB frames the kernel owns for their whole life,
// and the lock is what serialises access to the queue they are threaded onto.
unsafe impl Send for RunQueue {}

impl RunQueue {
    const fn new() -> Self {
        Self { head: None, tail: None, ready: 0 }
    }

    fn push(&mut self, mut tcb: NonNull<Tcb>) {
        // SAFETY: `tcb` is a live TCB and the lock makes this the only writer.
        unsafe { tcb.as_mut().next = None };
        match self.tail {
            Some(mut t) => unsafe { t.as_mut().next = Some(tcb) },
            None => self.head = Some(tcb),
        }
        self.tail = Some(tcb);
        self.ready += 1;
    }

    /// Take `tcb` off the queue wherever it sits. `Suspend` is the only caller:
    /// everything else leaves through `pop`.
    fn remove(&mut self, tcb: NonNull<Tcb>) -> bool {
        let mut prev: Option<NonNull<Tcb>> = None;
        let mut cursor = self.head;
        while let Some(mut cur) = cursor {
            // SAFETY: a live TCB, and the lock makes this the only writer.
            let next = unsafe { cur.as_ref().next };
            if cur == tcb {
                match prev {
                    // SAFETY: as above.
                    Some(mut p) => unsafe { p.as_mut().next = next },
                    None => self.head = next,
                }
                if self.tail == Some(cur) {
                    self.tail = prev;
                }
                // SAFETY: as above.
                unsafe { cur.as_mut().next = None };
                self.ready -= 1;
                return true;
            }
            prev = Some(cur);
            cursor = next;
        }
        false
    }

    fn pop(&mut self) -> Option<NonNull<Tcb>> {
        let mut head = self.head?;
        // Counted, not for statistics: invariant 4 says a call/reply pair must
        // not consult the run queue, and this is what a test can assert on.
        POPS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: as above.
        let next = unsafe { head.as_mut().next.take() };
        self.head = next;
        if next.is_none() {
            self.tail = None;
        }
        self.ready -= 1;
        Some(head)
    }
}

static QUEUE: SpinLock<RunQueue> = SpinLock::new(RunQueue::new());
static KERNEL_CTX: SpinLock<KernelContext> = SpinLock::new(KernelContext::new_const());
static SPAWNED: AtomicUsize = AtomicUsize::new(0);
static EXITED: AtomicUsize = AtomicUsize::new(0);
static KILLED: AtomicUsize = AtomicUsize::new(0);
static STOP_ON_EXIT: AtomicBool = AtomicBool::new(false);
static POPS: AtomicUsize = AtomicUsize::new(0);

/// The thread on this hart, outside the run queue's lock.
///
/// Which thread is current is per-hart state that no other hart reads, so
/// putting it behind the queue lock cost a compare-exchange and an interrupt
/// mask/unmask every time the fast path asked "who am I?" (D-033). With more
/// harts this becomes an array indexed by hartid, not a shared lock.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static LAST_BADGE: AtomicUsize = AtomicUsize::new(0);

/// The last few badges delivered, so a test can check that messages arrive in
/// the order they were sent. Counted for the same reason as [`queue_pops`]:
/// FIFO delivery is a property, not an implementation detail.
static BADGE_LOG: [AtomicUsize; 8] = [const { AtomicUsize::new(usize::MAX) }; 8];
static BADGE_LOG_LEN: AtomicUsize = AtomicUsize::new(0);

fn log_badge(badge: u64) {
    let n = BADGE_LOG_LEN.fetch_add(1, Ordering::Relaxed);
    if n < BADGE_LOG.len() {
        BADGE_LOG[n].store(badge as usize, Ordering::Relaxed);
    }
}

/// Badges delivered since [`reset_badge_log`], oldest first.
pub fn badge_log(out: &mut [u64]) -> usize {
    let n = BADGE_LOG_LEN.load(Ordering::Relaxed).min(BADGE_LOG.len()).min(out.len());
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = BADGE_LOG[i].load(Ordering::Relaxed) as u64;
    }
    n
}

pub fn reset_badge_log() {
    BADGE_LOG_LEN.store(0, Ordering::Relaxed);
}

impl KernelContext {
    const fn new_const() -> Self {
        Self { ra: 0, sp: 0, s: [0; 12] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// No frame left for a TCB.
    OutOfFrames,
}

/// Create a runnable thread in `space` and put it on the run queue.
pub fn spawn(
    space: &AddressSpace,
    entry: VirtAddr,
    stack_top: VirtAddr,
) -> Result<ThreadId, SpawnError> {
    spawn_with_cspace(space, entry, stack_top, RawCap::NULL)
}

/// As [`spawn`], giving the thread a capability space to invoke through.
pub fn spawn_with_cspace(
    space: &AddressSpace,
    entry: VirtAddr,
    stack_top: VirtAddr,
    cspace: RawCap,
) -> Result<ThreadId, SpawnError> {
    spawn_full(space, entry, stack_top, cspace, RawCap::NULL)
}

/// As [`spawn_with_cspace`], with a fault endpoint so the thread has a pager.
///
/// A TCB is not yet a capability a thread can invoke, so this is set at spawn
/// time rather than by a `SET_FAULT_EP` invocation. Wiring that up needs threads
/// to be made by retyping, which is the same deferred item as everything else
/// about TCB objects.
pub fn spawn_full(
    space: &AddressSpace,
    entry: VirtAddr,
    stack_top: VirtAddr,
    cspace: RawCap,
    fault_ep: RawCap,
) -> Result<ThreadId, SpawnError> {
    let frame = crate::mm::alloc_frame().ok_or(SpawnError::OutOfFrames)?;
    let id = crate::thread::next_id();

    // SAFETY: `frame` came from the allocator, so we own it and nothing else
    // has a TCB in it.
    let mut tcb = unsafe { Tcb::create(frame, id, space, entry, stack_top) };
    // SAFETY: we just made it; nothing else refers to it yet.
    unsafe {
        tcb.as_mut().cspace = cspace;
        tcb.as_mut().fault_ep = fault_ep;
    }

    QUEUE.lock().push(tcb);
    SPAWNED.fetch_add(1, Ordering::Relaxed);
    Ok(id)
}

/// Put a thread on the run queue directly.
///
/// The root task's thread arrives this way, because at boot there is no CSpace
/// to invoke `Resume` through. Everything after it is started by its parent.
///
/// # Safety
/// `tcb` must be a live, fully configured thread that is on no queue.
pub unsafe fn admit(tcb: NonNull<Tcb>) {
    QUEUE.lock().push(tcb);
    SPAWNED.fetch_add(1, Ordering::Relaxed);
}

pub fn ready_count() -> usize {
    QUEUE.lock().ready
}

pub fn spawned() -> usize {
    SPAWNED.load(Ordering::Relaxed)
}

/// Threads that ran off the end by calling `exit`.
pub fn exited() -> usize {
    EXITED.load(Ordering::Relaxed)
}

/// Threads the kernel destroyed because they faulted.
pub fn killed() -> usize {
    KILLED.load(Ordering::Relaxed)
}

/// How many times a thread has been taken off the run queue.
///
/// The fast path must not move this: a `call`/`reply` pair switches directly
/// from one thread to the other, so the only pops in a ping-pong are the two
/// that started the threads (invariant 4, D-031).
pub fn queue_pops() -> usize {
    POPS.load(Ordering::Relaxed)
}

/// The badge delivered by the most recent receive, for tests.
pub fn last_badge() -> u64 {
    LAST_BADGE.load(Ordering::Relaxed) as u64
}

/// The id of the thread on this hart, if one is running.
pub fn current_id() -> Option<ThreadId> {
    // SAFETY: the TCB is live for as long as it is current.
    current_tcb().map(|t| unsafe { t.as_ref().id })
}

/// Run threads until the run queue empties, then return.
///
/// The return path exists for shutdown and for tests. It is not on any hot path:
/// while threads exist, control leaves here only by `sret` (D-024).
pub fn run() {
    let mut ctx = KERNEL_CTX.lock();
    let ctx_ptr = &raw mut *ctx;
    drop(ctx);

    let Some(next) = take_next() else { return };

    // SAFETY: `ctx_ptr` is a static that outlives the call, and `next` is a
    // ready thread whose frame was built by `Tcb::create`.
    unsafe { enter_threads(ctx_ptr, activate(next)) }
}

/// Run threads until one of them exits, or the queue empties.
///
/// A thread that never yields cannot be waited for any other way, so this is how
/// a caller observes that preemption happened at all.
pub fn run_until_exit() {
    STOP_ON_EXIT.store(true, Ordering::Relaxed);
    run();
    STOP_ON_EXIT.store(false, Ordering::Relaxed);
}

/// Destroy every thread still on the queue. Teardown, not scheduling: nothing
/// may be current when it is called.
pub fn kill_all() -> usize {
    let mut n = 0;
    assert!(current_tcb().is_none(), "kill_all with a thread on the hart");
    while let Some(mut tcb) = take_next() {
        // SAFETY: off the queue and not current, so we are its only writer.
        unsafe { tcb.as_mut().state = ThreadState::Exited };
        n += 1;
    }
    n
}

/// Make `tcb` current, install its address space, and hand back its frame.
fn activate(mut tcb: NonNull<Tcb>) -> *mut TrapFrame {
    // SAFETY: `tcb` is a live TCB that only this hart is touching.
    let t = unsafe { tcb.as_mut() };
    t.state = ThreadState::Running;

    if t.uses_fp() {
        crate::thread::restore_fp(&t.fp);
    }
    // Threads that share an address space need no switch at all: `satp` already
    // holds the right value, and writing it would flush for nothing. seL4's
    // fast path makes the same check, and it is why threads in one process can
    // talk to each other almost for free (D-033).
    if crate::csr::satp::read() != t.satp {
        // SAFETY: the space was built by `AddressSpace`, so it maps the kernel half.
        unsafe { crate::csr::satp::write(t.satp) };

        // An unassigned space is ASID 0, which every other unassigned space
        // also uses, so its entries have to go. Once an ASID pool has given the
        // space a number of its own, the tag keeps them apart and the flush is
        // unnecessary -- what D-022 deferred and M4e delivered.
        if (t.satp >> 44) & 0xffff == 0 {
            crate::mm::flush_tlb_all();
        }
    }

    set_current(Some(tcb));
    t.frame_ptr()
}

fn take_next() -> Option<NonNull<Tcb>> {
    QUEUE.lock().pop()
}

/// Why a thread is coming off the hart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retire {
    /// Still runnable: back to the tail of the queue.
    Requeue,
    /// Called `exit`.
    Exited,
    /// Faulted, and the kernel destroyed it.
    Killed,
    /// Parked on an endpoint. Its state is already set and it is on no queue
    /// the scheduler owns; the endpoint will make it runnable again.
    Blocked,
}

/// Stop running the current thread and resume whatever is next.
fn retire(why: Retire) -> ! {
    let current = current_tcb();
    set_current(None);

    if let Some(mut tcb) = current {
        // SAFETY: the current thread is not on the queue, so we are its only writer.
        let t = unsafe { tcb.as_mut() };
        if t.uses_fp() {
            crate::thread::save_fp(&mut t.fp);
        }
        match why {
            Retire::Requeue => {
                t.state = ThreadState::Ready;
                QUEUE.lock().push(tcb);
            }
            Retire::Exited => {
                t.state = ThreadState::Exited;
                EXITED.fetch_add(1, Ordering::Relaxed);
                if STOP_ON_EXIT.load(Ordering::Relaxed) {
                    leave();
                }
            }
            Retire::Killed => {
                t.state = ThreadState::Exited;
                KILLED.fetch_add(1, Ordering::Relaxed);
            }
            // Already queued on an endpoint; touching the run queue here is
            // exactly the bug invariant 4 is about.
            Retire::Blocked => {}
        }
    }

    match take_next() {
        // SAFETY: a ready thread with a frame built by `Tcb::create`.
        Some(next) => unsafe { return_to_user(activate(next)) },
        None => leave(),
    }
}

/// Nothing left to run: go back to whoever called [`run`].
fn leave() -> ! {
    let ctx = KERNEL_CTX.lock();
    let ctx_ptr = &raw const *ctx;
    drop(ctx);
    // SAFETY: `run` filled this in before entering, and the stack it names is
    // still live because the kernel never unwound it.
    unsafe { resume_kernel(ctx_ptr) }
}

/// The Rust side of a trap taken in U-mode. Never returns: it always resumes
/// some thread, or leaves the scheduler.
#[unsafe(no_mangle)]
pub extern "C" fn user_trap(frame: *mut TrapFrame) -> ! {
    // SAFETY: `frame` is the first field of a live TCB, per `Tcb`'s layout
    // assertion, and the trap entry handed it to us.
    let tcb = unsafe { &mut *(frame as *mut Tcb) };

    match Cause::decode(crate::csr::scause::read()) {
        Cause::Interrupt(5) => {
            crate::time::on_tick();
            retire(Retire::Requeue)
        }
        Cause::Exception(8) => syscall(tcb),
        // A float in a thread that has not been given the FPU yet (D-025).
        // Any other illegal instruction is a genuine fault and falls through.
        Cause::Exception(2)
            if !tcb.uses_fp()
                && crate::thread::is_fp_instruction(crate::csr::stval::read()) =>
        {
            tcb.enable_fp();
            crate::thread::restore_fp(&tcb.fp);
            // Do not advance sepc: the thread retries the instruction.
            // SAFETY: the thread is still current and its frame is intact.
            unsafe { return_to_user(tcb.frame_ptr()) }
        }
        // Instruction, load and store page faults all go to the pager (D-034).
        cause @ (Cause::Exception(12) | Cause::Exception(13) | Cause::Exception(15)) => {
            deliver_fault(tcb, cause)
        }
        cause => {
            crate::println!(
                "thread {} killed: {} at {:#x}",
                tcb.id,
                cause.name(),
                tcb.frame.sepc
            );
            retire(Retire::Killed)
        }
    }
}

fn syscall(tcb: &mut Tcb) -> ! {
    let number = tcb.frame.x[reg::A7];
    let arg = tcb.frame.x[reg::A0];
    tcb.skip_ecall();

    match number {
        syscall::YIELD => retire(Retire::Requeue),
        syscall::EXIT => retire(Retire::Exited),
        syscall::PUTC => {
            crate::print!("{}", arg as u8 as char);
            tcb.set_return(result::OK);
        }
        syscall::GET_ID => tcb.set_return(tcb.id),
        syscall::CALL => invoke(tcb, true),
        syscall::SEND => invoke(tcb, false),
        syscall::RECV => sys_recv(tcb),
        syscall::REPLY => sys_reply(tcb, false),
        syscall::REPLY_RECV => sys_reply(tcb, true),
        _ => tcb.set_return(usize::MAX),
    }

    // SAFETY: the thread is still current and its frame is intact.
    unsafe { return_to_user(tcb.frame_ptr()) }
}

/// Resume `next` without consulting the run queue.
///
/// This is the direct switch invariant 4 is about: a `call`/`reply` pair moves
/// the hart from one thread to another and the scheduler never runs (D-031).
fn switch_direct(next: NonNull<Tcb>) -> ! {
    // Whatever is leaving the hart still owns the FP registers if it ever
    // touched one (D-025). `activate` restores them for the thread arriving.
    if let Some(mut outgoing) = current_tcb() {
        // SAFETY: the outgoing thread is not on any queue we are walking.
        let t = unsafe { outgoing.as_mut() };
        if t.uses_fp() {
            crate::thread::save_fp(&mut t.fp);
        }
    }
    // SAFETY: `next` is a runnable thread whose frame `Tcb::create` built.
    unsafe { return_to_user(activate(next)) }
}

/// Finish a syscall that did not block, returning `value` in `a0`.
fn finish(tcb: &mut Tcb, value: usize) -> ! {
    tcb.set_return(value);
    // SAFETY: the thread is still current and its frame is intact.
    unsafe { return_to_user(tcb.frame_ptr()) }
}

/// The capability space of the running thread.
fn cspace_of(tcb: &Tcb) -> Option<CSpace> {
    CSpace::new(tcb.cspace).ok()
}

/// `call` or `send` on whatever `a0` names (D-032).
fn invoke(tcb: &mut Tcb, is_call: bool) -> ! {
    let cptr = tcb.frame.x[reg::A0] as u64;
    let info = ipc::message_of(tcb);

    let Some(cs) = cspace_of(tcb) else { finish(tcb, result::ERR_NO_CSPACE) };
    let Ok(cap) = cs.read(cptr, cs.root_depth()) else {
        finish(tcb, result::ERR_BAD_CAP);
    };

    match cap.kind {
        ObjectType::Endpoint => ipc_send(tcb, cap, info, is_call),
        ObjectType::Untyped | ObjectType::DeviceUntyped => invoke_untyped(tcb, cs, cptr, info),
        ObjectType::CNode => invoke_cnode(tcb, cs, cptr, info),
        ObjectType::Frame | ObjectType::PageTable => invoke_mapping(tcb, cs, cptr, info),
        ObjectType::Tcb => invoke_tcb(tcb, cs, cap, info),
        _ => finish(tcb, result::ERR_BAD_CAP),
    }
}

/// Hand a message to a receiver, or block until one arrives.
fn ipc_send(tcb: &mut Tcb, ep_cap: RawCap, info: MessageInfo, is_call: bool) -> ! {
    // SAFETY: `ep_cap` came from this thread's CSpace, so it names a live
    // endpoint object, and only this hart is running kernel code.
    let ep = unsafe { ipc::endpoint_at(ep_cap.paddr) };

    // SAFETY: the queue holds live TCBs the kernel owns.
    if let Some(mut waiting) = unsafe { ep.dequeue(EndpointState::Receiving) } {
        // SAFETY: taken off the endpoint queue, so nothing else refers to it.
        let receiver = unsafe { waiting.as_mut() };
        deliver(tcb, receiver, info, ep_cap.badge);
        LAST_BADGE.store(ep_cap.badge as usize, Ordering::Relaxed);
        log_badge(ep_cap.badge);

        if is_call {
            receiver.reply = ipc::reply_cap(tcb.self_paddr);
            tcb.state = ThreadState::AwaitingReply;
            tcb.call_pending = false;
        } else {
            receiver.reply = RawCap::NULL;
            tcb.state = ThreadState::Ready;
        }
        receiver.state = ThreadState::Ready;

        if is_call {
            // The caller is not runnable, so nothing goes on the run queue and
            // the receiver gets the rest of this timeslice. The whole point.
            switch_direct(waiting);
        }
        // A bare `send` stays runnable; the receiver still gets the hart, and
        // the sender goes to the back of the queue.
        tcb.set_return(result::OK);
        // The lock is not reentrant, so `current_tcb` must be resolved before
        // `push` takes it -- Rust evaluates the receiver first.
        let me = current_tcb().expect("no current thread");
        QUEUE.lock().push(me);
        switch_direct(waiting);
    }

    // Nobody is waiting: park on the endpoint.
    tcb.badge = ep_cap.badge;
    tcb.call_pending = is_call;
    tcb.state = ThreadState::BlockedOnSend;
    let me = current_tcb().expect("no current thread");
    // SAFETY: this thread is current, so it is on no other queue.
    unsafe { ep.enqueue(me, EndpointState::Sending) };
    retire(Retire::Blocked)
}

/// Take a queued message, or block waiting for one.
fn sys_recv(tcb: &mut Tcb) -> ! {
    let cptr = tcb.frame.x[reg::A0] as u64;
    let Some(cs) = cspace_of(tcb) else { finish(tcb, result::ERR_NO_CSPACE) };
    let Ok(ep_cap) = cs.read(cptr, cs.root_depth()) else {
        finish(tcb, result::ERR_BAD_CAP);
    };
    if ep_cap.kind != ObjectType::Endpoint {
        finish(tcb, result::ERR_BAD_CAP)
    } else {
        receive_on(tcb, ep_cap)
    }
}

/// The receive half, shared by `recv` and `reply_recv`.
fn receive_on(tcb: &mut Tcb, ep_cap: RawCap) -> ! {
    // SAFETY: `ep_cap` came from a CSpace, so it names a live endpoint.
    let ep = unsafe { ipc::endpoint_at(ep_cap.paddr) };

    // SAFETY: the queue holds live TCBs.
    if let Some(mut queued) = unsafe { ep.dequeue(EndpointState::Sending) } {
        // SAFETY: off the queue, so nothing else refers to it.
        let sender = unsafe { queued.as_mut() };
        let info = ipc::message_of(sender);
        deliver(sender, tcb, info, sender.badge);
        LAST_BADGE.store(sender.badge as usize, Ordering::Relaxed);
        log_badge(sender.badge);

        if sender.call_pending {
            tcb.reply = ipc::reply_cap(sender.self_paddr);
            sender.state = ThreadState::AwaitingReply;
            sender.call_pending = false;
        } else {
            tcb.reply = RawCap::NULL;
            sender.state = ThreadState::Ready;
            sender.set_return(result::OK);
            QUEUE.lock().push(queued);
        }
        // We already have the hart and a message; just go back to user mode.
        // SAFETY: this thread is current and its frame is intact.
        unsafe { return_to_user(tcb.frame_ptr()) };
    }

    tcb.state = ThreadState::BlockedOnRecv;
    let me = current_tcb().expect("no current thread");
    // SAFETY: this thread is current, so it is on no other queue.
    unsafe { ep.enqueue(me, EndpointState::Receiving) };
    retire(Retire::Blocked)
}

/// Answer the caller whose reply capability this thread holds.
fn sys_reply(tcb: &mut Tcb, then_receive: bool) -> ! {
    if tcb.reply.kind != ObjectType::Reply {
        finish(tcb, result::ERR_NO_REPLY);
    }
    let info = ipc::message_of(tcb);

    // The reply capability names the caller's TCB directly, so answering it
    // costs no lookup at all.
    let mut caller = NonNull::new(crate::mm::phys_to_virt(tcb.reply.paddr).as_mut_ptr::<Tcb>())
        .expect("reply capability with a null TCB");
    // SAFETY: the caller is blocked in `AwaitingReply`, so it is on no queue
    // and nothing else is writing it.
    let callee = unsafe { caller.as_mut() };
    if callee.faulted {
        // The reply is permission to carry on, not a return value. Its
        // registers and `sepc` are untouched, so it re-runs the instruction
        // that faulted against whatever the pager has now arranged.
        callee.faulted = false;
    } else {
        deliver(tcb, callee, info, 0);
    }
    callee.state = ThreadState::Ready;
    tcb.reply = RawCap::NULL;

    if then_receive {
        let cptr = tcb.frame.x[reg::A0] as u64;
        if let Some(cs) = cspace_of(tcb)
            && let Ok(ep_cap) = cs.read(cptr, cs.root_depth())
            && ep_cap.kind == ObjectType::Endpoint
        {
            // SAFETY: a live endpoint from this thread's CSpace.
            let ep = unsafe { ipc::endpoint_at(ep_cap.paddr) };
            if ep.has_waiting(EndpointState::Sending) {
                // Someone was already queued: the caller we just answered goes
                // on the run queue, we keep the hart, and `receive_on` takes
                // the sender that has been waiting longest.
                QUEUE.lock().push(caller);
                receive_on(tcb, ep_cap);
            }
            tcb.state = ThreadState::BlockedOnRecv;
            // SAFETY: this thread is current, so it is on no other queue.
            let me = current_tcb().expect("no current thread");
            // SAFETY: this thread is current, so it is on no other queue.
            unsafe { ep.enqueue(me, EndpointState::Receiving) };
            // The server is parked, so the thread we just answered gets the
            // hart directly -- the other half of the fast path.
            switch_direct(caller);
        }
        finish(tcb, result::ERR_BAD_CAP);
    }

    // A bare reply: we stay runnable, but the caller gets the hart.
    tcb.set_return(result::OK);
    tcb.state = ThreadState::Ready;
    // As above: resolve the current thread before taking the lock to push it.
    let me = current_tcb().expect("no current thread");
    QUEUE.lock().push(me);
    switch_direct(caller)
}

/// Move a capability from the sender's CSpace into the receiver's (D-036).
///
/// The sender names the source in `a6` and the receiver names the destination
/// in `a6`, so both ends state their own half of the transfer. The copy becomes
/// a derivative of the original, which is what makes it revocable.
fn transfer_cap(from: &Tcb, to: &mut Tcb) -> Result<(), CapError> {
    let src = from.frame.x[reg::A0 + 6] as u64;
    let dst = to.frame.x[reg::A0 + 6] as u64;

    let from_cs = CSpace::new(from.cspace)?;
    let mut to_cs = CSpace::new(to.cspace)?;

    let slot = from_cs.resolve(src, from_cs.root_depth())?;
    // SAFETY: a live slot in the sender's CSpace, which only this hart touches.
    let cap = unsafe { slot.as_ref().cap };
    if cap.is_null() {
        return Err(CapError::Null);
    }
    if cap.rights & crate::cap::rights::GRANT == 0 {
        return Err(CapError::MissingRights {
            wanted: crate::cap::rights::GRANT,
            held: cap.rights,
        });
    }

    let depth = to_cs.root_depth();
    // The copy carries no badge of its own: badges identify a holder to a
    // server, and this is a new holder.
    to_cs.insert(dst, depth, RawCap { badge: 0, ..cap }, Some(slot))
}

/// Deliver a message, and the capability riding with it if there is one.
fn deliver(from: &Tcb, to: &mut Tcb, info: MessageInfo, badge: u64) {
    ipc::transfer(from, to, info, badge);
    if info.carries_cap() {
        // A failed transfer is reported in the receiver's a0, not by killing
        // anyone: the sender may simply have named a slot that is full.
        if transfer_cap(from, to).is_err() {
            to.frame.x[reg::A1] =
                MessageInfo::new(info.label(), info.length(), false).bits() as usize;
        }
    }
}

/// The thread on this hart, as a pointer. One atomic load.
#[inline(always)]
fn current_tcb() -> Option<NonNull<Tcb>> {
    NonNull::new(CURRENT.load(Ordering::Relaxed) as *mut Tcb)
}

#[inline(always)]
fn set_current(tcb: Option<NonNull<Tcb>>) {
    CURRENT.store(tcb.map_or(0, |t| t.as_ptr() as usize), Ordering::Relaxed);
}

// --- Invocations on kernel objects (D-032) ---

fn invoke_untyped(tcb: &mut Tcb, mut cs: CSpace, cptr: u64, info: MessageInfo) -> ! {
    if info.label() != label::RETYPE {
        finish(tcb, result::ERR_BAD_LABEL);
    }
    let depth = cs.root_depth();
    let kind = object_type_from(tcb.frame.x[reg::A0 + 2]);
    let size_bits = tcb.frame.x[reg::A0 + 3] as u8;
    let dst = tcb.frame.x[reg::A0 + 4] as u64;
    let count = tcb.frame.x[reg::A0 + 5];

    let Some(kind) = kind else { finish(tcb, result::ERR_BAD_LABEL) };
    if count == 0 || count > 32 {
        finish(tcb, result::ERR_BAD_LABEL);
    }

    let mut made = [RawCap::NULL; 32];
    let value = match cs.retype((cptr, depth), kind, size_bits, (dst, depth), &mut made[..count]) {
        Ok(()) => result::OK,
        Err(_) => result::ERR_BAD_CAP,
    };
    finish(tcb, value)
}

fn invoke_cnode(tcb: &mut Tcb, mut cs: CSpace, _cptr: u64, info: MessageInfo) -> ! {
    let depth = cs.root_depth();
    let src = tcb.frame.x[reg::A0 + 2] as u64;
    let dst = tcb.frame.x[reg::A0 + 3] as u64;
    let rights = tcb.frame.x[reg::A0 + 4] as u8;
    let badge = tcb.frame.x[reg::A0 + 5] as u64;

    let outcome = match info.label() {
        label::MINT => cs.mint((src, depth), (dst, depth), rights, badge).map(|()| result::OK),
        label::REVOKE => cs.revoke(src, depth).map(|_| result::OK),
        label::DELETE => cs.delete(src, depth).map(|_| result::OK),
        _ => finish(tcb, result::ERR_BAD_LABEL),
    };
    finish(tcb, outcome.unwrap_or(result::ERR_BAD_CAP))
}

/// `Map` and `Unmap`, invoked on the frame or page table being mapped (D-034).
fn invoke_mapping(tcb: &mut Tcb, cs: CSpace, cptr: u64, info: MessageInfo) -> ! {
    let depth = cs.root_depth();
    let vspace_cptr = tcb.frame.x[reg::A0 + 2] as u64;
    let vaddr = VirtAddr::new(tcb.frame.x[reg::A0 + 3]);
    let rights_mask = tcb.frame.x[reg::A0 + 4] as u8;
    let level = tcb.frame.x[reg::A0 + 5];

    let Ok(target) = cs.resolve(cptr, depth) else { finish(tcb, result::ERR_BAD_CAP) };

    match info.label() {
        label::MAP => {
            let Ok(vspace) = cs.read(vspace_cptr, depth) else {
                finish(tcb, result::ERR_BAD_CAP)
            };
            // SAFETY: `target` is a live slot in this thread's CSpace, which
            // only this hart is touching.
            let cap = unsafe { &mut target.clone().as_mut().cap };
            let outcome = if cap.kind == ObjectType::PageTable {
                crate::cap::vspace::map_table(cap, &vspace, vaddr, level)
            } else {
                // Executable only when the caller asks for it *and* the
                // capability carries GRANT -- mapping someone else's memory
                // executable is not something a plain WRITE right should allow.
                let executable = level != 0 && cap.rights & crate::cap::rights::GRANT != 0;
                crate::cap::vspace::map_frame(cap, &vspace, vaddr, rights_mask, executable)
            };
            finish(tcb, outcome.map_or(result::ERR_MAP, |()| result::OK))
        }
        label::UNMAP => {
            // SAFETY: as above.
            let cap = unsafe { &mut target.clone().as_mut().cap };
            finish(tcb, crate::cap::vspace::unmap(cap).map_or(result::ERR_MAP, |()| result::OK))
        }
        label::GET_ADDRESS => {
            // SAFETY: as above.
            let cap = unsafe { target.clone().as_ref().cap };
            // `WRITE`, not `READ`: a physical address is the one piece of
            // information that lets a holder aim a bus master at memory it has
            // no capability for, and this platform has no IOMMU (D-040). A
            // read-only frame handed to a client stays unlocatable.
            match Cap::<kind::Frame, { rights::WRITE }>::from_raw(cap) {
                // The address is the return value. No physical address can
                // collide with an error code, which lives at the top of the
                // range.
                Ok(frame) => finish(tcb, frame.paddr().as_usize()),
                Err(e) => finish(tcb, cap_result(e)),
            }
        }
        label::ASSIGN => {
            // SAFETY: as above.
            let cap = unsafe { &mut target.clone().as_mut().cap };
            let outcome = crate::cap::vspace::assign(cap);
            finish(tcb, outcome.map_or_else(cap_result, |()| result::OK))
        }
        _ => finish(tcb, result::ERR_BAD_LABEL),
    }
}

/// Turn a capability-layer error into the number userspace sees in `a0`.
fn cap_result(e: CapError) -> usize {
    match e {
        CapError::SelfInvocation | CapError::NotInactive => result::ERR_STATE,
        CapError::NotAssigned | CapError::AlreadyAssigned | CapError::Asid(_) => result::ERR_ASID,
        CapError::AlreadyMapped | CapError::Map(_) => result::ERR_MAP,
        _ => result::ERR_BAD_CAP,
    }
}

/// The thread invocations: `Configure`, `SetFaultEP`, `WriteRegisters`,
/// `Resume` and `Suspend` (D-037).
///
/// This is what replaces `sched::spawn` for anything userspace builds. The
/// kernel no longer decides who may create a thread; holding untyped memory and
/// a free slot is the whole qualification.
fn invoke_tcb(tcb: &mut Tcb, cs: CSpace, cap: RawCap, info: MessageInfo) -> ! {
    let depth = cs.root_depth();
    let typed = match crate::cap::tcb::check(cap, tcb) {
        Ok(t) => t,
        Err(e) => finish(tcb, cap_result(e)),
    };
    // SAFETY: `check` proved this is a live TCB capability naming a thread
    // other than the caller, so this is the only live reference to it -- the
    // single-hart invariant does the rest.
    let target = unsafe { crate::cap::tcb::tcb_at(typed.raw()) };

    let outcome = match info.label() {
        label::CONFIGURE => {
            let cspace = cs.read(tcb.frame.x[reg::A0 + 2] as u64, depth);
            let vspace = cs.read(tcb.frame.x[reg::A0 + 3] as u64, depth);
            let fault_ep = cs.read(tcb.frame.x[reg::A0 + 4] as u64, depth);
            match (cspace, vspace, fault_ep) {
                (Ok(c), Ok(v), Ok(f)) => crate::cap::tcb::configure(target, c, v, f),
                _ => Err(CapError::Null),
            }
        }
        label::SET_FAULT_EP => match cs.read(tcb.frame.x[reg::A0 + 2] as u64, depth) {
            Ok(ep) => crate::cap::tcb::set_fault_ep(target, ep),
            Err(e) => Err(e),
        },
        label::WRITE_REGISTERS => crate::cap::tcb::write_registers(
            target,
            VirtAddr::new(tcb.frame.x[reg::A0 + 2]),
            VirtAddr::new(tcb.frame.x[reg::A0 + 3]),
        ),
        label::RESUME => resume(target, typed.raw()),
        label::SUSPEND => suspend(target, typed.raw()),
        _ => finish(tcb, result::ERR_BAD_LABEL),
    };
    finish(tcb, outcome.map_or_else(cap_result, |()| result::OK))
}

/// Put a configured thread on the run queue.
fn resume(target: &mut Tcb, cap: &RawCap) -> Result<(), CapError> {
    if !target.is_configured() {
        return Err(CapError::NotAssigned);
    }
    if target.state != ThreadState::Inactive {
        return Err(CapError::NotInactive);
    }
    target.state = ThreadState::Ready;
    // SAFETY: the thread was inactive, so it is on no queue and no hart.
    let ptr = unsafe { crate::cap::tcb::tcb_ptr(cap) };
    QUEUE.lock().push(ptr);
    SPAWNED.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Take a runnable thread off the run queue.
///
/// `Running` cannot appear here: with one hart the only running thread is the
/// caller, and a thread invoking its own capability was already refused. A
/// thread blocked on an endpoint is refused outright, because a TCB does not
/// record *which* endpoint it is queued on and half-suspending it would leave a
/// dangling entry on that queue.
fn suspend(target: &mut Tcb, cap: &RawCap) -> Result<(), CapError> {
    match target.state {
        ThreadState::Inactive => Ok(()),
        ThreadState::Ready => {
            // SAFETY: a live TCB from a capability; the lock serialises the queue.
            let ptr = unsafe { crate::cap::tcb::tcb_ptr(cap) };
            QUEUE.lock().remove(ptr);
            target.state = ThreadState::Inactive;
            Ok(())
        }
        _ => Err(CapError::NotInactive),
    }
}

/// Deliver a fault to this thread's pager as if the thread had called it.
///
/// The thread blocks in `AwaitingReply` exactly as a caller does, and the reply
/// resumes it *without* touching its registers or advancing `sepc`, so the
/// faulting instruction runs again against whatever the pager arranged.
fn deliver_fault(tcb: &mut Tcb, cause: Cause) -> ! {
    if tcb.fault_ep.kind != ObjectType::Endpoint {
        crate::println!(
            "thread {} killed: {} at {:#x} (no fault endpoint)",
            tcb.id,
            cause.name(),
            tcb.frame.sepc
        );
        retire(Retire::Killed)
    }

    let is_write = matches!(cause, Cause::Exception(15));
    let is_fetch = matches!(cause, Cause::Exception(12));
    tcb.frame.x[reg::A0 + 2] = crate::csr::stval::read();
    tcb.frame.x[reg::A0 + 3] = tcb.frame.sepc;
    tcb.frame.x[reg::A0 + 4] = is_write as usize | ((is_fetch as usize) << 1);
    tcb.frame.x[reg::A1] = MessageInfo::new(label::FAULT_VM, 3, false).bits() as usize;
    tcb.faulted = true;

    let ep = tcb.fault_ep;
    ipc_send(tcb, ep, MessageInfo::new(label::FAULT_VM, 3, false), true)
}

/// What userspace may name as a retype target.
///
/// `Null` is not an object and `Reply` is minted by the kernel on `call`. The
/// finer rule -- device untyped becomes only frames and smaller device
/// untypeds -- belongs to the retype itself, where the type says it (D-040).
fn object_type_from(n: usize) -> Option<ObjectType> {
    match ObjectType::from_u8(u8::try_from(n).ok()?)? {
        ObjectType::Null | ObjectType::Reply => None,
        other => Some(other),
    }
}

/// Save the calling kernel context into `ctx`, then resume `frame` in U-mode.
///
/// Declared as returning: control comes back here through [`resume_kernel`],
/// not by falling off the end.
///
/// # Safety
/// `ctx` must outlive every thread, and `frame` must be resumable.
#[unsafe(naked)]
unsafe extern "C" fn enter_threads(ctx: *mut KernelContext, frame: *mut TrapFrame) {
    core::arch::naked_asm!(
        "sd ra,   0(a0)",
        "sd sp,   8(a0)",
        "sd s0,  16(a0)",
        "sd s1,  24(a0)",
        "sd s2,  32(a0)",
        "sd s3,  40(a0)",
        "sd s4,  48(a0)",
        "sd s5,  56(a0)",
        "sd s6,  64(a0)",
        "sd s7,  72(a0)",
        "sd s8,  80(a0)",
        "sd s9,  88(a0)",
        "sd s10, 96(a0)",
        "sd s11,104(a0)",
        "mv a0, a1",
        "tail {return_to_user}",
        return_to_user = sym return_to_user,
    )
}

/// Restore the context [`enter_threads`] saved and return from its caller.
///
/// # Safety
/// `ctx` must hold a context saved by [`enter_threads`] whose stack is still live.
#[unsafe(naked)]
unsafe extern "C" fn resume_kernel(ctx: *const KernelContext) -> ! {
    core::arch::naked_asm!(
        "ld ra,   0(a0)",
        "ld sp,   8(a0)",
        "ld s0,  16(a0)",
        "ld s1,  24(a0)",
        "ld s2,  32(a0)",
        "ld s3,  40(a0)",
        "ld s4,  48(a0)",
        "ld s5,  56(a0)",
        "ld s6,  64(a0)",
        "ld s7,  72(a0)",
        "ld s8,  80(a0)",
        "ld s9,  88(a0)",
        "ld s10, 96(a0)",
        "ld s11,104(a0)",
        "ret",
    )
}
