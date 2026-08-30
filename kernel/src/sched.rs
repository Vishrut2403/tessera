//! Round-robin scheduling over a single kernel stack per hart (D-024).

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::{AddressSpace, VirtAddr};
use crate::sync::SpinLock;
use crate::thread::{Tcb, ThreadId, ThreadState};
use crate::trap::{Cause, TrapFrame, reg, return_to_user};

/// The system calls M3 understands. M4 replaces all of them with capability
/// invocations; they exist so a user thread has something to say.
pub mod syscall {
    pub const YIELD: usize = 0;
    pub const EXIT: usize = 1;
    pub const PUTC: usize = 2;
    pub const GET_ID: usize = 3;
}

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
    current: Option<NonNull<Tcb>>,
    ready: usize,
}

// SAFETY: the pointers are to TCB frames the kernel owns for their whole life,
// and the lock is what serialises access to the queue they are threaded onto.
unsafe impl Send for RunQueue {}

impl RunQueue {
    const fn new() -> Self {
        Self { head: None, tail: None, current: None, ready: 0 }
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

    fn pop(&mut self) -> Option<NonNull<Tcb>> {
        let mut head = self.head?;
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
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
static KERNEL_CTX: SpinLock<KernelContext> = SpinLock::new(KernelContext::new_const());
static SPAWNED: AtomicUsize = AtomicUsize::new(0);
static EXITED: AtomicUsize = AtomicUsize::new(0);
static KILLED: AtomicUsize = AtomicUsize::new(0);
static STOP_ON_EXIT: AtomicBool = AtomicBool::new(false);

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
    let frame = crate::mm::alloc_frame().ok_or(SpawnError::OutOfFrames)?;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    // SAFETY: `frame` came from the allocator, so we own it and nothing else
    // has a TCB in it.
    let tcb = unsafe { Tcb::create(frame, id, space, entry, stack_top) };

    QUEUE.lock().push(tcb);
    SPAWNED.fetch_add(1, Ordering::Relaxed);
    Ok(id)
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

/// The id of the thread on this hart, if one is running.
pub fn current_id() -> Option<ThreadId> {
    // SAFETY: read under the lock; the TCB outlives the queue entry.
    QUEUE.lock().current.map(|t| unsafe { t.as_ref().id })
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
    assert!(QUEUE.lock().current.is_none(), "kill_all with a thread on the hart");
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
    // SAFETY: the space was built by `AddressSpace`, so it maps the kernel half.
    unsafe { crate::csr::satp::write(t.satp) };
    crate::mm::flush_tlb_all();

    QUEUE.lock().current = Some(tcb);
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
}

/// Stop running the current thread and resume whatever is next.
fn retire(why: Retire) -> ! {
    let current = QUEUE.lock().current.take();

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
            tcb.set_return(0);
        }
        syscall::GET_ID => tcb.set_return(tcb.id),
        _ => tcb.set_return(usize::MAX),
    }

    // SAFETY: the thread is still current and its frame is intact.
    unsafe { return_to_user(tcb.frame_ptr()) }
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
