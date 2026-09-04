//! Threads: the unit that runs, and the TCB that holds it when it is not running.

use core::ptr::NonNull;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::csr::sstatus_bits;
use crate::cap::RawCap;
use crate::mm::{AddressSpace, PAGE_SIZE, PhysAddr, VirtAddr, phys_to_virt};
use crate::trap::{TrapFrame, reg};

pub type ThreadId = usize;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// The next thread id. Ids are for diagnostics: authority is the capability.
pub fn next_id() -> ThreadId {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Retyped but never started: no address space, no CSpace, no entry point.
    Inactive,
    /// On the run queue, waiting for a hart.
    Ready,
    /// Currently on a hart.
    Running,
    /// Queued on an endpoint with a message to hand over.
    BlockedOnSend,
    /// Queued on an endpoint waiting for one.
    BlockedOnRecv,
    /// Sent a `call` and is waiting for the reply capability to be used.
    AwaitingReply,
    /// Finished. Its frame is never resumed again.
    Exited,
}

impl ThreadState {
    /// Whether the thread may be put on the run queue.
    pub const fn is_runnable(self) -> bool {
        matches!(self, ThreadState::Ready | ThreadState::Running)
    }

    pub const fn is_blocked(self) -> bool {
        matches!(
            self,
            ThreadState::BlockedOnSend | ThreadState::BlockedOnRecv | ThreadState::AwaitingReply
        )
    }
}

/// `sstatus.FS`, the two bits that decide whether `f0-f31` are usable (D-025).
pub mod fs {
    pub const SHIFT: usize = 13;
    pub const MASK: usize = 3 << SHIFT;
    pub const OFF: usize = 0 << SHIFT;
    pub const INITIAL: usize = 1 << SHIFT;
    pub const CLEAN: usize = 2 << SHIFT;
}

/// What a blocked thread is waiting on, so it can be removed from that queue
/// without searching every object in the system (D-048).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedOn {
    Nothing,
    Endpoint(PhysAddr),
    Notification(PhysAddr),
}

/// A thread control block.
#[repr(C)]
pub struct Tcb {
    pub frame: TrapFrame,
    /// `f0-f31`, restored only once the thread has actually used one (D-025).
    pub fp: [u64; 32],
    pub fp_valid: bool,
    pub state: ThreadState,
    pub id: ThreadId,
    /// The `satp` value that installs this thread's address space.
    pub satp: usize,
    /// Intrusive run queue link. The queue owns no memory of its own.
    pub next: Option<NonNull<Tcb>>,
    /// Intrusive endpoint queue link.
    pub ipc_next: Option<NonNull<Tcb>>,
    /// The object this thread is queued on while blocked. The link above says
    /// *where in* a queue it is; this says *which* queue, which is what lets a
    /// blocked thread be taken off it and killed (D-048).
    pub blocked_on: BlockedOn,
    /// The one-shot reply capability handed over by a `call` this thread
    /// received.
    pub reply: RawCap,
    /// Root CNode of this thread's capability space.
    pub cspace: RawCap,
    /// Badge of the capability the last sender invoked, delivered on receive.
    pub badge: u64,
    /// True while this thread is blocked on a `call` rather than a bare `send`,
    /// so whoever receives knows to take a reply capability.
    pub call_pending: bool,
    /// Where this thread's faults are delivered (D-034).
    pub fault_ep: RawCap,
    /// True while the thread is blocked on a fault rather than a syscall, so
    /// the reply resumes it instead of overwriting its registers.
    pub faulted: bool,
    /// This TCB's own physical address.
    pub self_paddr: PhysAddr,
}

const _: () = assert!(size_of::<Tcb>() <= PAGE_SIZE, "a TCB must fit in one frame");
const _: () = assert!(core::mem::offset_of!(Tcb, frame) == 0, "the trap entry casts frame to Tcb");

impl Tcb {
    /// Lay a new thread out in `frame_pa`, ready to be resumed into U-mode.
    ///
    /// # Safety
    /// `frame_pa` must be a frame we own exclusively, reachable through the
    /// direct map, and not already holding a live TCB.
    pub unsafe fn create(
        frame_pa: PhysAddr,
        id: ThreadId,
        space: &AddressSpace,
        entry: VirtAddr,
        stack_top: VirtAddr,
    ) -> NonNull<Tcb> {
        let ptr = phys_to_virt(frame_pa).as_mut_ptr::<Tcb>();
        let self_paddr = frame_pa;

        let mut frame = TrapFrame::default();
        frame.x[reg::SP] = stack_top.as_usize();
        frame.sepc = entry.as_usize();
        // SPP = 0 so `sret` drops to U-mode; SPIE = 1 so it re-enables
        // interrupts there; FS = Off so the first float traps and we allocate
        // lazily.
        frame.sstatus = sstatus_bits::SPIE | fs::OFF;

        // SAFETY: the caller promised an exclusively owned, mapped frame.
        unsafe {
            ptr.write(Tcb {
                frame,
                fp: [0; 32],
                fp_valid: false,
                state: ThreadState::Ready,
                id,
                satp: space.satp(),
                next: None,
                ipc_next: None,
                blocked_on: BlockedOn::Nothing,
                reply: RawCap::NULL,
                cspace: RawCap::NULL,
                badge: 0,
                call_pending: false,
                fault_ep: RawCap::NULL,
                faulted: false,
                self_paddr,
            });
            NonNull::new_unchecked(ptr)
        }
    }

    /// Lay out a TCB that exists but cannot run.
    ///
    /// # Safety
    /// `paddr` must be a TCB object we own exclusively and nothing refers to.
    pub unsafe fn init_inactive(paddr: PhysAddr) -> NonNull<Tcb> {
        let ptr = phys_to_virt(paddr).as_mut_ptr::<Tcb>();

        let mut frame = TrapFrame::default();
        frame.sstatus = sstatus_bits::SPIE | fs::OFF;

        // SAFETY: the caller promised an exclusively owned, untouched object.
        unsafe {
            ptr.write(Tcb {
                frame,
                fp: [0; 32],
                fp_valid: false,
                state: ThreadState::Inactive,
                id: next_id(),
                satp: 0,
                next: None,
                ipc_next: None,
                blocked_on: BlockedOn::Nothing,
                reply: RawCap::NULL,
                cspace: RawCap::NULL,
                badge: 0,
                call_pending: false,
                fault_ep: RawCap::NULL,
                faulted: false,
                self_paddr: paddr,
            });
            NonNull::new_unchecked(ptr)
        }
    }

    /// Whether this thread has everything it needs to be put on the run queue.
    pub const fn is_configured(&self) -> bool {
        self.satp != 0
    }

    /// Set where the thread starts and what stack it starts on.
    pub fn set_registers(&mut self, entry: VirtAddr, stack_top: VirtAddr) {
        self.frame.sepc = entry.as_usize();
        self.frame.x[reg::SP] = stack_top.as_usize();
    }

    pub fn frame_ptr(&mut self) -> *mut TrapFrame {
        &raw mut self.frame
    }

    /// The value `a0` will hold when the thread resumes.
    pub fn set_return(&mut self, value: usize) {
        self.frame.x[reg::A0] = value;
    }

    /// Move past the `ecall` that trapped, so resuming does not re-execute it.
    pub fn skip_ecall(&mut self) {
        self.frame.sepc += 4;
    }

    /// Grant this thread the FPU, restoring whatever state it had (D-025).
    pub fn enable_fp(&mut self) {
        self.frame.sstatus = (self.frame.sstatus & !fs::MASK)
            | if self.fp_valid { fs::CLEAN } else { fs::INITIAL };
        self.fp_valid = true;
    }

    pub fn uses_fp(&self) -> bool {
        self.frame.sstatus & fs::MASK != fs::OFF
    }
}

/// Whether an instruction word is a floating-point one.
pub fn is_fp_instruction(word: usize) -> bool {
    matches!(
        word as u32 & 0x7f,
        0b000_0111    // LOAD-FP
        | 0b010_0111  // STORE-FP
        | 0b100_0011  // MADD
        | 0b100_0111  // MSUB
        | 0b100_1011  // NMSUB
        | 0b100_1111  // NMADD
        | 0b101_0011  // OP-FP
    )
}

/// Run `f` with the FPU enabled in the *kernel's* `sstatus`, then put FS back.
fn with_fpu(f: impl FnOnce()) {
    // SAFETY: FS only governs whether FP instructions fault; nothing else reads it.
    let old = unsafe { crate::csr::sstatus::set(fs::CLEAN) };
    f();
    // SAFETY: restoring exactly the FS the kernel was running with.
    unsafe {
        crate::csr::sstatus::clear(fs::MASK);
        crate::csr::sstatus::set(old & fs::MASK);
    }
}

/// Save `f0-f31` into `dst`.
pub fn save_fp(dst: &mut [u64; 32]) {
    with_fpu(|| unsafe {
        core::arch::asm!(
            "fsd f0, 0({p})",
            "fsd f1, 8({p})",
            "fsd f2, 16({p})",
            "fsd f3, 24({p})",
            "fsd f4, 32({p})",
            "fsd f5, 40({p})",
            "fsd f6, 48({p})",
            "fsd f7, 56({p})",
            "fsd f8, 64({p})",
            "fsd f9, 72({p})",
            "fsd f10, 80({p})",
            "fsd f11, 88({p})",
            "fsd f12, 96({p})",
            "fsd f13, 104({p})",
            "fsd f14, 112({p})",
            "fsd f15, 120({p})",
            "fsd f16, 128({p})",
            "fsd f17, 136({p})",
            "fsd f18, 144({p})",
            "fsd f19, 152({p})",
            "fsd f20, 160({p})",
            "fsd f21, 168({p})",
            "fsd f22, 176({p})",
            "fsd f23, 184({p})",
            "fsd f24, 192({p})",
            "fsd f25, 200({p})",
            "fsd f26, 208({p})",
            "fsd f27, 216({p})",
            "fsd f28, 224({p})",
            "fsd f29, 232({p})",
            "fsd f30, 240({p})",
            "fsd f31, 248({p})",
            p = in(reg) dst.as_mut_ptr(),
            options(nostack),
        );
    });
}

/// Restore `f0-f31` from `src`.
pub fn restore_fp(src: &[u64; 32]) {
    with_fpu(|| unsafe {
        core::arch::asm!(
            "fld f0, 0({p})",
            "fld f1, 8({p})",
            "fld f2, 16({p})",
            "fld f3, 24({p})",
            "fld f4, 32({p})",
            "fld f5, 40({p})",
            "fld f6, 48({p})",
            "fld f7, 56({p})",
            "fld f8, 64({p})",
            "fld f9, 72({p})",
            "fld f10, 80({p})",
            "fld f11, 88({p})",
            "fld f12, 96({p})",
            "fld f13, 104({p})",
            "fld f14, 112({p})",
            "fld f15, 120({p})",
            "fld f16, 128({p})",
            "fld f17, 136({p})",
            "fld f18, 144({p})",
            "fld f19, 152({p})",
            "fld f20, 160({p})",
            "fld f21, 168({p})",
            "fld f22, 176({p})",
            "fld f23, 184({p})",
            "fld f24, 192({p})",
            "fld f25, 200({p})",
            "fld f26, 208({p})",
            "fld f27, 216({p})",
            "fld f28, 224({p})",
            "fld f29, 232({p})",
            "fld f30, 240({p})",
            "fld f31, 248({p})",
            p = in(reg) src.as_ptr(),
            options(nostack, readonly),
        );
    });
}
