//! Trap entry and dispatch.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::csr::{scause, sepc, sstatus, sstatus_bits, stval, stvec, stvec_mode};
use crate::println;

/// Everything a trap must preserve, laid out the way the trap entry indexes it.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TrapFrame {
    /// x0..x31 by architectural number; `x[0]` is written as zero for dumps.
    pub x: [usize; 32],
    pub sepc: usize,
    pub sstatus: usize,
}

/// Bytes the entry reserves for a frame: 272 rounded up to keep `sp` 16-aligned.
pub const FRAME_SIZE: usize = 288;

const _: () = assert!(size_of::<TrapFrame>() == 272, "the asm offsets below are hand-written");

/// Register indices the trap code and the thread code both need.
pub mod reg {
    pub const SP: usize = 2;
    pub const A0: usize = 10;
    pub const A1: usize = 11;
    pub const A7: usize = 17;
}

/// ABI names, for dumps. Index matches the architectural register number.
const REG_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// Breakpoints handled since boot; lets a test observe the trap path.
pub static BREAKPOINTS: AtomicUsize = AtomicUsize::new(0);

/// Install the trap vector.
pub fn init() {
    // Via `*const ()`: a direct fn-item-to-integer cast is linted against.
    let base = trap_entry as *const () as usize;
    // stvec's low two bits are the mode field, so a misaligned base selects vectored mode.
    assert!(base & 0b11 == 0, "trap entry is not 4-byte aligned");

    // SAFETY: `trap_entry` saves and restores every register it touches and ends in `sret`.
    unsafe { stvec::write(base | stvec_mode::DIRECT) };
}

/// The trap vector.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.trap")]
pub unsafe extern "C" fn trap_entry() -> ! {
    core::arch::naked_asm!(
        "csrrw sp, sscratch, sp",
        "bnez  sp, 100f",

        // From S-mode: sscratch was zero, so undo the swap and carve a frame
        // out of the stack we were already on.
        "csrrw sp, sscratch, sp",
        "addi sp, sp, -{frame_size}",
        "sd   x1, 8(sp)",
        "sd   x3, 24(sp)",
        "sd   x4, 32(sp)",
        "sd   x5, 40(sp)",
        "sd   x6, 48(sp)",
        "sd   x7, 56(sp)",
        "sd   x8, 64(sp)",
        "sd   x9, 72(sp)",
        "sd   x10, 80(sp)",
        "sd   x11, 88(sp)",
        "sd   x12, 96(sp)",
        "sd   x13, 104(sp)",
        "sd   x14, 112(sp)",
        "sd   x15, 120(sp)",
        "sd   x16, 128(sp)",
        "sd   x17, 136(sp)",
        "sd   x18, 144(sp)",
        "sd   x19, 152(sp)",
        "sd   x20, 160(sp)",
        "sd   x21, 168(sp)",
        "sd   x22, 176(sp)",
        "sd   x23, 184(sp)",
        "sd   x24, 192(sp)",
        "sd   x25, 200(sp)",
        "sd   x26, 208(sp)",
        "sd   x27, 216(sp)",
        "sd   x28, 224(sp)",
        "sd   x29, 232(sp)",
        "sd   x30, 240(sp)",
        "sd   x31, 248(sp)",
        "sd   zero, 0(sp)",
        "addi t0, sp, {frame_size}",
        "sd   t0, 16(sp)",
        "csrr t0, sepc",
        "sd   t0, 256(sp)",
        "csrr t0, sstatus",
        "sd   t0, 264(sp)",

        "mv   a0, sp",
        "call {dispatch}",

        "ld   t0, 256(sp)",
        "csrw sepc, t0",
        "ld   t0, 264(sp)",
        "csrw sstatus, t0",
        "ld   x1, 8(sp)",
        "ld   x3, 24(sp)",
        "ld   x4, 32(sp)",
        "ld   x5, 40(sp)",
        "ld   x6, 48(sp)",
        "ld   x7, 56(sp)",
        "ld   x8, 64(sp)",
        "ld   x9, 72(sp)",
        "ld   x10, 80(sp)",
        "ld   x11, 88(sp)",
        "ld   x12, 96(sp)",
        "ld   x13, 104(sp)",
        "ld   x14, 112(sp)",
        "ld   x15, 120(sp)",
        "ld   x16, 128(sp)",
        "ld   x17, 136(sp)",
        "ld   x18, 144(sp)",
        "ld   x19, 152(sp)",
        "ld   x20, 160(sp)",
        "ld   x21, 168(sp)",
        "ld   x22, 176(sp)",
        "ld   x23, 184(sp)",
        "ld   x24, 192(sp)",
        "ld   x25, 200(sp)",
        "ld   x26, 208(sp)",
        "ld   x27, 216(sp)",
        "ld   x28, 224(sp)",
        "ld   x29, 232(sp)",
        "ld   x30, 240(sp)",
        "ld   x31, 248(sp)",
        "addi sp, sp, {frame_size}",
        "sret",

        // From U-mode: sp is the frame inside the TCB, sscratch is the user sp.
        "100:",
        "sd   x1, 8(sp)",
        "sd   x3, 24(sp)",
        "sd   x4, 32(sp)",
        "sd   x5, 40(sp)",
        "sd   x6, 48(sp)",
        "sd   x7, 56(sp)",
        "sd   x8, 64(sp)",
        "sd   x9, 72(sp)",
        "sd   x10, 80(sp)",
        "sd   x11, 88(sp)",
        "sd   x12, 96(sp)",
        "sd   x13, 104(sp)",
        "sd   x14, 112(sp)",
        "sd   x15, 120(sp)",
        "sd   x16, 128(sp)",
        "sd   x17, 136(sp)",
        "sd   x18, 144(sp)",
        "sd   x19, 152(sp)",
        "sd   x20, 160(sp)",
        "sd   x21, 168(sp)",
        "sd   x22, 176(sp)",
        "sd   x23, 184(sp)",
        "sd   x24, 192(sp)",
        "sd   x25, 200(sp)",
        "sd   x26, 208(sp)",
        "sd   x27, 216(sp)",
        "sd   x28, 224(sp)",
        "sd   x29, 232(sp)",
        "sd   x30, 240(sp)",
        "sd   x31, 248(sp)",
        "sd   zero, 0(sp)",
        "csrr t0, sscratch",
        "sd   t0, 16(sp)",
        "csrr t0, sepc",
        "sd   t0, 256(sp)",
        "csrr t0, sstatus",
        "sd   t0, 264(sp)",

        // Zero marks "in the kernel", so a nested trap takes the S-mode path.
        "csrw sscratch, zero",
        "mv   a0, sp",

        // Onto the hart's one kernel stack.
        "lla  t0, {kernel_sp}",
        "ld   sp, 0(t0)",
        "tail {user_trap}",

        frame_size = const FRAME_SIZE,
        dispatch = sym dispatch,
        user_trap = sym crate::sched::user_trap,
        kernel_sp = sym KERNEL_SP,
    )
}

/// This hart's kernel stack.
#[repr(C, align(16))]
struct KernelStack([u8; KERNEL_STACK_SIZE]);

const KERNEL_STACK_SIZE: usize = 64 * 1024;

static mut TRAP_STACK: KernelStack = KernelStack([0; KERNEL_STACK_SIZE]);

/// Point the trap path at the built-in kernel stack.
pub fn use_default_kernel_stack() {
    let base = (&raw const TRAP_STACK) as usize;
    set_kernel_stack(base + KERNEL_STACK_SIZE);
}

/// Top of this hart's kernel stack, in a static so the entry can load it.
static KERNEL_SP: AtomicUsize = AtomicUsize::new(0);

/// Point the trap path at the kernel stack it should run on.
pub fn set_kernel_stack(top: usize) {
    assert!(top & 0xf == 0, "kernel stack top is not 16-byte aligned");
    KERNEL_SP.store(top, Ordering::Relaxed);
}

pub fn kernel_stack() -> usize {
    KERNEL_SP.load(Ordering::Relaxed)
}

/// Resume a thread: `sret` into U-mode with `frame` restored.
///
/// # Safety
/// `frame` must be a live `TrapFrame` whose `sstatus` returns to U-mode, and
/// the address space that thread expects must already be installed in `satp`.
#[unsafe(naked)]
#[unsafe(link_section = ".text.trap")]
pub unsafe extern "C" fn return_to_user(frame: *mut TrapFrame) -> ! {
    core::arch::naked_asm!(
        // The next trap from U-mode finds its frame here.
        "csrw sscratch, a0",
        "mv   t6, a0",
        "ld   t0, 256(t6)",
        "csrw sepc, t0",
        "ld   t0, 264(t6)",
        "csrw sstatus, t0",
        "ld   x1, 8(t6)",
        "ld   x2, 16(t6)",
        "ld   x3, 24(t6)",
        "ld   x4, 32(t6)",
        "ld   x5, 40(t6)",
        "ld   x6, 48(t6)",
        "ld   x7, 56(t6)",
        "ld   x8, 64(t6)",
        "ld   x9, 72(t6)",
        "ld   x10, 80(t6)",
        "ld   x11, 88(t6)",
        "ld   x12, 96(t6)",
        "ld   x13, 104(t6)",
        "ld   x14, 112(t6)",
        "ld   x15, 120(t6)",
        "ld   x16, 128(t6)",
        "ld   x17, 136(t6)",
        "ld   x18, 144(t6)",
        "ld   x19, 152(t6)",
        "ld   x20, 160(t6)",
        "ld   x21, 168(t6)",
        "ld   x22, 176(t6)",
        "ld   x23, 184(t6)",
        "ld   x24, 192(t6)",
        "ld   x25, 200(t6)",
        "ld   x26, 208(t6)",
        "ld   x27, 216(t6)",
        "ld   x28, 224(t6)",
        "ld   x29, 232(t6)",
        "ld   x30, 240(t6)",
        // t6 last, out of its own slot.
        "ld   x31, 248(t6)",
        "sret",
    )
}

/// Decoded trap cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Interrupt(usize),
    Exception(usize),
}

impl Cause {
    pub fn decode(scause: usize) -> Self {
        // The top bit distinguishes the two spaces; the rest is the code.
        const INTERRUPT: usize = 1 << (usize::BITS - 1);
        if scause & INTERRUPT != 0 {
            Cause::Interrupt(scause & !INTERRUPT)
        } else {
            Cause::Exception(scause)
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Cause::Interrupt(1) => "supervisor software interrupt",
            Cause::Interrupt(5) => "supervisor timer interrupt",
            Cause::Interrupt(9) => "supervisor external interrupt",
            Cause::Interrupt(_) => "reserved interrupt",
            Cause::Exception(0) => "instruction address misaligned",
            Cause::Exception(1) => "instruction access fault",
            Cause::Exception(2) => "illegal instruction",
            Cause::Exception(3) => "breakpoint",
            Cause::Exception(4) => "load address misaligned",
            Cause::Exception(5) => "load access fault",
            Cause::Exception(6) => "store/AMO address misaligned",
            Cause::Exception(7) => "store/AMO access fault",
            Cause::Exception(8) => "ecall from U-mode",
            Cause::Exception(9) => "ecall from S-mode",
            Cause::Exception(12) => "instruction page fault",
            Cause::Exception(13) => "load page fault",
            Cause::Exception(15) => "store/AMO page fault",
            Cause::Exception(_) => "reserved exception",
        }
    }
}

/// The Rust side of the trap vector.
#[unsafe(no_mangle)]
pub extern "C" fn dispatch(frame: &mut TrapFrame) {
    let cause = Cause::decode(scause::read());

    match cause {
        Cause::Interrupt(5) => crate::time::on_tick(),
        Cause::Interrupt(9) => crate::sched::on_external_interrupt(),
        Cause::Exception(3) => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            skip_faulting_instruction(frame);
        }
        _ => fatal(cause, frame),
    }
}

/// Advance past the instruction that trapped.
fn skip_faulting_instruction(frame: &mut TrapFrame) {
    let pc = frame.sepc;
    // SAFETY: `sepc` points at an instruction we just executed, so it is mapped.
    let low = unsafe { core::ptr::read_volatile(pc as *const u16) };
    frame.sepc = pc + if low & 0b11 == 0b11 { 4 } else { 2 };
}

/// Unhandled trap: dump everything and stop.
fn fatal(cause: Cause, frame: &TrapFrame) -> ! {
    println!();
    println!("=== UNHANDLED TRAP ===");
    println!("cause   : {} ({:?})", cause.name(), cause);
    println!("sepc    : {:#018x}", sepc::read());
    println!("stval   : {:#018x}", stval::read());
    let status = sstatus::read();
    println!(
        "sstatus : {:#018x}  (SPP={}, SPIE={}, SIE={})",
        status,
        (status & sstatus_bits::SPP != 0) as u8,
        (status & sstatus_bits::SPIE != 0) as u8,
        (status & sstatus_bits::SIE != 0) as u8,
    );
    println!("registers:");
    for i in 0..32 {
        print_reg(i, frame.x[i]);
    }
    panic!("unhandled trap: {}", cause.name());
}

fn print_reg(i: usize, v: usize) {
    // Four per line keeps the dump on one screen at 80 columns.
    crate::print!("  {:>4}={:#018x}", REG_NAMES[i], v);
    if i % 4 == 3 {
        println!();
    }
}
