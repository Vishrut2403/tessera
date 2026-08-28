//! Trap entry and dispatch.
//!
//! A trap is the only way control transfers into the kernel: a timer fires, a
//! page faults, a thread executes `ecall`. The hardware's contribution is
//! minimal and worth stating exactly, because everything here exists to fill the
//! gaps it leaves. On a trap to S-mode the hart:
//!
//! 1. writes the faulting PC into `sepc`,
//! 2. writes the reason into `scause` and the associated value into `stval`,
//! 3. copies `sstatus.SIE` into `sstatus.SPIE` and clears `SIE` (so we are not
//!    immediately re-interrupted),
//! 4. records the previous privilege in `sstatus.SPP`,
//! 5. sets `pc` to `stvec`.
//!
//! Note what it does *not* do: it does not switch stacks, and it does not save a
//! single general-purpose register. The trap handler is running on whatever `sp`
//! the interrupted code had, with every register still live. That is why the
//! entry point below must be naked — a compiler-generated prologue would clobber
//! registers we have not saved yet.
//!
//! **D-007: the entry below is correct only for traps taken in S-mode.** In M1
//! there is no user mode, so "the current stack" is always a kernel stack. When
//! M3 introduces threads that trap from U-mode, this needs the standard
//! `csrrw sp, sscratch, sp` swap and a per-thread kernel stack, and the frame
//! has to land in the TCB rather than on whatever stack happened to be live. The
//! 31 save/restore instructions survive that change; the prologue and epilogue
//! do not.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::csr::{scause, sepc, sstatus, sstatus_bits, stval, stvec, stvec_mode};
use crate::println;

/// The general-purpose register file as the trap entry lays it out.
///
/// `#[repr(C)]` because the assembly below indexes it by hand: `x[n]` lives at
/// byte offset `n * 8`. `x[0]` is the slot for the hardwired-zero register; the
/// entry stores an explicit zero there so dumps are not confusing.
///
/// Size is exactly 256 bytes, which keeps `sp` 16-byte aligned as the ABI
/// requires — 31 registers would be 248, and an unaligned `sp` is the kind of
/// bug that only shows up once something starts using vector or float loads.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrapFrame {
    pub x: [usize; 32],
}

/// ABI names, for dumps. Index matches the architectural register number.
const REG_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

/// Number of breakpoint exceptions handled since boot. Exists so a test can
/// prove the trap path actually ran rather than inferring it from not crashing.
pub static BREAKPOINTS: AtomicUsize = AtomicUsize::new(0);

/// Install the trap vector.
pub fn init() {
    // Via `*const ()`: casting a function item straight to an integer is
    // linted against (function_casts_as_integer) because it silently decays a
    // typed item through a pointer. Naming the pointer step makes it explicit.
    let base = trap_entry as *const () as usize;
    // stvec's low two bits are the mode field, so a misaligned base would
    // silently select vectored mode. The linker script aligns `.text.trap` to 4;
    // this asserts that it worked.
    assert!(base & 0b11 == 0, "trap entry is not 4-byte aligned");

    // SAFETY: `trap_entry` is a valid trap handler that saves and restores every
    // register it touches and ends in `sret`. Nothing has enabled interrupts
    // yet, so there is no window in which an old stvec is half-replaced.
    unsafe { stvec::write(base | stvec_mode::DIRECT) };
}

/// The trap vector. Never called from Rust; `stvec` points here.
///
/// Naked for the reason in the module docs: on entry, every general-purpose
/// register still belongs to the interrupted code, and a prologue would destroy
/// them before we could save them.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.trap")]
pub unsafe extern "C" fn trap_entry() -> ! {
    core::arch::naked_asm!(
        // Carve a TrapFrame out of the interrupted stack (D-007: valid only
        // because that stack is a kernel stack in M1).
        "addi sp, sp, -256",

        "sd   zero, 0(sp)",   // x0's slot, so dumps read cleanly
        "sd   x1,   8(sp)",
        // x2 (sp) is handled below: the value we want is the *pre-trap* sp.
        "sd   x3,   24(sp)",
        "sd   x4,   32(sp)",
        "sd   x5,   40(sp)",
        "sd   x6,   48(sp)",
        "sd   x7,   56(sp)",
        "sd   x8,   64(sp)",
        "sd   x9,   72(sp)",
        "sd   x10,  80(sp)",
        "sd   x11,  88(sp)",
        "sd   x12,  96(sp)",
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

        // Reconstruct the caller's sp. Safe to clobber t0 now: it is saved.
        "addi t0, sp, 256",
        "sd   t0,  16(sp)",

        // &mut TrapFrame is the first argument.
        "mv   a0, sp",
        "call {dispatch}",

        "ld   x1,    8(sp)",
        // x2 is restored by the stack adjustment, not by a load: the handler is
        // not permitted to relocate the interrupted stack in M1.
        "ld   x3,   24(sp)",
        "ld   x4,   32(sp)",
        "ld   x5,   40(sp)",
        "ld   x6,   48(sp)",
        "ld   x7,   56(sp)",
        "ld   x8,   64(sp)",
        "ld   x9,   72(sp)",
        "ld   x10,  80(sp)",
        "ld   x11,  88(sp)",
        "ld   x12,  96(sp)",
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

        "addi sp, sp, 256",

        // Return to sepc, restoring the pre-trap privilege from sstatus.SPP and
        // the pre-trap interrupt enable from sstatus.SPIE.
        "sret",

        dispatch = sym dispatch,
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
        // The top bit distinguishes the two spaces; the rest is the code. Both
        // number from zero, so cause 5 is either "timer interrupt" or "load
        // access fault" depending entirely on this bit.
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
        // M1 handles exactly one trap for real: `ebreak`. It is the cheapest
        // possible proof that the whole path works — save, dispatch, mutate
        // supervisor state, restore, resume.
        Cause::Exception(3) => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            skip_faulting_instruction();
        }
        _ => fatal(cause, frame),
    }
}

/// Advance `sepc` past the instruction that trapped.
///
/// `sepc` points *at* the faulting instruction, not after it, so returning
/// without touching it would re-execute the `ebreak` forever. The width is not a
/// constant: with the C extension, `ebreak` may have been assembled as the
/// 2-byte `c.ebreak`. RISC-V encodes length in the low bits — an instruction
/// whose bottom two bits are both set is 4 bytes wide, anything else is 2 — so
/// we read the halfword at `sepc` and ask it.
fn skip_faulting_instruction() {
    let pc = sepc::read();
    // SAFETY: `sepc` points at an instruction we just executed, so it is mapped
    // and readable. In M1 the MMU is off, so no address-space question arises;
    // from M3 this same read on a user PC needs sstatus.SUM set and a fault
    // handler behind it.
    let low = unsafe { core::ptr::read_volatile(pc as *const u16) };
    let width = if low & 0b11 == 0b11 { 4 } else { 2 };
    // SAFETY: resuming at the instruction after the one that trapped is the
    // defined semantics of a handled breakpoint.
    unsafe { sepc::write(pc + width) };
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
