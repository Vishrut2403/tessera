//! Trap entry and dispatch.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::csr::{scause, sepc, sstatus, sstatus_bits, stval, stvec, stvec_mode};
use crate::println;

/// The general-purpose register file as the trap entry lays it out.
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

/// The trap vector. Never called from Rust; `stvec` points here.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.trap")]
pub unsafe extern "C" fn trap_entry() -> ! {
    core::arch::naked_asm!(
        // Carve a TrapFrame out of the interrupted stack (D-007: S-mode traps only).
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

        // Reconstruct the caller's sp.
        "addi t0, sp, 256",
        "sd   t0,  16(sp)",

        // &mut TrapFrame is the first argument.
        "mv   a0, sp",
        "call {dispatch}",

        "ld   x1,    8(sp)",
        // x2 is restored by the stack adjustment, not by a load.
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

        // Return to sepc, restoring privilege and interrupt enable from sstatus.
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
        // M1 handles exactly one trap for real: `ebreak`.
        Cause::Exception(3) => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            skip_faulting_instruction();
        }
        _ => fatal(cause, frame),
    }
}

/// Advance `sepc` past the instruction that trapped.
fn skip_faulting_instruction() {
    let pc = sepc::read();
    // SAFETY: `sepc` points at an instruction we just executed, so it is mapped and readable.
    let low = unsafe { core::ptr::read_volatile(pc as *const u16) };
    let width = if low & 0b11 == 0b11 { 4 } else { 2 };
    // SAFETY: resuming past the trapping instruction is defined semantics for a handled breakpoint.
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
