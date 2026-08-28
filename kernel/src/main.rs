//! The kernel binary. Deliberately thin — everything real lives in the library
//! so that tests can link it (D-005).

#![no_std]
#![no_main]

use kernel::csr::{sstatus, sstatus_bits};
use kernel::{kernel_entry, layout, println, qemu, trap};

kernel_entry!(kmain);

/// First Rust code to run. `_start` has already set `gp`, zeroed `.bss`, and
/// installed the boot stack; `a0` and `a1` are still OpenSBI's.
///
/// `no_mangle` purely so `break kmain` works in gdb without demangling games.
#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();

    println!();
    println!("tessera :: M1");
    println!("  hart          : {}", hartid);
    println!("  device tree   : {:#x}", dtb_pa);
    println!("  sp            : {:#018x}", kernel::stack_pointer());
    println!(
        "  sstatus       : {:#018x} (SIE={})",
        sstatus::read(),
        (sstatus::read() & sstatus_bits::SIE != 0) as u8
    );
    println!();
    println!("memory layout:");
    println!(
        "  .text         : {:#012x}..{:#012x}  ({} B)",
        layout::text_start(),
        layout::text_end(),
        layout::text_end() - layout::text_start()
    );
    println!(
        "  .rodata       : {:#012x}..{:#012x}  ({} B)",
        layout::rodata_start(),
        layout::rodata_end(),
        layout::rodata_end() - layout::rodata_start()
    );
    println!(
        "  .data         : {:#012x}..{:#012x}  ({} B)",
        layout::data_start(),
        layout::data_end(),
        layout::data_end() - layout::data_start()
    );
    println!(
        "  .bss          : {:#012x}..{:#012x}  ({} B)",
        layout::bss_start(),
        layout::bss_end(),
        layout::bss_end() - layout::bss_start()
    );
    println!(
        "  boot stack    : {:#012x}..{:#012x}  ({} B)",
        layout::boot_stack_bottom(),
        layout::boot_stack_top(),
        layout::boot_stack_top() - layout::boot_stack_bottom()
    );
    println!(
        "  kernel image  : {:#012x}..{:#012x}  ({} KiB)",
        layout::kernel_start(),
        layout::kernel_end(),
        (layout::kernel_end() - layout::kernel_start()) / 1024
    );

    // Prove the trap path end to end: take a synchronous exception, have the
    // handler mutate supervisor state (advance sepc past the ebreak), and come
    // back with every register intact. If any of the 31 save/restore pairs in
    // trap_entry were wrong, the code after this point would misbehave in a way
    // that is very hard to attribute later.
    println!();
    println!("trap test: executing ebreak...");
    let before = trap::BREAKPOINTS.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: `ebreak` raises a breakpoint exception, which `dispatch` handles
    // by skipping the instruction. Nothing else observes it.
    unsafe { core::arch::asm!("ebreak") };
    let after = trap::BREAKPOINTS.load(core::sync::atomic::Ordering::Relaxed);
    println!("  returned from trap; breakpoints handled: {} -> {}", before, after);
    assert_eq!(after, before + 1, "breakpoint handler did not run");

    println!();
    println!("M1 complete. Parking. (Ctrl-A x to exit QEMU)");
    qemu::park()
}
