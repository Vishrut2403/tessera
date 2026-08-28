//! What `_start` is supposed to have established by the time Rust runs.
//!
//! Every assertion here is about an invariant that is invisible until it is
//! violated, at which point it presents as an unrelated mystery: a static that
//! is not zero, a stack pointer in the middle of nowhere, a `gp` that makes
//! every global access read the wrong address.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use core::sync::atomic::{AtomicU64, Ordering};

use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

extern "C" fn test_main_entry(_hartid: usize, _dtb_pa: usize) -> ! {
    kernel::init();
    test_main();
    qemu::exit_success()
}

// Placing a static in a *particular* section takes some care. An immutable
// `static X: u64 = 0` is read-only data and lands in .rodata no matter what it
// contains, which would make a "is .bss zeroed?" test silently test nothing.
// Interior mutability is what forces a static into writable memory, and then the
// initialiser decides which half: all-zero goes to .bss (or .sbss), anything
// else goes to .data (or .sdata). The linker script folds the small-data
// variants into the same ranges, so the address checks below hold either way.

/// Must read back as zero, or the zeroing loop in `_start` is wrong.
static BSS_PROBE: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];

/// Non-zero initialiser: proves initialised writable data survived the load.
static DATA_PROBE: AtomicU64 = AtomicU64::new(0xdead_beef_cafe_f00d);

/// Immutable, so read-only.
static RODATA_PROBE: u64 = 0x0123_4567_89ab_cdef;

#[test_case]
fn bss_is_zeroed() {
    for (i, w) in BSS_PROBE.iter().enumerate() {
        assert_eq!(w.load(Ordering::Relaxed), 0, "bss word {i} is not zero");
    }
}

#[test_case]
fn data_survived() {
    assert_eq!(DATA_PROBE.load(Ordering::Relaxed), 0xdead_beef_cafe_f00d);
}

#[test_case]
fn rodata_survived() {
    assert_eq!(RODATA_PROBE, 0x0123_4567_89ab_cdef);
}

#[test_case]
fn statics_live_in_the_right_sections() {
    let bss = &raw const BSS_PROBE as usize;
    let data = &raw const DATA_PROBE as usize;
    let rodata = &raw const RODATA_PROBE as usize;

    assert!((layout::bss_start()..layout::bss_end()).contains(&bss), "probe not in .bss");
    assert!((layout::data_start()..layout::data_end()).contains(&data), "probe not in .data");
    assert!(
        (layout::rodata_start()..layout::rodata_end()).contains(&rodata),
        "probe not in .rodata"
    );
}

#[test_case]
fn sp_is_inside_the_boot_stack() {
    let sp = kernel::stack_pointer();
    assert!(
        (layout::boot_stack_bottom()..=layout::boot_stack_top()).contains(&sp),
        "sp {sp:#x} outside boot stack {:#x}..{:#x}",
        layout::boot_stack_bottom(),
        layout::boot_stack_top()
    );
}

#[test_case]
fn stack_has_room_to_spare() {
    // If we are already deep in the stack this early, something recursed.
    let used = layout::boot_stack_top() - kernel::stack_pointer();
    assert!(used < 4096, "used {used} bytes of boot stack before any real work");
}

#[test_case]
fn kernel_is_where_opensbi_expects_it() {
    assert_eq!(layout::kernel_start(), 0x8020_0000);
}
