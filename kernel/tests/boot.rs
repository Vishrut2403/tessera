//! What `_start` is supposed to have established by the time Rust runs.

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

// Placing a static in a *particular* section takes some care.

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
fn kernel_is_loaded_where_opensbi_expects_it() {
    // The load address, not the link address -- see D-002.
    assert_eq!(layout::kernel_phys_range().start.as_usize(), 0x8020_0000);
}

#[test_case]
fn paging_is_on_and_we_are_in_the_high_half() {
    assert_eq!(kernel::mm::phys_offset(), kernel::mm::KERNEL_VMA);
    assert!(layout::text_start() > kernel::mm::KERNEL_VMA);
    // satp MODE field: 8 is Sv39.
    assert_eq!(kernel::csr::satp::read() >> 60, 8, "satp is not in Sv39 mode");
}
