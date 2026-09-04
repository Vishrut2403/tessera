//! Memory discovery and the frame allocator, against the real device tree.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use core::sync::atomic::{AtomicUsize, Ordering};

use kernel::mm::{self, MemoryMap, PAGE_SIZE, PhysAddr};
use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

/// The DTB pointer OpenSBI passed in a1, stashed for the test cases.
static DTB: AtomicUsize = AtomicUsize::new(0);

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    DTB.store(dtb_pa, Ordering::Relaxed);
    mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range())
        .expect("memory discovery failed");
    test_main();
    qemu::exit_success()
}

fn map() -> MemoryMap {
    mm::discover(PhysAddr::new(DTB.load(Ordering::Relaxed)), layout::kernel_phys_range())
        .expect("discovery failed")
}

#[test_case]
fn device_tree_reports_ram() {
    let m = map();
    assert!(!m.ram.is_empty(), "no RAM in the device tree");
    // QEMU virt starts RAM at 0x8000_0000 and we asked for 128 MiB.
    assert_eq!(m.ram.as_slice()[0].start, PhysAddr::new(0x8000_0000));
    assert_eq!(m.ram.total_bytes(), 128 * 1024 * 1024);
}

#[test_case]
fn kernel_image_is_reserved() {
    let m = map();
    let kernel = layout::kernel_phys_range();
    assert!(
        m.reserved.iter().any(|r| r.start <= kernel.start && r.end >= kernel.end),
        "the kernel image is not reserved, so it could be handed out as a free frame"
    );
}

#[test_case]
fn device_tree_blob_is_reserved() {
    let m = map();
    let dtb = PhysAddr::new(DTB.load(Ordering::Relaxed));
    assert!(
        m.reserved.iter().any(|r| r.contains(dtb)),
        "the DTB itself is not reserved, so the memory map would be overwritten"
    );
}

#[test_case]
fn firmware_reservation_is_honoured() {
    // OpenSBI publishes its own footprint in the memory reservation block.
    let m = map();
    assert!(
        m.reserved.iter().any(|r| r.contains(PhysAddr::new(0x8000_0000))),
        "the firmware's own region is not reserved"
    );
}

#[test_case]
fn free_never_intersects_reserved() {
    let m = map();
    for free in m.free.iter() {
        for res in m.reserved.iter() {
            assert!(
                !free.overlaps(res),
                "free region {free:?} overlaps reserved region {res:?}"
            );
        }
    }
}

#[test_case]
fn free_is_inside_ram() {
    let m = map();
    for free in m.free.iter() {
        assert!(
            m.ram.iter().any(|r| r.start <= free.start && free.end <= r.end),
            "free region {free:?} is not inside any RAM region"
        );
    }
}

#[test_case]
fn free_regions_are_page_aligned() {
    let m = map();
    for r in m.free.iter() {
        assert!(r.start.is_aligned(PAGE_SIZE), "{r:?} does not start on a page");
        assert!(r.end.is_aligned(PAGE_SIZE), "{r:?} does not end on a page");
        assert!(!r.is_empty(), "empty region left in the free list");
    }
}

#[test_case]
fn free_regions_are_disjoint_and_ordered() {
    let m = map();
    let s = m.free.as_slice();
    for w in s.windows(2) {
        assert!(w[0].end <= w[1].start, "free regions {:?} and {:?} are out of order", w[0], w[1]);
    }
}

#[test_case]
fn accounting_adds_up() {
    // Free + reserved must equal RAM, modulo sub-page fragments lost to alignment.
    let m = map();
    let free = m.free.total_bytes();
    let ram = m.ram.total_bytes();
    assert!(free < ram, "free cannot exceed RAM");
    // We should not be losing more than one page per free region to alignment.
    let lost = ram - free - m.reserved.total_bytes();
    assert!(lost <= PAGE_SIZE * m.free.len(), "lost {lost} bytes to rounding");
}

#[test_case]
fn allocator_returns_distinct_frames() {
    let a = mm::alloc_frame().expect("out of frames");
    let b = mm::alloc_frame().expect("out of frames");
    let c = mm::alloc_frame().expect("out of frames");
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert!(a < b && b < c, "bump allocator handed out addresses out of order");
}

#[test_case]
fn allocated_frames_are_page_aligned() {
    let f = mm::alloc_frame().expect("out of frames");
    assert!(f.is_aligned(PAGE_SIZE), "{f} is not page aligned");
}

#[test_case]
fn allocated_frames_are_inside_free_memory() {
    let m = map();
    let f = mm::alloc_frame().expect("out of frames");
    assert!(
        m.free.iter().any(|r| r.contains(f)),
        "allocator handed out {f}, which is not in any free region"
    );
}

#[test_case]
fn allocated_frames_are_zeroed() {
    // Page tables depend on this.
    let f = mm::alloc_frame().expect("out of frames");
    let ptr = mm::phys_to_virt(f).as_ptr::<u8>();
    for i in 0..PAGE_SIZE {
        // SAFETY: the frame was just allocated to us and is PAGE_SIZE long.
        let byte = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        assert_eq!(byte, 0, "byte {i} of a fresh frame is not zero");
    }
}

#[test_case]
fn dirty_frames_are_zeroed_on_the_next_allocation() {
    // Proves zeroing happens per allocation, not once at init.
    let f = mm::alloc_frame().expect("out of frames");
    let ptr = mm::phys_to_virt(f).as_mut_ptr::<u8>();
    // SAFETY: we own this frame.
    unsafe { core::ptr::write_bytes(ptr, 0xAA, PAGE_SIZE) };

    let g = mm::alloc_frame().expect("out of frames");
    let gptr = mm::phys_to_virt(g).as_ptr::<u8>();
    // SAFETY: we own this frame too.
    assert_eq!(unsafe { core::ptr::read_volatile(gptr) }, 0);
}

#[test_case]
fn allocation_shrinks_what_is_left_for_userspace() {
    // The remainder is what M4 hands out as untyped capabilities.
    let before = mm::FRAMES.lock().bytes_remaining();
    let _ = mm::alloc_frame().expect("out of frames");
    let after = mm::FRAMES.lock().bytes_remaining();
    assert_eq!(before - after, PAGE_SIZE);
}
