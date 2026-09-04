//! Device untyped memory: what the device tree says is there, what such a
//! region may become, and what must not happen to its bytes (D-040).

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::rights::{ALL, READ, WRITE};
use kernel::cap::{Cap, ObjectType, RawCap, kind};
use kernel::mm::{self, PAGE_SIZE, PhysAddr};
use kernel::{kernel_entry, layout, qemu};

kernel_entry!(test_main_entry);

static mut MAP: Option<mm::MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("discovery");
    // SAFETY: single hart, before any test runs.
    unsafe { (&raw mut MAP).write(Some(map)) };

    let kspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    // SAFETY: `kspace` maps this code, this stack and `gp` where they are.
    unsafe { mm::kernel_space::activate(&kspace) };

    test_main();
    qemu::exit_success()
}

fn map() -> mm::MemoryMap {
    // SAFETY: written once during boot, read-only thereafter.
    unsafe { (&raw const MAP).read() }.expect("no memory map")
}

/// One frame, filled with `byte`, as an untyped region of the given kind.
fn poisoned_region(byte: u8) -> PhysAddr {
    let pa = mm::alloc_frame().expect("no frames");
    let p = mm::phys_to_virt(pa).as_mut_ptr::<u8>();
    // SAFETY: a frame straight from the allocator, so we own it exclusively.
    unsafe { core::ptr::write_bytes(p, byte, PAGE_SIZE) };
    pa
}

fn first_byte(pa: PhysAddr) -> u8 {
    // SAFETY: a frame we own, read through the direct map.
    unsafe { mm::phys_to_virt(pa).as_ptr::<u8>().read_volatile() }
}

// --- What the device tree said ---

#[test_case]
fn the_device_tree_describes_devices_as_well_as_memory() {
    assert!(!map().devices.is_empty(), "no device regions were discovered");
}

#[test_case]
fn every_device_region_is_whole_pages() {
    for d in map().devices.iter() {
        assert_eq!(d.start.as_usize() % PAGE_SIZE, 0, "{d:?} does not start on a page");
        assert_eq!(d.len() % PAGE_SIZE, 0, "{d:?} is not a whole number of pages");
    }
}

#[test_case]
fn no_device_region_overlaps_ram() {
    let m = map();
    for d in m.devices.iter() {
        for r in m.ram.iter() {
            assert!(!d.overlaps(r), "{d:?} overlaps RAM at {r:?}");
        }
    }
}

#[test_case]
fn the_kernels_own_devices_are_not_handed_out() {
    // The console and the shutdown register.
    let m = map();
    for (name, pa) in mm::kernel_space::DEVICES {
        assert!(
            !m.devices.iter().any(|d| d.contains(PhysAddr::new(pa))),
            "{name} at {pa:#x} was handed out as a device untyped"
        );
    }
}

#[test_case]
fn the_virtio_transports_are_each_their_own_region() {
    // QEMU virt puts eight virtio-mmio transports at 0x1000_1000 upward, one
    // page each.
    let m = map();
    for i in 0..8 {
        let base = 0x1000_1000 + i * PAGE_SIZE;
        let found = m
            .devices
            .iter()
            .find(|d| d.start.as_usize() == base)
            .unwrap_or_else(|| panic!("no device region starts at {base:#x}"));
        assert_eq!(found.len(), PAGE_SIZE, "the transport at {base:#x} was merged with a neighbour");
    }
}

#[test_case]
fn the_uart_is_grown_to_a_page_but_still_excluded() {
    // Its `reg` is 0x100 long, which page-aligns outward onto the UART page --
    // and that page is the kernel's, so the region must be gone entirely rather
    // than trimmed to nothing and silently kept.
    assert!(
        !map().devices.iter().any(|d| d.contains(PhysAddr::new(kernel::uart::UART0_PHYS))),
        "the console page survived into the device list"
    );
}

// --- What a device untyped may become ---

fn device(pa: PhysAddr) -> Cap<kind::DeviceUntyped, { WRITE }> {
    Cap::from_raw(RawCap::device_untyped(pa, 12, ALL)).expect("device untyped")
}

fn ram(pa: PhysAddr) -> Cap<kind::Untyped, { WRITE }> {
    Cap::from_raw(RawCap::untyped(pa, 12, ALL)).expect("untyped")
}

#[test_case]
fn a_device_untyped_becomes_a_frame() {
    let mut out = [RawCap::NULL; 1];
    device(poisoned_region(0)).retype(ObjectType::Frame, 0, &mut out).expect("frame");
    assert_eq!(out[0].kind, ObjectType::Frame);
}

#[test_case]
fn a_device_untyped_becomes_a_smaller_device_untyped() {
    // Subdividing is how one holder hands a single transport to a driver.
    let mut out = [RawCap::NULL; 1];
    device(poisoned_region(0))
        .retype(ObjectType::DeviceUntyped, 12, &mut out)
        .expect("split");
    assert_eq!(out[0].kind, ObjectType::DeviceUntyped);
}

#[test_case]
fn a_device_untyped_becomes_nothing_the_kernel_writes() {
    // A CNode, a TCB, an endpoint and a page table are all memory the *kernel*
    // reads and writes.
    let pa = poisoned_region(0);
    for kind in [
        ObjectType::CNode,
        ObjectType::Tcb,
        ObjectType::Endpoint,
        ObjectType::PageTable,
        ObjectType::Untyped,
    ] {
        let mut out = [RawCap::NULL; 1];
        assert!(
            device(pa).retype(kind, 12, &mut out).is_err(),
            "a device untyped became a {}",
            kind.name()
        );
    }
}

#[test_case]
fn ordinary_memory_cannot_relabel_itself_as_a_device() {
    // The lie the whole distinction exists to prevent: claim RAM is a device,
    // and you have a region that is never zeroed between owners.
    let mut out = [RawCap::NULL; 1];
    assert!(ram(poisoned_region(0)).retype(ObjectType::DeviceUntyped, 12, &mut out).is_err());
}

// --- What must not happen to the bytes ---

#[test_case]
fn retyping_a_device_untyped_does_not_touch_its_bytes() {
    // The whole reason for the distinction: zeroing MMIO is a burst of stores
    // to live hardware, which on a real device is a reset or worse.
    let pa = poisoned_region(0xa5);
    let mut out = [RawCap::NULL; 1];
    device(pa).retype(ObjectType::Frame, 0, &mut out).expect("frame");
    assert_eq!(first_byte(pa), 0xa5, "the kernel wrote to device registers");
}

#[test_case]
fn retyping_ordinary_memory_still_zeroes_it() {
    // The other half of the same test: RAM must keep being scrubbed, or
    // retyping hands the next owner the last owner's secrets.
    let pa = poisoned_region(0xa5);
    let mut out = [RawCap::NULL; 1];
    ram(pa).retype(ObjectType::Frame, 0, &mut out).expect("frame");
    assert_eq!(first_byte(pa), 0, "a retyped RAM frame was not zeroed");
}

// --- GetAddress ---

#[test_case]
fn get_address_needs_write_on_the_frame() {
    // The right check itself, at the seam where a runtime mask becomes a type.
    let pa = poisoned_region(0);
    let writable = RawCap::new(ObjectType::Frame, ALL, 12, pa);
    let mut read_only = writable;
    read_only.rights = READ;

    assert!(Cap::<kind::Frame, { WRITE }>::from_raw(writable).is_ok());
    assert!(
        Cap::<kind::Frame, { WRITE }>::from_raw(read_only).is_err(),
        "a read-only frame would have given up its physical address"
    );
}

// --- The wire encoding ---

#[test_case]
fn every_object_type_survives_the_wire() {
    // `retype` carries the kind as a number.
    for (n, expected) in [
        (0u8, ObjectType::Null),
        (1, ObjectType::Untyped),
        (2, ObjectType::DeviceUntyped),
        (3, ObjectType::CNode),
        (4, ObjectType::Frame),
        (5, ObjectType::PageTable),
        (6, ObjectType::Tcb),
        (7, ObjectType::Endpoint),
        (8, ObjectType::Notification),
        (9, ObjectType::Reply),
        (10, ObjectType::IrqControl),
        (11, ObjectType::IrqHandler),
    ] {
        assert_eq!(ObjectType::from_u8(n), Some(expected));
        assert_eq!(expected as u8, n, "{} does not encode as {n}", expected.name());
    }
    assert_eq!(ObjectType::from_u8(12), None);
}
