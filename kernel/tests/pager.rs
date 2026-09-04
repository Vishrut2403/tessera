//! Page faults delivered as IPC to a userspace pager (D-034, D-035).

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::cspace::{CSpace, bootstrap};
use kernel::cap::object::SLOT_BITS;
use kernel::cap::rights::{ALL, GRANT, READ, WRITE};
use kernel::cap::vspace::vspace_cap;
use kernel::cap::{ObjectType, RawCap};
use kernel::csr::{interrupt_bits, sie, sstatus, sstatus_bits};
use kernel::ipc::MessageInfo;
use kernel::mm::{self, AddressSpace, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr, phys_to_virt};
use kernel::uprog::{A0, Prog};
use kernel::{kernel_entry, layout, qemu, sched, time, uprog};

kernel_entry!(test_main_entry);

static mut MAP: Option<mm::MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("discovery");
    // SAFETY: single hart, before any test runs.
    unsafe { (&raw mut MAP).write(Some(map)) };
    time::init(PhysAddr::new(dtb_pa));

    let kspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    // SAFETY: `kspace` maps this code, this stack and `gp` where they are.
    unsafe { mm::kernel_space::activate(&kspace) };

    test_main();
    qemu::exit_success()
}

// --- Layout of a client's world ---

const TEXT: usize = 0x1000_0000;
const STACK: usize = 0x2000_0000;
/// The page the client touches, which nothing maps up front.
const LAZY: usize = 0x4000_0000;

/// Slots, the same in every CSpace this test builds.
const FAULT_EP: u64 = 8;
const VSPACE: u64 = 9;
const L1_TABLE: u64 = 10;
const L0_TABLE: u64 = 11;
const FRAME: u64 = 12;
/// Copy-on-write: the pager's own address space, a second capability to the
/// shared frame so it can map it for itself, and the replacement frame.
const SELF_VSPACE: u64 = 13;
const ORIG_COPY: u64 = 14;
const NEW_FRAME: u64 = 15;

/// Scratch addresses in the pager's own space, inside the 2 MiB region its text
/// already occupies, so the intermediate tables are there and a leaf is enough.
const SCRATCH_SRC: usize = 0x1000_2000;
const SCRATCH_DST: usize = 0x1000_3000;

const D: u8 = 6;

fn kernel_mapper() -> mm::Mapper {
    // SAFETY: written once during boot, read-only thereafter.
    let map = unsafe { (&raw const MAP).read() }.expect("no memory map");
    let mut alloc = mm::FRAMES.lock();
    mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
}

fn aligned_region(bits: u8) -> RawCap {
    let size = 1usize << bits;
    let mut first = mm::alloc_frame().expect("no frames");
    while first.as_usize() & (size - 1) != 0 {
        first = mm::alloc_frame().expect("no frames");
    }
    for _ in 1..(size / PAGE_SIZE) {
        mm::alloc_frame().expect("no frames");
    }
    RawCap::untyped(first, bits, ALL)
}

fn new_cspace() -> CSpace {
    bootstrap(aligned_region(19), D + SLOT_BITS).expect("bootstrap")
}

fn endpoint() -> RawCap {
    let mut cs = new_cspace();
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (16, D), &mut made).expect("retype endpoint");
    core::mem::forget(cs);
    made[0]
}

/// A client address space with text and stack mapped, and `LAZY` deliberately
/// not mapped at all.
fn client_space(words: &[u32]) -> AddressSpace {
    let kernel = kernel_mapper();
    let text = mm::alloc_frame().expect("no frames");
    let stack = mm::alloc_frame().expect("no frames");
    // SAFETY: both came from the allocator, so we own them.
    unsafe { uprog::write_to_frame(text, words) };

    let mut alloc = mm::FRAMES.lock();
    let mut space = AddressSpace::new(&kernel, &mut *alloc).expect("address space");
    space.map(VirtAddr::new(TEXT), text, 0, PteFlags::USER_RX, &mut *alloc).expect("text");
    space.map(VirtAddr::new(STACK), stack, 0, PteFlags::USER_RW, &mut *alloc).expect("stack");
    space
}

/// The pager's CSpace: a capability to the client's address space, the two page
/// tables the mapping will need, and a frame to hand over.
fn pager_cspace(client: &AddressSpace, ep: RawCap) -> CSpace {
    let mut cs = new_cspace();
    cs.insert(FAULT_EP, D, ep, None).expect("fault endpoint");
    cs.insert(VSPACE, D, vspace_cap(client.root()), None).expect("vspace");

    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::PageTable, 0, (L1_TABLE, D), &mut made).expect("l1");
    cs.retype((0, D), ObjectType::PageTable, 0, (L0_TABLE, D), &mut made).expect("l0");
    cs.retype((0, D), ObjectType::Frame, 0, (FRAME, D), &mut made).expect("frame");
    cs
}

// --- User programs ---

/// The pager: receive one fault, install the two page tables and a frame at the
/// faulting address, then reply so the client retries.
fn pager_program() -> Prog<64> {
    let recv = Prog::<64>::new().li(A0, FAULT_EP as u32).syscall(sched::syscall::RECV);
    // a2 now holds the faulting address.
    let aligned = recv
        .raw(uprog::srli(A0 + 3, A0 + 2, 12))
        .raw(uprog::slli(A0 + 3, A0 + 3, 12))
        // Keep the page-aligned fault address in s1, which nothing else touches.
        .raw(uprog::mv(9, A0 + 3));

    let l1 = aligned
        .li(A0, L1_TABLE as u32)
        .li(A0 + 1, MessageInfo::new(sched::label::MAP, 4, false).bits() as u32)
        .li(A0 + 2, VSPACE as u32)
        .raw(uprog::mv(A0 + 3, 9))
        .li(A0 + 4, 0)
        .li(A0 + 5, 2)
        .syscall(sched::syscall::CALL);

    let l0 = l1
        .li(A0, L0_TABLE as u32)
        .li(A0 + 1, MessageInfo::new(sched::label::MAP, 4, false).bits() as u32)
        .li(A0 + 2, VSPACE as u32)
        .raw(uprog::mv(A0 + 3, 9))
        .li(A0 + 4, 0)
        .li(A0 + 5, 1)
        .syscall(sched::syscall::CALL);

    let frame = l0
        .li(A0, FRAME as u32)
        .li(A0 + 1, MessageInfo::new(sched::label::MAP, 4, false).bits() as u32)
        .li(A0 + 2, VSPACE as u32)
        .raw(uprog::mv(A0 + 3, 9))
        .li(A0 + 4, (READ | WRITE) as u32)
        .li(A0 + 5, 0)
        .syscall(sched::syscall::CALL);

    frame
        .li(A0 + 1, MessageInfo::new(0, 0, false).bits() as u32)
        .syscall(sched::syscall::REPLY)
        .exit()
}

/// A client that stores to `LAZY` and then exits.
fn client_program() -> Prog<32> {
    Prog::<32>::new()
        .li(9, (LAZY >> 12) as u32)
        .raw(uprog::slli(9, 9, 12))
        .li(10, 0x5a5a)
        // sd a0, 0(s1)
        .raw(uprog::sd(9, A0, 0))
        .exit()
}

/// A copy-on-write pager, entirely in userspace.
fn cow_pager() -> Prog<128> {
    const SRC_PTR: usize = 18; // s2
    const DST_PTR: usize = 19; // s3
    const COUNT: usize = 20; // s4
    const TMP: usize = 6; // t1
    const FAULT_VA: usize = 9; // s1
    let map4 = MessageInfo::new(sched::label::MAP, 4, false).bits() as u32;
    let unmap0 = MessageInfo::new(sched::label::UNMAP, 0, false).bits() as u32;

    let p = Prog::<128>::new()
        .li(A0, FAULT_EP as u32)
        .syscall(sched::syscall::RECV)
        // a2 is the faulting address; keep it page-aligned in s1.
        .raw(uprog::srli(FAULT_VA, A0 + 2, 12))
        .raw(uprog::slli(FAULT_VA, FAULT_VA, 12))
        // The shared frame, read-only, into our own space.
        .li(A0, ORIG_COPY as u32)
        .li(A0 + 1, map4)
        .li(A0 + 2, SELF_VSPACE as u32)
        .li(A0 + 3, SCRATCH_SRC as u32)
        .li(A0 + 4, READ as u32)
        .li(A0 + 5, 0)
        .syscall(sched::syscall::CALL)
        // The replacement, writable, into our own space.
        .li(A0, NEW_FRAME as u32)
        .li(A0 + 1, map4)
        .li(A0 + 2, SELF_VSPACE as u32)
        .li(A0 + 3, SCRATCH_DST as u32)
        .li(A0 + 4, (READ | WRITE) as u32)
        .li(A0 + 5, 0)
        .syscall(sched::syscall::CALL)
        // Copy a page, eight bytes at a time.
        .li(SRC_PTR, SCRATCH_SRC as u32)
        .li(DST_PTR, SCRATCH_DST as u32)
        .li(COUNT, (PAGE_SIZE / 8) as u32);
    let top = p.here();
    let p = p
        .raw(uprog::ld(TMP, SRC_PTR, 0))
        .raw(uprog::sd(DST_PTR, TMP, 0))
        .addi(SRC_PTR, 8)
        .addi(DST_PTR, 8)
        .addi(COUNT, -1)
        .bne_back(COUNT, top);

    p
        // Take the shared frame away from the client.
        .li(A0, FRAME as u32)
        .li(A0 + 1, unmap0)
        .syscall(sched::syscall::CALL)
        // Release our own two scratch mappings, so the copy can be mapped
        // elsewhere. A capability records one mapping at a time (D-034).
        .li(A0, ORIG_COPY as u32)
        .li(A0 + 1, unmap0)
        .syscall(sched::syscall::CALL)
        .li(A0, NEW_FRAME as u32)
        .li(A0 + 1, unmap0)
        .syscall(sched::syscall::CALL)
        // And give the client the copy, writable, where the original was.
        .li(A0, NEW_FRAME as u32)
        .li(A0 + 1, map4)
        .li(A0 + 2, VSPACE as u32)
        .raw(uprog::mv(A0 + 3, FAULT_VA))
        .li(A0 + 4, (READ | WRITE) as u32)
        .li(A0 + 5, 0)
        .syscall(sched::syscall::CALL)
        .li(A0 + 1, MessageInfo::new(0, 0, false).bits() as u32)
        .syscall(sched::syscall::REPLY)
        .exit()
}

fn run() {
    time::enable();
    time::arm_next_tick();
    // SAFETY: the dispatcher handles timer interrupts and no lock is held.
    unsafe { sstatus::set(sstatus_bits::SIE) };
    sched::run();
    // SAFETY: restoring the masked state the rest of the suite expects.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    unsafe { sie::clear(interrupt_bits::STIE) };
    time::disarm();
}

// --- Mapping invocations ---

#[test_case]
fn mapping_a_frame_records_where_it_went() {
    let space = client_space(client_program().as_slice());
    let cs = pager_cspace(&space, endpoint());

    let vs = cs.read(VSPACE, D).unwrap();
    assert_eq!(vs.kind, ObjectType::PageTable);
    assert_eq!(vs.paddr, space.root());

    // Two intermediate tables, then the frame.
    let va = VirtAddr::new(LAZY);
    let l1 = cs.resolve(L1_TABLE, D).unwrap();
    // SAFETY: a live slot in a CSpace only this hart is touching.
    let l1cap = unsafe { &mut l1.clone().as_mut().cap };
    kernel::cap::vspace::map_table(l1cap, &vs, va, 2).expect("map l1");

    let l0 = cs.resolve(L0_TABLE, D).unwrap();
    // SAFETY: as above.
    let l0cap = unsafe { &mut l0.clone().as_mut().cap };
    kernel::cap::vspace::map_table(l0cap, &vs, va, 1).expect("map l0");

    let f = cs.resolve(FRAME, D).unwrap();
    // SAFETY: as above.
    let fcap = unsafe { &mut f.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(fcap, &vs, va, READ | WRITE, false).expect("map frame");

    assert_eq!(fcap.mapping(), Some((space.root(), LAZY)), "the mapping was not recorded");
    let (pa, flags, level) = space.translate(va).expect("not mapped after Map");
    assert_eq!(pa, fcap.paddr);
    assert_eq!(level, 0);
    assert!(flags.contains(PteFlags::U) && flags.contains(PteFlags::W));
    assert!(!flags.contains(PteFlags::X), "a data page was mapped executable");
}

#[test_case]
fn mapping_without_the_intermediate_tables_asks_for_them() {
    let space = client_space(client_program().as_slice());
    let cs = pager_cspace(&space, endpoint());
    let vs = cs.read(VSPACE, D).unwrap();

    let f = cs.resolve(FRAME, D).unwrap();
    // SAFETY: a live slot only this hart is touching.
    let fcap = unsafe { &mut f.clone().as_mut().cap };

    // No L1 or L0 installed yet, so the kernel refuses rather than allocating
    // one behind userspace's back (D-035, invariant 1).
    let err = kernel::cap::vspace::map_frame(fcap, &vs, VirtAddr::new(LAZY), READ, false);
    assert_eq!(
        err,
        Err(kernel::cap::CapError::Map(kernel::mm::MapError::MissingTable)),
        "the kernel allocated a page table itself"
    );
    assert_eq!(fcap.mapping(), None, "a failed map recorded a mapping anyway");
}

#[test_case]
fn a_mapping_cannot_grant_rights_the_capability_lacks() {
    let space = client_space(client_program().as_slice());
    let mut cs = pager_cspace(&space, endpoint());
    let vs = cs.read(VSPACE, D).unwrap();
    let va = VirtAddr::new(LAZY);

    for (slot, level) in [(L1_TABLE, 2), (L0_TABLE, 1)] {
        let t = cs.resolve(slot, D).unwrap();
        // SAFETY: a live slot only this hart is touching.
        let cap = unsafe { &mut t.clone().as_mut().cap };
        kernel::cap::vspace::map_table(cap, &vs, va, level).expect("map table");
    }

    // Weaken the frame capability to read-only, then ask for a writable page.
    cs.mint((FRAME, D), (20, D), READ | GRANT, 0).expect("mint");
    let weak = cs.resolve(20, D).unwrap();
    // SAFETY: as above.
    let wcap = unsafe { &mut weak.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(wcap, &vs, va, READ | WRITE, false).expect("map");

    let (_, flags, _) = space.translate(va).expect("not mapped");
    assert!(!flags.contains(PteFlags::W), "a read-only capability produced a writable page");
    assert!(flags.contains(PteFlags::R));
}

// --- Revocation tears down mappings (D-034) ---

#[test_case]
fn revoking_a_frame_removes_its_mapping() {
    let space = client_space(client_program().as_slice());
    let mut cs = pager_cspace(&space, endpoint());
    let vs = cs.read(VSPACE, D).unwrap();
    let va = VirtAddr::new(LAZY);

    for (slot, level) in [(L1_TABLE, 2), (L0_TABLE, 1)] {
        let t = cs.resolve(slot, D).unwrap();
        // SAFETY: a live slot only this hart is touching.
        let cap = unsafe { &mut t.clone().as_mut().cap };
        kernel::cap::vspace::map_table(cap, &vs, va, level).expect("map table");
    }

    // Hand a copy to slot 20 and map *that*, so revoking the original has a
    // derivative to tear down, the case that matters.
    cs.mint((FRAME, D), (20, D), ALL, 0).expect("mint");
    let copy = cs.resolve(20, D).unwrap();
    // SAFETY: a live slot only this hart is touching.
    let ccap = unsafe { &mut copy.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(ccap, &vs, va, READ | WRITE, false).expect("map");

    assert!(space.translate(va).is_some(), "not mapped before revoke");

    cs.revoke(FRAME, D).expect("revoke");

    assert!(
        space.translate(va).is_none(),
        "the page is still mapped after its capability was revoked"
    );
    assert!(cs.read(20, D).unwrap().is_null());
}

#[test_case]
fn unmapping_clears_the_record_as_well_as_the_entry() {
    let space = client_space(client_program().as_slice());
    let cs = pager_cspace(&space, endpoint());
    let vs = cs.read(VSPACE, D).unwrap();
    let va = VirtAddr::new(LAZY);

    for (slot, level) in [(L1_TABLE, 2), (L0_TABLE, 1)] {
        let t = cs.resolve(slot, D).unwrap();
        // SAFETY: a live slot only this hart is touching.
        let cap = unsafe { &mut t.clone().as_mut().cap };
        kernel::cap::vspace::map_table(cap, &vs, va, level).expect("map table");
    }
    let f = cs.resolve(FRAME, D).unwrap();
    // SAFETY: as above.
    let fcap = unsafe { &mut f.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(fcap, &vs, va, READ | WRITE, false).expect("map");

    kernel::cap::vspace::unmap(fcap).expect("unmap");
    assert_eq!(fcap.mapping(), None);
    assert!(space.translate(va).is_none());

    // And it can be mapped again somewhere else.
    kernel::cap::vspace::map_frame(fcap, &vs, va, READ, false).expect("remap");
    assert!(space.translate(va).is_some());
}

// --- Faults as IPC ---

#[test_case]
fn a_thread_with_no_pager_is_killed_as_before() {
    let space = client_space(client_program().as_slice());
    let cs = new_cspace();
    sched::spawn_with_cspace(
        &space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *cs.root(),
    )
    .expect("spawn");

    let killed = sched::killed();
    run();
    assert_eq!(sched::killed(), killed + 1, "a pagerless fault should still be fatal");
    sched::kill_all();
}

#[test_case]
fn a_fault_reaches_the_pager_and_the_client_carries_on() {
    let ep = endpoint();
    let space = client_space(client_program().as_slice());

    let pager_cs = pager_cspace(&space, ep);
    let pager_space = client_space(pager_program().as_slice());
    let client_cs = new_cspace();

    // The pager is queued first, so it is blocked on recv before the client
    // faults; otherwise the fault would queue and both would be waiting.
    sched::spawn_with_cspace(
        &pager_space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *pager_cs.root(),
    )
    .expect("spawn pager");
    sched::spawn_full(
        &space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *client_cs.root(),
        ep,
    )
    .expect("spawn client");

    let (exited, killed) = (sched::exited(), sched::killed());
    run();

    assert_eq!(sched::killed(), killed, "the client was killed instead of paged");
    assert_eq!(sched::exited(), exited + 2, "both threads should finish");

    // The store the client retried after the reply must be visible in the frame
    // the pager mapped.
    let (pa, _, _) = space.translate(VirtAddr::new(LAZY)).expect("the page was never mapped");
    // SAFETY: a frame the pager retyped and mapped; readable through the direct map.
    let value = unsafe { core::ptr::read_volatile(phys_to_virt(pa).as_ptr::<u64>()) };
    assert_eq!(value, 0x5a5a, "the client's store did not land in the mapped page");

    sched::kill_all();
}

// --- Copy-on-write, entirely in userspace ---

#[test_case]
fn the_map_and_unmap_calls_a_pager_makes_compose_into_copy_on_write() {
    let ep = endpoint();

    // The page both sides start out sharing, with a recognisable pattern.
    let shared = mm::alloc_frame().expect("no frames");
    // SAFETY: a frame straight from the allocator, reachable through the direct map.
    unsafe { core::ptr::write_bytes(phys_to_virt(shared).as_mut_ptr::<u8>(), 0xaa, PAGE_SIZE) };

    // The client: read-only at LAZY, and a program that writes there.
    let client = client_space(client_program().as_slice());
    {
        let mut alloc = mm::FRAMES.lock();
        let mut c = client;
        c.map(VirtAddr::new(LAZY), shared, 0, PteFlags::USER_RX.union(PteFlags::R), &mut *alloc)
            .expect("map shared read-only");
        core::mem::forget(c);
    }
    // Rebuild a handle to the same space to inspect it afterwards.
    let client = client_space(client_program().as_slice());
    let _ = &client;

    // This drives the same invocations the pager program makes, but from the
    // kernel side, so a failure points at the primitives rather than at the
    // hand-encoded program.
    let mut cs = pager_cspace(&client, ep);
    let vs = cs.read(VSPACE, D).unwrap();
    let va = VirtAddr::new(LAZY);

    for (slot, level) in [(L1_TABLE, 2), (L0_TABLE, 1)] {
        let t = cs.resolve(slot, D).unwrap();
        // SAFETY: a live slot only this hart is touching.
        let cap = unsafe { &mut t.clone().as_mut().cap };
        kernel::cap::vspace::map_table(cap, &vs, va, level).expect("map table");
    }

    // A capability to the shared frame, mapped read-only into the client.
    let orig = RawCap {
        kind: ObjectType::Frame,
        rights: ALL,
        size_bits: 12,
        paddr: shared,
        ..RawCap::NULL
    };
    cs.insert(20, D, orig, None).expect("insert shared");
    let os = cs.resolve(20, D).unwrap();
    // SAFETY: a live slot only this hart is touching.
    let ocap = unsafe { &mut os.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(ocap, &vs, va, READ, false).expect("map shared ro");

    let (_, flags, _) = client.translate(va).expect("shared page not mapped");
    assert!(!flags.contains(PteFlags::W), "the shared page is writable, so nothing would fault");

    // --- the copy-on-write step ---
    let new = cs.read(FRAME, D).unwrap().paddr;
    // SAFETY: both are frames we own, reachable through the direct map.
    unsafe {
        core::ptr::copy_nonoverlapping(
            phys_to_virt(shared).as_ptr::<u8>(),
            phys_to_virt(new).as_mut_ptr::<u8>(),
            PAGE_SIZE,
        );
    }
    kernel::cap::vspace::unmap(ocap).expect("unmap shared");
    let f = cs.resolve(FRAME, D).unwrap();
    // SAFETY: as above.
    let fcap = unsafe { &mut f.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(fcap, &vs, va, READ | WRITE, false).expect("map copy");

    // The client now sees a writable private page.
    let (pa, flags, _) = client.translate(va).expect("copy not mapped");
    assert_eq!(pa, new);
    assert!(flags.contains(PteFlags::W), "the copy is not writable");

    // Writing through it must not disturb the page it was copied from.
    // SAFETY: a frame we own, reachable through the direct map.
    unsafe { core::ptr::write_volatile(phys_to_virt(new).as_mut_ptr::<u64>(), 0x1234) };
    // SAFETY: as above.
    let original = unsafe { core::ptr::read_volatile(phys_to_virt(shared).as_ptr::<u64>()) };
    assert_eq!(original, 0xaaaa_aaaa_aaaa_aaaa, "the write reached the shared page");
}

#[test_case]
fn the_cow_pager_program_assembles_and_fits_a_page() {
    // The pager is hand-encoded, so the thing that can silently go wrong is it
    // outgrowing the single page it is loaded into.
    let p = cow_pager();
    assert!(!p.as_slice().is_empty());
    assert!(
        p.as_slice().len() * 4 <= PAGE_SIZE,
        "the pager is {} bytes, more than the page it is mapped into",
        p.as_slice().len() * 4
    );
}

/// Wire up a client and a copy-on-write pager, and run them.
fn run_cow_end_to_end() -> (PhysAddr, PhysAddr) {
    let ep = endpoint();
    let client = client_space(client_program().as_slice());
    let pager = client_space(cow_pager().as_slice());

    let shared = mm::alloc_frame().expect("no frames");
    // SAFETY: a frame straight from the allocator, reachable through the direct map.
    unsafe { core::ptr::write_bytes(phys_to_virt(shared).as_mut_ptr::<u8>(), 0xaa, PAGE_SIZE) };

    let mut cs = new_cspace();
    cs.insert(FAULT_EP, D, ep, None).expect("fault ep");
    cs.insert(VSPACE, D, vspace_cap(client.root()), None).expect("client vspace");
    cs.insert(SELF_VSPACE, D, vspace_cap(pager.root()), None).expect("own vspace");

    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::PageTable, 0, (L1_TABLE, D), &mut made).expect("l1");
    cs.retype((0, D), ObjectType::PageTable, 0, (L0_TABLE, D), &mut made).expect("l0");
    cs.retype((0, D), ObjectType::Frame, 0, (NEW_FRAME, D), &mut made).expect("new frame");

    // The shared page, and a second capability to it the pager can map for
    // itself.
    cs.insert(
        FRAME,
        D,
        RawCap {
            kind: ObjectType::Frame,
            rights: ALL,
            size_bits: 12,
            paddr: shared,
            ..RawCap::NULL
        },
        None,
    )
    .expect("shared frame");
    cs.mint((FRAME, D), (ORIG_COPY, D), ALL, 0).expect("second handle");

    // Give the client the intermediate tables and the shared page, read-only,
    // so its store faults.
    let vs = cs.read(VSPACE, D).unwrap();
    let va = VirtAddr::new(LAZY);
    for (slot, level) in [(L1_TABLE, 2), (L0_TABLE, 1)] {
        let t = cs.resolve(slot, D).unwrap();
        // SAFETY: a live slot only this hart is touching.
        let cap = unsafe { &mut t.clone().as_mut().cap };
        kernel::cap::vspace::map_table(cap, &vs, va, level).expect("map table");
    }
    let f = cs.resolve(FRAME, D).unwrap();
    // SAFETY: as above.
    let fcap = unsafe { &mut f.clone().as_mut().cap };
    kernel::cap::vspace::map_frame(fcap, &vs, va, READ, false).expect("map shared ro");

    let client_cs = new_cspace();
    // The pager goes first, so it is blocked on receive before the client runs.
    sched::spawn_with_cspace(
        &pager,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *cs.root(),
    )
    .expect("spawn pager");
    sched::spawn_full(
        &client,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *client_cs.root(),
        ep,
    )
    .expect("spawn client");

    run();

    let (pa, flags, _) = client.translate(va).expect("nothing is mapped at the faulting address");
    assert!(flags.contains(PteFlags::W), "the page the client ended up with is not writable");
    core::mem::forget(cs);
    core::mem::forget(client_cs);
    (pa, shared)
}

#[test_case]
fn a_userspace_pager_performs_copy_on_write_end_to_end() {
    let (exited, killed) = (sched::exited(), sched::killed());
    let (got, shared) = run_cow_end_to_end();

    assert_eq!(sched::killed(), killed, "a thread was killed during the copy");
    assert_eq!(sched::exited(), exited + 2, "both threads should finish");

    assert_ne!(got, shared, "the client kept writing to the shared page");

    // The client's store landed in its private copy...
    // SAFETY: a frame the pager mapped, reachable through the direct map.
    let written = unsafe { core::ptr::read_volatile(phys_to_virt(got).as_ptr::<u64>()) };
    assert_eq!(written, 0x5a5a, "the client's store did not land in the copy");

    // ...the rest of the page was really copied, not just zeroed...
    // SAFETY: as above.
    let tail = unsafe { core::ptr::read_volatile(phys_to_virt(got).as_ptr::<u64>().add(64)) };
    assert_eq!(tail, 0xaaaa_aaaa_aaaa_aaaa, "the page was not copied, only replaced");

    // ...and the page it was copied from is untouched.
    // SAFETY: as above.
    let original = unsafe { core::ptr::read_volatile(phys_to_virt(shared).as_ptr::<u64>()) };
    assert_eq!(original, 0xaaaa_aaaa_aaaa_aaaa, "the write reached the shared page");

    sched::kill_all();
}
