//! Threads as objects: retype, configure, resume (D-037).

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::cspace::{CSpace, bootstrap};
use kernel::cap::object::SLOT_BITS;
use kernel::cap::rights::{ALL, READ, WRITE};
use kernel::cap::vspace::vspace_cap;
use kernel::cap::{CapError, ObjectType, RawCap};
use kernel::csr::{interrupt_bits, sie, sstatus, sstatus_bits};
use kernel::ipc::MessageInfo;
use kernel::mm::{self, AddressSpace, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr};
use kernel::thread::{Tcb, ThreadState};
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

const TEXT: usize = 0x1000_0000;
const STACK: usize = 0x2000_0000;

/// Slots in the parent's CSpace.
const CHILD_TCB: u64 = 8;
const CHILD_CNODE: u64 = 9;
const CHILD_VSPACE: u64 = 10;
const SPARE: u64 = 11;

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

/// Retype one object out of slot 0 into `dst`, and hand back the capability.
fn make(cs: &mut CSpace, kind: ObjectType, size_bits: u8, dst: u64) -> RawCap {
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), kind, size_bits, (dst, D), &mut made).expect("retype");
    made[0]
}

fn user_space(words: &[u32]) -> AddressSpace {
    let kernel = kernel_mapper();
    let text = mm::alloc_frame().expect("no frames");
    let stack = mm::alloc_frame().expect("no frames");
    // SAFETY: both came from the allocator, so we own them.
    unsafe { uprog::write_to_frame(text, words) };

    let mut alloc = mm::FRAMES.lock();
    let mut space = AddressSpace::new(&kernel, &mut *alloc).expect("address space");
    space.map(VirtAddr::new(TEXT), text, 0, PteFlags::USER_RX, &mut *alloc).expect("text");
    space.map(VirtAddr::new(STACK), stack, 0, PteFlags::USER_RW, &mut *alloc).expect("stack");
    // The kernel-built spaces the older tests use are still born on ASID 0.
    space.set_asid(kernel::cap::asid::assign_global().expect("asid"));
    space
}

/// Borrow the thread a TCB capability names.
fn thread_of(cap: &RawCap) -> &'static mut Tcb {
    // SAFETY: a TCB object this test just retyped, which nothing else holds.
    unsafe { kernel::cap::tcb::tcb_at(cap) }
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

// --- Retyping a thread ---

#[test_case]
fn a_retyped_thread_exists_but_cannot_run() {
    let mut cs = new_cspace();
    let tcb = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);

    let t = thread_of(&tcb);
    assert_eq!(t.state, ThreadState::Inactive);
    assert!(!t.is_configured(), "a fresh TCB must have no address space");
    assert!(t.cspace.is_null(), "a fresh TCB must have no capability space");
    assert!(t.fault_ep.is_null(), "a fresh TCB must have no pager");
}

#[test_case]
fn every_retyped_thread_gets_its_own_id() {
    let mut cs = new_cspace();
    let a = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);
    let b = make(&mut cs, ObjectType::Tcb, 0, SPARE);
    assert_ne!(thread_of(&a).id, thread_of(&b).id);
}

// --- Assigning an address space ---

#[test_case]
fn a_retyped_page_table_is_not_an_address_space_until_it_is_assigned() {
    let mut cs = new_cspace();
    let mut table = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);
    assert!(!table.is_assigned());

    kernel::cap::vspace::assign(&mut table).expect("assign");
    assert!(table.is_assigned(), "assign must bind an ASID");
    assert_ne!(table.asid, 0);
}

#[test_case]
fn assigning_installs_the_kernel_half() {
    let mut cs = new_cspace();
    let mut table = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);

    let kernel_root = mm::kernel_space::root().expect("kernel root");
    let first = mm::address_space::KERNEL_ROOT_FIRST;
    // SAFETY: both are live root tables reachable through the direct map.
    let entry_of = |root: PhysAddr, i: usize| unsafe {
        mm::phys_to_virt(root).as_ptr::<mm::page_table::PageTable>().read().entries[i]
    };

    assert_eq!(entry_of(table.paddr, first).bits(), 0, "empty before assign");
    kernel::cap::vspace::assign(&mut table).expect("assign");
    assert_eq!(
        entry_of(table.paddr, first).bits(),
        entry_of(kernel_root, first).bits(),
        "the trap handler must be mapped in every user root table",
    );
}

#[test_case]
fn assigning_twice_is_refused() {
    let mut cs = new_cspace();
    let mut table = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);
    kernel::cap::vspace::assign(&mut table).expect("assign");
    assert_eq!(kernel::cap::vspace::assign(&mut table), Err(CapError::AlreadyAssigned));
}

#[test_case]
fn only_a_page_table_can_be_assigned() {
    let mut cs = new_cspace();
    let mut frame = make(&mut cs, ObjectType::Frame, 0, SPARE);
    assert!(matches!(
        kernel::cap::vspace::assign(&mut frame),
        Err(CapError::WrongType { wanted: ObjectType::PageTable, .. })
    ));
}

#[test_case]
fn assigned_spaces_get_distinct_asids() {
    let mut cs = new_cspace();
    let mut a = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);
    let mut b = make(&mut cs, ObjectType::PageTable, 0, SPARE);
    kernel::cap::vspace::assign(&mut a).expect("assign a");
    kernel::cap::vspace::assign(&mut b).expect("assign b");
    assert_ne!(a.asid, b.asid, "two spaces sharing an ASID is the bug ASIDs prevent");
}

// --- Configuring a thread ---

#[test_case]
fn a_thread_cannot_be_configured_with_an_unassigned_space() {
    let mut cs = new_cspace();
    let tcb = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);
    let cnode = make(&mut cs, ObjectType::CNode, D + SLOT_BITS, CHILD_CNODE);
    let table = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);

    assert_eq!(
        kernel::cap::tcb::configure(thread_of(&tcb), cnode, table, RawCap::NULL),
        Err(CapError::NotAssigned),
    );
}

#[test_case]
fn configuring_gives_the_thread_a_space_a_cspace_and_a_satp() {
    let mut cs = new_cspace();
    let tcb = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);
    let cnode = make(&mut cs, ObjectType::CNode, D + SLOT_BITS, CHILD_CNODE);
    let mut table = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);
    kernel::cap::vspace::assign(&mut table).expect("assign");

    let t = thread_of(&tcb);
    kernel::cap::tcb::configure(t, cnode, table, RawCap::NULL).expect("configure");

    assert!(t.is_configured());
    assert_eq!(t.satp, mm::satp_for(table.paddr, mm::Asid::new(table.asid)));
    assert_eq!(t.cspace.paddr, cnode.paddr);
    assert_eq!(t.state, ThreadState::Inactive, "configuring must not start it");
}

#[test_case]
fn a_configured_thread_cannot_be_reconfigured_while_it_runs() {
    let mut cs = new_cspace();
    let tcb = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);
    let cnode = make(&mut cs, ObjectType::CNode, D + SLOT_BITS, CHILD_CNODE);
    let mut table = make(&mut cs, ObjectType::PageTable, 0, CHILD_VSPACE);
    kernel::cap::vspace::assign(&mut table).expect("assign");

    let t = thread_of(&tcb);
    kernel::cap::tcb::configure(t, cnode, table, RawCap::NULL).expect("configure");
    t.state = ThreadState::Ready;
    assert_eq!(
        kernel::cap::tcb::configure(t, cnode, table, RawCap::NULL),
        Err(CapError::NotInactive),
        "rewriting satp under a runnable thread must be refused",
    );
}

#[test_case]
fn a_thread_cannot_invoke_its_own_tcb_capability() {
    let mut cs = new_cspace();
    let tcb = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);
    let caller = thread_of(&tcb);
    assert_eq!(kernel::cap::tcb::check(tcb, caller), Err(CapError::SelfInvocation));
}

#[test_case]
fn configuring_a_thread_needs_write_on_its_capability() {
    let mut cs = new_cspace();
    let tcb = make(&mut cs, ObjectType::Tcb, 0, CHILD_TCB);
    let other = make(&mut cs, ObjectType::Tcb, 0, SPARE);

    let read_only = RawCap { rights: READ, ..tcb };
    assert!(matches!(
        kernel::cap::tcb::check(read_only, thread_of(&other)),
        Err(CapError::MissingRights { .. })
    ));
    assert!(kernel::cap::tcb::check(RawCap { rights: WRITE, ..tcb }, thread_of(&other)).is_ok());
}

// --- End to end: a thread built by invocation actually runs ---

/// The child: store a recognisable word to its stack, then exit.
fn child_program() -> Prog<16> {
    Prog::<16>::new().li(A0, 0x2b).raw(uprog::sd(2, A0, -8)).exit()
}

/// The parent: configure the child's TCB, give it an entry point and a stack,
/// and resume it.
fn parent_program() -> Prog<64> {
    let configure = MessageInfo::new(sched::label::CONFIGURE, 3, false).bits() as u32;
    let write_regs = MessageInfo::new(sched::label::WRITE_REGISTERS, 2, false).bits() as u32;
    let resume = MessageInfo::new(sched::label::RESUME, 0, false).bits() as u32;

    Prog::<64>::new()
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, configure)
        .li(A0 + 2, CHILD_CNODE as u32)
        .li(A0 + 3, CHILD_VSPACE as u32)
        .li(A0 + 4, SPARE as u32)
        .syscall(sched::syscall::CALL)
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, write_regs)
        .li(A0 + 2, (TEXT >> 12) as u32)
        .raw(uprog::slli(A0 + 2, A0 + 2, 12))
        .li(A0 + 3, ((STACK + PAGE_SIZE) >> 12) as u32)
        .raw(uprog::slli(A0 + 3, A0 + 3, 12))
        .syscall(sched::syscall::CALL)
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, resume)
        .syscall(sched::syscall::CALL)
        .exit()
}

#[test_case]
fn a_thread_created_by_retyping_and_started_by_invocation_runs() {
    let mut parent_cs = new_cspace();

    // The child's world, built out of the parent's untyped memory.
    let child_tcb = make(&mut parent_cs, ObjectType::Tcb, 0, CHILD_TCB);
    make(&mut parent_cs, ObjectType::CNode, D + SLOT_BITS, CHILD_CNODE);

    // The child's address space is still built kernel-side: retyping page
    // tables and mapping a program into them from userspace is M7b's job, once
    // there is a real program to load.
    let child_space = user_space(child_program().as_slice());
    let mut vspace = vspace_cap(child_space.root());
    vspace.asid = child_space.asid().as_u16();
    parent_cs.insert(CHILD_VSPACE, D, vspace, None).expect("vspace slot");

    let parent_space = user_space(parent_program().as_slice());
    sched::spawn_with_cspace(
        &parent_space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *parent_cs.root(),
    )
    .expect("spawn parent");

    let (exited, killed) = (sched::exited(), sched::killed());
    run();

    assert_eq!(sched::killed(), killed, "nothing should have faulted");
    assert_eq!(sched::exited(), exited + 2, "the parent and the child it started");
    assert_eq!(thread_of(&child_tcb).state, ThreadState::Exited);

    let (pa, _, _) = child_space.translate(VirtAddr::new(STACK)).expect("stack unmapped");
    // SAFETY: the child's stack frame, readable through the direct map.
    let value = unsafe {
        core::ptr::read_volatile(mm::phys_to_virt(pa).as_ptr::<u64>().byte_add(PAGE_SIZE - 8))
    };
    assert_eq!(value, 0x2b, "the child never ran");

    sched::kill_all();
}

// --- Refusals, observed from userspace ---

/// Read the word a program stored at `STACK + PAGE_SIZE - offset`.
fn stack_word(space: &AddressSpace, offset: usize) -> u64 {
    let (pa, _, _) = space.translate(VirtAddr::new(STACK)).expect("stack unmapped");
    // SAFETY: a stack frame this test mapped, readable through the direct map.
    unsafe {
        core::ptr::read_volatile(
            mm::phys_to_virt(pa).as_ptr::<u64>().byte_add(PAGE_SIZE - offset),
        )
    }
}

/// Resume a thread that was never configured, and record what came back.
fn resume_unconfigured_program() -> Prog<32> {
    let resume = MessageInfo::new(sched::label::RESUME, 0, false).bits() as u32;
    Prog::<32>::new()
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, resume)
        .syscall(sched::syscall::CALL)
        .raw(uprog::sd(2, A0, -8))
        .exit()
}

#[test_case]
fn a_thread_with_no_address_space_cannot_be_resumed() {
    let mut parent_cs = new_cspace();
    let child_tcb = make(&mut parent_cs, ObjectType::Tcb, 0, CHILD_TCB);

    let parent_space = user_space(resume_unconfigured_program().as_slice());
    sched::spawn_with_cspace(
        &parent_space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *parent_cs.root(),
    )
    .expect("spawn parent");

    let exited = sched::exited();
    run();

    assert_eq!(sched::exited(), exited + 1, "only the parent should have run");
    assert_eq!(
        stack_word(&parent_space, 8) as usize,
        sched::result::ERR_ASID,
        "resuming an unconfigured thread must fail, not start a thread with satp 0",
    );
    assert_eq!(thread_of(&child_tcb).state, ThreadState::Inactive);
    sched::kill_all();
}

/// Configure and resume the child, then immediately suspend it again.
fn suspend_program() -> Prog<64> {
    let configure = MessageInfo::new(sched::label::CONFIGURE, 3, false).bits() as u32;
    let write_regs = MessageInfo::new(sched::label::WRITE_REGISTERS, 2, false).bits() as u32;
    let resume = MessageInfo::new(sched::label::RESUME, 0, false).bits() as u32;
    let suspend = MessageInfo::new(sched::label::SUSPEND, 0, false).bits() as u32;

    Prog::<64>::new()
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, configure)
        .li(A0 + 2, CHILD_CNODE as u32)
        .li(A0 + 3, CHILD_VSPACE as u32)
        .li(A0 + 4, SPARE as u32)
        .syscall(sched::syscall::CALL)
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, write_regs)
        .li(A0 + 2, (TEXT >> 12) as u32)
        .raw(uprog::slli(A0 + 2, A0 + 2, 12))
        .li(A0 + 3, ((STACK + PAGE_SIZE) >> 12) as u32)
        .raw(uprog::slli(A0 + 3, A0 + 3, 12))
        .syscall(sched::syscall::CALL)
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, resume)
        .syscall(sched::syscall::CALL)
        .li(A0, CHILD_TCB as u32)
        .li(A0 + 1, suspend)
        .syscall(sched::syscall::CALL)
        .raw(uprog::sd(2, A0, -8))
        .exit()
}

#[test_case]
fn suspending_a_resumed_thread_takes_it_off_the_run_queue_before_it_runs() {
    let mut parent_cs = new_cspace();
    let child_tcb = make(&mut parent_cs, ObjectType::Tcb, 0, CHILD_TCB);
    make(&mut parent_cs, ObjectType::CNode, D + SLOT_BITS, CHILD_CNODE);

    let child_space = user_space(child_program().as_slice());
    let mut vspace = vspace_cap(child_space.root());
    vspace.asid = child_space.asid().as_u16();
    parent_cs.insert(CHILD_VSPACE, D, vspace, None).expect("vspace slot");

    let parent_space = user_space(suspend_program().as_slice());
    sched::spawn_with_cspace(
        &parent_space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *parent_cs.root(),
    )
    .expect("spawn parent");

    let exited = sched::exited();
    run();

    assert_eq!(stack_word(&parent_space, 8), 0, "suspend should have succeeded");
    assert_eq!(sched::exited(), exited + 1, "the child was suspended before it could run");
    assert_eq!(thread_of(&child_tcb).state, ThreadState::Inactive);
    assert_eq!(stack_word(&child_space, 8), 0, "the child ran anyway");
    sched::kill_all();
}
