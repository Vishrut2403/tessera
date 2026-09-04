//! Synchronous IPC: rendezvous, call/reply, and the scheduler staying out of it.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::cspace::{CSpace, bootstrap};
use kernel::cap::object::SLOT_BITS;
use kernel::cap::rights::{ALL, READ, WRITE};
use kernel::cap::{ObjectType, RawCap};
use kernel::csr::{interrupt_bits, sie, sstatus, sstatus_bits};
use kernel::ipc::MessageInfo;
use kernel::mm::{self, AddressSpace, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr};
use kernel::uprog::{self, A0, A7, Prog};
use kernel::{kernel_entry, layout, qemu, sched, time};

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

const USER_TEXT: usize = 0x1000_0000;
const USER_STACK: usize = 0x2000_0000;
/// The endpoint capability lives in slot 8 of every thread's CSpace.
const EP_SLOT: u64 = 8;
/// A second, deliberately weaker copy of the same endpoint.
const EP_WEAK: u64 = 9;
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

fn user_space(words: &[u32]) -> AddressSpace {
    let kernel = kernel_mapper();
    let text = mm::alloc_frame().expect("no frames");
    let stack = mm::alloc_frame().expect("no frames");
    // SAFETY: both frames came from the allocator, so we own them.
    unsafe { uprog::write_to_frame(text, words) };

    let mut alloc = mm::FRAMES.lock();
    let mut space = AddressSpace::new(&kernel, &mut *alloc).expect("address space");
    space.map(VirtAddr::new(USER_TEXT), text, 0, PteFlags::USER_RX, &mut *alloc).expect("text");
    space.map(VirtAddr::new(USER_STACK), stack, 0, PteFlags::USER_RW, &mut *alloc).expect("stack");
    space
}

/// A CSpace holding the same endpoint capability in slot 8.
fn cspace_with(endpoint: RawCap, badge: u64) -> CSpace {
    let mut cs = bootstrap(aligned_region(18), D + SLOT_BITS).expect("bootstrap");
    let mut ep = endpoint;
    if badge != 0 {
        ep.set_badge(badge);
    }
    cs.insert(EP_SLOT, D, ep, None).expect("insert endpoint");
    cs
}

fn spawn(words: &[u32], cs: &CSpace) -> AddressSpace {
    let space = user_space(words);
    sched::spawn_with_cspace(
        &space,
        VirtAddr::new(USER_TEXT),
        VirtAddr::new(USER_STACK + PAGE_SIZE),
        *cs.root(),
    )
    .expect("spawn");
    space
}

/// An endpoint object, carved from its own region.
fn endpoint() -> RawCap {
    let mut cs = bootstrap(aligned_region(18), D + SLOT_BITS).expect("bootstrap");
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (16, D), &mut made).expect("retype endpoint");
    core::mem::forget(cs);
    made[0]
}

// --- User programs ---

/// `call(ep, label, mr0); exit()`: a client that asks once and stops.
fn client(label: u64, mr0: u32) -> Prog<16> {
    Prog::new()
        .li(A0, EP_SLOT as u32)
        .li(A0 + 1, MessageInfo::new(label, 1, false).bits() as u32)
        .li(A0 + 2, mr0)
        .syscall(sched::syscall::CALL)
        .exit()
}

/// `recv(ep); reply(0x5a); exit()`: a server that answers once.
fn server_once() -> Prog<24> {
    Prog::new()
        .li(A0, EP_SLOT as u32)
        .syscall(sched::syscall::RECV)
        .li(A0 + 1, MessageInfo::new(0, 1, false).bits() as u32)
        .li(A0 + 2, 0x5a)
        .syscall(sched::syscall::REPLY)
        .exit()
}

fn exit_prog() -> Prog<4> {
    Prog::new().exit()
}

/// `a6 = n; loop { call(ep) } while --a6; exit()`.
fn client_loop(n: u32) -> Prog<32> {
    const COUNTER: usize = 16;
    let head = Prog::<32>::new().li(COUNTER, n);
    let top = head.here();
    head.li(A0, EP_SLOT as u32)
        .li(A0 + 1, MessageInfo::new(1, 1, false).bits() as u32)
        .li(A7, sched::syscall::CALL as u32)
        .ecall()
        .addi(COUNTER, -1)
        .bne_back(COUNTER, top)
        .exit()
}

/// `recv(ep); loop { reply_recv(ep) }`: a server that never stops.
fn server_loop() -> Prog<32> {
    let head = Prog::<32>::new().li(A0, EP_SLOT as u32).syscall(sched::syscall::RECV);
    let top = head.here();
    head.li(A0, EP_SLOT as u32)
        .li(A0 + 1, MessageInfo::new(0, 1, false).bits() as u32)
        .li(A7, sched::syscall::REPLY_RECV as u32)
        .ecall()
        .jump_back(top)
}

fn run_with_timer() {
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

// --- Message format ---

#[test_case]
fn a_message_header_packs_and_unpacks() {
    let info = MessageInfo::new(0x1234, 3, true);
    assert_eq!(info.label(), 0x1234);
    assert_eq!(info.length(), 3);
    assert!(info.carries_cap());

    let plain = MessageInfo::new(7, 0, false);
    assert_eq!(plain.label(), 7);
    assert_eq!(plain.length(), 0);
    assert!(!plain.carries_cap());
}

#[test_case]
fn a_message_cannot_claim_more_words_than_there_are_registers() {
    let info = MessageInfo::new(1, 99, false);
    assert_eq!(info.length(), kernel::ipc::MSG_REGS, "length was not clamped");
}

// --- Rendezvous ---

#[test_case]
fn a_fresh_endpoint_is_idle() {
    let ep = endpoint();
    assert_eq!(ep.kind, ObjectType::Endpoint);
    // SAFETY: a live endpoint object nothing else refers to.
    let e = unsafe { kernel::ipc::endpoint_at(ep.paddr) };
    assert_eq!(e.state, kernel::ipc::EndpointState::Idle);
    assert!(e.is_empty());
}

#[test_case]
fn a_caller_with_no_server_blocks_rather_than_spinning() {
    let ep = endpoint();
    let cs = cspace_with(ep, 0);
    let _c = spawn(client(1, 0x11).as_slice(), &cs);

    // Also queue something that exits, so the run queue drains and `run`
    // returns instead of the caller spinning forever.
    let cs2 = cspace_with(ep, 0);
    let _e = spawn(exit_prog().as_slice(), &cs2);

    let exited = sched::exited();
    sched::run();

    assert_eq!(sched::exited(), exited + 1, "only the exiting thread should finish");
    // SAFETY: a live endpoint.
    let e = unsafe { kernel::ipc::endpoint_at(ep.paddr) };
    assert_eq!(e.state, kernel::ipc::EndpointState::Sending, "the caller did not queue");
    assert!(!e.is_empty());
    sched::kill_all();
}

#[test_case]
fn a_call_and_a_reply_complete_a_round_trip() {
    let ep = endpoint();
    let server_cs = cspace_with(ep, 0);
    let client_cs = cspace_with(ep, 0xbeef);

    // The server is queued first, so it blocks on recv before the client runs.
    let _s = spawn(server_once().as_slice(), &server_cs);
    let _c = spawn(client(0x20, 0x99).as_slice(), &client_cs);

    let (exited, killed) = (sched::exited(), sched::killed());
    run_with_timer();

    assert_eq!(sched::killed(), killed, "a thread faulted during the round trip");
    assert_eq!(sched::exited(), exited + 2, "both threads should finish the round trip");
    sched::kill_all();
}

#[test_case]
fn the_badge_of_the_invoked_capability_reaches_the_receiver() {
    let ep = endpoint();
    let server_cs = cspace_with(ep, 0);
    // The client's copy of the endpoint carries a badge; the server should see
    // it, which is how a server tells its clients apart.
    let client_cs = cspace_with(ep, 0x7c0de);

    let _s = spawn(server_once().as_slice(), &server_cs);
    let _c = spawn(client(1, 0).as_slice(), &client_cs);

    let killed = sched::killed();
    run_with_timer();
    assert_eq!(sched::killed(), killed);

    // The server's TCB recorded the badge on receive.
    assert_eq!(sched::last_badge(), 0x7c0de, "the badge did not reach the receiver");
    sched::kill_all();
}

// --- Invariant 4 ---

#[test_case]
fn round_trips_do_not_consult_the_run_queue() {
    // Invariant 4, measured rather than asserted: run the same client/server
    // pair with two round trips and with sixteen, and compare how often a
    // thread was taken off the run queue.
    let pops = |trips: u32| {
        let ep = endpoint();
        let server_cs = cspace_with(ep, 0);
        let client_cs = cspace_with(ep, 0);

        let _s = spawn(server_loop().as_slice(), &server_cs);
        let _c = spawn(client_loop(trips).as_slice(), &client_cs);

        let before = sched::queue_pops();
        let exited = sched::exited();
        sched::run_until_exit();
        assert_eq!(sched::exited(), exited + 1, "the client did not finish {trips} trips");
        let n = sched::queue_pops() - before;
        sched::kill_all();
        n
    };

    let few = pops(2);
    let many = pops(16);
    assert_eq!(
        few, many,
        "the run queue was consulted {few} times for 2 round trips and {many} for 16, \
         so the scheduler is on the IPC path"
    );
}

// --- Object invocation (D-032) ---

#[test_case]
fn a_thread_with_no_cspace_cannot_invoke_anything() {
    let space = user_space(client(1, 0).as_slice());
    sched::spawn(&space, VirtAddr::new(USER_TEXT), VirtAddr::new(USER_STACK + PAGE_SIZE))
        .expect("spawn");

    // No CSpace, so the call fails rather than faulting or succeeding.
    let killed = sched::killed();
    let _e = spawn(exit_prog().as_slice(), &cspace_with(endpoint(), 0));
    sched::run();
    assert_eq!(sched::killed(), killed, "the thread was killed rather than refused");
    sched::kill_all();
}

#[test_case]
fn an_endpoint_capability_is_required_to_receive() {
    // Slot 9 is empty, so a recv on it must fail rather than block forever.
    let prog: Prog<12> =
        Prog::new().li(A0, 9).syscall(sched::syscall::RECV).exit();

    let cs = cspace_with(endpoint(), 0);
    let _t = spawn(prog.as_slice(), &cs);

    let (exited, killed) = (sched::exited(), sched::killed());
    sched::run();
    assert_eq!(sched::killed(), killed);
    assert_eq!(sched::exited(), exited + 1, "recv on an empty slot did not return");
    sched::kill_all();
}

// --- Capability transfer (D-036) ---

/// The slot a sender takes a capability from, and the one a receiver puts it in.
const SRC_SLOT: u64 = 20;
const DST_SLOT: u64 = 21;

/// `a6 = SRC_SLOT; call(ep, carrying a capability); exit()`.
fn cap_sender() -> Prog<24> {
    Prog::new()
        .li(A0, EP_SLOT as u32)
        .li(A0 + 1, MessageInfo::new(1, 0, true).bits() as u32)
        .li(A0 + 6, SRC_SLOT as u32)
        .syscall(sched::syscall::CALL)
        .exit()
}

/// `a6 = DST_SLOT; recv(ep); reply(); exit()`.
fn cap_receiver() -> Prog<24> {
    Prog::new()
        .li(A0, EP_SLOT as u32)
        .li(A0 + 6, DST_SLOT as u32)
        .syscall(sched::syscall::RECV)
        .li(A0 + 1, MessageInfo::new(0, 0, false).bits() as u32)
        .syscall(sched::syscall::REPLY)
        .exit()
}

#[test_case]
fn a_message_can_carry_a_capability() {
    let ep = endpoint();
    let recv_cs = cspace_with(ep, 0);
    let mut send_cs = cspace_with(ep, 0);

    // Something recognisable to hand over: a second endpoint.
    let gift = endpoint();
    send_cs.insert(SRC_SLOT, D, gift, None).expect("insert gift");
    assert!(recv_cs.read(DST_SLOT, D).unwrap().is_null(), "the destination is not empty");

    let _s = spawn(cap_receiver().as_slice(), &recv_cs);
    let _c = spawn(cap_sender().as_slice(), &send_cs);

    let (exited, killed) = (sched::exited(), sched::killed());
    sched::run();
    assert_eq!(sched::killed(), killed);
    assert_eq!(sched::exited(), exited + 2);

    let arrived = recv_cs.read(DST_SLOT, D).unwrap();
    assert_eq!(arrived.kind, ObjectType::Endpoint, "no capability arrived");
    assert_eq!(arrived.paddr, gift.paddr, "a different object arrived");
    assert_eq!(arrived.badge(), 0, "the copy kept the sender's badge");

    // It is a derivative, so revoking the original takes it away again.
    assert_eq!(send_cs.descendants(SRC_SLOT, D).unwrap(), 1);
    send_cs.revoke(SRC_SLOT, D).expect("revoke");
    assert!(recv_cs.read(DST_SLOT, D).unwrap().is_null(), "revoking did not reclaim the copy");

    sched::kill_all();
}

#[test_case]
fn a_capability_without_grant_is_not_transferred() {
    let ep = endpoint();
    let recv_cs = cspace_with(ep, 0);
    let mut send_cs = cspace_with(ep, 0);

    // No GRANT, so the sender may hold it but not hand it on.
    let gift = endpoint().with_rights(kernel::cap::rights::READ);
    send_cs.insert(SRC_SLOT, D, gift, None).expect("insert gift");

    let _s = spawn(cap_receiver().as_slice(), &recv_cs);
    let _c = spawn(cap_sender().as_slice(), &send_cs);

    let killed = sched::killed();
    sched::run();

    assert_eq!(sched::killed(), killed, "the send should be refused, not fatal");
    assert!(
        recv_cs.read(DST_SLOT, D).unwrap().is_null(),
        "a capability without GRANT was transferred anyway"
    );
    sched::kill_all();
}

#[test_case]
fn queued_senders_are_served_in_the_order_they_arrived() {
    // Three clients queue on an endpoint before any server exists, each holding
    // a differently badged copy of it.
    let ep = endpoint();
    let server_cs = cspace_with(ep, 0);
    let clients: [CSpace; 3] =
        [cspace_with(ep, 0x11), cspace_with(ep, 0x22), cspace_with(ep, 0x33)];

    let _c0 = spawn(client(1, 0).as_slice(), &clients[0]);
    let _c1 = spawn(client(1, 0).as_slice(), &clients[1]);
    let _c2 = spawn(client(1, 0).as_slice(), &clients[2]);
    // The server goes last, so all three are queued before it receives.
    let _s = spawn(server_loop().as_slice(), &server_cs);

    sched::reset_badge_log();
    let (exited, killed) = (sched::exited(), sched::killed());
    run_with_timer();

    assert_eq!(sched::killed(), killed);
    assert_eq!(sched::exited(), exited + 3, "not every client was served");

    let mut seen = [0u64; 8];
    let n = sched::badge_log(&mut seen);
    assert_eq!(n, 3, "expected three deliveries, saw {n}");
    assert_eq!(
        &seen[..3],
        &[0x11, 0x22, 0x33],
        "senders were served out of order: {:?}",
        &seen[..3]
    );
    sched::kill_all();
}

// --- Endpoint rights (D-042) ---

/// The same endpoint in slot 8, held with exactly `rights`.
fn cspace_holding(endpoint: RawCap, rights: u8) -> CSpace {
    let mut cs = bootstrap(aligned_region(18), D + SLOT_BITS).expect("bootstrap");
    cs.insert(EP_SLOT, D, endpoint.with_rights(rights), None).expect("insert endpoint");
    cs
}

/// `call(slot); *(sp - 8) = a0; exit()`.
fn call_recording(slot: u64) -> Prog<16> {
    Prog::new()
        .li(A0, slot as u32)
        .li(A0 + 1, MessageInfo::new(1, 1, false).bits() as u32)
        .li(A0 + 2, 0x11)
        .syscall(sched::syscall::CALL)
        .raw(uprog::sd(2, A0, -8))
        .exit()
}

/// `recv(slot); *(sp - 8) = a0; exit()`.
fn recv_recording(slot: u64) -> Prog<16> {
    Prog::new()
        .li(A0, slot as u32)
        .syscall(sched::syscall::RECV)
        .raw(uprog::sd(2, A0, -8))
        .exit()
}

/// `recv(ep); reply_recv(weak ep); *(sp - 8) = a0; exit()`.
fn reply_recv_recording() -> Prog<24> {
    Prog::new()
        .li(A0, EP_SLOT as u32)
        .syscall(sched::syscall::RECV)
        .li(A0, EP_WEAK as u32)
        .li(A0 + 1, MessageInfo::new(0, 1, false).bits() as u32)
        .syscall(sched::syscall::REPLY_RECV)
        .raw(uprog::sd(2, A0, -8))
        .exit()
}

fn stack_word(space: &AddressSpace, offset: usize) -> u64 {
    let (pa, _, _) = space.translate(VirtAddr::new(USER_STACK)).expect("stack unmapped");
    // SAFETY: a stack frame this test mapped, readable through the direct map.
    unsafe {
        core::ptr::read_volatile(
            mm::phys_to_virt(pa).as_ptr::<u64>().byte_add(PAGE_SIZE - offset),
        )
    }
}

#[test_case]
fn sending_needs_write_on_the_endpoint() {
    let ep = endpoint();
    let cs = cspace_holding(ep, READ);
    let space = spawn(call_recording(EP_SLOT).as_slice(), &cs);

    let killed = sched::killed();
    run_with_timer();

    assert_eq!(sched::killed(), killed, "the sender should be refused, not killed");
    assert_eq!(
        stack_word(&space, 8) as usize,
        sched::result::ERR_BAD_CAP,
        "a receive-only endpoint capability was allowed to send",
    );
    sched::kill_all();
}

#[test_case]
fn receiving_needs_read_on_the_endpoint() {
    let ep = endpoint();
    let cs = cspace_holding(ep, WRITE);
    let space = spawn(recv_recording(EP_SLOT).as_slice(), &cs);

    let killed = sched::killed();
    run_with_timer();

    assert_eq!(sched::killed(), killed);
    assert_eq!(
        stack_word(&space, 8) as usize,
        sched::result::ERR_BAD_CAP,
        "a send-only endpoint capability was allowed to receive",
    );
    sched::kill_all();
}

#[test_case]
fn the_receive_half_of_reply_recv_needs_read() {
    let ep = endpoint();
    // The server receives with a full capability and then names a send-only
    // copy of the same endpoint to `reply_recv`.
    let mut server_cs = cspace_holding(ep, ALL);
    server_cs.insert(EP_WEAK, D, ep.with_rights(WRITE), None).expect("weak copy");
    let client_cs = cspace_holding(ep, WRITE);

    let space = spawn(reply_recv_recording().as_slice(), &server_cs);
    let _c = spawn(client(1, 0).as_slice(), &client_cs);

    let killed = sched::killed();
    run_with_timer();

    assert_eq!(sched::killed(), killed);
    assert_eq!(
        stack_word(&space, 8) as usize,
        sched::result::ERR_BAD_CAP,
        "reply_recv received on a send-only endpoint capability",
    );
    sched::kill_all();
}

#[test_case]
fn a_send_only_client_can_still_call_a_receive_only_server() {
    let ep = endpoint();
    // The shape the whole check exists to make safe: the client may only send,
    // the server may only receive, and the reply rides the Reply capability.
    let server_cs = cspace_holding(ep, READ);
    let client_cs = cspace_holding(ep, WRITE);

    let _s = spawn(server_once().as_slice(), &server_cs);
    let _c = spawn(client(0x20, 0x99).as_slice(), &client_cs);

    let (exited, killed) = (sched::exited(), sched::killed());
    run_with_timer();

    assert_eq!(sched::killed(), killed, "a thread faulted during the round trip");
    assert_eq!(sched::exited(), exited + 2, "the round trip did not complete");
    sched::kill_all();
}
