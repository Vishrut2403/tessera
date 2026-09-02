//! The IPC fast path, measured (D-033, O-009).

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::asid::AsidPool;
use kernel::cap::cspace::{CSpace, bootstrap};
use kernel::cap::object::SLOT_BITS;
use kernel::cap::rights::ALL;
use kernel::cap::{ObjectType, RawCap};
use kernel::ipc::MessageInfo;
use kernel::mm::{self, AddressSpace, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr};
use kernel::{kernel_entry, layout, println, qemu, sched, uprog};

kernel_entry!(test_main_entry);

static mut MAP: Option<mm::MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range()).expect("discovery");
    // SAFETY: single hart, before anything else runs.
    unsafe { (&raw mut MAP).write(Some(map)) };

    let kspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    // SAFETY: `kspace` maps this code, this stack and `gp` where they are.
    unsafe { mm::kernel_space::activate(&kspace) };

    report();
    test_main();
    qemu::exit_success()
}

#[inline(always)]
fn instret() -> u64 {
    let v: u64;
    // SAFETY: `rdinstret` reads the unprivileged `instret` counter.
    unsafe { core::arch::asm!("rdinstret {v}", v = out(reg) v, options(nostack)) };
    v
}

/// Instructions between two adjacent reads.
fn floor() -> u64 {
    let a = instret();
    let b = instret();
    b - a
}

const EP_SLOT: u64 = 8;
const D: u8 = 6;
const USER_TEXT: usize = 0x1000_0000;
const USER_STACK: usize = 0x2000_0000;

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

/// As [`user_space`], optionally giving the space an ASID so switching to it
/// does not have to flush the whole TLB (D-030).
fn user_space_maybe_tagged(words: &[u32], pool: Option<&mut AsidPool>) -> AddressSpace {
    // SAFETY: written once during boot, read-only thereafter.
    let map = unsafe { (&raw const MAP).read() }.expect("no memory map");
    let kernel = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    let text = mm::alloc_frame().expect("no frames");
    let stack = mm::alloc_frame().expect("no frames");
    // SAFETY: both frames came from the allocator, so we own them.
    unsafe { uprog::write_to_frame(text, words) };

    let mut alloc = mm::FRAMES.lock();
    let mut space = AddressSpace::new(&kernel, &mut *alloc).expect("address space");
    space.map(VirtAddr::new(USER_TEXT), text, 0, PteFlags::USER_RX, &mut *alloc).expect("text");
    space.map(VirtAddr::new(USER_STACK), stack, 0, PteFlags::USER_RW, &mut *alloc).expect("stack");
    drop(alloc);
    if let Some(pool) = pool {
        pool.assign(&mut space).expect("no ASIDs left");
    }
    space
}

fn cspace_with(endpoint: RawCap) -> CSpace {
    let mut cs = bootstrap(aligned_region(18), D + SLOT_BITS).expect("bootstrap");
    cs.insert(EP_SLOT, D, endpoint, None).expect("insert endpoint");
    cs
}

fn endpoint() -> RawCap {
    let mut cs = bootstrap(aligned_region(18), D + SLOT_BITS).expect("bootstrap");
    let mut made = [RawCap::NULL; 1];
    cs.retype((0, D), ObjectType::Endpoint, 0, (16, D), &mut made).expect("retype");
    core::mem::forget(cs);
    made[0]
}

fn spawn(words: &[u32], cs: &CSpace) -> AddressSpace {
    spawn_tagged(words, cs, None)
}

fn spawn_tagged(words: &[u32], cs: &CSpace, pool: Option<&mut AsidPool>) -> AddressSpace {
    let space = user_space_maybe_tagged(words, pool);
    sched::spawn_with_cspace(
        &space,
        VirtAddr::new(USER_TEXT),
        VirtAddr::new(USER_STACK + PAGE_SIZE),
        *cs.root(),
    )
    .expect("spawn");
    space
}

/// Instructions retired running `trips` `call`/`reply` round trips, including
/// the fixed cost of starting and stopping the pair.
fn round_trips(trips: u32) -> u64 {
    round_trips_inner(trips, false)
}

fn round_trips_inner(trips: u32, tagged: bool) -> u64 {
    let mut pool = AsidPool::new(kernel::cap::asid::init());
    let ep = endpoint();
    let server_cs = cspace_with(ep);
    let client_cs = cspace_with(ep);
    let info = MessageInfo::new(1, 1, false).bits() as u32;

    let _s = spawn_tagged(
        uprog::ipc_server(
            EP_SLOT as u32,
            info,
            sched::syscall::RECV,
            sched::syscall::REPLY_RECV,
        )
        .as_slice(),
        &server_cs,
        if tagged { Some(&mut pool) } else { None },
    );
    let _c = spawn_tagged(
        uprog::ipc_client(
            EP_SLOT as u32,
            info,
            sched::syscall::CALL,
            sched::syscall::EXIT,
            trips,
        )
        .as_slice(),
        &client_cs,
        if tagged { Some(&mut pool) } else { None },
    );

    let start = instret();
    sched::run_until_exit();
    let end = instret();
    sched::kill_all();
    end - start
}

/// Both threads in *one* address space, so a switch between them is a `satp`
/// comparison instead of a write and a flush.
fn round_trips_shared(trips: u32) -> u64 {
    const SERVER_TEXT: usize = USER_TEXT;
    const CLIENT_TEXT: usize = USER_TEXT + PAGE_SIZE;

    let ep = endpoint();
    let server_cs = cspace_with(ep);
    let client_cs = cspace_with(ep);
    let info = MessageInfo::new(1, 1, false).bits() as u32;

    let server = uprog::ipc_server(
        EP_SLOT as u32,
        info,
        sched::syscall::RECV,
        sched::syscall::REPLY_RECV,
    );
    let client = uprog::ipc_client(
        EP_SLOT as u32,
        info,
        sched::syscall::CALL,
        sched::syscall::EXIT,
        trips,
    );

    // SAFETY: written once during boot, read-only thereafter.
    let map = unsafe { (&raw const MAP).read() }.expect("no memory map");
    let kernel = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("kernel space")
    };
    let stext = mm::alloc_frame().expect("no frames");
    let ctext = mm::alloc_frame().expect("no frames");
    let stack = mm::alloc_frame().expect("no frames");
    // SAFETY: all three came from the allocator, so we own them.
    unsafe {
        uprog::write_to_frame(stext, server.as_slice());
        uprog::write_to_frame(ctext, client.as_slice());
    }

    let space = {
        let mut alloc = mm::FRAMES.lock();
        let mut sp = AddressSpace::new(&kernel, &mut *alloc).expect("address space");
        sp.map(VirtAddr::new(SERVER_TEXT), stext, 0, PteFlags::USER_RX, &mut *alloc).unwrap();
        sp.map(VirtAddr::new(CLIENT_TEXT), ctext, 0, PteFlags::USER_RX, &mut *alloc).unwrap();
        sp.map(VirtAddr::new(USER_STACK), stack, 0, PteFlags::USER_RW, &mut *alloc).unwrap();
        sp
    };

    sched::spawn_with_cspace(
        &space,
        VirtAddr::new(SERVER_TEXT),
        VirtAddr::new(USER_STACK + PAGE_SIZE),
        *server_cs.root(),
    )
    .expect("spawn server");
    sched::spawn_with_cspace(
        &space,
        VirtAddr::new(CLIENT_TEXT),
        VirtAddr::new(USER_STACK + PAGE_SIZE),
        *client_cs.root(),
    )
    .expect("spawn client");

    let start = instret();
    sched::run_until_exit();
    let end = instret();
    sched::kill_all();
    end - start
}

/// Instructions retired running `n` null syscalls, for a baseline: this is what
/// crossing the U-to-S boundary costs before any IPC work happens at all.
fn null_syscalls(n: u32) -> u64 {
    const COUNTER: usize = 16;
    let head = uprog::Prog::<32>::new().li(COUNTER, n);
    let top = head.here();
    let prog = head
        .syscall(sched::syscall::GET_ID)
        .addi(COUNTER, -1)
        .bne_back(COUNTER, top)
        .exit();

    let cs = cspace_with(endpoint());
    let _t = spawn(prog.as_slice(), &cs);

    let start = instret();
    sched::run_until_exit();
    let end = instret();
    sched::kill_all();
    end - start
}

/// Measure at two sizes and take the difference, so the fixed cost of starting
/// and stopping the threads cancels out and what is left is the marginal cost
/// of one more round trip.
fn per_operation(small: u64, large: u64, delta: u32) -> u64 {
    (large - small) / delta as u64
}

fn report() {
    let f = floor();
    println!();
    println!("tessera :: IPC measurement");
    println!("  counter floor : {f} instructions between adjacent reads");

    if f > 64 {
        println!();
        println!("  NOT MEASURING: the counter is reading host wall-clock time,");
        println!("  not guest instructions (O-009). Re-run with `cargo bench-ipc`,");
        println!("  which adds -icount shift=0.");
        return;
    }

    let ipc = per_operation(round_trips_inner(100, false), round_trips_inner(1100, false), 1000);
    let tagged =
        per_operation(round_trips_inner(100, true), round_trips_inner(1100, true), 1000);
    let shared = per_operation(round_trips_shared(100), round_trips_shared(1100), 1000);
    let sys = per_operation(null_syscalls(100), null_syscalls(1100), 1000);

    println!();
    println!("  Instructions retired, marginal cost per operation.");
    println!("  Differential: (cost at 1100) - (cost at 100), divided by 1000,");
    println!("  so thread startup and teardown cancel.");
    println!();
    println!("  null syscall (ecall in, ecall out)   : {sys:>6}");
    println!("  IPC round trip, no ASID (full flush) : {ipc:>6}");
    println!("  IPC round trip, ASID-tagged spaces   : {tagged:>6}");
    println!("  IPC round trip, one shared space     : {shared:>6}");
    println!("  round trip / null syscall            : {:>6}x", tagged / sys.max(1));
    println!();
    println!("  A round trip is two U->S->U crossings, a message copy, two");
    println!("  direct switches and two address space changes. The run queue");
    println!("  is not consulted once (invariant 4).");
    println!();
    println!("  These are INSTRUCTIONS, not cycles. QEMU TCG has no cache, no");
    println!("  branch predictor and no pipeline, so a cycle count is not a");
    println!("  thing it can produce (O-009). Cycles need silicon.");
}

// --- The measurement has to keep working, so assert its shape ---

#[test_case]
fn the_measurement_is_differential_and_stable() {
    if floor() > 64 {
        return; // Not under -icount; nothing meaningful to check.
    }
    let a = per_operation(round_trips(100), round_trips(600), 500);
    let b = per_operation(round_trips(200), round_trips(700), 500);
    assert!(a > 0 && b > 0, "a round trip cannot cost zero instructions");

    // Two independent differential measurements of the same thing must agree,
    // or the fixed cost is not actually cancelling.
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    assert!(hi - lo <= hi / 20, "measurements disagree: {a} vs {b}");
}

#[test_case]
fn a_round_trip_costs_more_than_a_null_syscall_but_not_absurdly_more() {
    if floor() > 64 {
        return;
    }
    let ipc = per_operation(round_trips(100), round_trips(1100), 1000);
    let shared = per_operation(round_trips_shared(100), round_trips_shared(1100), 1000);
    let sys = per_operation(null_syscalls(100), null_syscalls(1100), 1000);

    assert!(ipc > sys, "IPC ({ipc}) is not more expensive than a null syscall ({sys})");
    assert!(
        ipc < sys * 10,
        "IPC ({ipc}) is more than 10x a null syscall ({sys}); the fast path is not fast"
    );
    // Threads sharing an address space skip the `satp` write and the flush, so
    // that case can never be the more expensive one.
    assert!(shared <= ipc, "shared-space IPC ({shared}) cost more than cross-space ({ipc})");
}
