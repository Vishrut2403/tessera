//! Threads in U-mode: does the trap path survive a privilege change, and does
//! round-robin actually round-robin?

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::csr::{interrupt_bits, sie, sstatus, sstatus_bits};
use kernel::mm::{self, AddressSpace, MemoryMap, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr};
use kernel::thread::fs;
use kernel::uprog::{self, A0, A7, ECALL, SPIN, USE_FP, li};
use kernel::{kernel_entry, layout, qemu, sched, time, trap};

kernel_entry!(test_main_entry);

static mut MAP: Option<MemoryMap> = None;

extern "C" fn test_main_entry(_hartid: usize, dtb_pa: usize) -> ! {
    kernel::init();
    let map = mm::init(PhysAddr::new(dtb_pa), layout::kernel_phys_range())
        .expect("memory discovery failed");
    // SAFETY: single hart, before any test runs.
    unsafe { (&raw mut MAP).write(Some(map)) };
    time::init(PhysAddr::new(dtb_pa));

    // Threads switch `satp` for real, so the kernel table must be the live one.
    let kspace = {
        let mut alloc = mm::FRAMES.lock();
        mm::kernel_space::build(&map, &mut *alloc).expect("could not build kernel space")
    };
    // SAFETY: `kspace` maps this code, this stack and `gp` where they already are.
    unsafe { mm::kernel_space::activate(&kspace) };

    test_main();
    qemu::exit_success()
}

const USER_TEXT: usize = 0x1000_0000;
const USER_STACK: usize = 0x2000_0000;

/// An address space holding one page of `words` as user text, plus a stack.
fn user_space(words: &[u32]) -> AddressSpace {
    let map = {
        // SAFETY: written once during boot, read-only thereafter.
        unsafe { (&raw const MAP).read() }.expect("memory map missing")
    };
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
    space
        .map(VirtAddr::new(USER_TEXT), text, 0, PteFlags::USER_RX, &mut *alloc)
        .expect("map text");
    space
        .map(VirtAddr::new(USER_STACK), stack, 0, PteFlags::USER_RW, &mut *alloc)
        .expect("map stack");
    space
}

fn spawn(words: &[u32]) -> AddressSpace {
    let space = user_space(words);
    sched::spawn(&space, VirtAddr::new(USER_TEXT), VirtAddr::new(USER_STACK + PAGE_SIZE))
        .expect("spawn failed");
    space
}

// --- Structure ---

#[test_case]
fn the_kernel_stack_is_not_the_boot_stack() {
    // If the trap path reset sp into the boot stack, returning from sched::run
    // would land on smashed frames.
    let ksp = trap::kernel_stack();
    assert_ne!(ksp, 0, "no kernel stack installed");
    assert!(
        ksp <= layout::boot_stack_bottom() || ksp > layout::boot_stack_top(),
        "the trap stack overlaps the boot stack"
    );
    assert_eq!(ksp & 0xf, 0, "kernel stack top is not 16-byte aligned");
}

#[test_case]
fn a_fresh_thread_starts_in_user_mode_with_no_fpu() {
    let space = user_space(&uprog::syscall(sched::syscall::EXIT));
    let mut alloc = mm::FRAMES.lock();
    let frame = alloc.alloc_frame().expect("no frames");
    drop(alloc);

    // SAFETY: a frame we own, not yet holding a TCB.
    let tcb = unsafe {
        kernel::thread::Tcb::create(
            frame,
            99,
            &space,
            VirtAddr::new(USER_TEXT),
            VirtAddr::new(USER_STACK + PAGE_SIZE),
        )
    };
    // SAFETY: we just created it and nothing else refers to it.
    let t = unsafe { tcb.as_ref() };

    assert_eq!(t.frame.sepc, USER_TEXT);
    assert_eq!(t.frame.x[2], USER_STACK + PAGE_SIZE, "sp was not set");
    assert_eq!(t.frame.sstatus & sstatus_bits::SPP, 0, "SPP set: it would sret to S-mode");
    assert_ne!(t.frame.sstatus & sstatus_bits::SPIE, 0, "SPIE clear: it would run uninterruptible");
    assert_eq!(t.frame.sstatus & fs::MASK, fs::OFF, "a new thread must not own the FPU");
    assert_eq!(t.satp, space.satp());
}

#[test_case]
fn an_empty_run_queue_returns_immediately() {
    assert_eq!(sched::ready_count(), 0);
    sched::run();
}

// --- Running ---

#[test_case]
fn a_thread_runs_and_exits() {
    let before = sched::exited();
    let _space = spawn(&uprog::syscall(sched::syscall::EXIT));
    assert_eq!(sched::ready_count(), 1);

    sched::run();

    assert_eq!(sched::ready_count(), 0, "the thread was left on the queue");
    assert_eq!(sched::exited(), before + 1);
    assert_eq!(sched::current_id(), None, "a thread is still marked current");
}

#[test_case]
fn a_thread_can_call_back_into_the_kernel() {
    // getid, then exit. If the syscall path is broken the thread faults instead.
    let mut words = [0u32; 4];
    words[0] = li(A7, sched::syscall::GET_ID as u32);
    words[1] = ECALL;
    words[2] = li(A7, sched::syscall::EXIT as u32);
    words[3] = ECALL;

    let (exited, killed) = (sched::exited(), sched::killed());
    let _space = spawn(&words);
    sched::run();
    assert_eq!(sched::killed(), killed, "the thread faulted instead of returning");
    assert_eq!(sched::exited(), exited + 1, "the thread did not reach exit");
}

#[test_case]
fn three_threads_all_get_to_run() {
    let before = sched::exited();
    assert_eq!(sched::ready_count(), 0, "a previous test left threads on the queue");
    let spaces = [
        spawn(&uprog::syscall(sched::syscall::EXIT)),
        spawn(&uprog::syscall(sched::syscall::EXIT)),
        spawn(&uprog::syscall(sched::syscall::EXIT)),
    ];
    assert_eq!(sched::ready_count(), 3);

    sched::run();

    assert_eq!(sched::exited(), before + 3, "not every thread ran");
    assert_eq!(sched::ready_count(), 0);
    drop(spaces);
}

#[test_case]
fn yielding_puts_a_thread_at_the_back_and_it_comes_round_again() {
    // yield, yield, exit, only reachable if the queue really is circular.
    let mut words = [0u32; 6];
    words[0] = li(A7, sched::syscall::YIELD as u32);
    words[1] = ECALL;
    words[2] = li(A7, sched::syscall::YIELD as u32);
    words[3] = ECALL;
    words[4] = li(A7, sched::syscall::EXIT as u32);
    words[5] = ECALL;

    let (exited, killed) = (sched::exited(), sched::killed());
    let _a = spawn(&words);
    let _b = spawn(&words);
    sched::run();
    assert_eq!(sched::killed(), killed, "a thread faulted while yielding");
    assert_eq!(sched::exited(), exited + 2);
}

// --- Preemption ---

#[test_case]
fn the_timer_preempts_a_thread_that_never_yields() {
    // A thread that branches to itself, and one that exits immediately.
    let _spinner = spawn(&[SPIN]);
    let _exiter = spawn(&uprog::syscall(sched::syscall::EXIT));

    let ticks = time::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let exited = sched::exited();

    time::enable();
    time::arm(time::now() + time::ms_to_ticks(1));
    // SAFETY: the dispatcher handles timer interrupts and no lock is held.
    unsafe { sstatus::set(sstatus_bits::SIE) };

    sched::run_until_exit();

    // SAFETY: restoring the masked state the rest of the suite expects.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    unsafe { sie::clear(interrupt_bits::STIE) };
    time::disarm();

    assert_eq!(sched::exited(), exited + 1, "the second thread never got the hart");
    assert!(
        time::TICKS.load(core::sync::atomic::Ordering::Relaxed) > ticks,
        "it ran without a timer interrupt, so nothing was preempted"
    );
    assert_eq!(sched::kill_all(), 1, "the spinner should be the one thread left");
}

// --- The FPU ---

#[test_case]
fn a_float_traps_once_and_then_the_thread_keeps_the_fpu() {
    // Two floats, then exit.
    let mut words = [0u32; 4];
    words[0] = USE_FP;
    words[1] = USE_FP;
    words[2] = li(A7, sched::syscall::EXIT as u32);
    words[3] = ECALL;

    let (exited, killed) = (sched::exited(), sched::killed());
    let _space = spawn(&words);
    sched::run();
    assert_eq!(sched::killed(), killed, "the thread died on a floating-point instruction");
    assert_eq!(sched::exited(), exited + 1);
}

// --- The wall ---

#[test_case]
fn a_thread_that_reads_unmapped_memory_is_killed() {
    // ld a0, 0(x0): nothing is mapped at 0 in a user space, so this must fault.
    let mut words = [0u32; 3];
    words[0] = 0x0000_3503;
    words[1] = li(A7, sched::syscall::EXIT as u32);
    words[2] = ECALL;

    let (exited, killed) = (sched::exited(), sched::killed());
    let _space = spawn(&words);
    sched::run();

    assert_eq!(sched::killed(), killed + 1, "the faulting thread was not killed");
    assert_eq!(sched::exited(), exited, "it reached exit, so the load succeeded");
}

#[test_case]
fn a_thread_reading_a_privileged_csr_is_killed_not_given_the_fpu() {
    // `csrr a0, satp` is an illegal instruction in U-mode.
    let mut words = [0u32; 3];
    words[0] = 0x1800_2573;
    words[1] = li(A7, sched::syscall::EXIT as u32);
    words[2] = ECALL;

    let (exited, killed) = (sched::exited(), sched::killed());
    let _space = spawn(&words);
    sched::run();

    assert_eq!(sched::killed(), killed + 1, "the privileged read was not fatal");
    assert_eq!(sched::exited(), exited, "the thread survived reading satp");
}

#[test_case]
fn user_text_is_not_writable_and_the_stack_is_not_executable() {
    let space = user_space(&uprog::syscall(sched::syscall::EXIT));

    let (_, text, _) = space.translate(VirtAddr::new(USER_TEXT)).expect("text unmapped");
    assert!(text.contains(PteFlags::X) && text.contains(PteFlags::U));
    assert!(!text.contains(PteFlags::W), "user text is writable");

    let (_, stack, _) = space.translate(VirtAddr::new(USER_STACK)).expect("stack unmapped");
    assert!(stack.contains(PteFlags::W) && stack.contains(PteFlags::U));
    assert!(!stack.contains(PteFlags::X), "the user stack is executable");
}

#[test_case]
fn a0_carries_the_syscall_result_back() {
    // getid into a0, store it to the stack, exit. Proves the return path.
    let mut words = [0u32; 6];
    words[0] = li(A7, sched::syscall::GET_ID as u32);
    words[1] = ECALL;
    // sd a0, -8(sp): sp points one past the stack page, so store below it.
    words[2] = 0xfea1_3c23;
    words[3] = li(A0, 0);
    words[4] = li(A7, sched::syscall::EXIT as u32);
    words[5] = ECALL;

    let (exited, killed) = (sched::exited(), sched::killed());
    let _space = spawn(&words);
    sched::run();
    assert_eq!(sched::killed(), killed, "the thread faulted storing its id");
    assert_eq!(sched::exited(), exited + 1);
}
