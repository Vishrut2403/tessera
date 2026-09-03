//! Endowing a capability space that is not your own: the kernel half of what
//! lets a userspace parent build a child out of a boot module (D-043).

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test::runner)]
#![reexport_test_harness_main = "test_main"]

use kernel::cap::cspace::{CSpace, bootstrap};
use kernel::cap::object::SLOT_BITS;
use kernel::cap::rights::{ALL, GRANT, READ};
use kernel::cap::{ObjectType, RawCap};
use kernel::csr::{interrupt_bits, sie, sstatus, sstatus_bits};
use kernel::ipc::MessageInfo;
use kernel::mm::{self, AddressSpace, PAGE_SIZE, PhysAddr, PteFlags, VirtAddr};
use kernel::uprog::{self, A0, Prog};
use kernel::sched::{label, result};
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

const TEXT: usize = 0x1000_0000;
const STACK: usize = 0x2000_0000;

/// Slots in the parent's CSpace. Slot 0 is its untyped, slot 1 its own root.
const GIFT: u64 = 8;
const CHILD: u64 = 9;
/// The same child CNode, held without `WRITE`.
const CHILD_RO: u64 = 10;
/// Where a mint is aimed, in whichever space the invoked CNode roots.
const TARGET: u64 = 3;

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

/// A parent holding a frame to give away and a child CNode to give it to, both
/// carved from its own untyped.
fn parent_cspace() -> CSpace {
    let mut cs = bootstrap(aligned_region(19), D + SLOT_BITS).expect("bootstrap");
    cs.retype((0, D), ObjectType::Frame, 0, (GIFT, D), &mut [RawCap::NULL]).expect("gift");
    cs.retype((0, D), ObjectType::CNode, D + SLOT_BITS, (CHILD, D), &mut [RawCap::NULL])
        .expect("child cnode");
    cs.mint((CHILD, D), (CHILD_RO, D), READ | GRANT, 0).expect("weaken");
    cs
}

fn child_of(cs: &CSpace) -> CSpace {
    CSpace::new(cs.read(CHILD, D).unwrap()).expect("the child slot is not a cnode")
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
    space.set_asid(kernel::cap::asid::assign_global().expect("asid"));
    space
}

/// `call(cnode, Mint, [src, dst, ALL, 0]); *(sp - 8) = a0; exit()`.
fn mint_prog(cnode: u64, src: u64, dst: u64) -> Prog<24> {
    Prog::new()
        .li(A0, cnode as u32)
        .li(A0 + 1, MessageInfo::new(label::MINT, 4, false).bits() as u32)
        .li(A0 + 2, src as u32)
        .li(A0 + 3, dst as u32)
        .li(A0 + 4, ALL as u32)
        .li(A0 + 5, 0)
        .syscall(sched::syscall::CALL)
        .raw(uprog::sd(2, A0, -8))
        .exit()
}

/// Run one program with `cs` as its capability space, and hand back what it
/// stored at the top of its stack.
fn run_recording(words: &[u32], cs: &CSpace) -> (AddressSpace, u64) {
    let space = user_space(words);
    sched::spawn_with_cspace(
        &space,
        VirtAddr::new(TEXT),
        VirtAddr::new(STACK + PAGE_SIZE),
        *cs.root(),
    )
    .expect("spawn");

    time::enable();
    time::arm_next_tick();
    // SAFETY: the dispatcher handles timer interrupts and no lock is held.
    unsafe { sstatus::set(sstatus_bits::SIE) };
    sched::run();
    // SAFETY: restoring the masked state the rest of the suite expects.
    unsafe { sstatus::clear(sstatus_bits::SIE) };
    // SAFETY: as above.
    unsafe { sie::clear(interrupt_bits::STIE) };
    time::disarm();

    let (pa, _, _) = space.translate(VirtAddr::new(STACK)).expect("stack unmapped");
    // SAFETY: a stack frame this test mapped, readable through the direct map.
    let word = unsafe {
        core::ptr::read_volatile(mm::phys_to_virt(pa).as_ptr::<u64>().byte_add(PAGE_SIZE - 8))
    };
    (space, word)
}

// --- The invoked CNode is the destination ---

#[test_case]
fn minting_into_a_child_cnode_lands_in_the_child_and_not_in_the_parent() {
    let cs = parent_cspace();
    let (_space, status) = run_recording(mint_prog(CHILD, GIFT, TARGET).as_slice(), &cs);
    assert_eq!(status as usize, result::OK, "the mint was refused");

    let child = child_of(&cs);
    let landed = child.read(TARGET, D).expect("nothing in the child");
    assert_eq!(landed.kind, ObjectType::Frame);
    assert_eq!(landed.paddr, cs.read(GIFT, D).unwrap().paddr, "a different frame arrived");
    assert!(cs.read(TARGET, D).unwrap().is_null(), "the copy landed in the parent too");
}

#[test_case]
fn a_child_cnode_held_without_write_cannot_be_minted_into() {
    let cs = parent_cspace();
    let (_space, status) = run_recording(mint_prog(CHILD_RO, GIFT, TARGET).as_slice(), &cs);
    assert_eq!(
        status as usize,
        result::ERR_BAD_CAP,
        "a read-only CNode capability was written through"
    );
    assert!(child_of(&cs).read(TARGET, D).unwrap().is_null(), "the refused copy landed anyway");
}

#[test_case]
fn invoking_your_own_root_cnode_still_mints_into_your_own_space() {
    let cs = parent_cspace();
    // The one call site every program up to M7d used, unchanged (D-043).
    let (_space, status) = run_recording(mint_prog(1, GIFT, TARGET).as_slice(), &cs);
    assert_eq!(status as usize, result::OK);

    let landed = cs.read(TARGET, D).expect("nothing in our own space");
    assert_eq!(landed.paddr, cs.read(GIFT, D).unwrap().paddr);
    assert!(child_of(&cs).read(TARGET, D).unwrap().is_null(), "it went to the child instead");
}

#[test_case]
fn a_frame_is_not_a_capability_space_to_mint_into() {
    let cs = parent_cspace();
    let (_space, status) = run_recording(mint_prog(GIFT, GIFT, TARGET).as_slice(), &cs);
    // `invoke` dispatches on the invoked object's kind before any label is
    // read, so a frame is offered `Map`/`Unmap` and never reaches the CNode
    // path at all -- the wrong label, not a bad capability.
    assert_eq!(status as usize, result::ERR_BAD_LABEL, "a frame was treated as a CNode");
    assert!(cs.read(TARGET, D).unwrap().is_null());
}

#[test_case]
fn what_a_child_receives_is_still_revocable_by_its_parent() {
    let mut cs = parent_cspace();
    let (_space, status) = run_recording(mint_prog(CHILD, GIFT, TARGET).as_slice(), &cs);
    assert_eq!(status as usize, result::OK);

    // Authority delegated across a capability space boundary is authority the
    // delegator can still take back: the copy is a derivative, not a peer.
    assert_eq!(cs.descendants(GIFT, D).unwrap(), 1);
    assert_eq!(cs.revoke(GIFT, D).unwrap(), 1);
    assert!(child_of(&cs).read(TARGET, D).unwrap().is_null(), "the child kept a revoked frame");
}

#[test_case]
fn a_child_cnode_is_only_as_deep_as_its_own_radix() {
    let cs = parent_cspace();
    let child = child_of(&cs);
    assert_eq!(child.root_depth(), D, "the child's radix is not its own");

    // 2^D slots, so an index above that wraps into the child rather than
    // reaching past it -- there is no second level to reach into.
    let (_space, status) = run_recording(mint_prog(CHILD, GIFT, 1 << D).as_slice(), &cs);
    assert_eq!(status as usize, result::OK);
    assert!(!child.read(0, D).unwrap().is_null(), "the index did not wrap to slot 0");
}

// --- Boot modules reach userspace ---

#[test_case]
fn the_kernel_carries_at_least_one_module_it_does_not_load() {
    assert!(!kernel::root::MODULES.is_empty());
    for (name, bytes) in kernel::root::MODULES {
        assert!(!name.is_empty(), "a module with no name cannot be asked for");
        assert!(bytes.len() > 64, "module {name} is too small to be an ELF");
        assert_ne!(
            bytes.as_ptr(),
            kernel::root::IMAGE.as_ptr(),
            "module {name} is the root task image again"
        );
    }
}

#[test_case]
fn a_module_name_survives_the_round_trip_through_the_boot_info() {
    for (name, bytes) in kernel::root::MODULES {
        let desc = abi::bootinfo::ModuleDesc::new(0x3020_0000, bytes.len() as u64, name);
        assert_eq!(desc.name(), name, "a module name did not survive being written down");
    }
    // Longer than the field, truncated rather than overrunning it.
    let long = abi::bootinfo::ModuleDesc::new(0, 0, "a-name-far-longer-than-sixteen-bytes");
    assert_eq!(long.name().len(), 16);
}
