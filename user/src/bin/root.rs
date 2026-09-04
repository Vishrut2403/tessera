//! The root task: the first program, and the last thing the kernel creates.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

use rt::abi::{BootInfo, MessageInfo, ObjectType, bootinfo, rights};
use rt::abi::bootinfo::ModuleDesc;
use rt::fdt::{Device, Fdt};
use rt::{entry, println, spawn, sys, thread_entry};

entry!(main);

/// Written by the child thread, read by the root task.
static CHILD_RAN: AtomicUsize = AtomicUsize::new(0);

/// Written to the scratch page when the root task has finished successfully.
pub const DONE: u64 = 0xd02e_0000_0000_0000;

/// What the root task writes to the page it shares an *address* -- not a page
/// -- with the task it spawns.
pub const PARENT_MAGIC: u64 = 0x0dad_0000_0000_0001;

/// Written to the scratch page once a spawned task has answered.
pub const SPAWNED: u64 = 0x5b1c_0000_0000_0000;

fn main() {
    // SAFETY: the kernel mapped a `BootInfo` here read-only before we ran, and
    // the magic and version are checked before anything else is believed.
    let bi = unsafe { &*(bootinfo::VADDR as *const BootInfo) };
    assert!(bi.is_valid(), "boot info page is not a boot info page");

    println!();
    println!("root task: hello from userspace, thread {}", sys::thread_id());
    println!("  image         : {:#x}..{:#x}", bi.image_start, bi.image_end);
    println!("  stack         : {:#x}..{:#x}", bi.stack_bottom, bi.stack_top);
    println!("  boot info     : {:#x}", bi.bootinfo_vaddr);
    println!("  free from     : {:#x}", bi.free_vaddr);
    println!("  cspace        : {} slots, radix {}", bi.cnode_slots, bi.cnode_radix);
    println!("  free slots    : {}..{}", bi.first_free_slot, bi.cnode_slots);

    let mut total = 0u64;
    for u in bi.untypeds() {
        total += u.bytes();
    }
    println!("  untyped       : {} regions, {} KiB total", bi.untyped_count, total / 1024);
    for (i, u) in bi.untypeds().iter().enumerate() {
        println!(
            "    slot {:<3}    : {:#012x}  2^{} = {} KiB{}",
            bi.untyped_slot(i),
            u.paddr,
            u.size_bits,
            u.bytes() / 1024,
            if u.is_device != 0 { "  (device)" } else { "" }
        );
    }

    // The biggest region that is actually memory.
    let (best, _) = bi
        .untypeds()
        .iter()
        .enumerate()
        .filter(|(_, u)| u.is_device == 0)
        .max_by_key(|(_, u)| u.size_bits)
        .expect("no untyped memory");
    let ut = bi.untyped_slot(best);

    // Slots we allocate ourselves, starting where the kernel stopped.
    let f = bi.first_free_slot;
    let (l1, l0, scratch, child_stack, child_tcb) = (f, f + 1, f + 2, f + 3, f + 4);

    sys::retype(ut, ObjectType::PageTable, 0, l1, 2).expect("retype page tables");
    sys::retype(ut, ObjectType::Frame, 0, scratch, 2).expect("retype frames");
    sys::retype(ut, ObjectType::Tcb, 0, child_tcb, 1).expect("retype tcb");
    println!();
    println!("  retyped       : 2 page tables, 2 frames, 1 thread out of slot {ut}");

    // Nothing maps `base` yet, and the two intermediate levels do not exist
    // either -- the kernel will not create them, so we do (D-035).
    let base = bi.free_vaddr as usize;
    let vspace = bootinfo::slot::VSPACE;
    sys::map_table(l1, vspace, base, 2).expect("map l1");
    sys::map_table(l0, vspace, base, 1).expect("map l0");
    sys::map_frame(scratch, vspace, base, rights::READ | rights::WRITE, false).expect("map frame");

    // SAFETY: a frame we retyped and just mapped read-write at `base`.
    unsafe {
        let p = base as *mut u64;
        p.write_volatile(0x7e55e7a);
        assert_eq!(p.read_volatile(), 0x7e55e7a);
    }
    println!("  mapped        : {base:#x} rw, wrote and read back a word");
    let phys = sys::get_address(scratch).expect("get_address");
    println!("  physically at : {phys:#x}  (what a virtqueue descriptor needs)");

    // A second thread in this address space: its own stack, our CSpace, our
    // page tables, and an entry point in the text we are running out of.
    let stack = base + 0x1000;
    sys::map_frame(child_stack, vspace, stack, rights::READ | rights::WRITE, false)
        .expect("map child stack");
    sys::tcb_configure(child_tcb, bootinfo::slot::CNODE, vspace, 0).expect("configure");
    sys::tcb_write_registers(child_tcb, child_start as *const () as usize, stack + 0x1000)
        .expect("write registers");
    sys::tcb_resume(child_tcb).expect("resume");
    println!("  spawned       : a thread at {:#x} on a stack at {:#x}", child_start as *const () as usize, stack);

    // Bounded: a child that never runs must fail the run, not hang it.
    let mut spins = 0;
    while CHILD_RAN.load(Ordering::Acquire) == 0 && spins < 1000 {
        sys::yield_now();
        spins += 1;
    }
    let child_id = CHILD_RAN.load(Ordering::Acquire);
    if child_id == 0 {
        println!("  child said    : nothing, after {spins} yields");
    } else {
        println!("  child said    : {child_id}");
    }

    // The finish line, in memory the kernel can read once we are done: reaching
    // here means every step above succeeded, and a panic would have exited
    // before writing it.
    // SAFETY: the scratch frame is still mapped read-write at `base`.
    unsafe { (base as *mut u64).add(1).write_volatile(DONE | child_id as u64) };

    check_device_untyped(bi, vspace, f + 8, base + 0x10000, ut);
    wait_for_an_interrupt(bi, vspace, ut, f + 16, base + 0x20000);
    let (spawned, disk, served) = spawn_a_driver(bi, vspace, ut, f + 24, base + 0x30000);

    // SAFETY: the scratch frame is still mapped read-write at `base`.
    unsafe {
        (base as *mut u64).add(4).write_volatile(spawned);
        (base as *mut u64).add(5).write_volatile(disk);
        (base as *mut u64).add(6).write_volatile(served as u64);
    }

    println!();
    println!("root task: done.");
}

/// Load a boot module into a process of its own -- new address space, new
/// capability space, new thread -- with no help from the kernel (D-043), then
/// bring it up as a device driver over the endpoint it starts with (D-044).
fn spawn_a_driver(
    bi: &BootInfo,
    vspace: u64,
    ram: u64,
    first_slot: u64,
    scratch: usize,
) -> (u64, u64, usize) {
    println!();
    println!("  spawning:");

    let (Some(blk), Some(fs), Some(client)) =
        (bi.module("blk"), bi.module("fs"), bi.module("client"))
    else {
        println!("    the boot info is missing a module");
        return (0, 0, 0);
    };
    println!("    modules       : {}, {} and {}", blk.name(), fs.name(), client.name());

    // A page of our own at the address every child will also have a page at.
    // Four processes, one virtual address, four different frames.
    let (ours, blk_ram, fs_ram, client_ram) =
        (first_slot, first_slot + 1, first_slot + 2, first_slot + 3);
    let (blk_service, fs_service) = (first_slot + 4, first_slot + 5);
    let (handler, ntfn, badged) = (first_slot + 6, first_slot + 7, first_slot + 8);

    sys::retype(ram, ObjectType::Frame, 0, ours, 1).expect("shared frame");
    sys::map_frame(ours, vspace, spawn::SHARED_VADDR, rights::READ | rights::WRITE, false)
        .expect("map ours");
    // SAFETY: a frame we just retyped and mapped read-write.
    unsafe { (spawn::SHARED_VADDR as *mut u64).write_volatile(PARENT_MAGIC) };

    // Memory of their own to retype from: a task that had to ask us for every
    // page table would not be much of a separate process.
    sys::retype(ram, ObjectType::Untyped, 18, blk_ram, 1).expect("driver untyped");
    sys::retype(ram, ObjectType::Untyped, 17, fs_ram, 1).expect("fs untyped");
    sys::retype(ram, ObjectType::Untyped, 16, client_ram, 1).expect("client untyped");

    // Two endpoints, four halves. Each server holds one with `READ` and cannot
    // send on it; each client holds one with `WRITE` and cannot receive on it.
    // Nobody can impersonate the service they use (D-042).
    sys::retype(ram, ObjectType::Endpoint, 0, blk_service, 1).expect("block service");
    sys::retype(ram, ObjectType::Endpoint, 0, fs_service, 1).expect("fs service");

    let mut nursery = spawn::Nursery::new(ram, first_slot + 9, vspace, scratch);

    // --- The driver: a device, an interrupt, and one service to answer ---
    let (transports, count) = virtio_transports(bi);
    let mut grants = [spawn::Grant { src: 0, dst: 0, rights: 0 }; 2 + MAX_TRANSPORTS];
    grants[0] = spawn::Grant { src: blk_ram, dst: spawn::UNTYPED, rights: rights::ALL };
    grants[1] = spawn::Grant { src: blk_service, dst: spawn::SERVICE, rights: rights::READ };
    for i in 0..count {
        grants[i + 2] = spawn::Grant {
            src: transports[i].1,
            dst: spawn::FIRST_DEVICE + i as u64,
            rights: rights::ALL,
        };
    }
    println!("    driver gets   : 256 KiB, {count} transports, and READ on the block service");
    let driver = spawn::spawn(module_bytes(blk), &mut nursery, &grants[..count + 2]).expect("blk");
    let (result, ready) = serve(&driver, &transports[..count], ram, handler, ntfn, badged);
    let (sectors, verified) = (ready & 0xffff_ffff, ready >> 32);
    println!("    driver up     : {sectors} sectors, {verified} of its own reads verified");
    assert!(sectors > 0, "the driver never brought a device up");
    assert_eq!(verified, 2, "the driver read back {verified} of its own 2 sectors");

    // --- The filesystem: a client of the driver, a server to everyone else ---
    let fs_grants = [
        spawn::Grant { src: fs_ram, dst: spawn::UNTYPED, rights: rights::ALL },
        spawn::Grant { src: blk_service, dst: spawn::UPSTREAM, rights: rights::WRITE },
        spawn::Grant { src: fs_service, dst: spawn::SERVICE, rights: rights::READ },
    ];
    println!("    fs gets       : 128 KiB, WRITE on the block service, READ on its own");
    let server = spawn::spawn(module_bytes(fs), &mut nursery, &fs_grants).expect("fs");
    let (_, mounted) = serve(&server, &[], ram, handler, ntfn, badged);
    println!("    fs up         : {} files", mounted & 0xffff_ffff);
    assert!(mounted & 0xffff_ffff > 0, "the filesystem server mounted nothing");

    // --- The client: a name, and nothing else ---
    let client_grants = [
        spawn::Grant { src: client_ram, dst: spawn::UNTYPED, rights: rights::ALL },
        spawn::Grant { src: fs_service, dst: spawn::UPSTREAM, rights: rights::WRITE },
    ];
    println!("    client gets   : 64 KiB and WRITE on the fs service, and nothing else");
    let task = spawn::spawn(module_bytes(client), &mut nursery, &client_grants).expect("client");
    let (_, ready) = serve(&task, &[], ram, handler, ntfn, badged);
    let checks = ready & 0xffff_ffff;
    println!("    client done   : {checks} of 3 checks passed against the filesystem");

    (result, sectors | verified << 32, checks as usize)
}

/// A boot module's bytes, as the root task sees them.
fn module_bytes(module: &ModuleDesc) -> &'static [u8] {
    // SAFETY: the kernel mapped the module read-only before we ran, and the
    // boot info says how long it is.
    unsafe { core::slice::from_raw_parts(module.vaddr as *const u8, module.size as usize) }
}

/// How many virtio-mmio transports the platform is expected to present.
const MAX_TRANSPORTS: usize = 8;

/// Every virtio-mmio transport the device tree names, paired with the device
/// untyped that covers it. Nothing is hardcoded: the tree says where each one
/// is and which source it raises.
fn virtio_transports(bi: &BootInfo) -> ([(Device, u64); MAX_TRANSPORTS], usize) {
    let mut out = [(Device::default(), 0u64); MAX_TRANSPORTS];
    let mut count = 0usize;

    // SAFETY: the kernel mapped the device tree read-only before we ran, and
    // the boot info says how long it is.
    let Some(fdt) = (unsafe { Fdt::new(bi.fdt_vaddr as *const u8, bi.fdt_size as usize) }) else {
        return (out, 0);
    };
    fdt.each_compatible(b"virtio,mmio", |device| {
        if count == MAX_TRANSPORTS {
            return;
        }
        // A transport we hold no capability for is one we cannot hand over.
        let found = bi
            .untypeds()
            .iter()
            .enumerate()
            .find(|(_, u)| u.is_device != 0 && u.paddr == device.paddr);
        if let Some((i, _)) = found {
            out[count] = (device, bi.untyped_slot(i));
            count += 1;
        }
    });
    (out, count)
}

/// The bring-up conversation, from the parent's side.
fn serve(
    child: &spawn::Child,
    transports: &[(Device, u64)],
    ram: u64,
    handler: u64,
    ntfn: u64,
    badged: u64,
) -> (u64, u64) {
    let mut result = 0u64;

    loop {
        let msg = sys::recv(child.endpoint);
        match msg.info.label() {
            spawn::HELLO => {
                // Answer before judging. A caller left blocked in `call` is a
                // hung system, and an assertion that hangs reports nothing --
                // the same reason `reply_recv` replies before it checks its
                // endpoint (D-042).
                sys::reply(MessageInfo::new(spawn::HELLO, 1, false), [0xacc_e5ed, 0, 0, 0])
                    .expect("reply");

                // SAFETY: our own frame, still mapped where we put it.
                let ours = unsafe { (spawn::SHARED_VADDR as *const u64).read_volatile() };
                println!("    child said    : thread {}, wrote {:#x}", msg.words[0], msg.words[1]);
                println!("    {:#x}    : {ours:#x} to us, {:#x} to it", msg.words[2], msg.words[1]);
                assert_eq!(ours, PARENT_MAGIC, "the child reached into our address space");
                assert_ne!(msg.words[1] as u64, PARENT_MAGIC, "the child read our page");
                result = SPAWNED | msg.words[0] as u64;
            }
            spawn::CLAIM_IRQ => {
                let irq =
                    claim_for(child, transports, msg.words[0], ram, handler, ntfn, badged);
                sys::reply(MessageInfo::new(spawn::CLAIM_IRQ, 1, false), [irq, 0, 0, 0])
                    .expect("reply");
            }
            spawn::READY => {
                // Again: the caller is blocked in `call` until this returns,
                // and it has to be free to run on before anything is judged.
                sys::reply(MessageInfo::new(spawn::READY, 0, false), [0; 4]).expect("reply");
                let (w0, w1) = (msg.words[0] as u64, msg.words[1] as u64);
                return (result, w0 | w1 << 32);
            }
            other => {
                println!("    unknown message {other:#x} from the driver");
                sys::reply(MessageInfo::new(0, 0, false), [0; 4]).expect("reply");
                return (result, 0);
            }
        }
    }
}

/// Claim the source the driver asked for, bind it to a notification, hand both
/// over -- and take back every transport it did not keep. Probing needs breadth;
/// running does not (D-044).
#[allow(clippy::too_many_arguments)]
fn claim_for(
    child: &spawn::Child,
    transports: &[(Device, u64)],
    index: usize,
    ram: u64,
    handler: u64,
    ntfn: u64,
    badged: u64,
) -> usize {
    let Some((device, _)) = transports.get(index) else {
        println!("    claim         : the driver asked for a transport we never gave it");
        return 0;
    };
    let Some(irq) = device.irq else {
        println!("    claim         : transport {index} raises no interrupt");
        return 0;
    };

    sys::retype(ram, ObjectType::Notification, 0, ntfn, 1).expect("notification");
    sys::mint(bootinfo::slot::CNODE, ntfn, badged, rights::ALL, spawn::DEVICE_BADGE)
        .expect("mint badge");
    sys::irq_get(bootinfo::slot::IRQ_CONTROL, irq as usize, handler).expect("irq_get");
    sys::irq_set_notification(handler, badged).expect("bind");

    sys::mint(child.cnode, handler, spawn::IRQ_HANDLER, rights::ALL, 0).expect("mint handler");
    sys::mint(child.cnode, badged, spawn::NOTIFICATION, rights::READ, spawn::DEVICE_BADGE)
        .expect("mint ntfn");

    // Everything it probed but did not want. `delete` empties the slot in the
    // child's CNode and revokes what was derived from it, so the frame the
    // driver mapped over those registers is unmapped with it.
    let mut taken = 0;
    for i in 0..transports.len() {
        if i != index {
            let _ = sys::delete(child.cnode, spawn::FIRST_DEVICE + i as u64);
            taken += 1;
        }
    }
    println!(
        "    claim         : {:#x} raises source {irq}; {taken} unused transports taken back",
        device.paddr
    );
    irq as usize
}

/// Check what a device untyped is and is not allowed to become, from the
/// outside — the same checks the kernel's tests make, made by a user program
/// holding nothing but capabilities (D-040).
fn check_device_untyped(bi: &BootInfo, vspace: u64, first_slot: u64, at: usize, ram: u64) {
    println!();
    println!("  device untyped:");

    // The biggest device region, so the small single-page ones stay whole for
    // whoever actually wants that device.
    let (i, u) = bi
        .untypeds()
        .iter()
        .enumerate()
        .filter(|(_, u)| u.is_device != 0)
        .max_by_key(|(_, u)| u.size_bits)
        .expect("no device regions");
    let dev = bi.untyped_slot(i);
    let (frame, spare, weak) = (first_slot, first_slot + 1, first_slot + 2);

    // A device region becomes a frame, and nothing else.
    sys::retype(dev, ObjectType::Frame, 0, frame, 1).expect("device untyped -> frame");
    assert!(
        sys::retype(dev, ObjectType::PageTable, 0, spare, 1).is_err(),
        "a page table was carved out of device registers"
    );
    assert!(
        sys::retype(dev, ObjectType::Tcb, 0, spare, 1).is_err(),
        "a thread was carved out of device registers"
    );
    // And RAM cannot claim to be a device: that is the lie the type prevents.
    assert!(
        sys::retype(ram, ObjectType::DeviceUntyped, 12, spare, 1).is_err(),
        "ordinary memory was relabelled as device registers"
    );
    println!("    slot {dev:<3}      : {:#012x}, 2^{}", u.paddr, u.size_bits);
    println!("    retype        : frame yes; page table, thread, and RAM->device all refused");

    // The capability says where the frame is; the boot info said where the
    // region is.
    sys::map_frame(frame, vspace, at, rights::READ | rights::WRITE, false).expect("map device");
    let phys = sys::get_address(frame).expect("get_address");
    assert_eq!(phys as u64, u.paddr, "a device frame is not where its untyped said");
    println!("    mapped at     : {at:#x} -> {phys:#012x}, which the boot info agrees with");

    // `GetAddress` needs WRITE.
    sys::mint(bootinfo::slot::CNODE, frame, weak, rights::READ, 0).expect("mint");
    assert!(sys::get_address(weak).is_err(), "a read-only frame gave up its address");
    println!("    read-only copy: refused GetAddress, as it must");

    // SAFETY: the scratch frame is mapped read-write at `at - 0x10000`.
    unsafe { ((at - 0x10000) as *mut u64).add(2).write_volatile(u.paddr) };
}

/// Goldfish RTC registers, from the device tree's `google,goldfish-rtc`.
mod rtc {
    pub const TIME_LOW: usize = 0x00;
    pub const TIME_HIGH: usize = 0x04;
    pub const ALARM_LOW: usize = 0x08;
    pub const ALARM_HIGH: usize = 0x0c;
    pub const IRQ_ENABLED: usize = 0x10;
    pub const CLEAR_INTERRUPT: usize = 0x1c;
}

/// SAFETY: `at` must be inside a device frame this task has mapped read-write.
unsafe fn mmio_read(at: usize, off: usize) -> u32 {
    // SAFETY: the caller promised a mapped device register. Volatile because
    // reads of a register are not redundant even when the address repeats.
    unsafe { ((at + off) as *const u32).read_volatile() }
}

/// SAFETY: as above.
unsafe fn mmio_write(at: usize, off: usize, value: u32) {
    // SAFETY: as above.
    unsafe { ((at + off) as *mut u32).write_volatile(value) }
}

/// Take a real interrupt, in userspace, as a notification (D-041).
fn wait_for_an_interrupt(bi: &BootInfo, vspace: u64, ram: u64, first_slot: u64, at: usize) {
    println!();
    println!("  interrupts:");

    // SAFETY: the kernel mapped the device tree read-only before we ran, and
    // the boot info says how long it is.
    let fdt = unsafe { Fdt::new(bi.fdt_vaddr as *const u8, bi.fdt_size as usize) };
    let Some(fdt) = fdt else {
        println!("    no device tree");
        return;
    };
    let Some(dev) = fdt.find(b"google,goldfish-rtc") else {
        println!("    no real-time clock in the device tree");
        return;
    };
    let Some(irq) = dev.irq else {
        println!("    the clock raises no interrupt");
        return;
    };
    println!("    device tree   : rtc at {:#x}, source {irq}", dev.paddr);

    let Some((i, _)) = bi
        .untypeds()
        .iter()
        .enumerate()
        .find(|(_, u)| u.is_device != 0 && u.paddr == dev.paddr)
    else {
        println!("    no device untyped covers it");
        return;
    };

    let (frame, ntfn, badged, handler) =
        (first_slot, first_slot + 1, first_slot + 2, first_slot + 3);
    sys::retype(bi.untyped_slot(i), ObjectType::Frame, 0, frame, 1).expect("rtc frame");
    sys::retype(ram, ObjectType::Notification, 0, ntfn, 1).expect("notification");
    sys::map_frame(frame, vspace, at, rights::READ | rights::WRITE, false).expect("map rtc");

    // The kernel signals with the badge of the capability it was given, so the
    // one it holds is a badged copy: that bit in the word is what says "the
    // clock", as opposed to anything else this notification comes to serve.
    const CLOCK: u64 = 1 << 0;
    sys::mint(bootinfo::slot::CNODE, ntfn, badged, rights::ALL, CLOCK).expect("mint badge");

    sys::irq_get(bootinfo::slot::IRQ_CONTROL, irq as usize, handler).expect("irq_get");
    assert!(
        sys::irq_get(bootinfo::slot::IRQ_CONTROL, irq as usize, handler + 1).is_err(),
        "the same source was claimed twice"
    );
    sys::irq_set_notification(handler, badged).expect("bind");
    println!("    claimed       : source {irq}, bound to a notification badged {CLOCK:#x}");

    // Arm the clock 20 ms out. Reading TIME_LOW latches TIME_HIGH, so the
    // order of these two reads is the protocol, not a preference.
    // SAFETY: `at` is the clock's registers, mapped read-write just above.
    let target = unsafe {
        let low = mmio_read(at, rtc::TIME_LOW) as u64;
        let high = mmio_read(at, rtc::TIME_HIGH) as u64;
        ((high << 32) | low) + 20_000_000
    };
    // SAFETY: as above. High before low: writing the low half is what arms it.
    unsafe {
        mmio_write(at, rtc::IRQ_ENABLED, 1);
        mmio_write(at, rtc::ALARM_HIGH, (target >> 32) as u32);
        mmio_write(at, rtc::ALARM_LOW, target as u32);
    }
    println!("    armed         : alarm 20 ms out; waiting with an empty run queue");

    let word = sys::wait(badged);
    println!("    woken         : notification word {word:#x}");
    assert_eq!(word, CLOCK, "woken by something that was not the clock");

    // The source is still masked, and the clock is still asserting until its
    // own status is cleared. Clear it first, then say so.
    // SAFETY: as above.
    unsafe { mmio_write(at, rtc::CLEAR_INTERRUPT, 1) };
    sys::irq_ack(handler).expect("ack");
    println!("    acknowledged  : device quiet, source unmasked again");

    // SAFETY: the scratch frame is mapped read-write at `at - 0x20000`.
    unsafe { ((at - 0x20000) as *mut u64).add(3).write_volatile(word | (irq as u64) << 32) };
}

thread_entry!(child_start => child);

extern "C" fn child() {
    println!("  child thread  : running as thread {}", sys::thread_id());
    CHILD_RAN.store(sys::thread_id(), Ordering::Release);
}
