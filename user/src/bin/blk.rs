//! The virtio-blk driver, as a process of its own (D-043, D-044).
//!
//! It holds no ambient authority at all: a CSpace, an address space, a TCB, an
//! endpoint to its parent, one untyped region, and the device untypeds it was
//! handed to probe. It cannot claim an interrupt -- only its parent holds
//! `IrqControl` -- so it asks.

#![no_std]
#![no_main]

use rt::abi::{MessageInfo, ObjectType, PAGE_SIZE, bootinfo, rights};
use rt::virtio::{self, Queue, Transport, desc_flags};
use rt::{entry, println, spawn, sys, vm};

entry!(main);

/// What the driver writes to the page its parent gave it. Distinct from the
/// parent's own word at the same address, which is the whole point.
pub const MAGIC: u64 = 0xb10c_0000_0000_0001;

/// Where the transports being probed are mapped, one page each.
const TRANSPORT_VADDR: usize = 0x1200_0000;
/// Where the one virtqueue lives.
const QUEUE_VADDR: usize = 0x1300_0000;
/// How many transports the parent hands over to probe.
const CANDIDATES: usize = 8;
/// virtio-blk puts its capacity, in 512-byte sectors, first in config space.
const BLK_CAPACITY: usize = 0;

/// The request buffers, in the same frame as the rings and clear of them.
const HEADER_OFF: usize = 512;
const DATA_OFF: usize = 1024;
const STATUS_OFF: usize = 2048;
const SECTOR: usize = 512;

/// A read request, and the status the device reports for one that worked.
const BLK_T_IN: u32 = 0;
const BLK_S_OK: u8 = 0;

/// Two sectors far apart, so "it always returns block zero" is not a way to
/// pass. `kernel/build.rs` writes each block's own number into it.
const READ_SECTORS: [u64; 2] = [5, 1000];

fn main() {
    let id = sys::thread_id();
    println!("  blk driver    : running as thread {id}, in an address space of its own");

    let vspace = bootinfo::slot::VSPACE;
    let mut alloc = vm::Alloc::new(spawn::UNTYPED, spawn::FIRST_FREE);

    say_hello(id);

    let mut frames = [0u64; CANDIDATES];
    let (sectors, verified) = match probe(&mut alloc, vspace, &mut frames) {
        Some((index, transport)) => {
            // Only the parent holds `IrqControl`, so the source is its to
            // claim. It also takes back the transports we did not want, which
            // is why probing broadly does not leave us holding seven devices
            // we have no use for.
            let reply = sys::call(
                bootinfo::slot::ENDPOINT,
                MessageInfo::new(spawn::CLAIM_IRQ, 1, false),
                [index, 0, 0, 0],
            );
            println!("    parent claimed: source {} for us", reply.words[0]);

            // The transports we probed but did not keep are gone. Deleting the
            // untyped in our CSpace revoked what we derived from it, so the
            // frame we mapped over those registers went with it -- asking that
            // frame where it is now finds nothing (D-043).
            let other = (index + 1) % CANDIDATES;
            assert!(
                sys::get_address(frames[other]).is_err(),
                "a frame derived from a revoked transport survived"
            );
            assert!(sys::get_address(frames[index]).is_ok(), "our own transport went with them");
            println!("    narrowed      : the transports we did not keep are no longer ours");

            match bring_up(&mut alloc, vspace, &transport) {
                Some((queue, sectors)) => (sectors, read_sectors(&queue, &transport)),
                None => (0, 0),
            }
        }
        None => {
            println!("    probe         : no block device behind any of {CANDIDATES} transports");
            (0, 0)
        }
    };

    // Always sent, success or not: the parent is blocked in `recv` and a
    // driver that gives up silently would hang it.
    sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::READY, 2, false),
        [sectors as usize, verified, 0, 0],
    );
}

/// Read each of `READ_SECTORS` and check the block says which one it is.
/// Returns how many came back correct.
fn read_sectors(queue: &Queue, transport: &Transport) -> usize {
    let mut verified = 0;
    for sector in READ_SECTORS {
        match read_one(queue, transport, sector) {
            Some((first, last)) => {
                // Each block of the image carries its own number at both ends,
                // so a read of the wrong block says which one it fetched.
                let want = 0x07e5_5e7a_0000_0000 | sector;
                if first == want && last == sector {
                    verified += 1;
                    println!("    read sector {sector:<4}: {first:#x}, and {last} at the far end");
                } else {
                    println!("    read sector {sector:<4}: wrong block -- {first:#x} / {last}");
                }
            }
            None => println!("    read sector {sector:<4}: failed"),
        }
    }
    verified
}

/// One 512-byte read: a three-descriptor chain, a kick, and a *blocking* wait
/// on the notification. The run queue is empty while we are in `wait`, so the
/// kernel idles until the device raises its line (D-041).
fn read_one(queue: &Queue, transport: &Transport, sector: u64) -> Option<(u64, u64)> {
    let (va, pa) = (queue.va(), queue.pa());

    // SAFETY: our own frame, mapped read-write, and these offsets are past the
    // three rings.
    unsafe {
        ((va + HEADER_OFF) as *mut u32).write_volatile(BLK_T_IN);
        ((va + HEADER_OFF + 4) as *mut u32).write_volatile(0);
        ((va + HEADER_OFF + 8) as *mut u64).write_volatile(sector);
        // A value the device must overwrite, so "it never ran" cannot read as
        // "it said ok".
        ((va + STATUS_OFF) as *mut u8).write_volatile(0xff);
    }

    // Three descriptors, because the flags are how the device learns which
    // parts it may write, and the status must be separate from the data.
    queue.set_desc(0, pa + HEADER_OFF as u64, 16, desc_flags::NEXT, 1);
    queue.set_desc(1, pa + DATA_OFF as u64, SECTOR as u32, desc_flags::NEXT | desc_flags::WRITE, 2);
    queue.set_desc(2, pa + STATUS_OFF as u64, 1, desc_flags::WRITE, 0);

    let before = queue.used_idx();
    queue.submit(0);
    transport.notify(0);

    let word = sys::wait(spawn::NOTIFICATION);

    // Clear the device's own reason first, then unmask the source: the
    // controller ignores a completion for a source that is not enabled, and a
    // device still asserting would raise again immediately (D-041).
    transport.ack_interrupt(transport.interrupt_status());
    sys::irq_ack(spawn::IRQ_HANDLER).ok()?;

    if word != spawn::DEVICE_BADGE {
        println!("    woken by {word:#x}, which is not the disk");
        return None;
    }
    if queue.used_idx() == before {
        println!("    the device raised an interrupt without finishing anything");
        return None;
    }

    let (id, len) = queue.used(before as usize);
    // SAFETY: the buffers the device has just finished writing.
    let status = unsafe { ((va + STATUS_OFF) as *const u8).read_volatile() };
    if id != 0 || status != BLK_S_OK {
        println!("    chain {id} came back with status {status:#x}, {len} bytes");
        return None;
    }

    // SAFETY: as above -- the 512-byte data buffer.
    unsafe {
        Some((
            ((va + DATA_OFF) as *const u64).read_volatile(),
            ((va + DATA_OFF + SECTOR - 8) as *const u64).read_volatile(),
        ))
    }
}

/// The isolation demonstration: our page at the address our parent also has a
/// page at holds our word, not theirs.
fn say_hello(id: usize) {
    // SAFETY: the parent mapped a frame here read-write before resuming us.
    let seen = unsafe {
        let p = spawn::SHARED_VADDR as *mut u64;
        p.write_volatile(MAGIC);
        p.read_volatile()
    };

    // We hold the endpoint with `WRITE` and nothing else, which is exactly
    // what `call` needs: the reply arrives through the Reply capability the
    // kernel mints, never back through the endpoint (D-042).
    let reply = sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::HELLO, 3, false),
        [id, seen as usize, spawn::SHARED_VADDR, 0],
    );
    println!("    shared page   : wrote {seen:#x} at {:#x}", spawn::SHARED_VADDR);
    println!("    parent said   : {:#x}", reply.words[0]);

    // An empty slot names nothing that can be copied out of it.
    assert!(sys::mint(bootinfo::slot::CNODE, bootinfo::slot::NULL, 60, rights::ALL, 0).is_err());
    assert!(
        sys::mint(bootinfo::slot::CNODE, bootinfo::slot::IRQ_CONTROL, 60, rights::ALL, 0).is_err(),
        "a driver was holding IrqControl"
    );
}

/// Map each transport the parent handed over and ask what is behind it.
/// Reading a transport is how a device is identified: the register block is
/// there whether or not QEMU attached anything, and an empty one answers zero.
fn probe(
    alloc: &mut vm::Alloc,
    vspace: u64,
    frames: &mut [u64; CANDIDATES],
) -> Option<(usize, Transport)> {
    let mut found = None;
    for i in 0..CANDIDATES {
        let at = TRANSPORT_VADDR + i * PAGE_SIZE;

        // A device untyped becomes a frame and nothing else (D-040).
        let frame = alloc.take();
        frames[i] = frame;
        if sys::retype(spawn::FIRST_DEVICE + i as u64, ObjectType::Frame, 0, frame, 1).is_err() {
            continue;
        }
        if vm::map(alloc, vspace, frame, at, rights::READ | rights::WRITE, false).is_err() {
            continue;
        }

        // SAFETY: a virtio-mmio register page we just mapped read-write, and
        // no other `Transport` names it.
        let transport = unsafe { Transport::new(at) };
        match transport.identify() {
            Ok(virtio::DEVICE_BLOCK) if found.is_none() => {
                println!("    transport {i}   : block device, vendor {:#x}", transport.vendor());
                found = Some((i, transport));
            }
            Ok(other) => println!("    transport {i}   : device type {other}, not ours"),
            Err(e) => println!("    transport {i}   : {e:?}"),
        }
    }
    found
}

/// Reset, negotiate, hand the device a queue, and say it may start. Returns
/// the capacity in sectors, or zero if the device would not come up: nothing
/// here panics, because a dead driver would leave its parent blocked.
fn bring_up(
    alloc: &mut vm::Alloc,
    vspace: u64,
    transport: &Transport,
) -> Option<(Queue, u64)> {
    if let Err(e) = transport.negotiate() {
        println!("    negotiation   : refused, {e:?}");
        return None;
    }
    println!("    negotiated    : status {:#x}, features accepted", transport.status());

    // One frame holds the descriptor table, the available ring and the used
    // ring. The device is a bus master, so what it is given is the *physical*
    // address -- which is why `GetAddress` needs `WRITE` on the frame (D-040).
    let Ok(frame) = alloc.object(ObjectType::Frame, 0) else { return None };
    let rw = rights::READ | rights::WRITE;
    if vm::map(alloc, vspace, frame, QUEUE_VADDR, rw, false).is_err() {
        println!("    queue 0       : could not be mapped");
        return None;
    }
    let Ok(base) = sys::get_address(frame) else { return None };

    // SAFETY: a frame we retyped -- so it arrived zeroed -- mapped read-write
    // at `QUEUE_VADDR`, and `get_address` says where the device sees it.
    let queue = unsafe { Queue::new(QUEUE_VADDR, base as u64) };

    match transport.configure_queue(0, queue.desc_pa(), queue.avail_pa(), queue.used_pa()) {
        Ok(max) => println!(
            "    queue 0       : {} of {max} slots, rings at {:#x} physical",
            virtio::QUEUE_SIZE,
            queue.pa()
        ),
        Err(e) => {
            println!("    queue 0       : refused, {e:?}");
            return None;
        }
    }

    transport.finish();
    let sectors = transport.config_u64(BLK_CAPACITY);
    println!(
        "    driver ok     : status {:#x}, {sectors} sectors, {} KiB",
        transport.status(),
        sectors / 2
    );
    Some((queue, sectors))
}
