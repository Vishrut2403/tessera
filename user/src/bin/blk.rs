//! The virtio-blk driver: a process of its own (D-043), brought up without
//! ambient authority (D-044), and a block server (D-046).
//!
//! It holds no ambient authority at all: a CSpace, an address space, a TCB, an
//! endpoint to its parent, one untyped region, and the device untypeds it was
//! handed to probe. It cannot claim an interrupt -- only its parent holds
//! `IrqControl` -- so it asks.

#![no_std]
#![no_main]

use rt::abi::{MessageInfo, ObjectType, PAGE_SIZE, bootinfo, rights};
use rt::virtio::{self, Queue, Transport, desc_flags};
use rt::{block, entry, println, spawn, sys, vm};

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

/// After this many blocks the driver walks into memory it holds no capability
/// for. A crash we schedule is still a crash: the kernel reports it as a fault
/// and the supervisor has to cope with it (D-048).
const CRASH_AFTER: usize = 4;

/// Two sectors far apart and clear of the filesystem, so "it always returns
/// block zero" is not a way to
/// pass. `kernel/build.rs` writes each block's own number into it.
const READ_SECTORS: [u64; 2] = [100, 1000];

fn main() {
    let id = sys::thread_id();
    println!("  blk driver    : running as thread {id}, in an address space of its own");

    let vspace = bootinfo::slot::VSPACE;
    let mut alloc = vm::Alloc::new(spawn::UNTYPED, spawn::FIRST_FREE);

    // The parent tells us whether we are the first driver or a replacement for
    // one that died. Only the first is asked to crash (D-048).
    let first_life = spawn::say_hello(MAGIC) == spawn::FIRST_LIFE;

    let mut frames = [0u64; CANDIDATES];
    let brought_up = match probe(&mut alloc, vspace, &mut frames) {
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

            bring_up(&mut alloc, vspace, &transport)
                .map(|(queue, sectors)| {
                    let verified = read_sectors(&queue, &transport);
                    (queue, transport, sectors, verified)
                })
        }
        None => {
            println!("    probe         : no block device behind any of {CANDIDATES} transports");
            None
        }
    };

    // Sent *before* the server loop, and sent whether or not the device came
    // up. Our parent is blocked in `recv` until it arrives -- and it is the
    // parent that then spawns the client we are about to wait for, so a driver
    // that started serving first would deadlock the pair of them.
    let (sectors, verified) = brought_up.as_ref().map_or((0, 0), |(_, _, s, v)| (*s, *v));
    sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(spawn::READY, 2, false),
        [sectors as usize, verified, 0, 0],
    );

    // From here we are a server rather than a program that read two sectors.
    if let Some((queue, transport, _, _)) = brought_up {
        let served = serve_blocks(&queue, &transport, first_life);
        println!("    served        : {served} blocks before the client said stop");
    }
}

/// Read each of `READ_SECTORS` and check the block says which one it is.
/// Returns how many came back correct.
fn read_sectors(queue: &Queue, transport: &Transport) -> usize {
    let mut verified = 0;
    for sector in READ_SECTORS {
        match read_into(queue, transport, sector, queue.pa() + DATA_OFF as u64) {
            Some(()) => {
                // SAFETY: our own frame, at the offset we just told the device
                // to fill.
                let (first, last) = unsafe {
                    (
                        ((queue.va() + DATA_OFF) as *const u64).read_volatile(),
                        ((queue.va() + DATA_OFF + SECTOR - 8) as *const u64).read_volatile(),
                    )
                };
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

/// One 512-byte read into `dest_pa`: a three-descriptor chain, a kick, and a
/// *blocking* wait on the notification. The run queue is empty while we are in
/// `wait`, so the kernel idles until the device raises its line (D-041).
///
/// `dest_pa` is a bare physical address on purpose. When a client asks for a
/// block that address is the *client's* frame, which this driver never maps and
/// therefore never has in its own address space at all (D-046).
fn read_into(queue: &Queue, transport: &Transport, sector: u64, dest_pa: u64) -> Option<()> {
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
    queue.set_desc(1, dest_pa, SECTOR as u32, desc_flags::NEXT | desc_flags::WRITE, 2);
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

    Some(())
}

/// Serve blocks until a client says stop. `reply_recv` is the loop the kernel
/// was built around (D-031): one syscall answers the last caller and waits for
/// the next, and the scheduler is never consulted on the way through.
fn serve_blocks(queue: &Queue, transport: &Transport, may_crash: bool) -> usize {
    let ok = MessageInfo::new(0, 1, false);
    // Kept across requests, and *not* across a restart: a driver rebuilt from
    // scratch has never heard of anyone, which is what forces its client to
    // say who it is again (D-048).
    let mut client_pa: Option<u64> = None;
    let mut served = 0usize;

    // Every receive names a slot, because a connect carries a capability and
    // may arrive at any time -- the first message a restarted driver gets is
    // a read from a client that thinks it is still connected.
    let mut msg = sys::recv_cap(spawn::SERVICE, spawn::CLIENT_FRAME);
    loop {
        let status = match msg.info.label() {
            block::CONNECT => match sys::get_address(spawn::CLIENT_FRAME) {
                // Asked for, never mapped: a descriptor needs a physical
                // address and nothing else, so a client's page is never in
                // this driver's address space at all (D-040, D-046).
                Ok(pa) => {
                    println!("    connected     : client buffer at {pa:#x}, never mapped here");
                    client_pa = Some(pa as u64);
                    block::OK
                }
                Err(_) => block::FAILED,
            },
            block::READ => match client_pa {
                None => block::NO_BUFFER,
                Some(pa) => match read_into(queue, transport, msg.words[0] as u64, pa) {
                    Some(()) => {
                        served += 1;
                        block::OK
                    }
                    None => block::FAILED,
                },
            },
            block::SHUTDOWN => {
                let _ = sys::reply(ok, [block::OK, 0, 0, 0]);
                return served;
            }
            _ => block::FAILED,
        };

        if may_crash && served == CRASH_AFTER {
            // Answer first: once we are dead nobody can wake a caller blocked
            // in `call`, so the crash happens between requests, never during
            // one (D-048).
            let _ = sys::reply(ok, [status, 0, 0, 0]);
            crash();
        }
        msg = sys::reply_recv_cap(spawn::SERVICE, ok, [status, 0, 0, 0], spawn::CLIENT_FRAME);
    }
}

/// Read an address we hold no capability for. The kernel turns that into IPC
/// to our fault endpoint (D-034), and we never run again.
fn crash() -> ! {
    println!("    crashing      : touching an address we hold no capability for");
    // SAFETY: none, deliberately. This read is the fault.
    unsafe { core::ptr::read_volatile(0xdead_0000 as *const u64) };
    unreachable!("the kernel let a read of unmapped memory complete")
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
