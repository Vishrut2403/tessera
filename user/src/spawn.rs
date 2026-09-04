//! Building a process out of a boot module, entirely in userspace (D-043).
//!
//! Nothing here is privileged: every step is an invocation on a capability the
//! parent already holds. The kernel is not told a process is being made.

use crate::abi::{MessageInfo, ObjectType, PAGE_SIZE, SLOT_BITS, bootinfo, label, rights};
use crate::elf::{Elf, ElfError, Segment};
use crate::{Error, println, sys, vm};

/// Where a spawned task finds the page its parent gave it. Both this and the
/// stack sit in the same 2 MiB region as the image, so one intermediate page
/// table covers the whole process.
pub const SHARED_VADDR: usize = 0x1010_0000;

const STACK_BOTTOM: usize = 0x1011_0000;
const STACK_PAGES: usize = 4;

/// The top of a spawned task's stack, which is what `WriteRegisters` is given.
pub const STACK_TOP: usize = STACK_BOTTOM + STACK_PAGES * PAGE_SIZE;

/// 2^6 slots: room for the four the child starts with and whatever it retypes.
pub const CNODE_RADIX: u8 = 6;

/// The bring-up protocol between a parent and the task it spawned, defined
/// once so both ends of the channel agree on it (D-038).
/// The first thing a spawned task says.
pub const HELLO: u64 = label::APP_BASE;
/// "Claim the interrupt source of the device in slot `FIRST_DEVICE + w0` for
/// me." Only the parent holds `IrqControl`, and only the child knows which
/// device it wants, so bring-up is two-phase (D-044).
pub const CLAIM_IRQ: u64 = label::APP_BASE + 1;
/// "I am up, and here is what I found." The last of the bring-up exchange.
pub const READY: u64 = label::APP_BASE + 2;

/// Slots a spawned task's CSpace may hold beyond the four it always gets.
/// Its own untyped memory.
pub const UNTYPED: u64 = bootinfo::slot::FIRST_UNTYPED;
/// The right to acknowledge one interrupt source, minted after it has asked.
pub const IRQ_HANDLER: u64 = 9;
/// The notification that source is bound to.
pub const NOTIFICATION: u64 = 10;
/// The badge a spawned driver's device interrupt arrives under, so both ends
/// agree on what a notification word means (D-038).
pub const DEVICE_BADGE: u64 = 1 << 1;
/// A service endpoint: the server holds it with `READ`, its clients with
/// `WRITE`, and neither can do the other's half (D-042).
pub const SERVICE: u64 = 11;
/// Where a server puts a capability a client hands it.
pub const CLIENT_FRAME: u64 = 12;
/// Device untypeds, one per candidate device, from here.
pub const FIRST_DEVICE: u64 = 16;
/// The first slot a spawned task may put objects of its own in.
pub const FIRST_FREE: u64 = 24;

/// One capability a parent hands a child at spawn time.
#[derive(Clone, Copy)]
pub struct Grant {
    /// The slot it lives in, in the parent's own CSpace.
    pub src: u64,
    /// The slot it will live in, in the child's.
    pub dst: u64,
    pub rights: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    Elf(ElfError),
    Sys(Error),
    /// The image runs into the addresses the stack and the shared page use.
    ImageTooLarge,
}

impl From<ElfError> for SpawnError {
    fn from(e: ElfError) -> Self {
        SpawnError::Elf(e)
    }
}

impl From<Error> for SpawnError {
    fn from(e: Error) -> Self {
        SpawnError::Sys(e)
    }
}

/// What a spawn draws on: memory to retype, slots to put the results in, and a
/// page of the parent's own address space to fill frames through.
pub struct Nursery {
    pub alloc: vm::Alloc,
    /// The parent's own address space, for the scratch mapping.
    pub vspace: u64,
    /// A page-aligned address in the parent that nothing is mapped at.
    pub scratch: usize,
}

impl Nursery {
    pub const fn new(untyped: u64, first_slot: u64, vspace: u64, scratch: usize) -> Self {
        Self { alloc: vm::Alloc::new(untyped, first_slot), vspace, scratch }
    }

    fn object(&mut self, kind: ObjectType, size_bits: u8) -> Result<u64, SpawnError> {
        Ok(self.alloc.object(kind, size_bits)?)
    }
}

/// A spawned task, named by the capabilities its parent kept.
pub struct Child {
    pub cnode: u64,
    pub vspace: u64,
    pub tcb: u64,
    /// The parent's end of the channel, held with every right.
    pub endpoint: u64,
    pub shared: u64,
    pub entry: usize,
}

/// Load `image` into a new address space, endow a new capability space, and
/// start a thread in it. The child is running when this returns.
pub fn spawn(image: &[u8], n: &mut Nursery, grants: &[Grant]) -> Result<Child, SpawnError> {
    let elf = Elf::parse(image)?;
    let (_, image_end) = elf.image_range()?;
    if image_end > SHARED_VADDR {
        return Err(SpawnError::ImageTooLarge);
    }

    let cnode = n.object(ObjectType::CNode, CNODE_RADIX + SLOT_BITS)?;
    let vspace = n.object(ObjectType::PageTable, 0)?;
    // A root page table is not an address space until it has the kernel's
    // upper half and an ASID, and `Assign` is what installs both (D-037).
    sys::assign(vspace)?;

    for segment in elf.segments() {
        load_segment(n, vspace, &segment?)?;
    }

    let rw = rights::READ | rights::WRITE;
    let shared = n.object(ObjectType::Frame, 0)?;
    vm::map(&mut n.alloc, vspace, shared, SHARED_VADDR, rw, false)?;

    for i in 0..STACK_PAGES {
        let frame = n.object(ObjectType::Frame, 0)?;
        vm::map(&mut n.alloc, vspace, frame, STACK_BOTTOM + i * PAGE_SIZE, rw, false)?;
    }

    let endpoint = n.object(ObjectType::Endpoint, 0)?;
    let tcb = n.object(ObjectType::Tcb, 0)?;

    // The child's whole world, in the slots `bootinfo::slot` names -- the same
    // convention the kernel uses for the root task, so one layout is learned
    // rather than two. The endpoint goes in with `WRITE` alone: the child is
    // the client here, and `call` needs no more than that (D-042).
    sys::mint(cnode, cnode, bootinfo::slot::CNODE, rights::ALL, 0)?;
    sys::mint(cnode, vspace, bootinfo::slot::VSPACE, rights::ALL, 0)?;
    sys::mint(cnode, tcb, bootinfo::slot::TCB, rights::ALL, 0)?;
    sys::mint(cnode, endpoint, bootinfo::slot::ENDPOINT, rights::WRITE, 0)?;

    // Whatever else this particular task is trusted with. Each is a derivative
    // of the parent's own capability, so the parent can take any of them back.
    for g in grants {
        sys::mint(cnode, g.src, g.dst, g.rights, 0)?;
    }

    sys::tcb_configure(tcb, cnode, vspace, 0)?;
    sys::tcb_write_registers(tcb, elf.entry(), STACK_TOP)?;
    sys::tcb_resume(tcb)?;

    Ok(Child { cnode, vspace, tcb, endpoint, shared, entry: elf.entry() })
}

/// Copy one `PT_LOAD` segment into fresh frames and map it into the child.
fn load_segment(n: &mut Nursery, vspace: u64, seg: &Segment) -> Result<(), SpawnError> {
    let mut mask = rights::READ;
    if seg.writable() {
        mask |= rights::WRITE;
    }

    let mut va = seg.vaddr & !(PAGE_SIZE - 1);
    let last = seg.vaddr + seg.mem_size;
    while va < last {
        let frame = n.object(ObjectType::Frame, 0)?;

        // The part of this page the file has bytes for. The rest stays zero,
        // which is what gives the `.bss` tail for free: retype zeroes frames.
        let from = va.max(seg.vaddr);
        let to = (va + PAGE_SIZE).min(seg.vaddr + seg.data.len());
        if to > from {
            sys::map_frame(frame, n.vspace, n.scratch, rights::READ | rights::WRITE, false)?;
            // SAFETY: a frame we just retyped, mapped read-write at `scratch`
            // in our own space, and `from - va` plus the length stays inside
            // the one page it covers.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    seg.data.as_ptr().add(from - seg.vaddr),
                    (n.scratch + (from - va)) as *mut u8,
                    to - from,
                );
            }
            sys::unmap(frame)?;
        }

        vm::map(&mut n.alloc, vspace, frame, va, mask, seg.executable())?;
        va += PAGE_SIZE;
    }
    Ok(())
}

/// The first exchange a spawned task has with its parent: write `magic` to the
/// page the parent gave it, prove what comes back is its own word and not the
/// parent's, and say which thread it is. Returns the parent's reply.
pub fn say_hello(magic: u64) -> u64 {
    // SAFETY: the parent mapped a frame here read-write before resuming us.
    let seen = unsafe {
        let p = SHARED_VADDR as *mut u64;
        p.write_volatile(magic);
        p.read_volatile()
    };

    // We hold the endpoint with `WRITE` and nothing else, which is exactly what
    // `call` needs: the reply arrives through the Reply capability the kernel
    // mints, never back through the endpoint (D-042).
    let reply = sys::call(
        bootinfo::slot::ENDPOINT,
        MessageInfo::new(HELLO, 3, false),
        [sys::thread_id(), seen as usize, SHARED_VADDR, 0],
    );
    println!("    shared page   : wrote {seen:#x} at {SHARED_VADDR:#x}");
    println!("    parent said   : {:#x}", reply.words[0]);
    reply.words[0] as u64
}
