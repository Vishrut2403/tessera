//! Building a process out of a boot module, entirely in userspace (D-043).
//!
//! Nothing here is privileged: every step is an invocation on a capability the
//! parent already holds. The kernel is not told a process is being made.

use crate::abi::{ObjectType, PAGE_SIZE, SLOT_BITS, bootinfo, label, rights};
use crate::elf::{Elf, ElfError, Segment};
use crate::{Error, sys};

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

/// The first thing a spawned task says to its parent, defined once so both
/// ends of the channel agree on it (D-038).
pub const HELLO: u64 = label::APP_BASE;

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
    pub untyped: u64,
    pub next_slot: u64,
    /// The parent's own address space, for the scratch mapping.
    pub vspace: u64,
    /// A mapped-nothing, page-aligned address in the parent whose intermediate
    /// page tables already exist.
    pub scratch: usize,
}

impl Nursery {
    fn take(&mut self) -> u64 {
        self.next_slot += 1;
        self.next_slot - 1
    }

    fn object(&mut self, kind: ObjectType, size_bits: u8) -> Result<u64, SpawnError> {
        let slot = self.take();
        sys::retype(self.untyped, kind, size_bits, slot, 1)?;
        Ok(slot)
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
pub fn spawn(image: &[u8], n: &mut Nursery) -> Result<Child, SpawnError> {
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

    // Ascending order throughout, which is what lets `Tables` remember only the
    // most recent level of each and still never build one twice.
    let mut tables = Tables { l2: None, l1: None };
    for segment in elf.segments() {
        load_segment(n, vspace, &segment?, &mut tables)?;
    }

    let shared = n.object(ObjectType::Frame, 0)?;
    map_into(n, vspace, shared, SHARED_VADDR, rights::READ | rights::WRITE, false, &mut tables)?;

    for i in 0..STACK_PAGES {
        let frame = n.object(ObjectType::Frame, 0)?;
        let va = STACK_BOTTOM + i * PAGE_SIZE;
        map_into(n, vspace, frame, va, rights::READ | rights::WRITE, false, &mut tables)?;
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

    sys::tcb_configure(tcb, cnode, vspace, 0)?;
    sys::tcb_write_registers(tcb, elf.entry(), STACK_TOP)?;
    sys::tcb_resume(tcb)?;

    Ok(Child { cnode, vspace, tcb, endpoint, shared, entry: elf.entry() })
}

/// The intermediate levels built so far, by the region each one covers.
struct Tables {
    l2: Option<usize>,
    l1: Option<usize>,
}

/// Copy one `PT_LOAD` segment into fresh frames and map it into the child.
fn load_segment(
    n: &mut Nursery,
    vspace: u64,
    seg: &Segment,
    tables: &mut Tables,
) -> Result<(), SpawnError> {
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

        map_into(n, vspace, frame, va, mask, seg.executable(), tables)?;
        va += PAGE_SIZE;
    }
    Ok(())
}

/// Map `frame` into the child, building whichever intermediate levels are still
/// missing. The kernel creates none of them (D-035).
fn map_into(
    n: &mut Nursery,
    vspace: u64,
    frame: u64,
    va: usize,
    mask: u8,
    exec: bool,
    tables: &mut Tables,
) -> Result<(), SpawnError> {
    let gib = va & !((1 << 30) - 1);
    if tables.l2 != Some(gib) {
        let t = n.object(ObjectType::PageTable, 0)?;
        sys::map_table(t, vspace, va, 2)?;
        tables.l2 = Some(gib);
        tables.l1 = None;
    }
    let two_mib = va & !((1 << 21) - 1);
    if tables.l1 != Some(two_mib) {
        let t = n.object(ObjectType::PageTable, 0)?;
        sys::map_table(t, vspace, va, 1)?;
        tables.l1 = Some(two_mib);
    }
    sys::map_frame(frame, vspace, va, mask, exec)?;
    Ok(())
}
