//! What the kernel tells the root task, and the only thing it ever tells it.
//!
//! One page, mapped read-only into the root task at a known address. After the
//! root task reads it the kernel is out of the resource business entirely: every
//! frame, page table, thread and endpoint in the system is retyped out of one of
//! the untypeds described here (D-038).

use crate::PAGE_SIZE;

/// `"tessera\0"`, so a garbage page is obvious rather than plausible.
pub const MAGIC: u64 = 0x7465_7373_6572_6100;

/// Bumped whenever a field moves. The root task refuses a version it does not
/// know, because reading this struct wrongly is unrecoverable.
pub const VERSION: u32 = 1;

/// Where the kernel maps the boot info page: above the image and the stack,
/// and inside the same gigabyte so it costs no extra page tables.
pub const VADDR: usize = 0x3000_0000;

/// The capability slots the kernel fills in before the root task runs.
///
/// Everything else in the root CNode is empty and is the root task's to use;
/// [`BootInfo::first_free_slot`] is where that starts.
pub mod slot {
    /// Always empty: a null cptr must not resolve to anything.
    pub const NULL: u64 = 0;
    /// The root CNode, as a capability inside itself.
    pub const CNODE: u64 = 1;
    /// The root task's address space: an assigned root page table (D-037).
    pub const VSPACE: u64 = 2;
    /// The root task's own TCB. Invoking it is refused (D-037).
    pub const TCB: u64 = 3;
    /// The read-only frame this struct lives in.
    pub const BOOTINFO: u64 = 4;
    /// The first slot holding an untyped region.
    pub const FIRST_UNTYPED: u64 = 8;
}

/// One region of untyped memory handed to the root task.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UntypedDesc {
    pub paddr: u64,
    /// Log2 of the region's size.
    pub size_bits: u8,
    /// Non-zero for a device region: retypable only into frames, and never
    /// zeroed, because zeroing MMIO writes device registers. Always zero until
    /// M7c introduces them.
    pub is_device: u8,
    _pad: [u8; 6],
}

impl UntypedDesc {
    pub const fn new(paddr: u64, size_bits: u8, is_device: bool) -> Self {
        Self { paddr, size_bits, is_device: is_device as u8, _pad: [0; 6] }
    }

    pub const fn bytes(&self) -> u64 {
        1u64 << self.size_bits
    }
}

/// How many regions the page has room to describe.
pub const MAX_UNTYPED: usize = 128;

#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub untyped_count: u32,

    /// Address bits the root CNode consumes. Every cptr below is used at this
    /// depth, because the root task's CSpace starts out one level deep. A `u64`
    /// so the struct has no implicit padding: it is written into a page
    /// userspace can read, and padding would be whatever the kernel stack held.
    pub cnode_radix: u64,
    pub cnode_slots: u64,

    /// Slots `[first_untyped, first_untyped + untyped_count)` hold the regions.
    pub first_untyped: u64,
    /// The first slot the kernel did not fill in.
    pub first_free_slot: u64,

    /// The root task's image, stack and this page, as it sees them.
    pub image_start: u64,
    pub image_end: u64,
    pub stack_bottom: u64,
    pub stack_top: u64,
    pub bootinfo_vaddr: u64,
    /// The lowest address the root task may map things at without colliding
    /// with anything the kernel put there.
    pub free_vaddr: u64,

    pub untyped: [UntypedDesc; MAX_UNTYPED],
}

const _: () = assert!(size_of::<BootInfo>() <= PAGE_SIZE);

impl BootInfo {
    pub const EMPTY: BootInfo = BootInfo {
        magic: MAGIC,
        version: VERSION,
        untyped_count: 0,
        cnode_radix: 0,
        cnode_slots: 0,
        first_untyped: slot::FIRST_UNTYPED,
        first_free_slot: slot::FIRST_UNTYPED,
        image_start: 0,
        image_end: 0,
        stack_bottom: 0,
        stack_top: 0,
        bootinfo_vaddr: VADDR as u64,
        free_vaddr: 0,
        untyped: [UntypedDesc { paddr: 0, size_bits: 0, is_device: 0, _pad: [0; 6] }; MAX_UNTYPED],
    };

    pub const fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.version == VERSION
    }

    pub fn untypeds(&self) -> &[UntypedDesc] {
        &self.untyped[..self.untyped_count as usize]
    }

    /// The cptr of the untyped described by `untypeds()[i]`.
    pub const fn untyped_slot(&self, i: usize) -> u64 {
        self.first_untyped + i as u64
    }
}
