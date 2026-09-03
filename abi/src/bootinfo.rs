//! What the kernel tells the root task, and the only thing it ever tells it.

use crate::PAGE_SIZE;

/// `"tessera\0"`, so a garbage page is obvious rather than plausible.
pub const MAGIC: u64 = 0x7465_7373_6572_6100;

/// Bumped whenever a field moves.
pub const VERSION: u32 = 3;

/// Where the kernel maps the boot info page: above the image and the stack, and
/// inside the same gigabyte so it costs no extra page tables.
pub const VADDR: usize = 0x3000_0000;

/// Where the device tree is mapped, read-only, in the same gigabyte.
pub const FDT_VADDR: usize = 0x3010_0000;

/// Where the boot modules are mapped, read-only, one after another (D-043).
pub const MODULE_VADDR: usize = 0x3020_0000;

/// The capability slots the kernel fills in before the root task runs.
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
    /// The right to claim interrupt sources (D-041). One exists.
    pub const IRQ_CONTROL: u64 = 5;
    /// A spawned task's endpoint back to whoever spawned it. Empty in the root
    /// task: the kernel is not on the other end of anything (D-043).
    pub const ENDPOINT: u64 = 6;
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
    /// zeroed, because zeroing MMIO writes device registers.
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

/// How many boot modules the page has room to describe.
pub const MAX_MODULES: usize = 4;

/// One image the kernel carried in and mapped read-only, for the root task to
/// load into a process of its own (D-043).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleDesc {
    pub vaddr: u64,
    pub size: u64,
    /// NUL-padded, so a module is found by name and not by position.
    pub name: [u8; 16],
}

impl ModuleDesc {
    pub const EMPTY: ModuleDesc = ModuleDesc { vaddr: 0, size: 0, name: [0; 16] };

    pub const fn new(vaddr: u64, size: u64, name: &str) -> Self {
        let (bytes, mut name_buf, mut i) = (name.as_bytes(), [0u8; 16], 0);
        while i < bytes.len() && i < 16 {
            name_buf[i] = bytes[i];
            i += 1;
        }
        Self { vaddr, size, name: name_buf }
    }

    pub fn name(&self) -> &str {
        let len = self.name.iter().position(|c| *c == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("?")
    }
}

#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub untyped_count: u32,

    /// Address bits the root CNode consumes.
    /// A `u64` so the struct has no implicit padding to leak.
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
    /// The device tree, mapped read-only.
    pub fdt_vaddr: u64,
    pub fdt_size: u64,
    /// The highest interrupt source the platform's controller has.
    pub max_irq: u64,
    /// The lowest address the root task may map things at without colliding
    /// with anything the kernel put there.
    pub free_vaddr: u64,
    /// A `u64` so the struct has no implicit padding to leak.
    pub module_count: u64,

    pub modules: [ModuleDesc; MAX_MODULES],
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
        fdt_vaddr: 0,
        fdt_size: 0,
        max_irq: 0,
        free_vaddr: 0,
        module_count: 0,
        modules: [ModuleDesc::EMPTY; MAX_MODULES],
        untyped: [UntypedDesc { paddr: 0, size_bits: 0, is_device: 0, _pad: [0; 6] }; MAX_UNTYPED],
    };

    pub const fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.version == VERSION
    }

    pub fn untypeds(&self) -> &[UntypedDesc] {
        &self.untyped[..self.untyped_count as usize]
    }

    pub fn modules(&self) -> &[ModuleDesc] {
        &self.modules[..self.module_count as usize]
    }

    /// The module called `name`, if the kernel carried one in.
    pub fn module(&self, name: &str) -> Option<&ModuleDesc> {
        self.modules().iter().find(|m| m.name() == name)
    }

    /// The cptr of the untyped described by `untypeds()[i]`.
    pub const fn untyped_slot(&self, i: usize) -> u64 {
        self.first_untyped + i as u64
    }
}
