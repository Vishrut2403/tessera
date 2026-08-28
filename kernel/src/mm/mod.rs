//! Memory management: address types, region arithmetic, physical frames.

pub mod addr;
pub mod frame;
pub mod page_table;
pub mod region;

use core::sync::atomic::{AtomicUsize, Ordering};

pub use addr::{KERNEL_VMA, PAGE_SHIFT, PAGE_SIZE, PhysAddr, VirtAddr};
pub use frame::BumpAllocator;
pub use page_table::{
    FrameAllocator, MapError, Mapper, PageTable, Pte, PteFlags, flush_tlb_all, flush_tlb_page,
};
pub use region::{CapacityExceeded, Region, RegionList};

use crate::fdt::{Fdt, FdtError, read_cells};
use crate::sync::SpinLock;

/// The kernel's frame allocator. Used during boot for page tables, then handed
/// over to M4 as untyped capabilities and never used again.
pub static FRAMES: SpinLock<BumpAllocator> = SpinLock::new(BumpAllocator::new());

/// Hand out one zeroed physical frame, or `None` if boot memory is exhausted.
pub fn alloc_frame() -> Option<PhysAddr> {
    FRAMES.lock().alloc_frame()
}

/// Discover memory and arm the frame allocator.
pub fn init(dtb: PhysAddr, kernel: Region) -> Result<MemoryMap, DiscoverError> {
    let map = discover(dtb, kernel)?;
    FRAMES.lock().init(&map.free);
    Ok(map)
}

/// Bound on how many regions any one list holds. Sized generously: QEMU virt
/// reports one RAM region and a handful of reservations, and a real board with
/// several DRAM banks and a dozen carve-outs still fits.
pub const MAX_REGIONS: usize = 32;

pub type Regions = RegionList<MAX_REGIONS>;

/// Translating between physical and virtual addresses.
///
/// Zero until M2c enables paging, then [`KERNEL_VMA`]. Keeping it in a variable
/// rather than a constant is what lets the same allocator and the same page
/// table walker run correctly both before and after the switch — before, the
/// hart is executing at physical addresses and the identity is right; after, the
/// direct map is right. Getting this wrong in either direction produces a fault
/// at an address that looks entirely reasonable.
static PHYS_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// Where a physical address is readable from, right now.
#[inline]
pub fn phys_to_virt(pa: PhysAddr) -> VirtAddr {
    VirtAddr::new(pa.as_usize() + PHYS_OFFSET.load(Ordering::Relaxed))
}

/// Inverse of [`phys_to_virt`]. Only valid for addresses inside the direct map.
#[inline]
pub fn virt_to_phys(va: VirtAddr) -> PhysAddr {
    PhysAddr::new(va.as_usize() - PHYS_OFFSET.load(Ordering::Relaxed))
}

/// Called exactly once, by the M2c paging switch.
pub fn set_phys_offset(offset: usize) {
    PHYS_OFFSET.store(offset, Ordering::Relaxed);
}

pub fn phys_offset() -> usize {
    PHYS_OFFSET.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverError {
    Fdt(FdtError),
    /// More regions than [`MAX_REGIONS`]. Raise the bound; do not silently drop.
    TooManyRegions,
    /// The device tree described no usable RAM, which cannot be true.
    NoMemory,
}

impl From<FdtError> for DiscoverError {
    fn from(e: FdtError) -> Self {
        DiscoverError::Fdt(e)
    }
}

impl From<CapacityExceeded> for DiscoverError {
    fn from(_: CapacityExceeded) -> Self {
        DiscoverError::TooManyRegions
    }
}

/// What physical memory exists and what is already spoken for.
#[derive(Debug, Clone, Copy)]
pub struct MemoryMap {
    /// Everything the device tree calls RAM.
    pub ram: Regions,
    /// Everything that must not be handed out.
    pub reserved: Regions,
    /// `ram - reserved`, trimmed to whole pages. What the allocator may use.
    pub free: Regions,
}

/// Read the memory map out of the device tree.
///
/// Must run before paging is enabled, or through a mapping that covers the blob:
/// `dtb` is the raw physical pointer OpenSBI left in `a1`.
///
/// Four things get reserved, and leaving out any one of them corrupts something
/// subtle:
///
/// 1. **The memory reservation block.** Firmware's own claim — on this platform
///    it is how OpenSBI protects the region its PMPs also guard.
/// 2. **`/reserved-memory` children.** The device tree's structured form of the
///    same idea.
/// 3. **The kernel image.** Nothing in the device tree knows where we were
///    loaded, so nothing else will protect us from allocating over ourselves.
/// 4. **The DTB blob itself.** It sits in ordinary RAM, and it is not
///    necessarily covered by its own reservation block. Handing it out as a free
///    frame means the memory map gets overwritten by the first thing that uses
///    it — after we have already read it, so the failure surfaces much later.
pub fn discover(dtb: PhysAddr, kernel: Region) -> Result<MemoryMap, DiscoverError> {
    // SAFETY: `dtb` is the pointer OpenSBI passed in a1, per the SBI boot
    // convention (D-003), and paging is off so it is directly addressable.
    let fdt = unsafe { Fdt::from_ptr(dtb.as_usize() as *const u8) }?;

    let mut ram = Regions::new();
    let mut reserved = Regions::new();

    // Cell counts come from the root node. Two and two on RV64, but a 32-bit
    // board says otherwise and we would rather read than assume.
    let mut address_cells = 2usize;
    let mut size_cells = 2usize;

    // First pass: the root's cell counts. They can appear after the child nodes
    // that need them in the token stream, so this cannot be folded into the
    // pass below.
    fdt.for_each_property(|p| {
        if p.depth == 0 {
            match p.name {
                "#address-cells" => {
                    if let Ok(v) = read_cells(p.value, 0, 1) {
                        address_cells = v as usize;
                    }
                }
                "#size-cells" => {
                    if let Ok(v) = read_cells(p.value, 0, 1) {
                        size_cells = v as usize;
                    }
                }
                _ => {}
            }
        }
    })?;

    let entry_bytes = (address_cells + size_cells) * 4;

    // Second pass: the regions themselves.
    let mut overflow = false;
    fdt.for_each_property(|p| {
        if p.name != "reg" || entry_bytes == 0 {
            return;
        }

        // `/memory` or `/memory@80000000` at depth 1 is RAM; anything under
        // `/reserved-memory` is a carve-out.
        let is_ram = p.depth == 1 && (p.node == "memory" || p.node.starts_with("memory@"));
        let is_reserved = p.depth == 2 && p.parent == "reserved-memory";
        if !is_ram && !is_reserved {
            return;
        }

        // `reg` is a list of (address, size) pairs, not a single one: a node may
        // describe several banks.
        let mut off = 0;
        while off + entry_bytes <= p.value.len() {
            let base = read_cells(p.value, off, address_cells);
            let size = read_cells(p.value, off + address_cells * 4, size_cells);
            off += entry_bytes;

            let (Ok(base), Ok(size)) = (base, size) else { continue };
            if size == 0 {
                continue;
            }
            let region = Region::from_start_len(PhysAddr::new(base as usize), size as usize);
            let target = if is_ram { &mut ram } else { &mut reserved };
            if target.push(region).is_err() {
                overflow = true;
            }
        }
    })?;

    if overflow {
        return Err(DiscoverError::TooManyRegions);
    }

    fdt.for_each_reservation(|addr, size| {
        let _ = reserved
            .push(Region::from_start_len(PhysAddr::new(addr as usize), size as usize));
    })?;

    reserved.push(kernel)?;
    reserved.push(Region::from_start_len(dtb, fdt.total_size()))?;

    ram.normalize();
    reserved.normalize();

    if ram.is_empty() {
        return Err(DiscoverError::NoMemory);
    }

    // Subtract first, then trim to page boundaries. The other order would round
    // a reservation's edges outward *before* subtracting, which is the safe
    // direction, but would also let a sub-page gap between two reservations
    // survive as a zero-frame region.
    let mut free = ram.subtract(&reserved)?;
    for r in free.as_mut_slice() {
        *r = r.page_aligned();
    }
    free.drop_empty();

    Ok(MemoryMap { ram, reserved, free })
}
