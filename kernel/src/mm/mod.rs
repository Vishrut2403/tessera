//! Memory management: address types, region arithmetic, physical frames.

pub mod addr;
pub mod address_space;
pub mod frame;
pub mod kernel_space;
pub mod page_table;
pub mod region;

use core::sync::atomic::{AtomicUsize, Ordering};

pub use addr::{KERNEL_VMA, PAGE_SHIFT, PAGE_SIZE, PhysAddr, VirtAddr};
pub use address_space::{AddressSpace, AddressSpaceError, Asid, install_kernel_half, satp_for};
pub use frame::BumpAllocator;
pub use page_table::{
    FrameAllocator, MapError, Mapper, PageTable, Pte, PteFlags, flush_tlb_all, flush_tlb_page,
};
pub use region::{CapacityExceeded, Region, RegionList};

use crate::fdt::{Fdt, FdtError, read_cells};
use crate::sync::SpinLock;

/// The kernel's frame allocator; boot only.
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

/// Bound on how many regions any one list holds.
pub const MAX_REGIONS: usize = 32;

pub type Regions = RegionList<MAX_REGIONS>;

/// Translating between physical and virtual addresses.
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
    /// Physical regions that are devices rather than memory, one per `reg`
    /// entry in the device tree, grown outward to whole pages (D-040).
    ///
    /// Deliberately *not* coalesced: adjacent devices stay separate
    /// capabilities, so retyping the untyped for one transport hands you that
    /// transport's page and not its neighbour's.
    pub devices: Regions,
}

/// Read the memory map out of the device tree.
pub fn discover(dtb: PhysAddr, kernel: Region) -> Result<MemoryMap, DiscoverError> {
    // SAFETY: `dtb` is the pointer OpenSBI passed in a1, per the SBI boot convention (D-003).
    let fdt = unsafe { Fdt::from_ptr(phys_to_virt(dtb).as_ptr::<u8>()) }?;

    let mut ram = Regions::new();
    let mut reserved = Regions::new();
    let mut devices = Regions::new();

    // Cell counts come from the root node.
    let mut address_cells = 2usize;
    let mut size_cells = 2usize;

    // First pass: the root's cell counts.
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

        // `/memory*` at depth 1 is RAM; anything under `/reserved-memory` is a carve-out.
        let is_ram = p.depth == 1 && (p.node == "memory" || p.node.starts_with("memory@"));
        let is_reserved = p.depth == 2 && p.parent == "reserved-memory";
        // A device is a `reg` on a child of `/soc`, or a top-level node with a
        // unit address that is not memory -- `flash@...`, `fw-cfg@...`. Nodes
        // deeper than that are behind a bus with its own cell counts (a PCI
        // child's `reg` is not a physical address), and `/cpus/cpu@0`'s `reg`
        // is a hart id, so neither is read with the root's cells.
        let is_device = !is_ram
            && !is_reserved
            && ((p.depth == 2 && p.parent == "soc")
                || (p.depth == 1 && p.node.contains('@')));
        if !is_ram && !is_reserved && !is_device {
            return;
        }

        // `reg` is a list of (address, size) pairs: a node may describe several banks.
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
            let target = if is_ram {
                &mut ram
            } else if is_reserved {
                &mut reserved
            } else {
                &mut devices
            };
            let region = if is_device { region.page_aligned_out() } else { region };
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

    // Subtract first, then trim to page boundaries.
    let mut free = ram.subtract(&reserved)?;
    for r in free.as_mut_slice() {
        *r = r.page_aligned();
    }
    free.drop_empty();

    // A device region overlapping RAM is a device tree we do not understand, and
    // one overlapping a device the kernel drives is the console or the shutdown
    // register: handing either to userspace would put the kernel's own hardware
    // in someone else's address space.
    let mut kept = Regions::new();
    for d in devices.iter() {
        let clashes_with_ram = ram.iter().any(|r| r.overlaps(d));
        let clashes_with_kernel = kernel_space::DEVICES
            .iter()
            .any(|(_, pa)| d.contains(PhysAddr::new(*pa)));
        if !clashes_with_ram && !clashes_with_kernel {
            kept.push(*d)?;
        }
    }
    kept.sort();
    let devices = kept;

    Ok(MemoryMap { ram, reserved, free, devices })
}
