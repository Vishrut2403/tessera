//! Building the kernel's own address space (D-013).

use core::sync::atomic::{AtomicUsize, Ordering};

use super::addr::{KERNEL_VMA, PAGE_SIZE, PhysAddr, VirtAddr};
use super::page_table::{FrameAllocator, MapError, Mapper, PteFlags, flush_tlb_all};
use super::region::{CapacityExceeded, Region};
use super::{MemoryMap, Regions};
use crate::layout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    Map(MapError),
    Capacity(CapacityExceeded),
}

impl From<MapError> for BuildError {
    fn from(e: MapError) -> Self {
        BuildError::Map(e)
    }
}

impl From<CapacityExceeded> for BuildError {
    fn from(e: CapacityExceeded) -> Self {
        BuildError::Capacity(e)
    }
}

/// Root of the live kernel table, or 0 before one exists.
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

pub fn root() -> Option<PhysAddr> {
    match KERNEL_ROOT.load(Ordering::Relaxed) {
        0 => None,
        pa => Some(PhysAddr::new(pa)),
    }
}

/// One contiguous piece of the kernel image, and how it should be mapped.
pub struct Section {
    pub name: &'static str,
    /// Virtual range, already rounded outward to whole pages.
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub flags: PteFlags,
}

impl Section {
    pub fn len(&self) -> usize {
        self.end.as_usize() - self.start.as_usize()
    }

    pub fn phys_start(&self) -> PhysAddr {
        PhysAddr::new(self.start.as_usize() - KERNEL_VMA)
    }
}

/// The kernel image, split by permission.
pub fn sections() -> [Section; 3] {
    let page_range = |start: usize, end: usize| {
        (VirtAddr::new(start).align_down(PAGE_SIZE), VirtAddr::new(end).align_up(PAGE_SIZE))
    };

    let (text_start, text_end) = page_range(layout::text_start(), layout::text_end());
    let (rodata_start, rodata_end) = page_range(layout::rodata_start(), layout::rodata_end());
    let (data_start, data_end) = page_range(layout::data_start(), layout::bss_end());

    [
        Section {
            name: ".text",
            start: text_start,
            end: text_end,
            flags: PteFlags::KERNEL_RX,
        },
        Section {
            name: ".rodata",
            start: rodata_start,
            end: rodata_end,
            flags: PteFlags::KERNEL_RO,
        },
        Section {
            name: ".data+.bss",
            start: data_start,
            end: data_end,
            flags: PteFlags::KERNEL_RW,
        },
    ]
}

/// MMIO the kernel itself needs; everything else belongs to a userspace driver.
pub const DEVICES: [(&str, usize); 2] =
    [("uart0", crate::uart::UART0_PHYS), ("sifive-test", crate::qemu::SIFIVE_TEST_PHYS)];

/// Construct the kernel address space. Does not activate it.
pub fn build(map: &MemoryMap, alloc: &mut impl FrameAllocator) -> Result<Mapper, BuildError> {
    let mut mapper = Mapper::new(alloc)?;

    // Kernel sections, at their linked addresses.
    for section in sections() {
        mapper.map_range(
            section.start,
            section.phys_start(),
            section.len(),
            section.flags,
            alloc,
        )?;
    }

    // Direct map of all RAM except the kernel image, which is already mapped.
    let mut carve = Regions::new();
    carve.push(layout::kernel_phys_range())?;
    let direct = map.ram.subtract(&carve)?;

    for region in direct.iter() {
        mapper.map_range(
            VirtAddr::new(KERNEL_VMA + region.start.as_usize()),
            region.start,
            region.len(),
            PteFlags::KERNEL_RW,
            alloc,
        )?;
    }

    // Device MMIO, at the same KERNEL_VMA offset.
    for (_, pa) in DEVICES {
        mapper.map_range(
            VirtAddr::new(KERNEL_VMA + pa),
            PhysAddr::new(pa),
            PAGE_SIZE,
            PteFlags::KERNEL_RW,
            alloc,
        )?;
    }

    // The interrupt controller, whose size the device tree reports: 6 MiB on
    // QEMU virt, because the per-context register blocks are 4 KiB apart.
    if let Some(plic) = map.plic {
        mapper.map_range(
            VirtAddr::new(KERNEL_VMA + plic.region.start.as_usize()),
            plic.region.start,
            plic.region.len(),
            PteFlags::KERNEL_RW,
            alloc,
        )?;
    }

    Ok(mapper)
}

/// Switch the hart onto `mapper`.
///
/// # Safety
/// `mapper` must map the running code, the stack and `gp` at the addresses they already have.
pub unsafe fn activate(mapper: &Mapper) {
    let satp = crate::boot::satp_value(mapper.root().as_usize());
    KERNEL_ROOT.store(mapper.root().as_usize(), Ordering::Relaxed);

    // SAFETY: see the contract above.
    unsafe { crate::csr::satp::write(satp) };
    flush_tlb_all();
}

/// The region of the address space the direct map occupies, for diagnostics.
pub fn direct_map_range(map: &MemoryMap) -> Option<Region> {
    let first = map.ram.iter().map(|r| r.start).min()?;
    let last = map.ram.iter().map(|r| r.end).max()?;
    Some(Region::new(first, last))
}
