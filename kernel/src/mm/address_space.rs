//! Address spaces: what M3 switches between and M4 hands out as a capability.

use super::addr::{KERNEL_VMA, PhysAddr, VirtAddr};
use super::page_table::{
    ENTRIES, FrameAllocator, MAX_LEVEL, MapError, Mapper, PteFlags, flush_tlb_all, page_size,
};

/// First root-table index belonging to the kernel half (D-021).
pub const KERNEL_ROOT_FIRST: usize = (KERNEL_VMA >> (12 + 9 * MAX_LEVEL)) & (ENTRIES - 1);

const SATP_SV39: usize = 8 << 60;
const SATP_ASID_SHIFT: usize = 44;

/// An address space identifier: `satp`'s ASID field, 16 bits on RV64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct Asid(u16);

impl Asid {
    /// What every space uses until M4 (D-022): spaces are kept apart by flushing.
    pub const UNASSIGNED: Asid = Asid(0);

    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// The address lies in the kernel half, which a user space may not touch.
    KernelHalf,
    /// The mapping lacks `U`, so userspace could not reach it in any case.
    NotUserAccessible,
    Map(MapError),
}

impl From<MapError> for AddressSpaceError {
    fn from(e: MapError) -> Self {
        AddressSpaceError::Map(e)
    }
}

/// A user address space: an empty lower half over a shared copy of the kernel's.
///
/// There is no `Drop`. Reclaiming the page table frames needs an allocator that
/// can free, which arrives in M4 with untyped memory and revocation (D-014).
pub struct AddressSpace {
    mapper: Mapper,
    asid: Asid,
    kernel_fingerprint: u64,
}

impl AddressSpace {
    /// Build a fresh space sharing `kernel`'s upper half.
    pub fn new(kernel: &Mapper, alloc: &mut impl FrameAllocator) -> Result<Self, MapError> {
        let mut mapper = Mapper::new(alloc)?;
        let upper = &kernel.root_table().entries[KERNEL_ROOT_FIRST..];
        mapper.root_table_mut().entries[KERNEL_ROOT_FIRST..].copy_from_slice(upper);

        Ok(Self {
            mapper,
            asid: Asid::UNASSIGNED,
            kernel_fingerprint: kernel_half_fingerprint(kernel),
        })
    }

    pub const fn root(&self) -> PhysAddr {
        self.mapper.root()
    }

    pub const fn asid(&self) -> Asid {
        self.asid
    }

    /// Bind an ASID. M4's ASID pool is what will hand these out.
    pub fn set_asid(&mut self, asid: Asid) {
        self.asid = asid;
    }

    /// The `satp` value that makes this space current.
    pub const fn satp(&self) -> usize {
        satp_for(self.root(), self.asid)
    }

    /// Switch this hart onto this space.
    ///
    /// # Safety
    /// The caller must be executing in the kernel half, which this space maps.
    pub unsafe fn activate(&self) {
        // SAFETY: see the contract above.
        unsafe { crate::csr::satp::write(self.satp()) };
        // Every space shares ASID 0 until M4, so stale entries must go (D-022).
        flush_tlb_all();
    }

    /// Map one page. Rejects anything the kernel half owns, or without `U`.
    pub fn map(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        level: usize,
        flags: PteFlags,
        alloc: &mut impl FrameAllocator,
    ) -> Result<(), AddressSpaceError> {
        check_user(va, page_size(level.min(MAX_LEVEL)))?;
        if !flags.contains(PteFlags::U) {
            return Err(AddressSpaceError::NotUserAccessible);
        }
        self.mapper.map(va, pa, level, flags, alloc)?;
        Ok(())
    }

    pub fn map_range(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        size: usize,
        flags: PteFlags,
        alloc: &mut impl FrameAllocator,
    ) -> Result<(), AddressSpaceError> {
        check_user(va, size)?;
        if !flags.contains(PteFlags::U) {
            return Err(AddressSpaceError::NotUserAccessible);
        }
        self.mapper.map_range(va, pa, size, flags, alloc)?;
        Ok(())
    }

    /// Remove a user mapping, returning the frame it pointed at.
    pub fn unmap(&mut self, va: VirtAddr) -> Result<PhysAddr, AddressSpaceError> {
        check_user(va, 1)?;
        Ok(self.mapper.unmap(va)?)
    }

    /// Resolve an address the way the hardware would. Kernel addresses resolve too.
    pub fn translate(&self, va: VirtAddr) -> Option<(PhysAddr, PteFlags, usize)> {
        self.mapper.translate(va)
    }

    /// Whether `kernel` has gained mappings this space did not copy (D-021).
    pub fn kernel_half_is_stale(&self, kernel: &Mapper) -> bool {
        kernel_half_fingerprint(kernel) != self.kernel_fingerprint
    }
}

/// Whether `va`, and `size` bytes after it, stay clear of the kernel's root entries.
fn check_user(va: VirtAddr, size: usize) -> Result<(), AddressSpaceError> {
    if !va.is_canonical() {
        return Err(MapError::NonCanonical.into());
    }
    let last = VirtAddr::new(va.as_usize().saturating_add(size.saturating_sub(1)));
    if va.vpn(MAX_LEVEL) >= KERNEL_ROOT_FIRST || last.vpn(MAX_LEVEL) >= KERNEL_ROOT_FIRST {
        return Err(AddressSpaceError::KernelHalf);
    }
    Ok(())
}

/// A cheap summary of the kernel's root entries, to detect a changed kernel half.
pub fn kernel_half_fingerprint(kernel: &Mapper) -> u64 {
    let mut acc = 0u64;
    for entry in &kernel.root_table().entries[KERNEL_ROOT_FIRST..] {
        acc = acc.rotate_left(7) ^ entry.bits();
    }
    acc
}

/// The `satp` that installs `root` under `asid`.
///
/// Separate from [`AddressSpace`] because a userspace-built address space is a
/// retyped page table and a capability, not an `AddressSpace` value (D-037).
pub const fn satp_for(root: PhysAddr, asid: Asid) -> usize {
    SATP_SV39 | ((asid.as_u16() as usize) << SATP_ASID_SHIFT) | root.page_number()
}

/// Copy the kernel's root entries into a page table that is about to become an
/// address space root.
///
/// Every user root table needs these: RISC-V does not switch `satp` on a trap,
/// so the trap handler runs with the faulting thread's table installed and must
/// be mapped in it (D-021).
///
/// # Safety
/// `root` must be a page table object we own exclusively and that is not
/// currently installed in `satp` on any hart.
pub unsafe fn install_kernel_half(root: PhysAddr, kernel_root: PhysAddr) {
    // SAFETY: both are live root tables reachable through the direct map, and
    // the caller promised exclusive access to the destination.
    unsafe {
        let dst = &mut *super::phys_to_virt(root).as_mut_ptr::<super::page_table::PageTable>();
        let src = &*super::phys_to_virt(kernel_root).as_ptr::<super::page_table::PageTable>();
        dst.entries[KERNEL_ROOT_FIRST..].copy_from_slice(&src.entries[KERNEL_ROOT_FIRST..]);
    }
}
