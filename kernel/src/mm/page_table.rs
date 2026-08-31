//! Sv39 page tables: entries, tables, and the three-level walk.

use core::fmt;

use super::addr::{PAGE_SHIFT, PAGE_SIZE, PhysAddr, VirtAddr};
use super::phys_to_virt;

/// Entries per table. 4096 / 8.
pub const ENTRIES: usize = 512;

/// Deepest level index. Sv39 has three levels: 2 (1 GiB), 1 (2 MiB), 0 (4 KiB).
pub const MAX_LEVEL: usize = 2;

/// Bytes mapped by one leaf at `level`.
pub const fn page_size(level: usize) -> usize {
    PAGE_SIZE << (9 * level)
}

// --- Flags ---

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct PteFlags(u64);

impl PteFlags {
    pub const EMPTY: Self = Self(0);
    /// Valid. Without it the hardware ignores every other bit.
    pub const V: Self = Self(1 << 0);
    pub const R: Self = Self(1 << 1);
    pub const W: Self = Self(1 << 2);
    pub const X: Self = Self(1 << 3);
    /// Reachable from user mode. Kernel mappings must leave this clear.
    pub const U: Self = Self(1 << 4);
    /// Global: the translation survives an ASID change.
    pub const G: Self = Self(1 << 5);
    /// Accessed.
    pub const A: Self = Self(1 << 6);
    /// Dirty.
    pub const D: Self = Self(1 << 7);

    /// Kernel code: read + execute, never writable, never user-reachable.
    pub const KERNEL_RX: Self = Self(Self::V.0 | Self::R.0 | Self::X.0 | Self::G.0 | Self::A.0);
    /// Kernel read-only data.
    pub const KERNEL_RO: Self = Self(Self::V.0 | Self::R.0 | Self::G.0 | Self::A.0);
    /// Kernel writable data, and the direct map. Never executable.
    pub const KERNEL_RW: Self =
        Self(Self::V.0 | Self::R.0 | Self::W.0 | Self::G.0 | Self::A.0 | Self::D.0);

    /// User data: never executable, never Global (an ASID switch must drop it).
    pub const USER_RW: Self =
        Self(Self::V.0 | Self::R.0 | Self::W.0 | Self::U.0 | Self::A.0 | Self::D.0);
    /// User code.
    pub const USER_RX: Self =
        Self(Self::V.0 | Self::R.0 | Self::X.0 | Self::U.0 | Self::A.0);

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits & 0xff)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// A leaf is any entry with at least one of R/W/X.
    pub const fn is_leaf(self) -> bool {
        self.intersects(Self(Self::R.0 | Self::W.0 | Self::X.0))
    }

    /// `W` without `R` is reserved by the spec, not write-only memory.
    pub const fn is_valid_combination(self) -> bool {
        !(self.contains(Self::W) && !self.contains(Self::R))
    }
}

impl core::ops::BitOr for PteFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl fmt::Debug for PteFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // One letter per bit, a dash where clear -- easier to scan in a dump than hex.
        let table = [
            (Self::V, 'V'),
            (Self::R, 'R'),
            (Self::W, 'W'),
            (Self::X, 'X'),
            (Self::U, 'U'),
            (Self::G, 'G'),
            (Self::A, 'A'),
            (Self::D, 'D'),
        ];
        for (bit, ch) in table {
            write!(f, "{}", if self.contains(bit) { ch } else { '-' })?;
        }
        Ok(())
    }
}

// --- Entries ---

const PPN_SHIFT: usize = 10;
const PPN_BITS: usize = 44;
const PPN_MASK: u64 = ((1 << PPN_BITS) - 1) << PPN_SHIFT;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Pte(u64);

impl Pte {
    pub const EMPTY: Self = Self(0);

    pub const fn bits(self) -> u64 {
        self.0
    }

    /// A leaf mapping `pa` with `flags`.
    pub fn leaf(pa: PhysAddr, flags: PteFlags) -> Self {
        Self(((pa.page_number() as u64) << PPN_SHIFT) | flags.union(PteFlags::V).bits())
    }

    /// A branch pointing at the next-level table at `pa`.
    pub fn branch(pa: PhysAddr) -> Self {
        Self(((pa.page_number() as u64) << PPN_SHIFT) | PteFlags::V.bits())
    }

    pub const fn is_valid(self) -> bool {
        self.0 & PteFlags::V.bits() != 0
    }

    pub const fn flags(self) -> PteFlags {
        PteFlags::from_bits(self.0)
    }

    pub const fn is_leaf(self) -> bool {
        self.is_valid() && self.flags().is_leaf()
    }

    pub const fn is_branch(self) -> bool {
        self.is_valid() && !self.flags().is_leaf()
    }

    /// Frame for a leaf, next-level table for a branch.
    pub const fn phys_addr(self) -> PhysAddr {
        PhysAddr::new((((self.0 & PPN_MASK) >> PPN_SHIFT) as usize) << PAGE_SHIFT)
    }
}

impl fmt::Debug for Pte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.is_valid() {
            return write!(f, "Pte(invalid)");
        }
        write!(
            f,
            "Pte({} {:?} {})",
            self.phys_addr(),
            self.flags(),
            if self.is_leaf() { "leaf" } else { "branch" }
        )
    }
}

// --- Tables ---

/// One level of page table: exactly one 4 KiB page, aligned to one.
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [Pte; ENTRIES],
}

impl PageTable {
    pub const fn empty() -> Self {
        Self { entries: [Pte::EMPTY; ENTRIES] }
    }
}

/// Borrow the table at `pa` through the current physical-memory mapping.
///
/// # Safety
/// `pa` must address a live page table frame, with no aliasing `&mut` for it while this lives.
unsafe fn table_ref<'a>(pa: PhysAddr) -> &'a PageTable {
    unsafe { &*phys_to_virt(pa).as_ptr::<PageTable>() }
}

/// Mutably borrow the table at `pa`.
///
/// # Safety
/// As [`table_ref`], plus exclusive access to the tree -- in practice via a `&mut Mapper`.
unsafe fn table_mut<'a>(pa: PhysAddr) -> &'a mut PageTable {
    unsafe { &mut *phys_to_virt(pa).as_mut_ptr::<PageTable>() }
}

// --- Mapping ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Virtual address is not sign-extended correctly for Sv39.
    NonCanonical,
    /// Level above [`MAX_LEVEL`].
    BadLevel,
    /// Virtual address not aligned to the page size at this level.
    MisalignedVirt,
    /// Physical address not aligned to the page size at this level.
    MisalignedPhys,
    /// Flags describe a branch (no R/W/X), or the reserved W-without-R encoding.
    BadFlags,
    /// Something is already mapped here.
    AlreadyMapped,
    /// Nothing is mapped here.
    NotMapped,
    /// A superpage already covers this address; splitting is not implemented.
    CoveredBySuperpage,
    /// The frame allocator is empty.
    OutOfFrames,
    /// An intermediate page table is missing. Userspace supplies them, so this
    /// is a request for one rather than something the kernel fixes (D-035).
    MissingTable,
}

/// Source of page table frames; becomes a capability in M4.
pub trait FrameAllocator {
    fn alloc_frame(&mut self) -> Option<PhysAddr>;
}

impl FrameAllocator for super::BumpAllocator {
    fn alloc_frame(&mut self) -> Option<PhysAddr> {
        super::BumpAllocator::alloc_frame(self)
    }
}

/// A page table tree, identified by the physical address of its root.
pub struct Mapper {
    root: PhysAddr,
}

impl Mapper {
    /// Wrap an existing root table.
    ///
    /// # Safety
    /// `root` must point at a zeroed or well-formed table frame no other `Mapper` is using.
    pub const unsafe fn from_root(root: PhysAddr) -> Self {
        Self { root }
    }

    /// Allocate a fresh, empty root table.
    pub fn new(alloc: &mut impl FrameAllocator) -> Result<Self, MapError> {
        // The allocator zeroes, so a fresh root is entirely invalid entries.
        let root = alloc.alloc_frame().ok_or(MapError::OutOfFrames)?;
        Ok(Self { root })
    }

    pub const fn root(&self) -> PhysAddr {
        self.root
    }

    /// The root table itself, for copying the kernel half into a new space.
    pub fn root_table(&self) -> &PageTable {
        // SAFETY: `self.root` is this Mapper's own root frame, borrowed with the tree.
        unsafe { table_ref(self.root) }
    }

    pub fn root_table_mut(&mut self) -> &mut PageTable {
        // SAFETY: as above; `&mut self` is exclusive access to the tree.
        unsafe { table_mut(self.root) }
    }

    /// Map one page of the size implied by `level`.
    pub fn map(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        level: usize,
        flags: PteFlags,
        alloc: &mut impl FrameAllocator,
    ) -> Result<(), MapError> {
        if level > MAX_LEVEL {
            return Err(MapError::BadLevel);
        }
        if !va.is_canonical() {
            return Err(MapError::NonCanonical);
        }
        if !flags.is_leaf() || !flags.is_valid_combination() {
            return Err(MapError::BadFlags);
        }
        let size = page_size(level);
        if !va.is_aligned(size) {
            return Err(MapError::MisalignedVirt);
        }
        if !pa.is_aligned(size) {
            return Err(MapError::MisalignedPhys);
        }

        let mut table = self.root;
        // Descend, creating branches, until we are at the level that will hold the leaf.
        let mut current = MAX_LEVEL;
        while current > level {
            let entry = {
                // SAFETY: `table` is reached by branches from the root; `&mut self` is exclusive.
                let t = unsafe { table_mut(table) };
                &mut t.entries[va.vpn(current)]
            };

            if !entry.is_valid() {
                let frame = alloc.alloc_frame().ok_or(MapError::OutOfFrames)?;
                *entry = Pte::branch(frame);
            } else if entry.is_leaf() {
                return Err(MapError::CoveredBySuperpage);
            }

            table = entry.phys_addr();
            current -= 1;
        }

        // SAFETY: as above.
        let t = unsafe { table_mut(table) };
        let entry = &mut t.entries[va.vpn(level)];
        if entry.is_valid() {
            return Err(MapError::AlreadyMapped);
        }
        *entry = Pte::leaf(pa, flags);
        Ok(())
    }

    /// Install a leaf without an allocator, failing if a branch is missing.
    ///
    /// Userspace supplies its own page table objects (D-035), so the kernel has
    /// nothing to allocate from here: a missing intermediate table is a
    /// [`MapError::MissingTable`] for the pager to fix, not a frame the kernel
    /// quietly takes. That is what keeps invariant 1 true on this path.
    pub fn map_leaf(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        level: usize,
        flags: PteFlags,
    ) -> Result<(), MapError> {
        self.check_leaf(va, pa, level, flags)?;

        let mut table = self.root;
        let mut current = MAX_LEVEL;
        while current > level {
            // SAFETY: reached by branches from this Mapper's root.
            let entry = unsafe { table_mut(table) }.entries[va.vpn(current)];
            if !entry.is_valid() {
                return Err(MapError::MissingTable);
            }
            if entry.is_leaf() {
                return Err(MapError::CoveredBySuperpage);
            }
            table = entry.phys_addr();
            current -= 1;
        }

        // SAFETY: as above.
        let entry = &mut unsafe { table_mut(table) }.entries[va.vpn(level)];
        if entry.is_valid() {
            return Err(MapError::AlreadyMapped);
        }
        *entry = Pte::leaf(pa, flags);
        Ok(())
    }

    /// Install an intermediate table supplied by userspace at `level`.
    pub fn map_table(
        &mut self,
        va: VirtAddr,
        table_pa: PhysAddr,
        level: usize,
    ) -> Result<(), MapError> {
        if level == 0 || level > MAX_LEVEL {
            return Err(MapError::BadLevel);
        }
        if !va.is_canonical() {
            return Err(MapError::NonCanonical);
        }
        if !table_pa.is_aligned(PAGE_SIZE) {
            return Err(MapError::MisalignedPhys);
        }

        let mut table = self.root;
        let mut current = MAX_LEVEL;
        while current > level {
            // SAFETY: reached by branches from this Mapper's root.
            let entry = unsafe { table_mut(table) }.entries[va.vpn(current)];
            if !entry.is_valid() {
                return Err(MapError::MissingTable);
            }
            if entry.is_leaf() {
                return Err(MapError::CoveredBySuperpage);
            }
            table = entry.phys_addr();
            current -= 1;
        }

        // SAFETY: as above.
        let entry = &mut unsafe { table_mut(table) }.entries[va.vpn(level)];
        if entry.is_valid() {
            return Err(MapError::AlreadyMapped);
        }
        *entry = Pte::branch(table_pa);
        Ok(())
    }

    fn check_leaf(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        level: usize,
        flags: PteFlags,
    ) -> Result<(), MapError> {
        if level > MAX_LEVEL {
            return Err(MapError::BadLevel);
        }
        if !va.is_canonical() {
            return Err(MapError::NonCanonical);
        }
        if !flags.is_leaf() || !flags.is_valid_combination() {
            return Err(MapError::BadFlags);
        }
        let size = page_size(level);
        if !va.is_aligned(size) {
            return Err(MapError::MisalignedVirt);
        }
        if !pa.is_aligned(size) {
            return Err(MapError::MisalignedPhys);
        }
        Ok(())
    }

    /// Map `size` bytes, choosing the largest superpage that fits at each step.
    pub fn map_range(
        &mut self,
        va: VirtAddr,
        pa: PhysAddr,
        size: usize,
        flags: PteFlags,
        alloc: &mut impl FrameAllocator,
    ) -> Result<(), MapError> {
        let mut offset = 0usize;
        while offset < size {
            let cur_va = va.offset(offset);
            let cur_pa = pa.offset(offset);
            let remaining = size - offset;

            let mut level = MAX_LEVEL;
            loop {
                let step = page_size(level);
                if step <= remaining && cur_va.is_aligned(step) && cur_pa.is_aligned(step) {
                    break;
                }
                if level == 0 {
                    break;
                }
                level -= 1;
            }

            self.map(cur_va, cur_pa, level, flags, alloc)?;
            offset += page_size(level);
        }
        Ok(())
    }

    /// Resolve a virtual address the way the hardware would.
    pub fn translate(&self, va: VirtAddr) -> Option<(PhysAddr, PteFlags, usize)> {
        if !va.is_canonical() {
            return None;
        }
        let mut table = self.root;
        for level in (0..=MAX_LEVEL).rev() {
            // SAFETY: `table` is the root or reached by following branches.
            let t = unsafe { table_ref(table) };
            let entry = t.entries[va.vpn(level)];

            if !entry.is_valid() {
                return None;
            }
            if entry.is_leaf() {
                let mask = page_size(level) - 1;
                let pa = PhysAddr::new(entry.phys_addr().as_usize() | (va.as_usize() & mask));
                return Some((pa, entry.flags(), level));
            }
            table = entry.phys_addr();
        }
        // Fell off the bottom: a branch at level 0, which the format forbids.
        None
    }

    /// Remove a mapping, returning the physical address it pointed at.
    pub fn unmap(&mut self, va: VirtAddr) -> Result<PhysAddr, MapError> {
        if !va.is_canonical() {
            return Err(MapError::NonCanonical);
        }
        let mut table = self.root;
        for level in (0..=MAX_LEVEL).rev() {
            // SAFETY: `&mut self` gives exclusive access to the tree.
            let t = unsafe { table_mut(table) };
            let entry = &mut t.entries[va.vpn(level)];

            if !entry.is_valid() {
                return Err(MapError::NotMapped);
            }
            if entry.is_leaf() {
                let pa = entry.phys_addr();
                *entry = Pte::EMPTY;
                return Ok(pa);
            }
            table = entry.phys_addr();
        }
        Err(MapError::NotMapped)
    }
}

// --- TLB ---

/// Invalidate every TLB entry on this hart.
#[inline]
pub fn flush_tlb_all() {
    // SAFETY: sfence.vma with both registers zero flushes everything.
    unsafe { core::arch::asm!("sfence.vma zero, zero", options(nostack)) };
}

/// Invalidate the TLB entries for one address.
#[inline]
pub fn flush_tlb_page(va: VirtAddr) {
    // SAFETY: as above; rs1 selects the address, rs2 = zero means all ASIDs.
    unsafe {
        core::arch::asm!("sfence.vma {va}, zero", va = in(reg) va.as_usize(), options(nostack))
    };
}
