//! Sv39 page tables: entries, tables, and the three-level walk.
//!
//! ## The format
//!
//! A 39-bit virtual address splits into three 9-bit indices and a 12-bit offset:
//!
//! ```text
//!  38      30 29      21 20      12 11         0
//! +----------+----------+----------+------------+
//! |  VPN[2]  |  VPN[1]  |  VPN[0]  |   offset   |
//! +----------+----------+----------+------------+
//! ```
//!
//! Each index selects one of 512 entries in a table, and 512 8-byte entries is
//! exactly one 4 KiB page — that is not a coincidence, it is the constraint the
//! whole format is built around. A page table is a page.
//!
//! A page table entry is:
//!
//! ```text
//!  63    54 53                10 9   8 7 6 5 4 3 2 1 0
//! +--------+--------------------+-----+-+-+-+-+-+-+-+-+
//! |reserved|      PPN[43:0]     | RSW |D|A|G|U|X|W|R|V|
//! +--------+--------------------+-----+-+-+-+-+-+-+-+-+
//! ```
//!
//! Note the PPN starts at bit 10, not bit 12: the entry stores a *page number*,
//! so the physical address is `(pte >> 10) << 12`. The two-bit RSW field is
//! reserved for software and the hardware never touches it — M4 may well want it
//! for capability bookkeeping.
//!
//! ## Leaves, branches, and superpages
//!
//! An entry with `V = 0` is invalid. With `V = 1` and R, W, X all clear it is a
//! **branch** pointing at the next level. With `V = 1` and any of R/W/X set it is
//! a **leaf**. Stopping early gives superpages: a leaf at level 1 maps 2 MiB, at
//! level 2 maps 1 GiB (D-016). A superpage leaf whose physical address is not
//! aligned to its own size faults — the hardware does not round for you.
//!
//! `W` without `R` is a reserved encoding, not a write-only page. We reject it
//! rather than let the hardware surprise us later.
//!
//! ## Where the unsafe is
//!
//! Two functions, [`table_ref`] and [`table_mut`], which turn the physical
//! address of a table into a reference through the current physical-memory
//! mapping. Everything else is safe code manipulating `Pte` values.

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

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

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
    /// Global: the mapping is present in every address space, so a TLB entry for
    /// it survives an ASID change. Correct for kernel mappings, catastrophic if
    /// set on one that is not actually global.
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
        // One letter per bit, a dash where it is clear -- far easier to scan in
        // a dump than a hex value.
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

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

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
    ///
    /// R, W, X are all clear — that is what makes it a branch — and so are A, D
    /// and U, which the spec requires to be zero in a non-leaf.
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

    /// The physical address this entry points at: the frame for a leaf, the
    /// next-level table for a branch.
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

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// One level of page table. Exactly one 4 KiB page, and aligned to one, because
/// the PPN field in a branch entry can only address whole pages.
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
/// `pa` must be the address of a live page table frame, and the caller must not
/// create an aliasing `&mut` for the same frame while this reference lives.
unsafe fn table_ref<'a>(pa: PhysAddr) -> &'a PageTable {
    unsafe { &*phys_to_virt(pa).as_ptr::<PageTable>() }
}

/// Mutably borrow the table at `pa`.
///
/// # Safety
/// As [`table_ref`], and the caller must hold exclusive access to the tree this
/// table belongs to. In practice that means going through a `&mut Mapper`.
unsafe fn table_mut<'a>(pa: PhysAddr) -> &'a mut PageTable {
    unsafe { &mut *phys_to_virt(pa).as_mut_ptr::<PageTable>() }
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Virtual address is not sign-extended correctly for Sv39.
    NonCanonical,
    /// Level above [`MAX_LEVEL`].
    BadLevel,
    /// Virtual address not aligned to the page size at this level.
    MisalignedVirt,
    /// Physical address not aligned to the page size at this level. A superpage
    /// leaf with a misaligned PPN faults; the hardware does not round.
    MisalignedPhys,
    /// Flags describe a branch (no R/W/X), or the reserved W-without-R encoding.
    BadFlags,
    /// Something is already mapped here.
    AlreadyMapped,
    /// Nothing is mapped here.
    NotMapped,
    /// A superpage at a higher level already covers this address; splitting it
    /// is not implemented.
    CoveredBySuperpage,
    /// The frame allocator is empty.
    OutOfFrames,
}

/// Source of page table frames. Implemented by the bump allocator; in M4 this
/// becomes a capability to untyped memory instead.
pub trait FrameAllocator {
    fn alloc_frame(&mut self) -> Option<PhysAddr>;
}

impl FrameAllocator for super::BumpAllocator {
    fn alloc_frame(&mut self) -> Option<PhysAddr> {
        super::BumpAllocator::alloc_frame(self)
    }
}

/// A page table tree, identified by the physical address of its root.
///
/// Holding a `Mapper` is the claim of exclusive access to the tree. That is what
/// makes the `&mut` in [`table_mut`] sound.
pub struct Mapper {
    root: PhysAddr,
}

impl Mapper {
    /// Wrap an existing root table.
    ///
    /// # Safety
    /// `root` must point at a zeroed or well-formed page table frame that no
    /// other `Mapper` is using.
    pub const unsafe fn from_root(root: PhysAddr) -> Self {
        Self { root }
    }

    /// Allocate a fresh, empty root table.
    pub fn new(alloc: &mut impl FrameAllocator) -> Result<Self, MapError> {
        // The allocator zeroes, so the new root is entirely invalid entries,
        // which is exactly what an empty address space is.
        let root = alloc.alloc_frame().ok_or(MapError::OutOfFrames)?;
        Ok(Self { root })
    }

    pub const fn root(&self) -> PhysAddr {
        self.root
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
        // Descend, creating branches, until we are at the level that will hold
        // the leaf. Note the loop does not run at all when level == MAX_LEVEL:
        // a 1 GiB leaf lives in the root table itself.
        let mut current = MAX_LEVEL;
        while current > level {
            let entry = {
                // SAFETY: `table` is the root or a frame reached by following
                // branch entries from it, and `&mut self` gives us exclusive
                // access to the whole tree.
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

    /// Map `size` bytes, choosing the largest superpage that fits at each step.
    ///
    /// The choice is constrained by three things at once: both addresses must be
    /// aligned to the page size, and the page must fit in what is left. Building
    /// the direct map out of 4 KiB pages would take hundreds of tables; with
    /// this it takes one 1 GiB leaf.
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
    ///
    /// Returns the physical address, the leaf's flags, and the level the leaf
    /// was found at. The offset carried through is the offset within the
    /// *superpage*, not within 4 KiB — which is why the mask comes from the
    /// level rather than being `PAGE_SIZE - 1`.
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
    ///
    /// Intermediate tables are deliberately left behind. They cost one frame
    /// each, the bump allocator could not reclaim them anyway (D-014), and
    /// freeing them would mean proving no sibling entry is still live.
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

// ---------------------------------------------------------------------------
// TLB
// ---------------------------------------------------------------------------

/// Invalidate every TLB entry on this hart.
///
/// The MMU is allowed to cache translations indefinitely, so *any* change to a
/// page table that could have been walked already must be followed by an
/// `sfence.vma`. Not doing so produces a stale translation, which presents as
/// memory that reads correctly through one address and wrongly through another.
#[inline]
pub fn flush_tlb_all() {
    // SAFETY: sfence.vma with both registers zero flushes everything. It cannot
    // fault, but it must not be reordered with the page table writes it is
    // ordering, hence no `nomem`.
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
