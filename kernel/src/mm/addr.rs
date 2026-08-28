//! Physical and virtual addresses as distinct types.
//!
//! CLAUDE.md invariant 5: never a bare `usize`. The reason is not pedantry. In
//! M2c the kernel starts running at a virtual address while page tables keep
//! storing physical ones, and from then on a `usize` that is 0x8020_1000 could
//! be either a real physical frame or a virtual address that happens to be in
//! the identity window. Confusing the two produces a fault whose address looks
//! plausible, which is the worst kind. Making them different types means the
//! compiler catches the mistake instead of the MMU.
//!
//! Both are newtypes over `usize` with `#[repr(transparent)]`, so they cost
//! nothing at runtime and can still be handed to assembly.

use core::fmt;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// The offset at which the kernel — and, from M2c, all of physical memory —
/// appears in the virtual address space.
///
/// This is not an arbitrary round number. Sv39 requires canonical addresses:
/// bits 63:39 must all equal bit 38. `0xFFFF_FFC0_0000_0000` is exactly -2^38,
/// the *lowest* legal address in the upper half. Anything below it is
/// non-canonical and faults on use.
pub const KERNEL_VMA: usize = 0xFFFF_FFC0_0000_0000;

/// A physical address. Meaningful to the MMU and to devices; not dereferenceable
/// once paging is on (that is what [`crate::mm::phys_to_virt`] is for).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct PhysAddr(usize);

/// A virtual address. What the hart actually translates.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct VirtAddr(usize);

impl PhysAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Physical page number: the address shifted down by the page size. This is
    /// what a page table entry actually stores.
    pub const fn page_number(self) -> usize {
        self.0 >> PAGE_SHIFT
    }

    pub const fn page_offset(self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }

    /// Round down to a multiple of `align`, which must be a power of two.
    pub const fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Round up to a multiple of `align`, which must be a power of two.
    ///
    /// Saturating rather than wrapping: rounding up an address near the top of
    /// the space must not produce a small number, which would silently turn a
    /// bounds check into its opposite.
    pub const fn align_up(self, align: usize) -> Self {
        Self(self.0.saturating_add(align - 1) & !(align - 1))
    }

    pub const fn is_aligned(self, align: usize) -> bool {
        self.0 & (align - 1) == 0
    }

    pub const fn offset(self, bytes: usize) -> Self {
        Self(self.0 + bytes)
    }
}

impl VirtAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    pub const fn page_offset(self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }

    pub const fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub const fn align_up(self, align: usize) -> Self {
        Self(self.0.saturating_add(align - 1) & !(align - 1))
    }

    pub const fn is_aligned(self, align: usize) -> bool {
        self.0 & (align - 1) == 0
    }

    pub const fn offset(self, bytes: usize) -> Self {
        Self(self.0 + bytes)
    }

    /// The 9-bit index this address uses at page table `level`.
    ///
    /// Sv39 splits the virtual page number into three 9-bit fields, one per
    /// level: level 2 is bits 38:30, level 1 is 29:21, level 0 is 20:12. Each
    /// indexes a 512-entry table, and 512 = 2^9 is why the fields are 9 bits.
    pub const fn vpn(self, level: usize) -> usize {
        (self.0 >> (PAGE_SHIFT + 9 * level)) & 0x1ff
    }

    /// Whether the address is canonical: bits 63:39 must replicate bit 38.
    ///
    /// A non-canonical address faults on *use*, not on construction, so
    /// checking here turns a mysterious page fault into a caught mistake.
    pub const fn is_canonical(self) -> bool {
        let top = self.0 >> 38;
        top == 0 || top == (usize::MAX >> 38)
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#012x}", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}
