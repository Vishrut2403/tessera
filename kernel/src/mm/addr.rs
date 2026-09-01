//! Physical and virtual addresses as distinct types.

use core::fmt;

pub use abi::{PAGE_SHIFT, PAGE_SIZE};

/// Virtual offset of the kernel and, from M2c, of all physical memory.
pub const KERNEL_VMA: usize = 0xFFFF_FFC0_0000_0000;

/// A physical address; not dereferenceable once paging is on.
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

    /// Physical page number: what a page table entry actually stores.
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
    pub const fn vpn(self, level: usize) -> usize {
        (self.0 >> (PAGE_SHIFT + 9 * level)) & 0x1ff
    }

    /// Whether the address is canonical: bits 63:39 must replicate bit 38.
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
