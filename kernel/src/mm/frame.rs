//! The physical frame allocator: a bump pointer over the free regions (D-014).
//!
//! ## Why this is barely an allocator
//!
//! A-002 says the kernel has no heap and that userspace retypes untyped memory
//! into objects. So the only allocation the kernel ever legitimately performs is
//! during boot, for its own page tables, before there is a userspace to ask.
//! After M4 hands the remaining free regions to the root task as untyped
//! capabilities, this allocator stops being used entirely.
//!
//! That is why it is a bump pointer and cannot free. A kernel that cannot free
//! also cannot double-free, cannot fragment, and cannot be exhausted by a
//! malicious caller — because there is no caller. seL4 works exactly this way:
//! bounded bump allocation during boot, then untyped capabilities forever.
//!
//! The consequence, stated plainly so it is not a surprise in M4: **frames
//! handed out here are gone for good.** They are kernel page tables, they live
//! as long as the kernel does, and they are subtracted from what M4 will offer
//! userspace. If a later milestone needs reclaimable kernel memory, that is a
//! design change, not a tweak.

use super::addr::{PAGE_SIZE, PhysAddr};
use super::region::Region;
use super::{Regions, phys_to_virt};

pub struct BumpAllocator {
    regions: Regions,
    /// Index into `regions` of the region we are currently handing out of.
    current: usize,
    /// Next address to hand out. Always within `regions[current]`, or past its
    /// end when that region is exhausted.
    cursor: PhysAddr,
    allocated: usize,
}

impl Default for BumpAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl BumpAllocator {
    pub const fn new() -> Self {
        Self {
            regions: Regions::new(),
            current: 0,
            cursor: PhysAddr::new(0),
            allocated: 0,
        }
    }

    /// Take ownership of the free regions.
    ///
    /// The regions must already be page-aligned; `MemoryMap::free` guarantees
    /// that, and asserting it here would be checking our own arithmetic rather
    /// than a caller's input.
    pub fn init(&mut self, free: &Regions) {
        self.regions = *free;
        self.current = 0;
        self.cursor = free.iter().next().map_or(PhysAddr::new(0), |r| r.start);
        self.allocated = 0;
    }

    /// Hand out one zeroed 4 KiB frame.
    ///
    /// Zeroed because every current consumer is a page table, and a page table
    /// full of uninitialised memory is a table full of entries with random V
    /// bits pointing at random physical addresses. Doing it here rather than
    /// making each caller remember is the difference between an invariant and a
    /// convention.
    pub fn alloc_frame(&mut self) -> Option<PhysAddr> {
        while self.current < self.regions.len() {
            let region = self.regions.as_slice()[self.current];
            if self.cursor.as_usize() + PAGE_SIZE <= region.end.as_usize() {
                let frame = self.cursor;
                self.cursor = self.cursor.offset(PAGE_SIZE);
                self.allocated += 1;
                zero_frame(frame);
                return Some(frame);
            }
            // This region is exhausted; move to the next.
            self.current += 1;
            if let Some(next) = self.regions.as_slice().get(self.current) {
                self.cursor = next.start;
            }
        }
        None
    }

    pub fn frames_allocated(&self) -> usize {
        self.allocated
    }

    pub fn bytes_allocated(&self) -> usize {
        self.allocated * PAGE_SIZE
    }

    /// What is left, as regions — this is what M4 turns into untyped
    /// capabilities. The partially consumed region is reported from the cursor,
    /// not from its original start.
    pub fn remaining(&self) -> Regions {
        let mut out = Regions::new();
        for (i, region) in self.regions.iter().enumerate() {
            if i < self.current {
                continue;
            }
            let start = if i == self.current { self.cursor } else { region.start };
            let _ = out.push(Region::new(start, region.end));
        }
        out
    }

    pub fn bytes_remaining(&self) -> usize {
        self.remaining().total_bytes()
    }
}

/// Zero a frame through whatever mapping currently reaches physical memory.
///
/// `phys_to_virt` is the identity before M2c and the direct map after, so this
/// works in both phases without the caller knowing which one it is in.
fn zero_frame(frame: PhysAddr) {
    let ptr = phys_to_virt(frame).as_mut_ptr::<u8>();
    // SAFETY: `frame` came from a free region — memory the device tree calls
    // RAM, minus everything reserved — so we own it exclusively and it is
    // PAGE_SIZE bytes long. `write_bytes` on a u8 pointer has no alignment
    // requirement beyond 1.
    unsafe { core::ptr::write_bytes(ptr, 0, PAGE_SIZE) };
}
