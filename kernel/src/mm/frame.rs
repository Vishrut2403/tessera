//! The physical frame allocator: a bump pointer over the free regions (D-014).

use super::addr::{PAGE_SIZE, PhysAddr};
use super::region::Region;
use super::{Regions, phys_to_virt};

pub struct BumpAllocator {
    regions: Regions,
    /// Index into `regions` of the region we are currently handing out of.
    current: usize,
    /// Next address to hand out.
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
    pub fn init(&mut self, free: &Regions) {
        self.regions = *free;
        self.current = 0;
        self.cursor = free.iter().next().map_or(PhysAddr::new(0), |r| r.start);
        self.allocated = 0;
    }

    /// Hand out one zeroed 4 KiB frame.
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

    /// What is left; M4 turns this into untyped capabilities.
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
fn zero_frame(frame: PhysAddr) {
    let ptr = phys_to_virt(frame).as_mut_ptr::<u8>();
    // SAFETY: `frame` came from a free region, so we own it exclusively for PAGE_SIZE bytes.
    unsafe { core::ptr::write_bytes(ptr, 0, PAGE_SIZE) };
}
