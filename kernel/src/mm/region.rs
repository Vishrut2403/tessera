//! Half-open physical address ranges, and the set arithmetic over them that
//! turns "what RAM exists" plus "what is already spoken for" into "what is
//! free".
//!
//! Fixed-capacity arrays throughout. That is not a limitation working around the
//! lack of a heap — it is the point (A-002). A kernel that cannot allocate
//! cannot fail to allocate, so every one of these lists has a bound that is
//! visible in the type and an overflow that is an explicit error rather than a
//! silent truncation.

use core::fmt;

use super::addr::{PAGE_SIZE, PhysAddr};

/// A half-open range `[start, end)`.
///
/// Half-open because it composes: adjacent regions share an endpoint, an empty
/// region is `start == end` rather than a special case, and length is
/// `end - start` with no off-by-one. Inclusive ranges make the region ending at
/// the top of the address space unrepresentable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: PhysAddr,
    pub end: PhysAddr,
}

impl Region {
    pub const fn new(start: PhysAddr, end: PhysAddr) -> Self {
        Self { start, end }
    }

    pub const fn from_start_len(start: PhysAddr, len: usize) -> Self {
        Self { start, end: PhysAddr::new(start.as_usize() + len) }
    }

    pub const fn len(&self) -> usize {
        self.end.as_usize().saturating_sub(self.start.as_usize())
    }

    pub const fn is_empty(&self) -> bool {
        self.start.as_usize() >= self.end.as_usize()
    }

    pub const fn contains(&self, addr: PhysAddr) -> bool {
        self.start.as_usize() <= addr.as_usize() && addr.as_usize() < self.end.as_usize()
    }

    pub const fn overlaps(&self, other: &Region) -> bool {
        self.start.as_usize() < other.end.as_usize()
            && other.start.as_usize() < self.end.as_usize()
    }

    /// Shrink to whole pages: start rounds up, end rounds down.
    ///
    /// Deliberately conservative in both directions. A partial page at either
    /// end is unusable as a frame, and rounding *outward* would hand out memory
    /// that belongs to whatever the region was carved out of.
    pub const fn page_aligned(&self) -> Self {
        Self { start: self.start.align_up(PAGE_SIZE), end: self.end.align_down(PAGE_SIZE) }
    }

    pub const fn frame_count(&self) -> usize {
        self.len() / PAGE_SIZE
    }
}

impl fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{} ({} KiB)", self.start, self.end, self.len() / 1024)
    }
}

/// Overflow of a fixed-capacity list. Always a bug in the caller's sizing, never
/// something to recover from at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityExceeded;

/// A bounded set of regions.
#[derive(Clone, Copy)]
pub struct RegionList<const N: usize> {
    regions: [Region; N],
    len: usize,
}

impl<const N: usize> Default for RegionList<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RegionList<N> {
    pub const EMPTY: Region =
        Region { start: PhysAddr::new(0), end: PhysAddr::new(0) };

    pub const fn new() -> Self {
        Self { regions: [Self::EMPTY; N], len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn as_slice(&self) -> &[Region] {
        &self.regions[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [Region] {
        &mut self.regions[..self.len]
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Region> {
        self.as_slice().iter()
    }

    /// Remove any region that has become empty.
    ///
    /// Page-aligning a region smaller than a page collapses it to nothing, and
    /// a zero-length region left in the list would later be reported as usable
    /// memory containing no frames.
    pub fn drop_empty(&mut self) {
        let mut write = 0;
        for read in 0..self.len {
            if !self.regions[read].is_empty() {
                self.regions[write] = self.regions[read];
                write += 1;
            }
        }
        self.len = write;
    }

    /// Append a region. Empty regions are dropped rather than stored, so callers
    /// never have to filter them out downstream.
    pub fn push(&mut self, region: Region) -> Result<(), CapacityExceeded> {
        if region.is_empty() {
            return Ok(());
        }
        if self.len == N {
            return Err(CapacityExceeded);
        }
        self.regions[self.len] = region;
        self.len += 1;
        Ok(())
    }

    pub fn total_bytes(&self) -> usize {
        self.iter().map(|r| r.len()).sum()
    }

    /// Sort by start address and merge every overlapping or touching pair.
    ///
    /// Insertion sort: N is at most a couple of dozen, and an insertion sort is
    /// a dozen lines that are obviously correct, which beats a clever sort we
    /// would have to trust. Merging *touching* regions (`end == start`) and not
    /// just overlapping ones matters — the reserved ranges we get from firmware
    /// are frequently exactly adjacent, and leaving them separate would make the
    /// subtraction below emit zero-length gaps between them.
    pub fn normalize(&mut self) {
        let s = &mut self.regions[..self.len];
        for i in 1..s.len() {
            let mut j = i;
            while j > 0 && s[j - 1].start > s[j].start {
                s.swap(j - 1, j);
                j -= 1;
            }
        }

        let mut write = 0;
        for read in 1..self.len {
            if self.regions[read].start.as_usize() <= self.regions[write].end.as_usize() {
                if self.regions[read].end > self.regions[write].end {
                    self.regions[write].end = self.regions[read].end;
                }
            } else {
                write += 1;
                self.regions[write] = self.regions[read];
            }
        }
        if self.len > 0 {
            self.len = write + 1;
        }
    }

    /// Everything in `self` that is not in `cuts`.
    ///
    /// `cuts` is normalized first, so the inner loop can assume sorted,
    /// non-overlapping cuts and walk each region once — the whole thing is
    /// linear rather than quadratic. `cursor` tracks how far into the current
    /// region we have accounted for; every gap between the cursor and the next
    /// cut is free memory.
    pub fn subtract<const M: usize>(
        &self,
        cuts: &RegionList<M>,
    ) -> Result<RegionList<N>, CapacityExceeded> {
        let mut cuts = *cuts;
        cuts.normalize();

        let mut out = RegionList::<N>::new();
        for region in self.iter() {
            let mut cursor = region.start;
            for cut in cuts.iter() {
                if cut.end <= cursor {
                    continue; // entirely behind us
                }
                if cut.start >= region.end {
                    break; // sorted, so everything after is too
                }
                if cut.start > cursor {
                    let end = if cut.start < region.end { cut.start } else { region.end };
                    out.push(Region::new(cursor, end))?;
                }
                if cut.end > cursor {
                    cursor = cut.end;
                }
                if cursor >= region.end {
                    break;
                }
            }
            if cursor < region.end {
                out.push(Region::new(cursor, region.end))?;
            }
        }
        Ok(out)
    }
}

impl<const N: usize> fmt::Debug for RegionList<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(start: usize, end: usize) -> Region {
        Region::new(PhysAddr::new(start), PhysAddr::new(end))
    }

    fn list<const N: usize>(items: &[Region]) -> RegionList<N> {
        let mut l = RegionList::<N>::new();
        for i in items {
            l.push(*i).unwrap();
        }
        l
    }

    #[test_case]
    fn normalize_sorts_and_merges_overlaps() {
        let mut l = list::<8>(&[r(300, 400), r(100, 200), r(150, 250)]);
        l.normalize();
        assert_eq!(l.as_slice(), &[r(100, 250), r(300, 400)]);
    }

    #[test_case]
    fn normalize_merges_touching_regions() {
        // end == start, no overlap. Firmware reservations are frequently exactly
        // adjacent, and leaving these separate makes subtract emit empty gaps.
        let mut l = list::<8>(&[r(100, 200), r(200, 300)]);
        l.normalize();
        assert_eq!(l.as_slice(), &[r(100, 300)]);
    }

    #[test_case]
    fn normalize_keeps_disjoint_regions_apart() {
        let mut l = list::<8>(&[r(100, 200), r(201, 300)]);
        l.normalize();
        assert_eq!(l.len(), 2);
    }

    #[test_case]
    fn subtract_cut_in_the_middle_splits() {
        let ram = list::<8>(&[r(0, 1000)]);
        let cuts = list::<8>(&[r(400, 600)]);
        assert_eq!(ram.subtract(&cuts).unwrap().as_slice(), &[r(0, 400), r(600, 1000)]);
    }

    #[test_case]
    fn subtract_trims_both_ends() {
        let ram = list::<8>(&[r(100, 900)]);
        let cuts = list::<8>(&[r(0, 200), r(800, 1000)]);
        assert_eq!(ram.subtract(&cuts).unwrap().as_slice(), &[r(200, 800)]);
    }

    #[test_case]
    fn subtract_covering_cut_removes_everything() {
        let ram = list::<8>(&[r(100, 200)]);
        let cuts = list::<8>(&[r(0, 1000)]);
        assert!(ram.subtract(&cuts).unwrap().is_empty());
    }

    #[test_case]
    fn subtract_ignores_non_overlapping_cuts() {
        let ram = list::<8>(&[r(100, 200)]);
        let cuts = list::<8>(&[r(0, 50), r(500, 600)]);
        assert_eq!(ram.subtract(&cuts).unwrap().as_slice(), &[r(100, 200)]);
    }

    #[test_case]
    fn subtract_handles_unsorted_overlapping_cuts() {
        // The exact shape firmware hands us: out of order, overlapping.
        let ram = list::<8>(&[r(0, 1000)]);
        let cuts = list::<8>(&[r(700, 800), r(100, 300), r(200, 400)]);
        assert_eq!(
            ram.subtract(&cuts).unwrap().as_slice(),
            &[r(0, 100), r(400, 700), r(800, 1000)]
        );
    }

    #[test_case]
    fn subtract_across_several_regions() {
        let ram = list::<8>(&[r(0, 100), r(200, 300), r(400, 500)]);
        let cuts = list::<8>(&[r(50, 250)]);
        assert_eq!(ram.subtract(&cuts).unwrap().as_slice(), &[r(0, 50), r(250, 300), r(400, 500)]);
    }

    #[test_case]
    fn page_aligned_shrinks_inward() {
        // Rounding outward would hand out memory belonging to a neighbour.
        let region = r(0x1001, 0x2fff).page_aligned();
        assert_eq!(region, r(0x2000, 0x2000));
        assert!(region.is_empty());
    }

    #[test_case]
    fn push_rejects_overflow_rather_than_truncating() {
        let mut l = RegionList::<2>::new();
        assert!(l.push(r(0, 1)).is_ok());
        assert!(l.push(r(2, 3)).is_ok());
        assert_eq!(l.push(r(4, 5)), Err(CapacityExceeded));
    }

    #[test_case]
    fn push_silently_drops_empty_regions() {
        let mut l = RegionList::<2>::new();
        l.push(r(5, 5)).unwrap();
        assert!(l.is_empty());
    }
}
