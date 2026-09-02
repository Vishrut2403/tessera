//! A device tree reader, in userspace and outside the TCB (D-041).
//!
//! The kernel has its own minimal walk, because it must find RAM before
//! anything else exists. This one answers the questions a driver asks — which
//! node claims to be a given device, where its registers are, which interrupt
//! it raises — and every line of it is unprivileged. The duplication is the
//! point: putting these queries in a crate the kernel links would drag them
//! back into the trusted computing base.

const MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// One device, as the tree describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Device {
    pub paddr: u64,
    pub size: u64,
    /// The source number it raises, or `None` if it raises none.
    pub irq: Option<u32>,
}

pub struct Fdt<'a> {
    blob: &'a [u8],
    structs: usize,
    structs_end: usize,
    strings: usize,
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn cells(v: &[u8], off: usize, n: usize) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..n {
        out = (out << 32) | be32(v, off + i * 4)? as u64;
    }
    Some(out)
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A NUL-terminated string at `off`, as bytes without the terminator.
fn cstr(b: &[u8], off: usize) -> Option<&[u8]> {
    let rest = b.get(off..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    Some(&rest[..end])
}

impl<'a> Fdt<'a> {
    /// # Safety
    /// `ptr` must point at a device tree blob of at least `len` bytes that
    /// stays mapped for `'a`. The kernel maps ours read-only before we run.
    pub unsafe fn new(ptr: *const u8, len: usize) -> Option<Self> {
        // SAFETY: the caller promised `len` readable bytes at `ptr`.
        let blob = unsafe { core::slice::from_raw_parts(ptr, len) };
        if be32(blob, 0)? != MAGIC {
            return None;
        }
        let structs = be32(blob, 8)? as usize;
        let strings = be32(blob, 12)? as usize;
        let size_struct = be32(blob, 36)? as usize;
        let end = structs.checked_add(size_struct)?;
        if end > blob.len() || strings > blob.len() {
            return None;
        }
        Some(Self { blob, structs, structs_end: end, strings })
    }

    /// Call `f` for every property, with the name of the node holding it.
    fn walk(&self, mut f: impl FnMut(&[u8], &[u8], &'a [u8])) -> Option<()> {
        let mut off = self.structs;
        let mut depth = 0usize;
        // Only the innermost name is needed: every node we care about is
        // identified by its own `compatible`, not by where it sits.
        let mut names: [&[u8]; 16] = [b""; 16];

        while off < self.structs_end {
            let token = be32(self.blob, off)?;
            off += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name = cstr(self.blob, off)?;
                    off += align4(name.len() + 1);
                    if depth < names.len() {
                        names[depth] = name;
                    }
                    depth += 1;
                }
                FDT_END_NODE => depth = depth.saturating_sub(1),
                FDT_PROP => {
                    let len = be32(self.blob, off)? as usize;
                    let name_off = be32(self.blob, off + 4)? as usize;
                    off += 8;
                    let value = self.blob.get(off..off + len)?;
                    off += align4(len);
                    let name = cstr(self.blob, self.strings + name_off)?;
                    let node = names[depth.saturating_sub(1).min(names.len() - 1)];
                    f(node, name, value);
                }
                FDT_NOP => {}
                FDT_END => return Some(()),
                _ => return None,
            }
        }
        Some(())
    }

    /// The first device whose `compatible` list contains `what`.
    ///
    /// Two passes, because a property can name its node but a node cannot name
    /// its properties: the first finds which node matches, the second reads
    /// that node's `reg` and `interrupts`.
    pub fn find(&self, what: &[u8]) -> Option<Device> {
        let mut node = [0u8; 64];
        let mut node_len = 0usize;
        self.walk(|n, name, value| {
            if node_len == 0
                && name == b"compatible"
                && value.windows(what.len()).any(|w| w == what)
                && n.len() <= node.len()
            {
                node[..n.len()].copy_from_slice(n);
                node_len = n.len();
            }
        })?;
        if node_len == 0 {
            return None;
        }

        let mut device = Device::default();
        self.walk(|n, name, value| {
            if n != &node[..node_len] {
                return;
            }
            match name {
                // Two address cells and two size cells: what `/` and `/soc`
                // both declare on this platform.
                b"reg" => {
                    if let (Some(p), Some(s)) = (cells(value, 0, 2), cells(value, 8, 2)) {
                        device.paddr = p;
                        device.size = s;
                    }
                }
                b"interrupts" => device.irq = be32(value, 0),
                _ => {}
            }
        })?;

        (device.size != 0).then_some(device)
    }
}
