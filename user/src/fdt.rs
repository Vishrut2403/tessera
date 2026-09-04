//! A device tree reader, in userspace and outside the TCB (D-041).

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
    /// stays mapped for `'a`.
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

    /// Every device whose `compatible` list contains `what`, in tree order.
    /// Properties arrive grouped by node, so a node is complete as soon as the
    /// next one starts, which is why the last one is flushed after the walk.
    pub fn each_compatible(&self, what: &[u8], mut f: impl FnMut(Device)) -> Option<()> {
        let mut name_buf = [0u8; 64];
        let mut name_len = 0usize;
        let mut device = Device::default();
        let mut matches = false;
        let f = &mut f;

        self.walk(|node, prop, value| {
            if node.len() > name_buf.len() {
                return;
            }
            if name_len != node.len() || name_buf[..name_len] != *node {
                if matches && device.size != 0 {
                    f(device);
                }
                name_buf[..node.len()].copy_from_slice(node);
                name_len = node.len();
                device = Device::default();
                matches = false;
            }
            match prop {
                b"compatible" => {
                    matches = value.windows(what.len()).any(|w| w == what);
                }
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

        if matches && device.size != 0 {
            f(device);
        }
        Some(())
    }

    /// The first device whose `compatible` list contains `what`.
    pub fn find(&self, what: &[u8]) -> Option<Device> {
        let mut found = None;
        self.each_compatible(what, |d| {
            if found.is_none() {
                found = Some(d);
            }
        })?;
        found
    }
}
