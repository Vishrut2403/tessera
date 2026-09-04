//! A minimal flattened device tree reader.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtError {
    /// Magic number is not 0xd00dfeed, so the pointer is not a DTB at all.
    BadMagic,
    /// A read ran off the end of the blob.
    Truncated,
    /// A token we do not recognise: the stream is corrupt or a newer format.
    BadToken(u32),
    /// A string in the blob is not valid UTF-8.
    BadString,
    /// Nesting deeper than we track.
    TooDeep,
}

const FDT_MAGIC: u32 = 0xd00d_feed;

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// Deepest nesting we track node names for.
const MAX_DEPTH: usize = 8;

const HEADER_SIZE: usize = 40;

#[derive(Clone, Copy, Debug)]
struct Header {
    total_size: usize,
    off_struct: usize,
    off_strings: usize,
    off_rsvmap: usize,
    size_struct: usize,
}

/// One property, as handed to a visitor.
pub struct Property<'a> {
    /// Depth of the node owning this property; the root is 0.
    pub depth: usize,
    /// Name of the owning node, e.g. `memory@80000000`.
    pub node: &'a str,
    /// Name of the owning node's parent, e.g. `reserved-memory`.
    pub parent: &'a str,
    /// Property name, e.g. `reg`.
    pub name: &'a str,
    /// Raw big-endian value bytes.
    pub value: &'a [u8],
}

pub struct Fdt<'a> {
    blob: &'a [u8],
    header: Header,
}

impl<'a> Fdt<'a> {
    /// Interpret `ptr` as a flattened device tree.
    ///
    /// # Safety
    /// `ptr` must point at a DTB whose `totalsize` bytes stay readable and
    /// unmutated for `'a`.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Self, FdtError> {
        // Bounded header read first: totalsize is untrustworthy until the magic checks out.
        let head = unsafe { core::slice::from_raw_parts(ptr, HEADER_SIZE) };

        if be32(head, 0)? != FDT_MAGIC {
            return Err(FdtError::BadMagic);
        }

        let header = Header {
            total_size: be32(head, 4)? as usize,
            off_struct: be32(head, 8)? as usize,
            off_strings: be32(head, 12)? as usize,
            off_rsvmap: be32(head, 16)? as usize,
            size_struct: be32(head, 36)? as usize,
        };

        if header.total_size < HEADER_SIZE {
            return Err(FdtError::Truncated);
        }

        // SAFETY: magic checked, so `total_size` is the blob's own length, readable per the caller.
        let blob = unsafe { core::slice::from_raw_parts(ptr, header.total_size) };

        // Validate the block offsets once, so every later read is against a checked blob.
        if header.off_struct + header.size_struct > blob.len()
            || header.off_strings > blob.len()
            || header.off_rsvmap > blob.len()
        {
            return Err(FdtError::Truncated);
        }

        Ok(Self { blob, header })
    }

    pub fn total_size(&self) -> usize {
        self.header.total_size
    }

    /// Visit every `(address, size)` pair in the memory reservation block.
    pub fn for_each_reservation<F>(&self, mut f: F) -> Result<(), FdtError>
    where
        F: FnMut(u64, u64),
    {
        let mut off = self.header.off_rsvmap;
        loop {
            let addr = be64(self.blob, off)?;
            let size = be64(self.blob, off + 8)?;
            // A zero-length entry terminates the list, not a zero-byte reservation at address zero.
            if addr == 0 && size == 0 {
                return Ok(());
            }
            f(addr, size);
            off += 16;
        }
    }

    /// Walk the structure block, calling `f` for every property.
    pub fn for_each_property<F>(&self, mut f: F) -> Result<(), FdtError>
    where
        F: FnMut(Property<'_>),
    {
        let mut off = self.header.off_struct;
        let end = self.header.off_struct + self.header.size_struct;
        let mut depth: usize = 0;
        let mut names: [&str; MAX_DEPTH] = [""; MAX_DEPTH];

        while off < end {
            let token = be32(self.blob, off)?;
            off += 4;

            match token {
                FDT_BEGIN_NODE => {
                    let name = cstr(self.blob, off)?;
                    off += align4(name.len() + 1);
                    if depth >= MAX_DEPTH {
                        return Err(FdtError::TooDeep);
                    }
                    names[depth] = name;
                    depth += 1;
                }
                FDT_END_NODE => {
                    // Saturating: a corrupt blob should not take the kernel down.
                    depth = depth.saturating_sub(1);
                }
                FDT_PROP => {
                    let len = be32(self.blob, off)? as usize;
                    let name_off = be32(self.blob, off + 4)? as usize;
                    off += 8;
                    let value =
                        self.blob.get(off..off + len).ok_or(FdtError::Truncated)?;
                    off += align4(len);

                    let name = cstr(self.blob, self.header.off_strings + name_off)?;
                    let node = if depth >= 1 { names[depth - 1] } else { "" };
                    let parent = if depth >= 2 { names[depth - 2] } else { "" };

                    f(Property {
                        depth: depth.saturating_sub(1),
                        node,
                        parent,
                        name,
                        value,
                    });
                }
                FDT_NOP => {}
                FDT_END => return Ok(()),
                other => return Err(FdtError::BadToken(other)),
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Fdt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fdt({} bytes)", self.header.total_size)
    }
}

/// Read `cells` consecutive 4-byte big-endian cells as one number.
pub fn read_cells(value: &[u8], offset: usize, cells: usize) -> Result<u64, FdtError> {
    let mut acc: u64 = 0;
    for i in 0..cells {
        acc = (acc << 32) | be32(value, offset + i * 4)? as u64;
    }
    Ok(acc)
}

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn be32(b: &[u8], off: usize) -> Result<u32, FdtError> {
    let s = b.get(off..off + 4).ok_or(FdtError::Truncated)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], off: usize) -> Result<u64, FdtError> {
    Ok(((be32(b, off)? as u64) << 32) | be32(b, off + 4)? as u64)
}

fn cstr(b: &[u8], off: usize) -> Result<&str, FdtError> {
    let rest = b.get(off..).ok_or(FdtError::Truncated)?;
    let len = rest.iter().position(|&c| c == 0).ok_or(FdtError::Truncated)?;
    core::str::from_utf8(&rest[..len]).map_err(|_| FdtError::BadString)
}
