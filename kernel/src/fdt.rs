//! A minimal flattened device tree reader.
//!
//! OpenSBI handed us a DTB pointer in `a1` (D-003), and that blob is the only
//! honest answer to "how much RAM is there and what is already spoken for".
//! Hardcoding QEMU virt's map would work today and be wrong on the Milk-V.
//!
//! We read three things and nothing else: the `/memory` nodes, the
//! `/reserved-memory` children, and the memory reservation block. This is not a
//! general device tree library — M7 will extend it for virtio discovery.
//!
//! ## Format, briefly
//!
//! A DTB is three blocks behind a header, all big-endian (the format predates
//! RISC-V and was born on big-endian PowerPC):
//!
//! - the **memory reservation block**: `(u64 address, u64 size)` pairs, ending
//!   with a pair of zeroes. Firmware uses it to say "do not touch this".
//! - the **structure block**: a token stream. `BEGIN_NODE` (1) opens a node and
//!   is followed by its NUL-terminated name; `PROP` (3) is followed by a length,
//!   an offset into the strings block for the property's name, and the value;
//!   `END_NODE` (2) closes; `NOP` (4) is padding; `END` (9) terminates. Every
//!   item is padded to a 4-byte boundary.
//! - the **strings block**: property names, deduplicated, referenced by offset.
//!
//! ## Where the unsafe is
//!
//! Exactly one place: [`Fdt::from_ptr`], which turns a raw pointer from firmware
//! into a `&[u8]`. Everything above it is safe code doing bounds-checked slice
//! reads, so a malformed blob produces an `FdtError` rather than a wild read.
//! That is design requirement (b) in miniature.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtError {
    /// Magic number is not 0xd00dfeed — the pointer is not a DTB at all.
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

/// Deepest nesting we track node names for. The device tree is far deeper than
/// this in general, but we only ever look at depth 0, 1 and 2.
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
    /// `ptr` must point at a DTB whose declared `totalsize` bytes are all
    /// readable and will not be mutated for `'a`. In practice this is the
    /// pointer OpenSBI passed in `a1`, and it must be called before paging is
    /// enabled or through a mapping that covers the blob.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Self, FdtError> {
        // Read the header through a minimal slice first: we cannot trust
        // `totalsize` until we have validated the magic, and we cannot read
        // `totalsize` without a slice. 40 bytes is the fixed header size, so
        // this bootstrap read is bounded even for a garbage pointer.
        // SAFETY: caller guarantees the blob is readable; the header is the
        // first 40 bytes of any valid DTB.
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

        // SAFETY: magic checked, so this really is a DTB and `total_size` is
        // its own account of its length, which the caller has promised is
        // readable.
        let blob = unsafe { core::slice::from_raw_parts(ptr, header.total_size) };

        // Validate the block offsets now, once, so every later read is against
        // a blob we have already established is self-consistent.
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
            // A zero-length entry terminates the list; it is not a reservation
            // of zero bytes at address zero.
            if addr == 0 && size == 0 {
                return Ok(());
            }
            f(addr, size);
            off += 16;
        }
    }

    /// Walk the structure block, calling `f` for every property.
    ///
    /// One pass, no allocation, no index built. Callers filter on the node and
    /// property names they care about. `names` is a small stack of the node
    /// names currently open, which is what lets a visitor distinguish a `reg`
    /// under `/reserved-memory` from one under `/soc`.
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
                    // Saturating rather than panicking: a corrupt blob with an
                    // unbalanced END_NODE should not take the kernel down
                    // before we have even found out how much RAM exists.
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
///
/// The device tree describes addresses in units of 32-bit cells, with the count
/// given by the enclosing node's `#address-cells` / `#size-cells`. On RV64 both
/// are 2, so an address is two cells concatenated most-significant first — but
/// reading it generically means a 32-bit board does not need a second code path.
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
