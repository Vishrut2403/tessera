// The on-disk layout, defined once (D-047). Regular comments, not inner doc
// comments: this file is `include!`d by `kernel/build.rs`, which writes the
// image, as well as compiled into the filesystem server, which reads it. It
// has no imports and no dependencies, because the two sides of a format that
// must not drift should not be able to.

/// `"tesseraf"`, so a block of zeroes is obvious rather than plausible.
pub const MAGIC: u64 = 0x6661_7265_7373_6574;
pub const VERSION: u32 = 1;

pub const BLOCK_SIZE: usize = 512;

/// Fixed blocks. Everything is at a known place because a read-only filesystem
/// has nothing to allocate and therefore nothing to look up.
pub const SUPER_BLOCK: u32 = 0;
pub const INODE_BLOCK: u32 = 1;
pub const NAME_BLOCK: u32 = 2;
pub const FIRST_DATA_BLOCK: u32 = 3;

/// Blocks the filesystem occupies. Every block from here on carries its own
/// number instead, which is what the block-level tests check (D-044).
pub const FS_BLOCKS: u32 = 64;

/// An inode is 32 bytes, so sixteen of them fit in one block.
pub const INODE_SIZE: usize = 32;
pub const DIRECT: usize = 7;
pub const MAX_FILES: usize = BLOCK_SIZE / INODE_SIZE;

/// A name entry is 32 bytes too: 24 of name and an inode index. Twenty-four
/// bytes is not a coincidence. It is three registers, so a client can send a
/// whole filename in one four-register message (D-047).
pub const NAME_LEN: usize = 24;
pub const NAME_ENTRY: usize = 32;

/// The largest file the format can describe.
pub const MAX_FILE_SIZE: usize = DIRECT * BLOCK_SIZE;

pub fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut v = 0u64;
    let mut i = 8;
    while i > 0 {
        i -= 1;
        v = (v << 8) | b[off + i] as u64;
    }
    v
}

pub fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

// --- Superblock: magic, version, file count ---

pub fn write_super(block: &mut [u8], files: u32) {
    put_u64(block, 0, MAGIC);
    put_u32(block, 8, VERSION);
    put_u32(block, 12, files);
    put_u32(block, 16, BLOCK_SIZE as u32);
    put_u32(block, 20, FS_BLOCKS);
}

pub fn super_is_valid(block: &[u8]) -> bool {
    get_u64(block, 0) == MAGIC
        && get_u32(block, 8) == VERSION
        && get_u32(block, 16) == BLOCK_SIZE as u32
}

pub fn super_files(block: &[u8]) -> u32 {
    get_u32(block, 12)
}

// --- Inodes: a size in bytes, then direct block numbers ---

pub fn write_inode(block: &mut [u8], i: usize, size: u32, direct: &[u32]) {
    let at = i * INODE_SIZE;
    put_u32(block, at, size);
    for (k, b) in direct.iter().enumerate() {
        put_u32(block, at + 4 + k * 4, *b);
    }
}

pub fn inode_size(block: &[u8], i: usize) -> u32 {
    get_u32(block, i * INODE_SIZE)
}

/// The `k`th direct block of inode `i`, or zero if it has none. Block zero
/// is the superblock, so it can never be a file's data.
pub fn inode_direct(block: &[u8], i: usize, k: usize) -> u32 {
    if k >= DIRECT { 0 } else { get_u32(block, i * INODE_SIZE + 4 + k * 4) }
}

// --- Names: a flat table, one entry per file ---

pub fn write_name(block: &mut [u8], i: usize, name: &str, inode: u32) {
    let at = i * NAME_ENTRY;
    let bytes = name.as_bytes();
    let n = if bytes.len() < NAME_LEN { bytes.len() } else { NAME_LEN };
    block[at..at + n].copy_from_slice(&bytes[..n]);
    put_u32(block, at + NAME_LEN, inode);
}

/// Whether entry `i` is the name in `want`, compared over the whole fixed
/// field so a short name cannot prefix-match a longer one.
pub fn name_matches(block: &[u8], i: usize, want: &[u8; NAME_LEN]) -> bool {
    let at = i * NAME_ENTRY;
    &block[at..at + NAME_LEN] == want.as_slice()
}

pub fn name_inode(block: &[u8], i: usize) -> u32 {
    get_u32(block, i * NAME_ENTRY + NAME_LEN)
}
