//! A PT_LOAD-only ELF64 reader, unprivileged: the root task loads boot modules
//! into processes of their own with it (D-043). A copy of the kernel's reader,
//! for the same reason `fdt.rs` is one. Sharing it would put the loader back
//! inside the TCB.

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    /// Not 64-bit, not little-endian, or not RISC-V.
    WrongFormat,
    /// Not `ET_EXEC`: a position-independent image would need relocations.
    NotExecutable,
    /// A program header, or the bytes a segment claims, ran off the end.
    Truncated,
    /// `p_filesz` exceeds `p_memsz`, so the segment does not fit in itself.
    BadSegment,
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const CLASS64: u8 = 2;
const LITTLE_ENDIAN: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_RISCV: u16 = 243;
const PT_LOAD: u32 = 1;

pub mod flags {
    pub const EXEC: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const READ: u32 = 1 << 2;
}

/// One `PT_LOAD` segment: where it goes, and what to put there.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub vaddr: usize,
    /// Bytes from the file. The rest of `mem_size` is zero (`.bss`).
    pub data: &'a [u8],
    pub mem_size: usize,
    pub flags: u32,
}

impl Segment<'_> {
    pub const fn readable(&self) -> bool {
        self.flags & flags::READ != 0
    }
    pub const fn writable(&self) -> bool {
        self.flags & flags::WRITE != 0
    }
    pub const fn executable(&self) -> bool {
        self.flags & flags::EXEC != 0
    }
}

pub struct Elf<'a> {
    bytes: &'a [u8],
    entry: usize,
    ph_off: usize,
    ph_entry_size: usize,
    ph_count: usize,
}

/// Read a little-endian integer at `off`, or `None` if it does not fit.
macro_rules! get {
    ($ty:ty, $bytes:expr, $off:expr) => {{
        const N: usize = size_of::<$ty>();
        $bytes
            .get($off..$off + N)
            .and_then(|s| <[u8; N]>::try_from(s).ok())
            .map(<$ty>::from_le_bytes)
    }};
}

impl<'a> Elf<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < 64 {
            return Err(ElfError::TooSmall);
        }
        if bytes[..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if bytes[4] != CLASS64 || bytes[5] != LITTLE_ENDIAN {
            return Err(ElfError::WrongFormat);
        }
        if get!(u16, bytes, 18) != Some(EM_RISCV) {
            return Err(ElfError::WrongFormat);
        }
        // A shared object would need its relocations applied, and nothing here
        // applies relocations; refusing is better than loading it wrong.
        if get!(u16, bytes, 16) != Some(ET_EXEC) {
            return Err(ElfError::NotExecutable);
        }

        let entry = get!(u64, bytes, 24).ok_or(ElfError::Truncated)? as usize;
        let ph_off = get!(u64, bytes, 32).ok_or(ElfError::Truncated)? as usize;
        let ph_entry_size = get!(u16, bytes, 54).ok_or(ElfError::Truncated)? as usize;
        let ph_count = get!(u16, bytes, 56).ok_or(ElfError::Truncated)? as usize;

        if ph_entry_size < 56 {
            return Err(ElfError::Truncated);
        }
        // The whole table has to be inside the file before any of it is read.
        ph_off
            .checked_add(ph_count * ph_entry_size)
            .filter(|end| *end <= bytes.len())
            .ok_or(ElfError::Truncated)?;

        Ok(Self { bytes, entry, ph_off, ph_entry_size, ph_count })
    }

    pub const fn entry(&self) -> usize {
        self.entry
    }

    /// The `PT_LOAD` segments, in the order the file lists them.
    pub fn segments(&self) -> impl Iterator<Item = Result<Segment<'a>, ElfError>> + '_ {
        (0..self.ph_count).filter_map(move |i| {
            let off = self.ph_off + i * self.ph_entry_size;
            let kind = get!(u32, self.bytes, off)?;
            if kind != PT_LOAD {
                return None;
            }
            Some(self.segment_at(off))
        })
    }

    fn segment_at(&self, off: usize) -> Result<Segment<'a>, ElfError> {
        let t = ElfError::Truncated;
        let flags = get!(u32, self.bytes, off + 4).ok_or(t)?;
        let file_off = get!(u64, self.bytes, off + 8).ok_or(t)? as usize;
        let vaddr = get!(u64, self.bytes, off + 16).ok_or(t)? as usize;
        let file_size = get!(u64, self.bytes, off + 32).ok_or(t)? as usize;
        let mem_size = get!(u64, self.bytes, off + 40).ok_or(t)? as usize;

        if file_size > mem_size {
            return Err(ElfError::BadSegment);
        }
        let end = file_off.checked_add(file_size).ok_or(t)?;
        let data = self.bytes.get(file_off..end).ok_or(t)?;
        vaddr.checked_add(mem_size).ok_or(t)?;

        Ok(Segment { vaddr, data, mem_size, flags })
    }

    /// The lowest and highest virtual addresses any `PT_LOAD` covers.
    pub fn image_range(&self) -> Result<(usize, usize), ElfError> {
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for seg in self.segments() {
            let seg = seg?;
            lo = lo.min(seg.vaddr);
            hi = hi.max(seg.vaddr + seg.mem_size);
        }
        if lo > hi { Err(ElfError::BadSegment) } else { Ok((lo, hi)) }
    }
}
