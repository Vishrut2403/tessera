//! Making objects and mapping them, in userspace. The kernel builds no
//! intermediate page tables, so whoever wants a mapping builds them (D-035).

use crate::abi::ObjectType;
use crate::{Result, sys};

/// Untyped memory to make objects from, and the slots to put them in.
pub struct Alloc {
    pub untyped: u64,
    pub next_slot: u64,
}

impl Alloc {
    pub const fn new(untyped: u64, first_slot: u64) -> Self {
        Self { untyped, next_slot: first_slot }
    }

    pub fn take(&mut self) -> u64 {
        self.next_slot += 1;
        self.next_slot - 1
    }

    /// Retype one object and hand back the slot it landed in.
    pub fn object(&mut self, kind: ObjectType, size_bits: u8) -> Result<u64> {
        let slot = self.take();
        sys::retype(self.untyped, kind, size_bits, slot, 1)?;
        Ok(slot)
    }
}

/// Map `frame` at `va`, retyping whichever intermediate levels turn out to be
/// missing. Nothing here tracks what has been built: the kernel refuses with
/// `ERR_NO_TABLE` until every level exists, which is the only signal needed.
pub fn map(
    a: &mut Alloc,
    vspace: u64,
    frame: u64,
    va: usize,
    rights: u8,
    exec: bool,
) -> Result {
    // Two levels can be missing, so three attempts is one more than enough.
    for _ in 0..3 {
        match sys::map_frame(frame, vspace, va, rights, exec) {
            Err(e) if e.is_missing_table() => add_table(a, vspace, va)?,
            other => return other,
        }
    }
    sys::map_frame(frame, vspace, va, rights, exec)
}

/// Supply the outermost level that is still missing. The kernel says only
/// *that* a level is missing, not which, so the outer one is offered first and
/// the same capability goes in at the inner level if the outer already exists.
fn add_table(a: &mut Alloc, vspace: u64, va: usize) -> Result {
    let table = a.object(ObjectType::PageTable, 0)?;
    if sys::map_table(table, vspace, va, 2).is_ok() {
        return Ok(());
    }
    sys::map_table(table, vspace, va, 1)
}
