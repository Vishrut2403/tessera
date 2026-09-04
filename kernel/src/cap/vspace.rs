//! Mapping invocations: what a userspace pager uses to install a page (D-035).

use super::{CapError, ObjectType, RawCap, asid, rights};
use crate::mm::page_table::{MapError, Mapper, PteFlags};
use crate::mm::{PhysAddr, VirtAddr, flush_tlb_page, install_kernel_half};

/// Turn capability rights into page table permissions.
/// `U` always, `G` never: a global user mapping would outlive an ASID (D-025).
pub fn flags_for(rights: u8, executable: bool) -> PteFlags {
    let mut flags = PteFlags::V.union(PteFlags::U).union(PteFlags::A);
    if rights & rights::READ != 0 {
        flags = flags.union(PteFlags::R);
    }
    if rights & rights::WRITE != 0 {
        flags = flags.union(PteFlags::W).union(PteFlags::D);
    }
    if executable {
        flags = flags.union(PteFlags::X);
    }
    flags
}

/// Borrow the address space a page table capability names.
///
/// # Safety
/// `cap` must be a live page table capability naming a root table, and the
/// caller must hold exclusive access to that tree.
pub unsafe fn mapper_for(cap: &RawCap) -> Mapper {
    // SAFETY: the caller promised a live root table only we are touching.
    unsafe { Mapper::from_root(cap.paddr) }
}

/// Install `frame` into the address space `vspace` names, at `vaddr`.
pub fn map_frame(
    frame: &mut RawCap,
    vspace: &RawCap,
    vaddr: VirtAddr,
    rights_mask: u8,
    executable: bool,
) -> Result<(), CapError> {
    if frame.kind != ObjectType::Frame {
        return Err(CapError::WrongType { wanted: ObjectType::Frame, found: frame.kind });
    }
    if vspace.kind != ObjectType::PageTable {
        return Err(CapError::WrongType { wanted: ObjectType::PageTable, found: vspace.kind });
    }
    if frame.mapping().is_some() {
        return Err(CapError::AlreadyMapped);
    }
    // A capability cannot install permissions it does not itself carry.
    let granted = frame.rights & rights_mask;

    // SAFETY: `vspace` is a live root table from the caller's CSpace.
    let mut mapper = unsafe { mapper_for(vspace) };
    mapper
        .map_leaf(vaddr, frame.paddr, 0, flags_for(granted, executable))
        .map_err(CapError::Map)?;

    frame.set_mapping(vspace.paddr, vaddr.as_usize());
    flush_tlb_page(vaddr);
    Ok(())
}

/// Install a userspace-supplied page table as an intermediate level.
pub fn map_table(
    table: &mut RawCap,
    vspace: &RawCap,
    vaddr: VirtAddr,
    level: usize,
) -> Result<(), CapError> {
    if table.kind != ObjectType::PageTable {
        return Err(CapError::WrongType { wanted: ObjectType::PageTable, found: table.kind });
    }
    if vspace.kind != ObjectType::PageTable {
        return Err(CapError::WrongType { wanted: ObjectType::PageTable, found: vspace.kind });
    }
    if table.mapping().is_some() {
        return Err(CapError::AlreadyMapped);
    }

    // SAFETY: `vspace` is a live root table from the caller's CSpace.
    let mut mapper = unsafe { mapper_for(vspace) };
    mapper.map_table(vaddr, table.paddr, level).map_err(CapError::Map)?;

    table.set_mapping(vspace.paddr, vaddr.as_usize());
    Ok(())
}

/// Remove whatever mapping a capability records, if any.
pub fn unmap(cap: &mut RawCap) -> Result<(), CapError> {
    let Some((root, vaddr)) = cap.mapping() else {
        return Ok(());
    };
    let va = VirtAddr::new(vaddr);

    // SAFETY: the root recorded in the capability was a live address space when
    // the mapping was made, and revocation runs before that space is reused.
    let mut mapper = unsafe { Mapper::from_root(root) };
    match mapper.unmap(va) {
        // Already gone is not an error: the address space may have been torn
        // down first, which is the ordinary case when a process dies.
        Ok(_) | Err(MapError::NotMapped) => {}
        Err(e) => return Err(CapError::Map(e)),
    }
    cap.clear_mapping();
    flush_tlb_page(va);
    Ok(())
}

/// The root page table capability for an address space the kernel built.
pub fn vspace_cap(root: PhysAddr) -> RawCap {
    RawCap {
        kind: ObjectType::PageTable,
        rights: rights::ALL,
        size_bits: crate::mm::PAGE_SHIFT as u8,
        paddr: root,
        ..RawCap::NULL
    }
}

/// Turn a retyped page table into an address space root (D-037).
pub fn assign(table: &mut RawCap) -> Result<(), CapError> {
    if table.kind != ObjectType::PageTable {
        return Err(CapError::WrongType {
            wanted: ObjectType::PageTable,
            found: table.kind,
        });
    }
    if table.is_assigned() {
        return Err(CapError::AlreadyAssigned);
    }
    // A table already installed somewhere is an intermediate level, not a root.
    if table.mapping().is_some() {
        return Err(CapError::AlreadyMapped);
    }
    let kernel_root = crate::mm::kernel_space::root().ok_or(CapError::NoKernelSpace)?;

    // SAFETY: `table` names a page table object from the caller's CSpace that
    // is mapped nowhere, so no hart has it installed in `satp`.
    unsafe { install_kernel_half(table.paddr, kernel_root) };

    let assigned = asid::assign_global().map_err(CapError::Asid)?;
    table.asid = assigned.as_u16();
    Ok(())
}
