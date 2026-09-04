//! Loading the root task: the last thing the kernel creates by itself (D-039).

use abi::bootinfo::{self, BootInfo, ModuleDesc, UntypedDesc};

use crate::cap::cspace::{CSpace, init_cnode};
use crate::cap::object::SLOT_BITS;
use crate::cap::rights::{ALL, READ};
use crate::cap::vspace::vspace_cap;
use crate::cap::{CapError, ObjectType, RawCap};
use crate::elf::{Elf, ElfError, Segment};
use crate::mm::{
    AddressSpace, Mapper, MemoryMap, PAGE_SHIFT, PAGE_SIZE, PhysAddr, PteFlags, Region, VirtAddr,
    phys_to_virt,
};
use crate::thread::{Tcb, ThreadId};

/// The root task's ELF, built by `build.rs` and embedded in `.rodata`.
pub static IMAGE: &[u8] = include_bytes!(env!("ROOT_TASK_ELF"));

/// The images the kernel carries in but does not load: it copies each into
/// frames and maps them read-only, and the root task loads them itself into
/// processes of their own (D-043). Multiboot calls these modules; Fuchsia's
/// kernel carries a whole bootfs the same way.
pub static MODULES: [(&str, &[u8]); 3] = [
    ("blk", include_bytes!(env!("BLK_ELF"))),
    ("fs", include_bytes!(env!("FS_ELF"))),
    ("client", include_bytes!(env!("CLIENT_ELF"))),
];

/// Top of the root task's stack. Its image is linked well below this.
pub const STACK_TOP: usize = 0x2000_0000;
pub const STACK_PAGES: usize = 4;

/// The lowest address the kernel maps nothing at, and the root task's to use.
pub const FREE_VADDR: usize = 0x4000_0000;

/// 2^8 slots of 2^7 bytes: a 32 KiB root CNode.
const CNODE_BITS: u8 = 8 + SLOT_BITS;

/// The largest untyped the kernel will hand over, so one region cannot swallow
/// all of RAM into a single capability that is awkward to subdivide.
const MAX_UNTYPED_BITS: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootError {
    Elf(ElfError),
    /// A segment asks to be both writable and executable.
    WriteExecute,
    /// Two segments share a page, so mapping one would overwrite the other.
    OverlappingSegments,
    /// A segment lands in the kernel half, or above the boot info page.
    BadAddress,
    OutOfMemory,
    Cap(CapError),
    Asid,
}

impl From<ElfError> for RootError {
    fn from(e: ElfError) -> Self {
        RootError::Elf(e)
    }
}

impl From<CapError> for RootError {
    fn from(e: CapError) -> Self {
        RootError::Cap(e)
    }
}

/// What was built, for the boot log to print.
pub struct RootTask {
    pub id: ThreadId,
    pub entry: usize,
    pub image: (usize, usize),
    /// Kept rather than forgotten: `AddressSpace` has no `Drop`, and holding it
    /// lets the boot log and the tests look at what the root task built.
    pub space: AddressSpace,
    pub cnode: RawCap,
    pub untypeds: usize,
    pub untyped_bytes: u64,
    /// How many of `untypeds` are device regions rather than RAM (D-040).
    pub devices: usize,
    /// Boot modules mapped read-only for the root task to load (D-043).
    pub modules: usize,
}

/// Build the root task's address space, capability space and thread, and put it
/// on the run queue.
pub fn load(kernel: &Mapper, map: &MemoryMap) -> Result<RootTask, RootError> {
    let elf = Elf::parse(IMAGE)?;
    let (image_start, image_end) = elf.image_range()?;

    let mut space = {
        let mut alloc = crate::mm::FRAMES.lock();
        AddressSpace::new(kernel, &mut *alloc).map_err(|_| RootError::OutOfMemory)?
    };
    // Without an ASID the space is not an address space: a `Configure` naming
    // it would be refused, and the root task could never make a thread (D-037).
    space.set_asid(crate::cap::asid::assign_global().map_err(|_| RootError::Asid)?);

    for segment in elf.segments() {
        map_segment(&mut space, &segment?)?;
    }

    for i in 0..STACK_PAGES {
        let va = STACK_TOP - (i + 1) * PAGE_SIZE;
        let frame = crate::mm::alloc_frame().ok_or(RootError::OutOfMemory)?;
        map_one(&mut space, va, frame, PteFlags::USER_RW)?;
    }

    let info_frame = crate::mm::alloc_frame().ok_or(RootError::OutOfMemory)?;
    map_one(&mut space, bootinfo::VADDR, info_frame, PteFlags::USER_RO)?;

    // The device tree, read-only, at its own address.
    let fdt = map.fdt.page_aligned_out();
    let fdt_offset = map.fdt.start.as_usize() - fdt.start.as_usize();
    for (i, page) in (fdt.start.as_usize()..fdt.end.as_usize()).step_by(PAGE_SIZE).enumerate() {
        map_one(
            &mut space,
            bootinfo::FDT_VADDR + i * PAGE_SIZE,
            PhysAddr::new(page),
            PteFlags::USER_RO,
        )?;
    }

    // The boot modules, copied into frames of their own so no page of kernel
    // `.rodata` is ever reachable from userspace, and mapped read-only.
    let mut modules = [ModuleDesc::EMPTY; bootinfo::MAX_MODULES];
    let mut module_va = bootinfo::MODULE_VADDR;
    for (i, (name, bytes)) in MODULES.iter().take(bootinfo::MAX_MODULES).enumerate() {
        map_module(&mut space, module_va, bytes)?;
        modules[i] = ModuleDesc::new(module_va as u64, bytes.len() as u64, name);
        module_va += (bytes.len() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    }

    let cnode_pa = alloc_aligned(CNODE_BITS).ok_or(RootError::OutOfMemory)?;
    let tcb_pa = crate::mm::alloc_frame().ok_or(RootError::OutOfMemory)?;

    // Every allocation the kernel makes for the root task is now behind us, so
    // what is left is exactly what the root task gets.
    let free = crate::mm::FRAMES.lock().remaining();

    // SAFETY: `cnode_pa` is 2^CNODE_BITS bytes of memory we just took from the
    // allocator, so nothing else refers to it.
    unsafe { init_cnode(cnode_pa, CNODE_BITS) };
    let cnode = RawCap::new(ObjectType::CNode, ALL, CNODE_BITS, cnode_pa);
    let mut cs = CSpace::new(cnode)?;
    let depth = cs.root_depth();

    // The root CNode is not derived from any untyped the root task holds, so
    // revoking one of them can no longer destroy the space it is stored in --
    // the trap D-029 describes for a CSpace bootstrapped out of its own region.
    cs.insert(bootinfo::slot::CNODE, depth, cnode, None)?;
    cs.insert(
        bootinfo::slot::VSPACE,
        depth,
        {
            let mut v = vspace_cap(space.root());
            v.asid = space.asid().as_u16();
            v
        },
        None,
    )?;
    cs.insert(
        bootinfo::slot::TCB,
        depth,
        RawCap::new(ObjectType::Tcb, ALL, PAGE_SHIFT as u8, tcb_pa),
        None,
    )?;
    cs.insert(
        bootinfo::slot::IRQ_CONTROL,
        depth,
        RawCap::new(ObjectType::IrqControl, ALL, 0, PhysAddr::new(0)),
        None,
    )?;
    let mut info_cap = RawCap::new(ObjectType::Frame, READ, PAGE_SHIFT as u8, info_frame);
    info_cap.set_mapping(space.root(), bootinfo::VADDR);
    cs.insert(bootinfo::slot::BOOTINFO, depth, info_cap, None)?;

    // Every interrupt source starts unclaimed; the root task is the only holder
    // of the right to claim any of them.
    crate::irq::reset();

    let mut info = BootInfo {
        fdt_vaddr: (bootinfo::FDT_VADDR + fdt_offset) as u64,
        fdt_size: map.fdt.len() as u64,
        max_irq: map.plic.map_or(0, |p| p.ndev as u64),
        cnode_radix: depth as u64,
        cnode_slots: cs.root_slots() as u64,
        image_start: image_start as u64,
        image_end: image_end as u64,
        stack_bottom: (STACK_TOP - STACK_PAGES * PAGE_SIZE) as u64,
        stack_top: STACK_TOP as u64,
        free_vaddr: FREE_VADDR as u64,
        module_count: MODULES.len().min(bootinfo::MAX_MODULES) as u64,
        modules,
        ..BootInfo::EMPTY
    };

    // RAM first, then devices, so the boot log reads in the order the root task
    // will care about them.
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut devices = 0usize;
    for (regions, is_device) in [(&free, false), (&map.devices, true)] {
        for region in regions.iter() {
            for desc in split(*region, is_device) {
                if count == bootinfo::MAX_UNTYPED
                    || info.first_untyped + count as u64 >= info.cnode_slots
                {
                    break;
                }
                let paddr = PhysAddr::new(desc.paddr as usize);
                let cap = if is_device {
                    RawCap::device_untyped(paddr, desc.size_bits, ALL)
                } else {
                    RawCap::untyped(paddr, desc.size_bits, ALL)
                };
                cs.insert(info.first_untyped + count as u64, depth, cap, None)?;
                info.untyped[count] = desc;
                if is_device {
                    devices += 1;
                } else {
                    bytes += desc.bytes();
                }
                count += 1;
            }
        }
    }
    info.untyped_count = count as u32;
    info.first_free_slot = info.first_untyped + count as u64;
    let module_count = info.module_count as usize;

    // SAFETY: `info_frame` is a frame we own, reachable through the direct map,
    // and `BootInfo` fits in a page by construction.
    unsafe { phys_to_virt(info_frame).as_mut_ptr::<BootInfo>().write(info) };

    let id = crate::thread::next_id();
    // SAFETY: `tcb_pa` came from the allocator, so nothing else has a TCB in it.
    let mut tcb = unsafe {
        Tcb::create(tcb_pa, id, &space, VirtAddr::new(elf.entry()), VirtAddr::new(STACK_TOP))
    };
    // SAFETY: we just made it; it is on no queue and nothing else refers to it.
    unsafe { tcb.as_mut().cspace = cnode };
    // SAFETY: a fully configured thread that is on no queue yet.
    unsafe { crate::sched::admit(tcb) };

    Ok(RootTask {
        id,
        entry: elf.entry(),
        image: (image_start, image_end),
        space,
        cnode,
        untypeds: count,
        untyped_bytes: bytes,
        devices,
        modules: module_count,
    })
}

/// Copy a boot module into fresh frames and map it read-only (D-043).
fn map_module(space: &mut AddressSpace, at: usize, bytes: &[u8]) -> Result<(), RootError> {
    for (i, chunk) in bytes.chunks(PAGE_SIZE).enumerate() {
        let frame = crate::mm::alloc_frame().ok_or(RootError::OutOfMemory)?;
        // SAFETY: a page we just took from the allocator, reachable through the
        // direct map; `chunk` is at most one page. The tail stays zero because
        // frames arrive zeroed, so nothing else leaks into the last page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                phys_to_virt(frame).as_mut_ptr::<u8>(),
                chunk.len(),
            )
        };
        map_one(space, at + i * PAGE_SIZE, frame, PteFlags::USER_RO)?;
    }
    Ok(())
}

/// Copy one `PT_LOAD` segment into fresh frames and map them.
fn map_segment(space: &mut AddressSpace, seg: &Segment) -> Result<(), RootError> {
    if seg.writable() && seg.executable() {
        return Err(RootError::WriteExecute);
    }
    if seg.vaddr == 0 || seg.vaddr + seg.mem_size > bootinfo::VADDR {
        return Err(RootError::BadAddress);
    }

    let mut flags = PteFlags::V | PteFlags::U | PteFlags::A;
    if seg.readable() {
        flags = flags | PteFlags::R;
    }
    if seg.writable() {
        flags = flags | PteFlags::W | PteFlags::D;
    }
    if seg.executable() {
        flags = flags | PteFlags::X;
    }

    let first = seg.vaddr & !(PAGE_SIZE - 1);
    let last = seg.vaddr + seg.mem_size;
    let mut va = first;
    while va < last {
        let frame = crate::mm::alloc_frame().ok_or(RootError::OutOfMemory)?;

        // The part of this page the file has bytes for; the rest stays zero.
        let from = va.max(seg.vaddr);
        let to = (va + PAGE_SIZE).min(seg.vaddr + seg.data.len());
        if to > from {
            let src = &seg.data[from - seg.vaddr..to - seg.vaddr];
            let dst = phys_to_virt(frame).as_mut_ptr::<u8>();
            // SAFETY: `frame` is a page we own, reachable through the direct
            // map, and `from - va` plus the length stays inside it.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst.add(from - va), src.len()) };
        }

        map_one(space, va, frame, flags)?;
        va += PAGE_SIZE;
    }
    Ok(())
}

fn map_one(
    space: &mut AddressSpace,
    va: usize,
    frame: PhysAddr,
    flags: PteFlags,
) -> Result<(), RootError> {
    if space.translate(VirtAddr::new(va)).is_some() {
        return Err(RootError::OverlappingSegments);
    }
    let mut alloc = crate::mm::FRAMES.lock();
    space
        .map(VirtAddr::new(va), frame, 0, flags, &mut *alloc)
        .map_err(|_| RootError::OutOfMemory)
}

/// Take 2^`bits` bytes of aligned, contiguous physical memory.
fn alloc_aligned(bits: u8) -> Option<PhysAddr> {
    let size = 1usize << bits;
    let mut first = crate::mm::alloc_frame()?;
    while first.as_usize() & (size - 1) != 0 {
        first = crate::mm::alloc_frame()?;
    }
    for _ in 1..(size / PAGE_SIZE) {
        crate::mm::alloc_frame()?;
    }
    Some(first)
}

/// Cut a free region into the largest aligned power-of-two blocks that fit.
pub fn split(region: Region, is_device: bool) -> impl Iterator<Item = UntypedDesc> {
    let mut start = region.start.as_usize();
    let end = region.end.as_usize();
    core::iter::from_fn(move || {
        if start >= end {
            return None;
        }
        let alignment = if start == 0 { MAX_UNTYPED_BITS } else { start.trailing_zeros() };
        let remaining = usize::BITS - 1 - (end - start).leading_zeros();
        let bits = alignment.min(remaining).min(MAX_UNTYPED_BITS);
        if bits < PAGE_SHIFT as u32 {
            return None;
        }
        let desc = UntypedDesc::new(start as u64, bits as u8, is_device);
        start += 1usize << bits;
        Some(desc)
    })
}
