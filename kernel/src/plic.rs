//! The platform-level interrupt controller (D-041).

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::fdt::{Fdt, read_cells};
use crate::mm::{PhysAddr, Region, VirtAddr};
use crate::sync::SpinLock;

/// Register offsets, from the SiFive PLIC specification.
mod reg {
    /// Per-source priority, one 32-bit word each. Source 0 does not exist.
    pub const PRIORITY: usize = 0x0000;
    /// Per-context enable bits, 0x80 bytes (1024 sources) per context.
    pub const ENABLE: usize = 0x2000;
    pub const ENABLE_STRIDE: usize = 0x80;
    /// Per-context threshold, then claim/complete, 0x1000 bytes per context.
    pub const THRESHOLD: usize = 0x20_0000;
    pub const CONTEXT_STRIDE: usize = 0x1000;
    pub const CLAIM: usize = 0x20_0004;
}

/// The S-mode external interrupt cause, which is how a hart's supervisor
/// context is recognised in the controller's `interrupts-extended` list.
const CAUSE_S_EXTERNAL: u64 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlicInfo {
    pub region: Region,
    /// Highest source number the controller implements.
    pub ndev: usize,
    /// Which of the controller's contexts is this hart's supervisor mode.
    pub context: usize,
}

/// Where the controller is, once the kernel address space has mapped it.
static BASE: AtomicUsize = AtomicUsize::new(0);
static INFO: SpinLock<Option<PlicInfo>> = SpinLock::new(None);

/// Find the controller in the device tree.
pub fn find(fdt: &Fdt) -> Option<PlicInfo> {
    // The node name is copied out rather than borrowed: a `Property` only lives
    // for the duration of the callback that produced it.
    let mut node = [0u8; 64];
    let mut node_len = 0usize;
    let mut ndev = 0usize;
    let _ = fdt.for_each_property(|p| {
        if p.name == "compatible" && contains(p.value, b"plic") && p.node.len() <= node.len() {
            node[..p.node.len()].copy_from_slice(p.node.as_bytes());
            node_len = p.node.len();
        }
    });
    if node_len == 0 {
        return None;
    }
    let node = &node[..node_len];

    let mut region = None;
    let mut context = None;
    let _ = fdt.for_each_property(|p| {
        if p.node.as_bytes() != node {
            return;
        }
        match p.name {
            "riscv,ndev" => ndev = read_cells(p.value, 0, 1).unwrap_or(0) as usize,
            "reg" => {
                let base = read_cells(p.value, 0, 2);
                let size = read_cells(p.value, 8, 2);
                if let (Ok(base), Ok(size)) = (base, size) {
                    region =
                        Some(Region::from_start_len(PhysAddr::new(base as usize), size as usize));
                }
            }
            // Pairs of (interrupt parent, cause).
            "interrupts-extended" => {
                for (i, chunk) in p.value.chunks_exact(8).enumerate() {
                    if read_cells(chunk, 4, 1) == Ok(CAUSE_S_EXTERNAL) && context.is_none() {
                        context = Some(i);
                    }
                }
            }
            _ => {}
        }
    });

    Some(PlicInfo { region: region?, ndev, context: context? })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Arm the driver against a controller the kernel address space already maps.
pub fn init(info: PlicInfo) {
    // Devices are mapped at the direct-map offset, like everything else the
    // kernel reaches physically.
    BASE.store(crate::mm::phys_to_virt(info.region.start).as_usize(), Ordering::Relaxed);
    *INFO.lock() = Some(info);

    // Every source starts at priority 1, above the threshold so it can be
    // delivered, and disabled so nothing arrives until someone claims it.
    for irq in 1..=info.ndev {
        write(reg::PRIORITY + irq * 4, 1);
        disable(irq);
    }
    // Threshold 0: accept any priority above zero.
    write(reg::THRESHOLD + info.context * reg::CONTEXT_STRIDE, 0);
}

pub fn info() -> Option<PlicInfo> {
    *INFO.lock()
}

pub fn is_ready() -> bool {
    BASE.load(Ordering::Relaxed) != 0
}

fn base() -> Option<VirtAddr> {
    match BASE.load(Ordering::Relaxed) {
        0 => None,
        v => Some(VirtAddr::new(v)),
    }
}

fn write(offset: usize, value: u32) {
    let Some(base) = base() else { return };
    // SAFETY: `offset` is inside the controller's mapped registers, which the
    // kernel address space maps read-write for exactly this purpose.
    unsafe { base.as_mut_ptr::<u8>().add(offset).cast::<u32>().write_volatile(value) };
}

fn read(offset: usize) -> u32 {
    let Some(base) = base() else { return 0 };
    // SAFETY: as above.
    unsafe { base.as_ptr::<u8>().add(offset).cast::<u32>().read_volatile() }
}

fn enable_word(irq: usize) -> usize {
    let context = INFO.lock().map_or(0, |i| i.context);
    reg::ENABLE + context * reg::ENABLE_STRIDE + (irq / 32) * 4
}

pub fn enable(irq: usize) {
    let word = enable_word(irq);
    write(word, read(word) | (1 << (irq % 32)));
}

pub fn disable(irq: usize) {
    let word = enable_word(irq);
    write(word, read(word) & !(1 << (irq % 32)));
}

pub fn is_enabled(irq: usize) -> bool {
    read(enable_word(irq)) & (1 << (irq % 32)) != 0
}

/// Take the highest-priority pending source, if any. Zero means none.
pub fn claim() -> Option<usize> {
    let context = INFO.lock().map_or(0, |i| i.context);
    match read(reg::CLAIM + context * reg::CONTEXT_STRIDE) {
        0 => None,
        irq => Some(irq as usize),
    }
}

/// Tell the controller this hart is finished with `irq`.
/// Must happen while the source is still enabled, or it is ignored.
pub fn complete(irq: usize) {
    let context = INFO.lock().map_or(0, |i| i.context);
    write(reg::CLAIM + context * reg::CONTEXT_STRIDE, irq as u32);
}
