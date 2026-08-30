//! The timer: what preempts a thread (O-004, D-023).

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::fdt::{Fdt, read_cells};
use crate::mm::{PhysAddr, phys_to_virt};

/// QEMU virt's `timebase-frequency`, used if the device tree does not say.
const DEFAULT_HZ: u64 = 10_000_000;

/// How long a thread runs before the timer takes the hart back.
pub const TIMESLICE_MS: u64 = 10;

static TIMEBASE_HZ: AtomicU64 = AtomicU64::new(DEFAULT_HZ);
static HAS_SSTC: AtomicBool = AtomicBool::new(false);

/// Timer interrupts taken since boot.
pub static TICKS: AtomicUsize = AtomicUsize::new(0);

/// Read the ISA extensions and the tick rate out of the device tree.
pub fn init(dtb: PhysAddr) {
    // SAFETY: the pointer OpenSBI passed in a1, reached through the direct map.
    let Ok(fdt) = (unsafe { Fdt::from_ptr(phys_to_virt(dtb).as_ptr::<u8>()) }) else {
        return;
    };

    let mut hz = None;
    let mut sstc = false;
    let _ = fdt.for_each_property(|p| match p.name {
        "timebase-frequency" => {
            if let Ok(v) = read_cells(p.value, 0, p.value.len() / 4) {
                hz = Some(v);
            }
        }
        // A stringlist; "sstc" must be a whole element, not a substring of one.
        "riscv,isa-extensions" => {
            if p.value.split(|b| *b == 0).any(|e| e == b"sstc") {
                sstc = true;
            }
        }
        _ => {}
    });

    if let Some(hz) = hz.filter(|h| *h > 0) {
        TIMEBASE_HZ.store(hz, Ordering::Relaxed);
    }
    HAS_SSTC.store(sstc, Ordering::Relaxed);
}

pub fn timebase_hz() -> u64 {
    TIMEBASE_HZ.load(Ordering::Relaxed)
}

/// Whether we can arm the timer ourselves instead of asking OpenSBI.
pub fn has_sstc() -> bool {
    HAS_SSTC.load(Ordering::Relaxed)
}

/// The `time` counter: a wall clock in `timebase_hz()` units.
#[inline]
pub fn now() -> u64 {
    let t: u64;
    // SAFETY: `rdtime` is a read of the unprivileged `time` CSR; mcounteren.TM is set.
    unsafe { core::arch::asm!("rdtime {t}", t = out(reg) t, options(nostack)) };
    t
}

pub fn ms_to_ticks(ms: u64) -> u64 {
    ms * timebase_hz() / 1000
}

/// Arm the timer for an absolute deadline.
pub fn arm(deadline: u64) {
    if has_sstc() {
        // SAFETY: `stimecmp` only schedules an interrupt; nothing else observes it.
        unsafe { crate::csr::stimecmp::write(deadline as usize) };
    } else {
        crate::sbi::set_timer(deadline);
    }
}

/// Arm the timer one timeslice from now.
pub fn arm_next_tick() {
    arm(now() + ms_to_ticks(TIMESLICE_MS));
}

/// A timer interrupt arrived: count it and arm the next one.
pub fn on_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    arm_next_tick();
}

/// Enable timer interrupts on this hart. Global `sstatus.SIE` is separate.
pub fn enable() {
    // SAFETY: `sie.STIE` only unmasks an interrupt the dispatcher handles.
    unsafe { crate::csr::sie::set(crate::csr::interrupt_bits::STIE) };
}

/// Push the deadline out of reach, which is how `sstc` expresses "no timer".
pub fn disarm() {
    arm(u64::MAX);
}
