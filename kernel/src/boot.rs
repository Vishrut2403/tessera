//! Entry, and the transition into the higher half (D-002, D-013).

use crate::mm::addr::KERNEL_VMA;

/// Bootstrap root page table; no allocator exists yet.
#[repr(C, align(4096))]
struct EarlyTable([u64; 512]);

static mut EARLY_ROOT: EarlyTable = EarlyTable([0; 512]);

/// Carried across the jump: same physical bytes, read through the high alias.
static mut BOOT_HARTID: usize = 0;
static mut BOOT_DTB: usize = 0;
static mut BOOT_MAIN: usize = 0;

/// Sv39 in `satp`'s MODE field.
const SATP_SV39: usize = 8 << 60;

/// Compose a `satp` value. ASID is 0 until M4.
pub const fn satp_value(root_pa: usize) -> usize {
    SATP_SV39 | (root_pa >> 12)
}

/// Emit the kernel entry point; hands control to `$main` in the high half.
#[macro_export]
macro_rules! kernel_entry {
    ($main:path) => {
        /// Kernel entry. Called by OpenSBI at the physical address.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".text.boot")]
        pub unsafe extern "C" fn _start() -> ! {
            ::core::arch::naked_asm!(
                // a0 = hartid, a1 = DTB physical address; both must survive.

                // gp: norelax, since relaxing this to gp-relative would be circular.
                ".option push",
                ".option norelax",
                "lla   gp, __global_pointer$",
                ".option pop",

                // Zero .bss.
                "lla   t0, __bss_start",
                "lla   t1, __bss_end",
                "bgeu  t0, t1, 2f",
                "1:",
                "sd    zero, 0(t0)",
                "addi  t0, t0, 8",
                "bltu  t0, t1, 1b",
                "2:",

                "lla   sp, __boot_stack_top",

                // Terminate the frame-pointer and return-address chains.
                "mv    s0, zero",
                "mv    ra, zero",

                // `lla`, not `la`: explicitly PC-relative.
                "lla   a2, {main}",
                "tail  {early_boot}",

                main = sym $main,
                early_boot = sym $crate::boot::early_boot,
            )
        }
    };
}

/// Write one byte to the UART, bypassing every abstraction.
fn early_putc(byte: u8) {
    const THR: *mut u8 = 0x1000_0000 as *mut u8;
    const LSR: *const u8 = 0x1000_0005 as *const u8;
    const THR_EMPTY: u8 = 1 << 5;
    // SAFETY: QEMU virt's UART0, identity-addressable with the MMU off.
    unsafe {
        while core::ptr::read_volatile(LSR) & THR_EMPTY == 0 {}
        core::ptr::write_volatile(THR, byte);
    }
}

/// Print during the early phase; `&str` literals resolve PC-relative.
pub fn early_print(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            early_putc(b'\r');
        }
        early_putc(b);
    }
}

/// Print a 64-bit value in hex, without `core::fmt`.
pub fn early_hex(value: usize) {
    early_print("0x");
    let mut v = value;
    let mut digits = [0u8; 16];
    for i in (0..16).rev() {
        let nibble = (v & 0xf) as u8;
        digits[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        v >>= 4;
    }
    for d in digits {
        early_putc(d);
    }
}

/// Install one 1 GiB leaf mapping `va` to `pa`.
///
/// # Safety
/// `root` must point at a 512-entry table, and `pa` must be 1 GiB aligned.
unsafe fn map_gigapage(root: *mut u64, va: usize, pa: usize) {
    const V: u64 = 1 << 0;
    const R: u64 = 1 << 1;
    const W: u64 = 1 << 2;
    const X: u64 = 1 << 3;
    const G: u64 = 1 << 5;
    const A: u64 = 1 << 6;
    const D: u64 = 1 << 7;

    let index = (va >> 30) & 0x1ff;
    // The PPN sits at bit 10 and holds a page *number*, hence >> 12 then << 10.
    let pte = (((pa >> 12) as u64) << 10) | V | R | W | X | G | A | D;
    unsafe { root.add(index).write(pte) };
}

/// Build the bootstrap table and return the `satp` value that activates it.
///
/// # Safety
/// Call once, before paging is enabled.
unsafe fn build_early_table() -> usize {
    const DEVICES: usize = 0x0000_0000;
    const DRAM: usize = 0x8000_0000;

    // PC-relative, so this is the table's physical address.
    let root = (&raw mut EARLY_ROOT) as *mut u64;

    unsafe {
        map_gigapage(root, DEVICES, DEVICES);
        map_gigapage(root, KERNEL_VMA + DEVICES, DEVICES);
        map_gigapage(root, DRAM, DRAM);
        map_gigapage(root, KERNEL_VMA + DRAM, DRAM);
    }

    satp_value(root as usize)
}

/// Turn on Sv39 and jump to the high half.
///
/// # Safety
/// `satp` must map both the current PC and `next`; `offset` is what `sp` and `gp` need added.
#[unsafe(naked)]
unsafe extern "C" fn enter_high_half(satp: usize, next: usize, offset: usize) -> ! {
    core::arch::naked_asm!(
        // Paging is live from the instruction after this one.
        "csrw satp, a0",
        // Orders the page table stores against the walker's reads.
        "sfence.vma zero, zero",
        // The stack and the global pointer still hold physical addresses.
        "add  sp, sp, a2",
        "add  gp, gp, a2",
        // Into the high half.
        "jr   a1",
    )
}

/// The early phase, in full.
///
/// # Safety
/// Called only by `_start`, once, with the MMU off.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn early_boot(hartid: usize, dtb: usize, main_phys: usize) -> ! {
    early_print("\ntessera: early boot, enabling Sv39\n");

    // The jump clobbers a0-a2, so stash the arguments first.
    unsafe {
        (&raw mut BOOT_HARTID).write(hartid);
        (&raw mut BOOT_DTB).write(dtb);
        (&raw mut BOOT_MAIN).write(main_phys + KERNEL_VMA);
    }

    // SAFETY: first and only call, paging still off.
    let satp = unsafe { build_early_table() };
    early_print("  satp      = ");
    early_hex(satp);
    early_print("\n  root      = ");
    early_hex((&raw mut EARLY_ROOT) as usize);

    // PC-relative, so physical; + KERNEL_VMA gives the post-paging address.
    let next = (high_entry as *const () as usize) + KERNEL_VMA;
    early_print("\n  high_entry= ");
    early_hex(next);
    early_print("\n  jumping\n");

    // SAFETY: the table maps the current PC identity-wise and `next` high; KERNEL_VMA shifts sp and gp.
    unsafe { enter_high_half(satp, next, KERNEL_VMA) }
}

/// First code to run in the high half.
extern "C" fn high_entry() -> ! {
    // The identity device mapping is still live, so this works on both sides.
    early_print("  landed in the high half\n");

    // From here on, a physical address is reachable at `pa + KERNEL_VMA`.
    crate::mm::set_phys_offset(KERNEL_VMA);

    // SAFETY: written by `early_boot` on this hart before the jump; the same bytes, high alias.
    let (main, hartid, dtb) = unsafe {
        (
            (&raw const BOOT_MAIN).read(),
            (&raw const BOOT_HARTID).read(),
            (&raw const BOOT_DTB).read(),
        )
    };
    // SAFETY: `main` is the high alias of the fn `kernel_entry!` passed to `early_boot`.
    let main: extern "C" fn(usize, usize) -> ! = unsafe { core::mem::transmute(main) };
    main(hartid, dtb)
}
