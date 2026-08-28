/* tessera kernel linker script.
 *
 * D-002: in M1 the MMU is off and the kernel is linked at the physical address
 * OpenSBI drops us at, so KERNEL_VMA is 0 and every AT() below is the identity.
 * The VMA/LMA machinery is written out anyway so that M2's move to a higher-half
 * kernel is a one-line change here plus a boot trampoline, not a rewrite:
 *
 *     KERNEL_VMA = 0xffffffc000000000;
 *
 * At that point VMA = KERNEL_VMA + KERNEL_LMA + offset and LMA stays physical,
 * which is exactly what AT(ADDR(section) - KERNEL_VMA) expresses.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* Where OpenSBI hands off. OpenSBI itself occupies 0x80000000..0x80200000 on
 * QEMU virt; 0x80200000 is the conventional S-mode payload address. */
KERNEL_LMA = 0x80200000;

/* Virtual offset applied to the kernel. Zero until M2. */
KERNEL_VMA = 0x0;

/* Boot stack for the single hart that runs M1. Lives in .bss, so it costs
 * nothing in the image. 64 KiB is generous; it exists so a deep panic-format
 * call chain cannot silently run off the end. */
BOOT_STACK_SIZE = 64K;

SECTIONS
{
    . = KERNEL_VMA + KERNEL_LMA;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_VMA)
    {
        __text_start = .;

        /* The entry point must be the first thing in the image. KEEP() stops
         * --gc-sections from removing it: nothing in Rust ever calls _start. */
        KEEP(*(.text.boot))

        /* stvec holds the trap entry and requires 4-byte alignment (its low two
         * bits are the mode field, D-006). Aligning here rather than relying on
         * the compiler's function alignment makes the requirement explicit and
         * survives the C extension's 2-byte function alignment.
         * This claim must come before *(.text.*) — lld matches in order. */
        . = ALIGN(4);
        KEEP(*(.text.trap))

        *(.text .text.*)
        __text_end = .;
    }

    . = ALIGN(4096);
    .rodata : AT(ADDR(.rodata) - KERNEL_VMA)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        __rodata_end = .;
    }

    . = ALIGN(4096);
    .data : AT(ADDR(.data) - KERNEL_VMA)
    {
        __data_start = .;
        *(.data .data.*)

        /* RISC-V linker relaxation rewrites some global accesses to be
         * gp-relative. gp must point 0x800 past the start of the small-data
         * area so that a signed 12-bit offset covers .sdata and .sbss.
         * D-012: _start loads this before any Rust code runs. */
        . = ALIGN(8);
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.*)
        *(.got .got.plt)
        __data_end = .;
    }

    . = ALIGN(4096);
    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VMA)
    {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)

        /* The boot stack is inside the zeroed range. That is only safe because
         * the zeroing loop in _start uses no stack at all (D-012). */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += BOOT_STACK_SIZE;
        __boot_stack_top = .;

        /* The zeroing loop stores 8 bytes at a time and does not check for a
         * ragged tail, so the end must be 8-byte aligned. */
        . = ALIGN(8);
        __bss_end = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ :
    {
        /* panic=abort: unwind tables are dead weight in a kernel image. */
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
