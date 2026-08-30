/* tessera kernel linker script: linked high, loaded physical (D-002).
 * VMA = KERNEL_VMA + KERNEL_LMA, LMA stays physical -- what AT() expresses. */

OUTPUT_ARCH(riscv)

/* e_entry must be physical: OpenSBI jumps to it with the MMU off. */
ENTRY(_start_phys)

/* Where OpenSBI hands off: the conventional S-mode payload address. */
KERNEL_LMA = 0x80200000;

/* Virtual offset applied to the kernel. */
KERNEL_VMA = 0xffffffc000000000;

/* Boot stack for the boot hart. In .bss, so it costs nothing in the image. */
BOOT_STACK_SIZE = 64K;

SECTIONS
{
    . = KERNEL_VMA + KERNEL_LMA;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_VMA)
    {
        __text_start = .;

        /* First in the image; KEEP() because nothing in Rust calls _start. */
        KEEP(*(.text.boot))

        /* stvec's low two bits are the mode field, so the trap entry needs
         * 4-byte alignment (D-006). Must precede *(.text.*): lld matches in order. */
        . = ALIGN(4);
        KEEP(*(.text.trap))

        *(.text .text.*)
        __text_end = .;
    }

    /* Plain assignment, not PROVIDE(): ENTRY() does not count as a reference,
     * so PROVIDE would leave it undefined and e_entry would come out 0. */
    _start_phys = _start - KERNEL_VMA;

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

        /* gp sits 0x800 into the small-data area so a signed 12-bit offset
         * covers .sdata and .sbss; _start loads it before any Rust runs (D-012). */
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

        /* Inside the zeroed range: safe only because _start's zeroing loop
         * uses no stack (D-012). */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += BOOT_STACK_SIZE;
        __boot_stack_top = .;

        /* The zeroing loop stores 8 bytes at a time with no ragged-tail check. */
        . = ALIGN(8);
        __bss_end = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ :
    {
        /* panic=abort: unwind tables are dead weight. */
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
