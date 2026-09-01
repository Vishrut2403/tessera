/* Linker script for tessera user programs (D-039).
 *
 * Flat, static, no relocations: the kernel's loader walks PT_LOAD headers and
 * nothing else. Each segment is page-aligned so the loader can map it with the
 * permissions the ELF asks for and no two segments share a page. */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* Well clear of the null page, and far below the boot info page. */
USER_BASE = 0x10000000;

SECTIONS
{
    . = USER_BASE;
    __image_start = .;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.data.rel.ro .data.rel.ro.*)
    }

    . = ALIGN(4096);
    .data : {
        *(.data .data.*)
        . = ALIGN(8);
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.*)
        *(.got .got.plt)
    }

    /* No ALIGN: .bss shares the writable segment with .data, which is what
     * makes p_memsz exceed p_filesz and gives the loader something to zero. */
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
