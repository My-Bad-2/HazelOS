/* Tell the linker that we want an AArch64 ELF64 output file */
OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)

ENTRY(user_start)

PHDRS {
    requests    PT_LOAD    FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
    text        PT_LOAD    FLAGS((1 << 0) | (1 << 2)); /* Execute + Read */
    rodata      PT_LOAD    FLAGS((1 << 2));            /* Read only */
    dynamic     PT_DYNAMIC FLAGS((1 << 2));            /* Read only */
    data        PT_LOAD    FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
}

SECTIONS
{
    /* Start at 4MiB for safety */
    . = 0x400000;
    __image_base = .;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)

        /* Place constructors here to ensure they are read-only */
        . = ALIGN(8);
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array .ctors))
        PROVIDE_HIDDEN(__init_array_end = .);

        . = ALIGN(8);
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array .dtors))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } :rodata

    /* Keep dynamic relocations for KASLR/PIE loading. */
    .dynamic : {
        __dynamic_start = .;
        KEEP(*(.dynamic))
        __dynamic_end = .;
    } :rodata :dynamic

    .rela.dyn : {
        __rela_dyn_start = .;
        KEEP(*(.rela.dyn))
        KEEP(*(.rela.*))
        __rela_dyn_end = .;
    } :rodata

    .rel.dyn : {
        __rel_dyn_start = .;
        KEEP(*(.rel.dyn))
        KEEP(*(.rel.*))
        __rel_dyn_end = .;
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.got.plt)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    .stack (NOLOAD) : {
        . = ALIGN(16);
        *(.stack)
        . = ALIGN(16);
    } :data

    __image_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
