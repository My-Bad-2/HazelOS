/* Tell the linker that we want an x86_64 ELF64 output file */
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(_start)

PHDRS
{
    requests  PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
    text      PT_LOAD FLAGS((1 << 0) | (1 << 2)); /* Execute + Read */
    rodata    PT_LOAD FLAGS((1 << 2));            /* Read only */
    data      PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
}

SECTIONS
{
    /* Kernel virtual base. */
    . = 0xffffffff80000000;

    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :requests

    /* Align to page boundary. */
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .text : {
        __text_start = .;
        PROVIDE(__isr_text_start = .);
        *(.text.isr)
        PROVIDE(__isr_text_end = .);

        *(.text .text.*)
        *(.init .init.*)
        *(.fini .fini.*)
        __text_end = .;
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

.rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.gcc_except_table .gcc_except_table.*)

        . = ALIGN(8);
        __preinit_array_start = .;
        KEEP(*(.preinit_array))
        __preinit_array_end = .;

        . = ALIGN(8);
        __init_array_start = .;
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP(*(.init_array))
        /* Map legacy ctors directly into the init_array */
        KEEP(*(SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.ctors))
        __init_array_end = .;

        . = ALIGN(8);
        __fini_array_start = .;
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
        KEEP(*(.fini_array))
        /* Map legacy dtors directly into the fini_array */
        KEEP(*(SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.dtors))
        __fini_array_end = .;

        __rodata_end = .;
    } :rodata

    .eh_frame : {
        KEEP(*(.eh_frame*))
    } :rodata

    /* Align to page boundary. */
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.got.plt)
        __data_end = .;
    } :data

    .bss : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Drop non-loadable metadata. */
    /DISCARD/ : {
        *(.note .note.*)
        *(.comment)
    }
}