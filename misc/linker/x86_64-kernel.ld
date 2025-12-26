/* Tell the linker that we want an x86_64 ELF64 output file */
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(_start)

PHDRS {
    requests    PT_LOAD    FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
    text        PT_LOAD    FLAGS((1 << 0) | (1 << 2)); /* Execute + Read */
    rodata      PT_LOAD    FLAGS((1 << 2));            /* Read only */
    data        PT_LOAD    FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
}

SECTIONS
{
    . = 0xffffffff80000000;

    .requests : {
        KEEP(*(.requests_start))
        KEEP(*(.requests))
        KEEP(*(.requests_end))
    } :requests

    /* Align to page boundar */
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
        
        /* Unit Test Section */
        . = ALIGN(8);
        __start_tests = .;
        KEEP(*(.tests))
        __stop_tests  = .;        
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)
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

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}