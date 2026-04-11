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

    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :requests

    /* Align to page boundar */
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .text : {
        PROVIDE(__isr_text_start = .);
        *(.text.isr)
        PROVIDE(__isr_text_end = .);

        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)   
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}