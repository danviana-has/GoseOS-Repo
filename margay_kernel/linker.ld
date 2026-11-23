OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    limine_requests PT_LOAD FLAGS((1 << 1) | (1 << 2));       /* R W */
    text            PT_LOAD FLAGS((1 << 0) | (1 << 2));       /* R X */
    rodata          PT_LOAD FLAGS((1 << 2));                  /* R   */
    data            PT_LOAD FLAGS((1 << 1) | (1 << 2));       /* R W */
}

SECTIONS
{
    . = 0xffffffff80000000;

    __kernel_start = .;

    .limine_requests : ALIGN(4096) {
        __limine_requests_start = .;
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
        __limine_requests_end = .;
    } :limine_requests

    . = ALIGN(4096);
    __text_start = .;
    .text : {
        *(.text .text.*)
    } :text
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata
    . = ALIGN(4096);
    __rodata_end = .;

    __roottask_start = .;
    .roottask : {
        KEEP(*(.roottask .roottask.*))
    } :rodata
    . = ALIGN(4096);
    __roottask_end = .;

    __data_start = .;
    .data : {
        *(.data .data.*)
    } :data

    . = ALIGN(4096);
    __bss_start = .;
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(4096);
    __bss_end = .;

    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
