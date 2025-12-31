ENTRY(_start)

SECTIONS
{
    . = 0x40080000;

    .boot :
    {
        KEEP(*(.text.boot))
    }

    .text :
    {
        *(.text*)
    }

    .rodata :
    {
        *(.rodata*)
    }

    .data :
    {
        *(.data*)
    }

    .bss :
    {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
    }

    /* End of kernel image for boot header */
    . = ALIGN(4096);
    _end = .;
}
