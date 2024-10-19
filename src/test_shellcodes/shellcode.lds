SECTIONS
{
	. = 0x10000000;
	.all : { *(.text*) *(.rodata* .bss* .data*) } :all
}

PHDRS {
	all PT_LOAD;
}
