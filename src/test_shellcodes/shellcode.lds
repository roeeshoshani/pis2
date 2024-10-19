SECTIONS
{
	. = 0x10000000;
	.all : {
		*(.text*)
		*(.rodata*)
		*(.bss*)
		*(.data*)
	} :all
	/DISCARD/ : {
		*(.note.gnu.build-id)
		*(.comment)
	}
}

PHDRS {
	all PT_LOAD;
}
