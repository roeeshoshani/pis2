SECTIONS
{
	. = 0x10000000;
	.all : {
		*(.shellcode_entry)
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
