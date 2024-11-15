ENTRY(_start)
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

	/*
	 * the mips linker needs the _gp symbol to do its relocations properly. i'm honestly not sure what value should be put
	 * here, but this seems to work fine.
	 */
	HIDDEN (_gp = ALIGN (16));

	/DISCARD/ : {
		*(.note.gnu.build-id)
		*(.comment)
	}
}

PHDRS {
	all PT_LOAD;
}
