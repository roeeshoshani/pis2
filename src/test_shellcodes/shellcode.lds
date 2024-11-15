ENTRY(_start)
SECTIONS
{
	. = 0x10000000;
	.all : {
		*(.shellcode_entry)
		*(.text*)
		*(.rodata*)
		*(.data*)
		*(.got*)
		*(.bss*)
	} :all

	/*
	 * the mips linker needs the _gp symbol to do its relocations properly. this is the value that will be put in `_gp`
	 * at runtime, and all global variable memory accesses will be relative to it. so, just make it point to the end of
	 * all our code, and all accesses will use negative offsets to access the stuff before it.
	 */
	HIDDEN (_gp = ALIGN (16));

	/DISCARD/ : {
		*(.note.gnu.*)
		*(.comment)
	}
}

PHDRS {
	all PT_LOAD;
}
