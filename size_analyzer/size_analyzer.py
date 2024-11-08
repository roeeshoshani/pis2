#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile
from pathlib import Path
import fire
import matplotlib.pyplot as plt

def analyze_elf(elf: ELFFile):
    fn_sizes = {}
    for symtab_section in elf.iter_sections(type='SHT_SYMTAB'):
        for symbol in symtab_section.iter_symbols():
            if symbol.entry.st_size == 0:
                continue
            fn_sizes[symbol.name] = symbol.entry.st_size

    labels = list(fn_sizes.keys())
    sizes = list(fn_sizes.values())

    # Plot the pie chart
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Function Size Distribution in Binary")
    plt.show()

def size_analyzer(elf_file_path: str):
    with open(elf_file_path, 'rb') as raw_file:
        analyze_elf(ELFFile(raw_file))

if __name__ == '__main__':
    fire.Fire(size_analyzer)
