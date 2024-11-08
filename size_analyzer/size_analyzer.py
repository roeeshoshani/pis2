#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile
from pathlib import Path
import fire
import plotly.graph_objects as go

def analyze_elf(elf: ELFFile):
    fn_sizes = {}

    size_shdr_names = ['.text', '.rodata', '.data']
    total_size = 0
    for size_shdr_name in size_shdr_names:
        shdr = elf.get_section_by_name(size_shdr_name)
        total_size += shdr.data_size

    total_kb = total_size // 1024

    for symtab_section in elf.iter_sections(type='SHT_SYMTAB'):
        for symbol in symtab_section.iter_symbols():
            if symbol.entry.st_size == 0:
                continue
            fn_sizes[symbol.name] = symbol.entry.st_size

    labels = list(fn_sizes.keys())
    sizes = list(fn_sizes.values())

    fig = go.Figure(data=[go.Pie(labels=labels, values=sizes, hoverinfo="label+value+percent", textinfo="none")])
    fig.update_layout(
        title_text=f"Function Size Distribution in Binary (Total {total_kb}k)",
        template="plotly_dark",
    )
    fig.show()

def size_analyzer(elf_file_path: str):
    with open(elf_file_path, 'rb') as raw_file:
        analyze_elf(ELFFile(raw_file))

if __name__ == '__main__':
    fire.Fire(size_analyzer)
