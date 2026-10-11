"""Tiny synthetic ELF32 (ARM, little-endian) writer for tests that need exact, known contents."""
from __future__ import annotations

import struct

TEXT_ADDR, DATA_ADDR, BSS_SIZE = 0x08000000, 0x20000000, 64
SYMS = [  # name, value, size, info(bind<<4|type), shndx
    ("main.c", 0, 0, (0 << 4) | 4, 0xFFF1),                 # STT_FILE, ABS
    ("thumb_fn", TEXT_ADDR | 1, 8, (0 << 4) | 2, 1),        # local FUNC in .text, Thumb bit set
    ("zero_size_fn", TEXT_ADDR + 8, 0, (1 << 4) | 2, 1),    # global FUNC with size 0
    ("g_data", DATA_ADDR, 4, (1 << 4) | 1, 2),              # global OBJECT in .data
    ("g_bss", DATA_ADDR + 4, BSS_SIZE, (1 << 4) | 1, 3),    # global OBJECT in .bss
    ("_estack", DATA_ADDR + 0x1000, 0, (1 << 4) | 0, 0xFFF1),  # NOTYPE ABS
]


def make_arm_elf(path, strip_symbols: bool = False) -> None:
    text = bytes(range(16))
    data = b"\x01\x00\x00\x00"
    strtab = b"\0"
    sym_blob = b"\0" * 16
    if not strip_symbols:
        for name, val, size, info, shndx in SYMS:
            off = len(strtab)
            strtab += name.encode() + b"\0"
            sym_blob += struct.pack("<IIIBBH", off, val, size, info, 0, shndx)
    shnames = [b"", b".text", b".data", b".bss"] + ([b".symtab", b".strtab"] if not strip_symbols else []) + [b".shstrtab"]
    shstr, name_off = b"", []
    for n in shnames:
        name_off.append(len(shstr))
        shstr += n + b"\0"
    ehsize, phsize, shsize = 52, 32, 40
    phnum = 2
    text_off = ehsize + phsize * phnum
    data_off = text_off + len(text)
    pos = data_off + len(data)
    blobs = []
    if not strip_symbols:
        blobs += [(sym_blob, pos), (strtab, pos + len(sym_blob))]
        pos += len(sym_blob) + len(strtab)
    blobs.append((shstr, pos))
    shoff = pos + len(shstr)
    nsec = len(shnames)
    hdr = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    hdr += struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, TEXT_ADDR | 1, ehsize, shoff, 0x05000000, ehsize, phsize,
                       phnum, shsize, nsec, nsec - 1)
    ph = struct.pack("<IIIIIIII", 1, text_off, TEXT_ADDR, TEXT_ADDR, len(text), len(text), 5, 4)
    ph += struct.pack("<IIIIIIII", 1, data_off, DATA_ADDR, TEXT_ADDR + 0x100, len(data), len(data) + BSS_SIZE, 6, 4)

    def sh(name, typ, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack("<IIIIIIIIII", name, typ, flags, addr, off, size, link, info, align, entsize)

    shdrs = sh(0, 0, 0, 0, 0, 0)
    shdrs += sh(name_off[1], 1, 6, TEXT_ADDR, text_off, len(text), align=2)
    shdrs += sh(name_off[2], 1, 3, DATA_ADDR, data_off, len(data), align=4)
    shdrs += sh(name_off[3], 8, 3, DATA_ADDR + 4, data_off + len(data), BSS_SIZE, align=4)
    if not strip_symbols:
        shdrs += sh(name_off[4], 2, 0, 0, blobs[0][1], len(sym_blob), link=5, info=2, align=4, entsize=16)
        shdrs += sh(name_off[5], 3, 0, 0, blobs[1][1], len(strtab))
    shdrs += sh(name_off[-1], 3, 0, 0, blobs[-1][1], len(shstr))
    with open(path, "wb") as fh:
        fh.write(hdr + ph + text + data)
        for b, _ in blobs:
            fh.write(b)
        fh.write(shdrs)
