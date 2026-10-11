import random

from elfmem import analysis as an
from elfmem.memory_analyzer import MemoryRegion, summarize, top_sections, top_symbols
from elfmem.models import SymKind
from elfmem.visualization import TreeItem, items_from_symbols, layout_treemap, squarify

FLASH = MemoryRegion("FLASH", 0x08000000, 0x1000)
RAM = MemoryRegion("RAM", 0x20000000, 0x2000)


def test_regions_and_load_image_accounting(arm_elf):
    res = an.analyze_elf(str(arm_elf), regions=[FLASH, RAM])
    m = res.memory
    use = {u.region.name: u for u in m.region_usage}
    assert use["FLASH"].used_bytes == 16            # .text by VMA
    assert use["FLASH"].load_image_bytes == 4        # .data load image (LMA in flash, runs in RAM)
    assert use["RAM"].used_bytes == 4 + 64           # .data + .bss by VMA
    assert abs(use["RAM"].percent - 100 * 68 / 0x2000) < 1e-9
    assert (m.berkeley_text, m.berkeley_data, m.berkeley_bss) == (16, 4, 64)
    assert m.load_filesz == 20 and m.load_memsz == 84   # file size != runtime size
    by = {s.name: s for s in res.elf.symbols}
    assert by["g_bss"].region == "RAM" and by["thumb_fn"].region == "FLASH"


def test_no_regions_is_reported_not_invented(arm_elf):
    res = an.analyze_elf(str(arm_elf))
    assert res.memory.region_usage == []
    assert any("No memory regions" in w for w in res.memory.warnings)


def test_section_overflow_warning(arm_elf):
    res = an.analyze_elf(str(arm_elf), regions=[MemoryRegion("TINY", 0x08000000, 8), RAM])
    assert any("extends past" in w for w in res.memory.warnings)


def test_top_lists_exclude_aliases_and_sort(build):
    res = an.analyze_elf(str(build.elf))
    funcs = top_symbols(res.elf.symbols, SymKind.FUNCTION, 5)
    assert [f.size for f in funcs] == sorted((f.size for f in funcs), reverse=True)
    data = top_symbols(res.elf.symbols, SymKind.DATA, 3)
    assert data[0].size >= data[-1].size
    assert top_sections(res.elf, 3)[0].size >= top_sections(res.elf, 3)[-1].size


def test_squarify_area_proportional_and_inside_bounds():
    rnd = random.Random(1)
    vals = sorted((rnd.randint(1, 5000) for _ in range(500)), reverse=True)
    rects = squarify(vals, 0, 0, 1000, 600)
    assert len(rects) == len(vals)
    total = sum(vals)
    for v, (x, y, w, h) in zip(vals, rects):
        assert abs(w * h - v / total * 600000) < 1e-3 * 600000
        assert x >= -1e-6 and y >= -1e-6 and x + w <= 1000 + 1e-6 and y + h <= 600 + 1e-6
    assert abs(sum(w * h for _, _, w, h in rects) - 600000) < 1e-3


def test_layout_groups_and_many_items():
    items = [TreeItem(f"f{i}", (i % 97) + 1, group=f".sec{i % 5}", symbol_id=i) for i in range(20000)]
    tiles = layout_treemap(items, 1200, 800, max_items_per_group=1000)
    leaf = [t for t in tiles if not t.is_group]
    assert sum(1 for t in tiles if t.is_group) == 5
    assert len(leaf) == 5 * 1001 and any(t.item.label.startswith("other (") for t in leaf)
    assert all(t.x + t.w <= 1200 + 1e-6 and t.y + t.h <= 800 + 1e-6 for t in tiles)


def test_items_from_symbols_filters(build):
    res = an.analyze_elf(str(build.elf))
    items = items_from_symbols(res.elf.symbols, SymKind.FUNCTION, "section", min_size=20)
    assert items and all(i.size >= 20 for i in items)
