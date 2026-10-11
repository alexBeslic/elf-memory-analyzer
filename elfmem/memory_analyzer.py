"""Memory accounting: configurable regions, section classification totals, top consumers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import (CAT_BSS, CAT_CODE, CAT_DATA, CAT_DEBUG, CAT_NON_ALLOC, CAT_OTHER_ALLOC, CAT_RODATA,
                     ElfModel, SectionInfo, Symbol, SymKind)


@dataclass
class MemoryRegion:
    name: str
    origin: int
    length: int
    description: str = ""

    def contains(self, addr: int) -> bool:
        return self.origin <= addr < self.origin + self.length

    @property
    def end(self) -> int:
        return self.origin + self.length

    def to_dict(self) -> dict:
        return {"name": self.name, "origin": self.origin, "length": self.length, "description": self.description}

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryRegion":
        return cls(str(d["name"]), int(d["origin"]), int(d["length"]), str(d.get("description", "")))


def region_for(addr: int, regions: list[MemoryRegion]) -> Optional[str]:
    for r in regions:
        if r.contains(addr):
            return r.name
    return None


@dataclass
class RegionUsage:
    region: MemoryRegion
    used_bytes: int = 0       # sections placed here by run-time address (VMA)
    load_image_bytes: int = 0  # initialised data whose load address (LMA) is here but runs elsewhere

    @property
    def total_used(self) -> int:
        return self.used_bytes + self.load_image_bytes

    @property
    def percent(self) -> Optional[float]:
        return 100.0 * self.total_used / self.region.length if self.region.length else None


@dataclass
class MemorySummary:
    category_bytes: dict[str, int] = field(default_factory=dict)
    berkeley_text: int = 0
    berkeley_data: int = 0
    berkeley_bss: int = 0
    load_filesz: int = 0
    load_memsz: int = 0
    section_alloc_total: int = 0
    region_usage: list[RegionUsage] = field(default_factory=list)
    unplaced_sections: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def assign_regions(elf: ElfModel, regions: list[MemoryRegion]) -> list[str]:
    """Annotate sections and symbols with their region. Returns warnings (e.g. overflow)."""
    warns: list[str] = []
    for s in elf.sections:
        s.region = s.lma_region = None
        if not s.alloc or s.size == 0 or s.tls:
            continue
        s.region = region_for(s.addr, regions)
        if s.region and not any(r.name == s.region and s.end <= r.end for r in regions):
            warns.append(f"Section {s.name} extends past the end of region {s.region}.")
        if s.lma is not None and s.lma != s.addr:
            s.lma_region = region_for(s.lma, regions)
    sec_region = {s.name: s.region for s in elf.sections}
    for sym in elf.symbols:
        sym.region = region_for(sym.address, regions) if regions else None
        if sym.region is None and sym.section in sec_region and not regions:
            sym.region = None
    return warns


def summarize(elf: ElfModel, regions: list[MemoryRegion]) -> MemorySummary:
    """Compute category totals and per-region usage. Section sizes are not run-time usage."""
    out = MemorySummary()
    cats = {c: 0 for c in (CAT_CODE, CAT_RODATA, CAT_DATA, CAT_BSS, CAT_OTHER_ALLOC, CAT_DEBUG, CAT_NON_ALLOC)}
    for s in elf.sections:
        if s.index == 0:
            continue
        cats[s.category] = cats.get(s.category, 0) + s.size
    out.category_bytes = cats
    out.section_alloc_total = sum(cats[c] for c in (CAT_CODE, CAT_RODATA, CAT_DATA, CAT_BSS, CAT_OTHER_ALLOC))
    out.berkeley_text = cats[CAT_CODE] + cats[CAT_RODATA] + cats[CAT_OTHER_ALLOC]
    out.berkeley_data, out.berkeley_bss = cats[CAT_DATA], cats[CAT_BSS]
    loads = [g for g in elf.segments if g.type == "PT_LOAD"]
    out.load_filesz = sum(g.filesz for g in loads)
    out.load_memsz = sum(g.memsz for g in loads)
    out.warnings = assign_regions(elf, regions)
    usage = {r.name: RegionUsage(r) for r in regions}
    for s in elf.sections:
        if not s.alloc or s.size == 0 or s.tls:
            continue
        if s.region:
            usage[s.region].used_bytes += s.size
        elif regions:
            out.unplaced_sections.append(s.name)
        if s.lma_region:
            usage[s.lma_region].load_image_bytes += s.size
    out.region_usage = list(usage.values())
    if not regions:
        out.warnings.append("No memory regions configured: per-region usage and percentages of physical "
                            "memory are unavailable (percentages shown are relative to the allocated total).")
    return out


def top_symbols(symbols: list[Symbol], kind: SymKind, n: int = 20) -> list[Symbol]:
    """Largest symbols of ``kind`` (aliases excluded so shared bytes are not counted twice)."""
    pool = [s for s in symbols if s.kind == kind and s.alias_of is None and s.size > 0]
    return sorted(pool, key=lambda s: s.size, reverse=True)[:n]


def top_stack(symbols: list[Symbol], n: int = 20) -> list[Symbol]:
    pool = [s for s in symbols if s.kind == SymKind.FUNCTION and s.stack_bytes is not None and s.alias_of is None]
    return sorted(pool, key=lambda s: s.stack_bytes or 0, reverse=True)[:n]


def top_sections(elf: ElfModel, n: int = 20) -> list[SectionInfo]:
    return sorted((s for s in elf.sections if s.alloc and s.size > 0), key=lambda s: s.size, reverse=True)[:n]
