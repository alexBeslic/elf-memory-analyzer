"""Treemap layout (squarified) and chart data preparation. Pure Python, no Qt."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .memory_analyzer import MemoryRegion
from .models import ElfModel, SectionInfo, Symbol, SymKind


@dataclass
class TreeItem:
    label: str
    size: int
    group: str = ""
    symbol_id: Optional[int] = None
    section: Optional[str] = None
    address: Optional[int] = None
    kind: str = ""


@dataclass
class Tile:
    x: float
    y: float
    w: float
    h: float
    item: Optional[TreeItem]
    group: str
    is_group: bool = False


def squarify(values: list[float], x: float, y: float, w: float, h: float) -> list[tuple[float, float, float, float]]:
    """Bruls et al. squarified treemap. ``values`` must be positive and sorted descending."""
    if not values or w <= 0 or h <= 0:
        return []
    scale = w * h / sum(values)
    areas = [v * scale for v in values]
    rects: list[tuple[float, float, float, float]] = []

    def worst(row: list[float], side: float) -> float:
        s = sum(row)
        return max(max(side * side * r / (s * s), (s * s) / (side * side * r)) for r in row)

    i = 0
    while i < len(areas):
        side = min(w, h)
        row = [areas[i]]
        i += 1
        while i < len(areas) and worst(row + [areas[i]], side) <= worst(row, side):
            row.append(areas[i])
            i += 1
        s = sum(row)
        if w >= h:
            rw, yy = s / h, y
            for a in row:
                rh = a / rw
                rects.append((x, yy, rw, rh))
                yy += rh
            x += rw
            w -= rw
        else:
            rh, xx = s / w, x
            for a in row:
                rw = a / rh
                rects.append((xx, y, rw, rh))
                xx += rw
            y += rh
            h -= rh
        if w <= 0 or h <= 0:
            break
    return rects


def layout_treemap(items: list[TreeItem], width: float, height: float, grouped: bool = True,
                   max_items_per_group: int = 2500, header: float = 15.0) -> list[Tile]:
    """Lay out items; each group becomes a header tile plus its children. Area is proportional to size."""
    items = [i for i in items if i.size > 0]
    if not items or width <= 0 or height <= 0:
        return []
    groups: dict[str, list[TreeItem]] = {}
    for it in items:
        groups.setdefault(it.group if grouped else "", []).append(it)
    glist = []
    for name, members in groups.items():
        members.sort(key=lambda m: m.size, reverse=True)
        if len(members) > max_items_per_group:
            rest = members[max_items_per_group:]
            members = members[:max_items_per_group] + [
                TreeItem(f"other ({len(rest)} items)", sum(m.size for m in rest), name)]
        glist.append((name, members, sum(m.size for m in members)))
    glist.sort(key=lambda g: g[2], reverse=True)
    tiles: list[Tile] = []
    for (name, members, total), (gx, gy, gw, gh) in zip(glist, squarify([g[2] for g in glist], 0, 0, width, height)):
        hdr = header if grouped and name and gh > header * 2 and gw > 40 else 0.0
        if hdr:
            tiles.append(Tile(gx, gy, gw, hdr, TreeItem(f"{name}  ({total:,} B)", total, name), name, True))
        for m, (x, y, w, h) in zip(members, squarify([m.size for m in members], gx, gy + hdr, gw, gh - hdr)):
            tiles.append(Tile(x, y, w, h, m, name))
    return tiles


def items_from_symbols(symbols: list[Symbol], kind: SymKind, group_by: str = "section",
                       min_size: int = 1) -> list[TreeItem]:
    out = []
    for s in symbols:
        if s.kind != kind or s.size < max(1, min_size) or s.alias_of is not None:
            continue
        if group_by == "category":
            g = s.category or "unknown"
        elif group_by == "region":
            g = s.region or "(no region)"
        elif group_by == "none":
            g = ""
        else:
            g = s.section or "(none)"
        out.append(TreeItem(s.display_name, s.size, g, s.id, s.section, s.address, kind.value))
    return out


def items_from_sections(sections: list[SectionInfo], group_by: str = "category") -> list[TreeItem]:
    return [TreeItem(s.name, s.size, s.category if group_by == "category" else "", None, s.name, s.addr, "section")
            for s in sections if s.alloc and s.size > 0 and not s.tls]


def items_from_regions(elf: ElfModel, regions: list[MemoryRegion]) -> list[TreeItem]:
    out = []
    for s in elf.sections:
        if s.alloc and s.size > 0 and not s.tls:
            out.append(TreeItem(s.name, s.size, s.region or "(no region)", None, s.name, s.addr, "section"))
    return out
