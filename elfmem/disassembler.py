"""External-toolchain disassembly (objdump) with safe argument handling."""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .models import ElfModel, Symbol, SymKind
from .toolchain import MACHINE_PREFIXES, ToolchainConfig, resolve_tool

log = logging.getLogger(__name__)

INSN_RE = re.compile(r"^\s*(?P<addr>[0-9a-f]+):\t(?P<bytes>[0-9a-f ]*?)\s*(?:\t(?P<text>.*))?$")
FUNC_HDR_RE = re.compile(r"^(?P<addr>[0-9a-f]+) <(?P<name>.+)>:$")
MAX_ESTIMATED_SIZE = 64 * 1024


@dataclass
class Instruction:
    address: int
    raw: str
    mnemonic: str
    operands: str
    comment: str = ""

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.operands}".strip()


@dataclass
class DisasmResult:
    ok: bool
    instructions: list[Instruction] = field(default_factory=list)
    error: str = ""
    troubleshooting: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    start: int = 0
    end: int = 0
    end_estimated: bool = False


def function_bounds(sym: Symbol, elf: ElfModel) -> tuple[int, int, bool]:
    """Return (start, end, estimated). Zero-sized symbols use the next symbol/section end."""
    if sym.size > 0:
        return sym.address, sym.address + sym.size, False
    nxt = None
    for s in elf.symbols:
        if s.section == sym.section and s.address > sym.address and s.kind != SymKind.OTHER:
            if nxt is None or s.address < nxt:
                nxt = s.address
    sec = elf.section_by_name(sym.section) if sym.section else None
    limit = sec.end if sec else sym.address + 256
    end = min(x for x in (nxt, limit) if x is not None)
    return sym.address, min(end, sym.address + MAX_ESTIMATED_SIZE), True


def parse_objdump(text: str) -> list[Instruction]:
    """Parse ``objdump -d`` output lines into instructions (handles wrapped byte lines)."""
    out: list[Instruction] = []
    for line in text.splitlines():
        m = INSN_RE.match(line)
        if not m:
            continue
        body = m.group("text")
        raw = m.group("bytes").strip()
        if body is None or not body.strip():
            if out and raw:  # continuation line holding more instruction bytes
                out[-1].raw += " " + raw
            continue
        comment = ""
        for sep in (" # ", "\t# ", "\t; ", " ; "):
            if sep in body:
                body, comment = body.split(sep, 1)
                break
        parts = body.strip().split(None, 1)
        out.append(Instruction(int(m.group("addr"), 16), raw, parts[0], parts[1].strip() if len(parts) > 1 else "",
                               comment.strip()))
    return out


def _troubleshoot(machine: str, objdump: str, stderr: str) -> list[str]:
    tips = []
    prefixes = MACHINE_PREFIXES.get(machine, [])
    if prefixes:
        tips.append("This ELF targets %s; use a matching objdump such as %s." %
                    (machine, " or ".join(p + "objdump" for p in prefixes)))
    tips.append("Set the objdump path in Toolchain Settings (or choose the matching preset).")
    if "not recognized" in stderr or "can't disassemble" in stderr.lower() or "unknown architecture" in stderr.lower():
        tips.append(f"'{os.path.basename(objdump)}' was built without support for this architecture. "
                    "Host objdump usually only handles x86; install the target toolchain's binutils.")
    tips.append("llvm-objdump also works for most targets (preset 'Clang / LLVM').")
    return tips


def disassemble(elf_path: str, start: int, end: int, cfg: ToolchainConfig, machine: str = "",
                timeout: float = 60.0) -> DisasmResult:
    """Disassemble ``[start, end)`` using the configured/auto-detected objdump."""
    res = DisasmResult(ok=False, start=start, end=end)
    exe = resolve_tool(cfg, "objdump", machine)
    if not exe:
        res.error = "No objdump executable found."
        res.troubleshooting = ["Install binutils for the target (e.g. arm-none-eabi-binutils) and add it to PATH,",
                               "or set the objdump path in Toolchain Settings."] + _troubleshoot(machine, "", "")
        return res
    try:
        extra = shlex.split(cfg.objdump_args) if cfg.objdump_args.strip() else []
    except ValueError as exc:
        res.error = f"Invalid objdump options: {exc}"
        return res
    if end <= start:
        res.error = "Empty address range (function size is zero or unknown)."
        return res
    cmd = [exe, "-d", "-z", "--wide", f"--start-address=0x{start:x}", f"--stop-address=0x{end:x}",
           *extra, os.path.abspath(elf_path)]
    res.command = cmd
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False,
                              errors="replace")
    except subprocess.TimeoutExpired:
        res.error = f"objdump timed out after {timeout:.0f}s."
        return res
    except OSError as exc:
        res.error = f"Cannot run {exe}: {exc}"
        res.troubleshooting = _troubleshoot(machine, exe, "")
        return res
    if proc.returncode != 0:
        res.error = f"objdump failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
        res.troubleshooting = _troubleshoot(machine, exe, proc.stderr)
        return res
    res.instructions = parse_objdump(proc.stdout)
    if not res.instructions:
        res.error = "objdump produced no instructions for this range."
        res.troubleshooting = _troubleshoot(machine, exe, proc.stderr) + [
            "The range may be data, not code, or the section may not be present in the file image."]
        return res
    res.ok = True
    return res


def format_disassembly(instrs: list[Instruction], lines_in_range: Optional[list] = None,
                       read_source=None) -> tuple[str, dict[int, int]]:
    """Render to text. Returns (text, address -> 0-based line number). Optionally interleaves source."""
    lines: list[str] = []
    addr_line: dict[int, int] = {}
    src_by_addr: dict[int, tuple[str, int]] = {}
    for a, f, l in (lines_in_range or []):
        src_by_addr.setdefault(a, (f, l))
    last = None
    for ins in instrs:
        if ins.address in src_by_addr and src_by_addr[ins.address] != last:
            last = src_by_addr[ins.address]
            txt = read_source(*last) if read_source else None
            lines.append(f"; {os.path.basename(last[0])}:{last[1]}" + (f"   {txt}" if txt else ""))
        addr_line[ins.address] = len(lines)
        cm = f"    ; {ins.comment}" if ins.comment else ""
        lines.append(f"{ins.address:08x}:  {ins.raw:<20}  {ins.mnemonic:<8} {ins.operands}{cm}".rstrip())
    return "\n".join(lines), addr_line
