"""Toolchain profiles, tool detection/validation and configuration persistence.

The ELF analysis itself never needs these tools. They are only used for
disassembly (objdump), demangling (c++filt) and optional diagnostics.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Optional

ROLES = ("objdump", "nm", "readelf", "cxxfilt", "compiler")


@dataclass
class Preset:
    name: str
    label: str
    family: str
    su_dialect: str
    candidates: dict[str, list[str]]
    objdump_args: str = ""


def _gnu(prefixes: list[str], compiler: str = "gcc", cxx: str = "c++filt") -> dict[str, list[str]]:
    return {"objdump": [p + "objdump" for p in prefixes], "nm": [p + "nm" for p in prefixes],
            "readelf": [p + "readelf" for p in prefixes], "cxxfilt": [p + "c++filt" for p in prefixes] + [cxx],
            "compiler": [p + compiler for p in prefixes]}


PRESETS: dict[str, Preset] = {p.name: p for p in [
    Preset("gnu-native", "GCC / GNU binutils (host)", "gcc", "gcc", _gnu([""])),
    Preset("gnu-arm-embedded", "GNU Arm Embedded (arm-none-eabi-)", "gcc", "gcc", _gnu(["arm-none-eabi-"])),
    Preset("gnu-aarch64", "GNU AArch64 bare-metal (aarch64-none-elf-)", "gcc", "gcc", _gnu(["aarch64-none-elf-"])),
    Preset("gnu-riscv", "GNU RISC-V (riscv*-elf-)", "gcc", "gcc",
           _gnu(["riscv-none-elf-", "riscv64-unknown-elf-", "riscv32-unknown-elf-"])),
    Preset("gnu-xtensa", "GNU Xtensa / ESP32 (xtensa-esp32-elf-)", "gcc", "gcc",
           _gnu(["xtensa-esp32-elf-", "xtensa-esp32s3-elf-", "xtensa-lx106-elf-"])),
    Preset("gnu-tricore", "GNU TriCore (tricore-elf-)", "gcc", "gcc", _gnu(["tricore-elf-", "tricore-"])),
    Preset("gnu-avr", "GNU AVR (avr-)", "gcc", "gcc", _gnu(["avr-"])),
    Preset("clang-llvm", "Clang / LLVM", "clang", "clang",
           {"objdump": ["llvm-objdump"], "nm": ["llvm-nm"], "readelf": ["llvm-readelf"],
            "cxxfilt": ["llvm-cxxfilt", "c++filt"], "compiler": ["clang"]}),
    Preset("custom", "Custom / vendor toolchain", "custom", "gcc",
           {r: [] for r in ROLES}),
]}

# ELF machine -> binutils prefixes to try when no objdump is configured.
MACHINE_PREFIXES: dict[str, list[str]] = {
    "EM_ARM": ["arm-none-eabi-", "arm-linux-gnueabihf-", "arm-none-linux-gnueabihf-"],
    "EM_AARCH64": ["aarch64-none-elf-", "aarch64-linux-gnu-"],
    "EM_RISCV": ["riscv-none-elf-", "riscv64-unknown-elf-", "riscv32-unknown-elf-", "riscv64-linux-gnu-"],
    "EM_XTENSA": ["xtensa-esp32-elf-", "xtensa-esp32s3-elf-", "xtensa-lx106-elf-"],
    "EM_TRICORE": ["tricore-elf-", "tricore-"], "EM_AVR": ["avr-"], "EM_MSP430": ["msp430-elf-"], "EM_MIPS": ["mips-linux-gnu-", "mipsel-linux-gnu-"],
    "EM_PPC": ["powerpc-eabi-", "powerpc-linux-gnu-"], "EM_386": [""], "EM_X86_64": [""],
}


@dataclass
class ToolchainConfig:
    preset: str = "gnu-native"
    family: str = "gcc"
    compiler: str = ""
    objdump: str = ""
    nm: str = ""
    readelf: str = ""
    cxxfilt: str = ""
    objdump_args: str = ""
    demangle: bool = True
    load_dwarf: bool = True
    su_dialect: str = "gcc"
    build_dir: str = ""   # legacy; the build directory is now per ELF session and no longer persisted
    memory_regions: list[dict] = field(default_factory=list)  # legacy; regions are stored per ELF
    toolchain_dir: str = ""
    tool_prefix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ToolchainConfig":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})

    def apply_preset(self, name: str) -> None:
        preset = PRESETS.get(name)
        if not preset:
            return
        self.preset, self.family, self.su_dialect = preset.name, preset.family, preset.su_dialect
        self.objdump_args = preset.objdump_args


@dataclass
class ToolCheck:
    role: str
    path: str
    ok: bool
    message: str
    version: str = ""


def config_dir() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "elfmem"


def load_config(path: Optional[Path] = None) -> ToolchainConfig:
    p = path or config_dir() / "toolchain.json"
    try:
        return ToolchainConfig.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return ToolchainConfig()


def save_config(cfg: ToolchainConfig, path: Optional[Path] = None) -> Path:
    p = path or config_dir() / "toolchain.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg.to_dict(), indent=2), encoding="utf-8")
    return p


def find_executable(candidates: list[str]) -> str:
    for c in candidates:
        found = shutil.which(c)
        if found:
            return found
    return ""


def detect_tools(preset_name: str) -> dict[str, str]:
    """Find executables on PATH for each role of the given preset (empty string = not found)."""
    preset = PRESETS.get(preset_name, PRESETS["custom"])
    return {role: find_executable(preset.candidates.get(role, [])) for role in ROLES}


def validate_tool(role: str, path: str, timeout: float = 10.0) -> ToolCheck:
    """Check that ``path`` exists, runs and looks like the expected tool."""
    if not path:
        return ToolCheck(role, path, False, "not configured")
    exe = shutil.which(path) or path
    if not os.path.isfile(exe):
        return ToolCheck(role, path, False, f"file not found: {path}")
    if not os.access(exe, os.X_OK):
        return ToolCheck(role, path, False, f"not executable: {exe}")
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return ToolCheck(role, exe, False, "timed out running --version")
    except OSError as exc:
        return ToolCheck(role, exe, False, f"cannot execute: {exc}")
    text = (proc.stdout or proc.stderr or "").strip()
    first = text.splitlines()[0] if text else ""
    if proc.returncode != 0 and not first:
        return ToolCheck(role, exe, False, f"--version failed (exit {proc.returncode})")
    expect = {"objdump": "objdump", "nm": "nm", "readelf": "readelf", "cxxfilt": "filt"}.get(role)
    low = text.lower()
    if expect and expect not in low and "llvm" not in low:
        return ToolCheck(role, exe, False, f"does not look like {role}: '{first}'", first)
    return ToolCheck(role, exe, True, "ok", first)


def validate_config(cfg: ToolchainConfig) -> list[ToolCheck]:
    """Validate every configured tool; unconfigured tools are reported as optional."""
    checks = []
    for role in ROLES:
        path = getattr(cfg, role)
        if path:
            checks.append(validate_tool(role, path))
        else:
            found = find_executable(PRESETS.get(cfg.preset, PRESETS["custom"]).candidates.get(role, []))
            checks.append(ToolCheck(role, found, bool(found),
                                    f"auto-detected: {found}" if found else "not configured and not found on PATH"))
    return checks


@dataclass
class ToolchainCandidate:
    prefix: str
    directory: str
    tools: dict[str, str]

    @property
    def score(self) -> tuple:
        return (int("objdump" in self.tools), len(self.tools), int(bool(self.prefix)))


_ROLE_RE = {
    "objdump": re.compile(r"^(?P<p>.*?)objdump$"), "nm": re.compile(r"^(?P<p>.*?)nm$"),
    "readelf": re.compile(r"^(?P<p>.*?)readelf$"), "cxxfilt": re.compile(r"^(?P<p>.*?)c\+\+filt$|^(?P<p2>.*?)cxxfilt$"),
    "compiler": re.compile(r"^(?P<p>.*?)(?:gcc|clang)(?:-\d+(?:\.\d+)*)?$"),
}
_BAD_PREFIX = ("gcc-", "g++-", "cc-", "c++-", "cpp-", "gcov-", "lto-")


def _bin_dirs(root: str) -> list[str]:
    root = os.path.abspath(root)
    if os.path.isfile(root):
        root = os.path.dirname(root)
    dirs = [root, os.path.join(root, "bin")]
    try:
        for e in sorted(os.scandir(root), key=lambda x: x.name)[:80]:
            if e.is_dir(follow_symlinks=False):
                dirs += [os.path.join(e.path, "bin")]
    except OSError:
        pass
    return [d for d in dirs if os.path.isdir(d)]


def scan_toolchain_dir(root: str) -> list[ToolchainCandidate]:
    """Find GNU/LLVM binutils-style tools in a toolchain folder (or its ``bin`` subfolders).

    Tool names are ``<prefix><tool>`` (``tricore-elf-objdump``); every distinct prefix becomes a candidate,
    best candidate first. Un-prefixed copies in nested ``<target>/bin`` folders rank below prefixed ones.
    """
    found: dict[str, ToolchainCandidate] = {}
    for d in _bin_dirs(root):
        try:
            entries = sorted(os.scandir(d), key=lambda x: x.name)
        except OSError:
            continue
        for e in entries:
            if not e.is_file():
                continue
            stem = re.sub(r"\.(exe|bat|cmd)$", "", e.name, flags=re.I)
            if os.name != "nt" and not os.access(e.path, os.X_OK):
                continue
            for role, rx in _ROLE_RE.items():
                m = rx.match(stem)
                if not m:
                    continue
                prefix = m.groupdict().get("p") or m.groupdict().get("p2") or ""
                if prefix and (not prefix.endswith("-") or prefix.endswith(_BAD_PREFIX)):
                    continue
                cand = found.setdefault(prefix, ToolchainCandidate(prefix, d, {}))
                cand.tools.setdefault(role, e.path)
    return sorted(found.values(), key=lambda c: c.score, reverse=True)


def resolve_tool(cfg: ToolchainConfig, role: str, machine: Optional[str] = None) -> str:
    """Pick the executable for ``role``: explicit path > toolchain folder (+prefix) > machine names > preset names."""
    explicit = getattr(cfg, role, "")
    if explicit:
        return shutil.which(explicit) or explicit
    if cfg.toolchain_dir:
        cands = scan_toolchain_dir(cfg.toolchain_dir)
        if cfg.tool_prefix:
            cands = [c for c in cands if c.prefix == cfg.tool_prefix] or cands
        for c in cands:
            if role in c.tools:
                return c.tools[role]
    names: list[str] = []
    if machine and role != "compiler":
        names += [p + {"cxxfilt": "c++filt"}.get(role, role) for p in MACHINE_PREFIXES.get(machine, [])]
    names += PRESETS.get(cfg.preset, PRESETS["custom"]).candidates.get(role, [])
    if role == "objdump":
        names += ["objdump", "llvm-objdump"]
    if role == "cxxfilt":
        names += ["c++filt", "llvm-cxxfilt"]
    return find_executable(names)
