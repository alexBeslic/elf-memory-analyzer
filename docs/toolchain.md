# Toolchain configuration

The ELF analysis (symbols, sections, segments, memory summary, treemap, stack matching) needs **no** external
tool. Tools are only used when a feature requires them:

| Tool | Used for | Without it |
|------|----------|-----------|
| `objdump` (GNU or `llvm-objdump`) | Assembly view, call graph | Assembly tab explains what is missing |
| `c++filt` (or `llvm-cxxfilt`) | Demangling `_Z...` names | Mangled names are shown, with a warning |
| `nm`, `readelf`, compiler | Validation / diagnostics only | Nothing breaks |

## Presets
`GCC host`, `GNU Arm Embedded (arm-none-eabi-)`, `AArch64 bare-metal`, `RISC-V`, `Xtensa/ESP32`, `AVR`,
`Clang/LLVM`, and `Custom`. Choosing a preset searches `PATH` for that family's tools. Anything you type in a
path field overrides detection. If no objdump is configured, one is chosen from the ELF's machine type
(e.g. `EM_ARM` -> `arm-none-eabi-objdump`), then generic `objdump`/`llvm-objdump`.

**Important:** the host `objdump` on Linux usually only understands x86. For Cortex-M firmware use
`arm-none-eabi-objdump` or `llvm-objdump`.

## Options
* **objdump options**: extra flags split with `shlex` and passed without a shell, e.g. `-M intel`, `-M force-thumb`.
* **Stack report dialect**: `gcc` (`-fstack-usage`, tab-separated `file:line:col:name<TAB>bytes<TAB>qualifier`).
  The parser also accepts whitespace-separated `name bytes qualifier` lines. `clang` currently uses the same parser.
* **Build directory**: default directory searched recursively for `*.su` files.
* Settings are stored as JSON in `~/.config/elfmem/toolchain.json` (`%APPDATA%\elfmem` on Windows,
  `~/Library/Application Support/elfmem` on macOS).

## Adding a vendor toolchain
Select `Custom`, set the objdump/c++filt paths, and add extra options if needed. To add a permanent preset, add a
`Preset(...)` entry to `PRESETS` in `elfmem/toolchain.py`. To support another stack-report format, add a parser that
returns `StackRecord` objects (see `elfmem/stack_usage.py`); the matcher is format-independent.
