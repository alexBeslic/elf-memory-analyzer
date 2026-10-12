# Toolchain configuration

The ELF analysis (symbols, sections, segments, memory summary, treemap, stack matching) needs **no** external
tool. Tools are only used when a feature requires them:

| Tool | Used for | Without it |
|------|----------|-----------|
| `objdump` (GNU or `llvm-objdump`) | Assembly view, call graph | Assembly tab explains what is missing |
| `c++filt` (or `llvm-cxxfilt`) | Demangling `_Z...` names | Mangled names are shown, with a warning |
| `nm`, `readelf`, compiler | Validation / diagnostics only | Nothing breaks |

## Quick setup: point at the toolchain folder
On the Toolchain Settings page enter (or browse to) the folder that contains the compiler - the `bin` folder, or the
install root - and press **Scan**. The scan looks in that folder, its `bin` subfolder and `<target>/bin` subfolders for
files named `<prefix>objdump`, `<prefix>nm`, `<prefix>readelf`, `<prefix>c++filt` and `<prefix>gcc`/`clang`
(`.exe`/`.bat` accepted). Every distinct prefix found (e.g. `tricore-elf-`) becomes a candidate; the one with the most
tools is selected and all tool fields are filled. If a folder holds several toolchains, choose the right prefix from the
*Tool prefix* list; you can also type a prefix yourself. Helper tools such as `gcc-nm` or `gcc-ar` are ignored.
The folder and prefix are stored, so tools resolve automatically even if you clear individual fields.
Resolution order: explicit tool path > toolchain folder + prefix > ELF-machine defaults (e.g. `EM_TRICORE` ->
`tricore-elf-`) > preset names on `PATH`.

## Memory regions
Memory Map page -> **Import**: GNU ld `.map` files (the *Memory Configuration* table), linker scripts (`MEMORY { ... }`,
numbers with K/M/G suffixes) and JSON (`{"regions":[{"name":"FLASH","origin":"0x08000000","length":"512K"}]}`).
A `<elf-name>.map` beside the ELF is imported automatically. Overlapping regions (cached/uncached aliases) are allowed:
each address is assigned to the smallest region that contains it.

## Compiler call-graph info
Compile with `-fcallgraph-info=su,da` (GCC 10+). The `.ci` files are found with the `.su` files when you open the build
directory.

## Presets
`GCC host`, `GNU Arm Embedded (arm-none-eabi-)`, `GNU TriCore (tricore-elf-)`, `AArch64 bare-metal`, `RISC-V`, `Xtensa/ESP32`, `AVR`,
`Clang/LLVM`, and `Custom`. Choosing a preset searches `PATH` for that family's tools. Anything you type in a
path field overrides detection. If no objdump is configured, one is chosen from the ELF's machine type
(e.g. `EM_ARM` -> `arm-none-eabi-objdump`), then generic `objdump`/`llvm-objdump`.

**Important:** the host `objdump` on Linux usually only understands x86. For Cortex-M firmware use
`arm-none-eabi-objdump` or `llvm-objdump`.

## Options
* **objdump options**: extra flags split with `shlex` and passed without a shell, e.g. `-M intel`, `-M force-thumb`.
* **Stack report dialect**: `gcc` (`-fstack-usage`, tab-separated `file:line:col:name<TAB>bytes<TAB>qualifier`).
  The parser also accepts whitespace-separated `name bytes qualifier` lines. `clang` currently uses the same parser.
* **Build directory**: chosen per ELF on the Stack Analysis page (or by dropping a folder on the window); it is no longer a persistent setting.
* Settings are stored as JSON in `~/.config/elfmem/toolchain.json` (`%APPDATA%\elfmem` on Windows,
  `~/Library/Application Support/elfmem` on macOS).

## Adding a vendor toolchain
Select `Custom`, set the objdump/c++filt paths, and add extra options if needed. To add a permanent preset, add a
`Preset(...)` entry to `PRESETS` in `elfmem/toolchain.py`. To support another stack-report format, add a parser that
returns `StackRecord` objects (see `elfmem/stack_usage.py`); the matcher is format-independent.
