# Packaging for end users (no Python install needed)

    pip install -e ".[dev]"
    pyinstaller --noconfirm --windowed --name elfmem \
        --collect-submodules elftools elfmem/gui/app.py

The result is in `dist/elfmem/`. Build on each target OS (Windows, macOS, Linux); PyInstaller does
not cross-compile. External tools (objdump, c++filt) are *not* bundled: they come from the user's
embedded toolchain and are configured on the Toolchain Settings page.

Status: this packaging recipe was **not executed** in the development environment; run it once per
platform and smoke-test `dist/elfmem/elfmem` before distributing.
