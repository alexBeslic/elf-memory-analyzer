import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
SRC = Path(__file__).parent / "fixtures" / "src"


@pytest.fixture(scope="session")
def build(tmp_path_factory):
    """Compile the fixture programs with GCC (-fstack-usage) and link them. Skips if no compiler."""
    gcc, gxx = shutil.which("gcc"), shutil.which("g++")
    if not (gcc and gxx):
        pytest.skip("gcc/g++ not available")
    root = tmp_path_factory.mktemp("fw")
    (root / "app").mkdir()
    (root / "lib" / "nested").mkdir(parents=True)
    flags = ["-g", "-O1", "-fstack-usage", "-ffunction-sections", "-fdata-sections"]
    objs = []
    for cc, src, out in ((gcc, "main.c", "app/main.o"), (gcc, "other.c", "lib/nested/other.o"),
                         (gxx, "cxx.cpp", "lib/cxx.o")):
        subprocess.run([cc, *flags, "-c", str(SRC / src), "-o", str(root / out)], check=True, cwd=root)
        objs.append(str(root / out))
    elf = root / "fw.elf"
    subprocess.run([gxx, "-g", *objs, "-o", str(elf)], check=True)
    stripped = root / "fw_stripped.elf"
    shutil.copy(elf, stripped)
    subprocess.run(["strip", str(stripped)], check=True)
    return type("Build", (), {"root": root, "elf": elf, "stripped": stripped, "objs": objs})


@pytest.fixture(scope="session")
def arm_elf(tmp_path_factory):
    from elfgen import make_arm_elf
    p = tmp_path_factory.mktemp("arm") / "arm.elf"
    make_arm_elf(p)
    return p
