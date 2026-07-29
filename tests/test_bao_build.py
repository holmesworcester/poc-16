"""The optional native attachment seam stays feature-scoped."""
import subprocess
import sys
from pathlib import Path

from core import bao

ROOT = Path(__file__).resolve().parent.parent
BUILD = "python3 -m pip install ./native/bao_py"


def test_facts_import_without_the_native_extension():
    script = f"""
import importlib.abc
import sys

class BlockBao(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "tinyp2p_bao":
            raise ModuleNotFoundError(
                "blocked native extension", name=fullname)

sys.meta_path.insert(0, BlockBao())
import facts
from core import bao
assert bao.geometry(0) == 0
assert bao.span(1, bao.WIDTH + 7) == (bao.WIDTH, 7)
try:
    bao.prepare("unused", "unused")
except RuntimeError as error:
    assert {BUILD!r} in str(error)
else:
    raise AssertionError("Bao loaded despite the import blocker")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_vendored_build_command_is_exact_and_documented():
    assert BUILD == bao.BUILD_COMMAND
    assert (ROOT / "native/bao_py/pyproject.toml").is_file()
    assert BUILD in (ROOT / "README.md").read_text()
