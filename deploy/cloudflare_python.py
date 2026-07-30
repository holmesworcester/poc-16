"""Shared build-only helpers for segregated Cloudflare Python Workers."""
from pathlib import Path
import shutil


MINT_CORE_MODULES = (
    "__init__.py",
    "bao.py",
    "btreap.py",
    "catalog.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "grants.py",
    "indexes.py",
    "ingress.py",
    "kernel.py",
    "limits.py",
    "manifest.py",
    "mint.py",
    "object_store.py",
    "peer_capability.py",
    "shape.py",
    "suppression.py",
    "suppression_state.py",
    "worker.py",
)


def patch_pynacl(vendored):
    """Disable eager EM_ASM registration in a vendored Workers PyNaCl."""
    vendored = Path(vendored)
    matches = tuple((vendored / "nacl").glob("_sodium*.so"))
    if len(matches) != 1:
        raise RuntimeError("expected one vendored PyNaCl _sodium module")
    module = matches[0]
    raw = module.read_bytes()
    if not raw.startswith(b"\x00asm"):
        raise RuntimeError("vendored PyNaCl _sodium is not WebAssembly")
    pairs = (
        (b"__start_em_asm", b"__start_em_xsm"),
        (b"__stop_em_asm", b"__stop_em_xsm"),
    )
    for original, disabled in pairs:
        if raw.count(original) == 1 and disabled not in raw:
            raw = raw.replace(original, disabled)
        elif raw.count(disabled) != 1 or original in raw:
            raise RuntimeError("unexpected PyNaCl EM_ASM export layout")
    temporary = module.with_suffix(".patched")
    temporary.write_bytes(raw)
    temporary.replace(module)

    bindings = vendored / "nacl" / "bindings" / "__init__.py"
    source = bindings.read_text()
    initializer = "# Initialize Sodium\nsodium_init()\n"
    disabled = (
        "# Workerd compatibility: deterministic primitives need no RNG init.\n"
    )
    if initializer in source and disabled not in source:
        source = source.replace(initializer, disabled)
        bindings.write_text(source)
    elif source.count(disabled) != 1 or initializer in source:
        raise RuntimeError("unexpected PyNaCl sodium initializer layout")


def copy_python_modules(vendored, destination):
    """Copy the locked Worker dependencies inside one staged base directory."""
    vendored = Path(vendored)
    destination = Path(destination)
    if not (vendored / "nacl").is_dir():
        raise RuntimeError("vendored Python Worker dependencies are absent")
    shutil.copytree(
        vendored,
        destination,
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".synced", "pyvenv.cfg"),
    )
