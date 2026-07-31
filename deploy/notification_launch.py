"""Small deploy-only gate for real mobile notification launch evidence."""
import hashlib
import json
from pathlib import Path


LAUNCH_RECORD_SCHEMA = "poc16-mobile-notification-launch-v1"
MAX_LAUNCH_RECORD_BYTES = 4_096
PLATFORMS = ("ios", "android")


def _canon(value):
    return json.dumps(
        value, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def launch_record(platform, binding):
    """Encode evidence only after the named real-device launch has passed."""
    if platform not in PLATFORMS or not isinstance(binding, dict) \
            or not binding:
        raise ValueError("mobile launch binding")
    raw = _canon({
        "binding": binding,
        "platform": platform,
        "result": "passed",
        "schema": LAUNCH_RECORD_SCHEMA,
    })
    if len(raw) > MAX_LAUNCH_RECORD_BYTES:
        raise ValueError("mobile launch binding")
    return raw


def _require(path, platform, binding):
    if path is None:
        raise RuntimeError(
            f"{platform} real-device launch record is required")
    try:
        raw = Path(path).read_bytes()
    except (OSError, TypeError):
        raise RuntimeError(
            f"cannot read {platform} real-device launch record") from None
    if not 0 < len(raw) <= MAX_LAUNCH_RECORD_BYTES:
        raise RuntimeError(
            f"invalid {platform} real-device launch record")
    try:
        value = json.loads(raw)
        canonical = _canon(value)
        expected = launch_record(platform, binding)
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError(
            f"invalid {platform} real-device launch record") from None
    if raw != canonical or raw != expected:
        raise RuntimeError(
            f"invalid {platform} real-device launch record")


def require_mobile_launches(paths, expected_binding):
    """Require exact canonical iOS and Android evidence for one deployment."""
    if not isinstance(paths, dict) or set(paths) != set(PLATFORMS):
        raise ValueError("mobile launch record paths")
    for platform in PLATFORMS:
        _require(paths[platform], platform, expected_binding)


def tree_digest(root):
    """Hash exact staged deploy inputs with path and byte boundaries."""
    root = Path(root)
    paths = sorted(path for path in root.rglob("*") if path.is_file())
    if not paths:
        raise ValueError("empty deploy input tree")
    digest = hashlib.sha256()
    for path in paths:
        name = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


__all__ = (
    "LAUNCH_RECORD_SCHEMA",
    "MAX_LAUNCH_RECORD_BYTES",
    "launch_record",
    "require_mobile_launches",
    "tree_digest",
)
