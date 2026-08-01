"""Small binding validators shared by notification Worker roles."""

from core.object_store import validate_store_prefix
from core.shape import valid_fid


RELEASE_FORMAT = "poc16-cloudflare-notification-runtime-v1"


def text(env, name):
    value = getattr(env, name)
    if not isinstance(value, str):
        value = str(value)
    if not value:
        raise ValueError(f"missing {name} binding")
    return value


def enabled(env):
    value = text(env, "NOTIFICATIONS_ENABLED")
    if value not in {"0", "1"}:
        raise ValueError("NOTIFICATIONS_ENABLED binding")
    return value == "1"


def release(env, role):
    """Return the exact cross-role release marker used to reject skew."""
    if text(env, "POC16_DEPLOYMENT_ROLE") != role:
        raise ValueError("notification role binding")
    identity = text(env, "POC16_DEPLOYMENT_IDENTITY")
    software = text(env, "POC16_SOFTWARE_DIGEST")
    release_id = text(env, "POC16_RELEASE_ID")
    if not all(valid_fid(value)
               for value in (identity, software, release_id)):
        raise ValueError("notification release bindings")
    return {
        "enabled": enabled(env),
        "format": RELEASE_FORMAT,
        "identity": identity,
        "release_id": release_id,
        "role": role,
        "software_digest": software,
    }


async def require_peer(service, role, local):
    """Fail closed unless a bound peer serves the same immutable release."""
    method = getattr(service, "release", None)
    if not callable(method):
        raise ValueError("notification peer release method")
    observed = await method()
    expected = {**local, "role": role}
    if observed != expected:
        raise ValueError("notification release skew")


def prefix(env, name):
    value = text(env, name).strip("/")
    try:
        return validate_store_prefix(value)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError(f"{name} binding") from error


__all__ = (
    "RELEASE_FORMAT", "enabled", "prefix", "release", "require_peer",
    "text",
)
