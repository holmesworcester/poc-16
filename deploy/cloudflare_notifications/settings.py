"""Small binding validators shared by the two notification roles."""

from core.object_store import validate_store_prefix


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


def prefix(env, name):
    value = text(env, name).strip("/")
    try:
        return validate_store_prefix(value)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError(f"{name} binding") from error


__all__ = ("enabled", "prefix", "text")
