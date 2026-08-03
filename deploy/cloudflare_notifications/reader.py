"""Private canonical R2 read gateway for notification Workers."""
from dataclasses import dataclass

from adapters.r2.reader import R2ReadBindingStore
from core.limits import MAX_ROOT_BYTES
from core.object_store import ABSENT, Versioned, validate_store_prefix
from core.shape import valid_fid

if __package__:
    from .settings import release
else:
    from settings import release


def _text(env, name):
    value = getattr(env, name)
    if not isinstance(value, str):
        value = str(value)
    if not value:
        raise ValueError(f"missing {name} binding")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    workspace: str
    bucket: object
    prefix: str
    identity: str

    @classmethod
    def from_env(cls, env):
        if _text(env, "POC16_DEPLOYMENT_ROLE") \
                != "notification-canonical-reader":
            raise ValueError("notification reader role binding")
        workspace = _text(env, "WORKSPACE")
        identity = _text(env, "POC16_DEPLOYMENT_IDENTITY")
        if not valid_fid(workspace) or not valid_fid(identity):
            raise ValueError("notification reader identity bindings")
        prefix = _text(env, "CANONICAL_PREFIX").strip("/")
        try:
            validate_store_prefix(prefix)
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("CANONICAL_PREFIX binding") from error
        return cls(workspace, getattr(env, "CANONICAL"), prefix, identity)


def store(env):
    settings = Settings.from_env(env)
    return R2ReadBindingStore(settings.bucket, settings.prefix)


async def get_bounded(env, key, maximum):
    return await store(env).get_bounded(key, maximum)


async def read_versioned(env, key, maximum=MAX_ROOT_BYTES):
    value = await store(env).read_versioned(key, maximum)
    if value is ABSENT:
        return {"status": "absent"}
    if not isinstance(value, Versioned):
        raise TypeError("canonical reader response")
    return {
        "status": "versioned",
        "token": value.token.value,
        "value": value.value,
    }


async def list_page(env, prefix, cursor=None, limit=256):
    page = await store(env).list_page(prefix, cursor, limit)
    return {"cursor": page.cursor, "keys": list(page.keys)}


def release_state(env):
    return release(env, "notification-canonical-reader")


__all__ = (
    "Settings", "get_bounded", "list_page", "read_versioned",
    "release_state",
)
