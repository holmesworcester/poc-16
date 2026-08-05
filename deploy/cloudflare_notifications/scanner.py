"""Scheduled Cloudflare binding composition for shared discovery."""
from dataclasses import dataclass

from adapters.cloudflare.queue import CloudflareQueueCarrier
from adapters.cloudflare.read_service import ReadServiceStore
from adapters.r2.worker import R2BindingStore
from core.shape import valid_fid
from notifications.discovery import (
    BOOTSTRAP_BACKFILL,
    BOOTSTRAP_CURRENT,
    REBOOTSTRAP_CURRENT,
    NotificationDiscovery,
    NotificationState,
)

if __package__:
    from .settings import enabled, prefix, release, require_peer, text
else:
    from settings import enabled, prefix, release, require_peer, text


@dataclass(frozen=True, slots=True)
class Settings:
    enabled: bool
    workspace: str
    canonical_reader: object
    state: object
    queue: object
    state_prefix: str
    identity: str
    bootstrap: str

    @classmethod
    def from_env(cls, env):
        if text(env, "POC16_DEPLOYMENT_ROLE") != "notification-scanner":
            raise ValueError("notification scanner role binding")
        workspace = text(env, "WORKSPACE")
        identity = text(env, "POC16_DEPLOYMENT_IDENTITY")
        bootstrap = text(env, "NOTIFICATION_BOOTSTRAP_MODE")
        if not valid_fid(workspace) or not valid_fid(identity):
            raise ValueError("notification scanner identity bindings")
        if bootstrap not in {
                "none", BOOTSTRAP_CURRENT, BOOTSTRAP_BACKFILL,
                REBOOTSTRAP_CURRENT}:
            raise ValueError("NOTIFICATION_BOOTSTRAP_MODE binding")
        canonical = getattr(env, "CANONICAL_READER")
        state = getattr(env, "NOTIFICATION_STATE")
        if canonical is state:
            raise ValueError("canonical reader and notification state differ")
        if not callable(getattr(canonical, "get_bounded", None)) \
                or not callable(getattr(canonical, "read_versioned", None)) \
                or not callable(getattr(canonical, "list_page", None)) \
                or not callable(getattr(canonical, "release", None)):
            raise ValueError("CANONICAL_READER binding")
        queue = getattr(env, "NOTIFICATION_QUEUE")
        if not callable(getattr(queue, "send", None)):
            raise ValueError("NOTIFICATION_QUEUE binding")
        return cls(
            enabled(env), workspace, canonical, state, queue,
            prefix(env, "NOTIFICATION_STATE_PREFIX"),
            identity,
            bootstrap,
        )


def _state(settings):
    return NotificationState(
        R2BindingStore(settings.state, settings.state_prefix),
        settings.workspace,
        settings.identity,
    )


async def scan(env):
    """Run exactly one bounded shared cursor turn."""
    settings = Settings.from_env(env)
    local = release(env, "notification-scanner")
    await require_peer(
        settings.canonical_reader, "notification-canonical-reader", local)
    discovery = NotificationDiscovery(
        ReadServiceStore(settings.canonical_reader),
        R2BindingStore(settings.state, settings.state_prefix),
        settings.workspace,
        CloudflareQueueCarrier(settings.queue),
        owner=settings.identity,
    )
    if settings.bootstrap == BOOTSTRAP_CURRENT:
        await discovery.bootstrap_current()
        return "bootstrapped-current"
    if settings.bootstrap == BOOTSTRAP_BACKFILL:
        await discovery.bootstrap_backfill()
        return "bootstrapped-backfill"
    if settings.bootstrap == REBOOTSTRAP_CURRENT:
        await discovery.rebootstrap_current()
        return "rebootstrapped-current"
    if not settings.enabled:
        return "disabled"
    return (await discovery.run_once()).status


async def get_state_bounded(env, key, maximum):
    """Private read-only RPC used by the Queue consumer."""
    settings = Settings.from_env(env)
    return await _state(settings).get_bounded(key, maximum)


async def pending(env, body_oid):
    """Classify only an exact content OID against the private cursor."""
    return await _state(Settings.from_env(env)).pending(body_oid)


async def complete(env, body_oid):
    """Advance only the exact current pending content OID."""
    return await _state(Settings.from_env(env)).complete(body_oid)


def release_state(env):
    return release(env, "notification-scanner")


__all__ = (
    "Settings", "complete", "get_state_bounded", "pending", "release_state",
    "scan",
)
