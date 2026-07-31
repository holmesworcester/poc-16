"""Scheduled Cloudflare binding composition for shared discovery."""
from dataclasses import dataclass

from adapters.cloudflare.queue import CloudflareQueueCarrier
from adapters.cloudflare.read_service import ReadServiceStore
from adapters.r2.reader import R2ReadBindingStore
from adapters.r2.worker import R2BindingStore
from core.shape import valid_fid
from notifications.discovery import NotificationDiscovery

if __package__:
    from .settings import enabled, prefix, text
else:
    from settings import enabled, prefix, text


@dataclass(frozen=True, slots=True)
class Settings:
    enabled: bool
    workspace: str
    canonical_reader: object
    state: object
    queue: object
    state_prefix: str
    identity: str

    @classmethod
    def from_env(cls, env):
        if text(env, "POC16_DEPLOYMENT_ROLE") != "notification-scanner":
            raise ValueError("notification scanner role binding")
        workspace = text(env, "WORKSPACE")
        identity = text(env, "POC16_DEPLOYMENT_IDENTITY")
        if not valid_fid(workspace) or not valid_fid(identity):
            raise ValueError("notification scanner identity bindings")
        canonical = getattr(env, "CANONICAL_READER")
        state = getattr(env, "NOTIFICATION_STATE")
        if canonical is state:
            raise ValueError("canonical reader and notification state differ")
        if not callable(getattr(canonical, "get_bounded", None)) \
                or not callable(getattr(canonical, "read_versioned", None)):
            raise ValueError("CANONICAL_READER binding")
        queue = getattr(env, "NOTIFICATION_QUEUE")
        if not callable(getattr(queue, "send", None)):
            raise ValueError("NOTIFICATION_QUEUE binding")
        return cls(
            enabled(env), workspace, canonical, state, queue,
            prefix(env, "NOTIFICATION_STATE_PREFIX"),
            identity,
        )


async def scan(env):
    """Run exactly one bounded shared cursor turn."""
    settings = Settings.from_env(env)
    if not settings.enabled:
        return "disabled"
    discovery = NotificationDiscovery(
        ReadServiceStore(settings.canonical_reader),
        R2BindingStore(settings.state, settings.state_prefix),
        settings.workspace,
        CloudflareQueueCarrier(settings.queue),
        owner=settings.identity,
    )
    return (await discovery.run_once()).status


async def get_state_bounded(env, key, maximum):
    """Private read-only RPC used by the Queue consumer."""
    settings = Settings.from_env(env)
    return await R2ReadBindingStore(
        settings.state, settings.state_prefix,
    ).get_bounded(key, maximum)


__all__ = ("Settings", "get_state_bounded", "scan")
