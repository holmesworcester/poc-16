"""Cloudflare Queue composition around the shared notification worker."""
from dataclasses import dataclass
from time import time_ns

from adapters.cloudflare.fcm_service import FcmServiceBinding
from adapters.cloudflare.notification_state import NotificationStateService
from adapters.cloudflare.queue import delivery_from_message
from adapters.cloudflare.read_service import ReadServiceStore
from core.crypto import load_sk
from core.shape import valid_fid
from notifications.carrier import ACK, delivery_disposition
from notifications.forest import current_repository
from notifications.worker import NotificationWorker, handle_carrier_delivery

if __package__:
    from .settings import enabled, release, require_peer, text
else:
    from settings import enabled, release, require_peer, text


MAX_BATCH_SIZE = 10
RETRY_DELAY_SECONDS = 30


@dataclass(frozen=True, slots=True)
class Settings:
    enabled: bool
    workspace: str
    canonical_reader: object
    state: object
    fcm: object
    push_secret: object
    identity: str
    push_node: str

    @classmethod
    def from_env(cls, env):
        if text(env, "POC16_DEPLOYMENT_ROLE") != "notification-consumer":
            raise ValueError("notification consumer role binding")
        workspace = text(env, "WORKSPACE")
        identity = text(env, "POC16_DEPLOYMENT_IDENTITY")
        push_node = text(env, "PUSH_NODE")
        if not valid_fid(workspace) or not valid_fid(identity) \
                or not valid_fid(push_node):
            raise ValueError("notification consumer identity bindings")
        canonical = getattr(env, "CANONICAL_READER")
        state = getattr(env, "NOTIFICATION_STATE_SERVICE")
        try:
            secret = load_sk(text(env, "PUSH_NODE_SECRET"))
        except (TypeError, ValueError) as error:
            raise ValueError("PUSH_NODE_SECRET binding") from error
        if secret.verify_key.encode().hex() != push_node:
            raise ValueError("PUSH_NODE_SECRET does not match PUSH_NODE")
        fcm = getattr(env, "FCM_BOUNDARY")
        if len({id(canonical), id(state), id(fcm)}) != 3:
            raise ValueError("notification services must be segregated")
        if not callable(getattr(canonical, "get_bounded", None)) \
                or not callable(getattr(canonical, "read_versioned", None)) \
                or not callable(getattr(canonical, "list_page", None)) \
                or not callable(getattr(canonical, "release", None)):
            raise ValueError("CANONICAL_READER binding")
        if not all(callable(getattr(state, name, None))
                   for name in ("get_bounded", "pending", "complete",
                                "release", "wake")):
            raise ValueError("NOTIFICATION_STATE_SERVICE binding")
        if not callable(getattr(fcm, "send", None)) \
                or not callable(getattr(fcm, "release", None)):
            raise ValueError("FCM_BOUNDARY binding")
        return cls(
            enabled(env), workspace, canonical, state, fcm, secret,
            identity, push_node,
        )


def _retry(message):
    # Retry delay is also configured on the consumer.  Pass it explicitly so
    # provider fakes and deployments agree on each per-message disposition.
    message.retry(delaySeconds=RETRY_DELAY_SECONDS)


async def consume(env, batch):
    """ACK/RETRY every Queue message independently and fail closed."""
    settings = Settings.from_env(env)
    try:
        messages = tuple(batch.messages)
    except Exception as error:
        raise TypeError("Cloudflare Queue batch") from error
    if len(messages) > MAX_BATCH_SIZE:
        for message in messages:
            _retry(message)
        return
    if not settings.enabled:
        for message in messages:
            _retry(message)
        return

    local = release(env, "notification-consumer")
    try:
        await require_peer(
            settings.canonical_reader, "notification-canonical-reader", local)
        await require_peer(
            settings.state, "notification-scanner", local)
        await require_peer(
            settings.fcm, "notification-fcm-boundary", local)
    except Exception:
        for message in messages:
            _retry(message)
        return

    canonical = ReadServiceStore(settings.canonical_reader)
    state = NotificationStateService(settings.state, settings.identity)
    provider = FcmServiceBinding(settings.fcm, local)

    async def current(workspace):
        if workspace != settings.workspace:
            raise ValueError("notification workspace")
        return await current_repository(canonical, workspace)

    worker = NotificationWorker(
        current,
        settings.push_secret,
        provider,
        lambda: time_ns() // 1_000_000,
    )

    for message in messages:
        delivery = delivery_from_message(message)
        if delivery is None:
            # Provider-envelope poison cannot become valid on retry.
            message.ack()
            continue

        async def handle(item):
            return await handle_carrier_delivery(
                item, settings.workspace, state, worker, wake=state.wake)

        disposition = await delivery_disposition(delivery, handle)
        if disposition is ACK:
            message.ack()
        else:
            _retry(message)


__all__ = (
    "MAX_BATCH_SIZE",
    "RETRY_DELAY_SECONDS",
    "Settings",
    "consume",
)
