"""Narrow client for the private notification-state Worker service."""

from adapters.cloudflare.read_service import ReadServiceStore
from core.shape import valid_fid
from notifications.discovery import (
    PENDING_CURRENT,
    PENDING_NONCURRENT,
    PENDING_RETRY,
)


class NotificationStateService:
    """Read historical roots and complete only the exact pending body."""

    __slots__ = ("owner", "reader", "service")

    def __init__(self, service, owner):
        if not valid_fid(owner) \
                or not all(callable(getattr(service, name, None))
                           for name in (
                               "get_bounded", "pending", "complete", "wake")):
            raise TypeError("Cloudflare notification-state service")
        self.owner = owner
        self.reader = ReadServiceStore(service, versioned=False)
        self.service = service

    async def get_bounded(self, key, maximum):
        return await self.reader.get_bounded(key, maximum)

    async def pending(self, body_oid):
        status = await self.service.pending(body_oid)
        if status not in {PENDING_CURRENT, PENDING_NONCURRENT}:
            raise ValueError("notification pending response")
        return status

    async def complete(self, body_oid):
        status = await self.service.complete(body_oid)
        if status not in {PENDING_NONCURRENT, PENDING_RETRY}:
            raise ValueError("notification completion response")
        return status

    async def wake(self):
        await self.service.wake()


__all__ = ("NotificationStateService",)
