"""Small family-owned value exposed to notification delivery workers."""
from dataclasses import dataclass

from core.limits import MAX_ATOM_VALUE_BYTES, valid_bounded_text
from core.shape import valid_fid


@dataclass(frozen=True, slots=True)
class NotificationTrigger:
    kind: str
    channel: str
    mentions: tuple[str, ...] = ()

    def __post_init__(self):
        if not valid_bounded_text(self.kind, MAX_ATOM_VALUE_BYTES) \
                or not valid_bounded_text(
                    self.channel, MAX_ATOM_VALUE_BYTES) \
                or not isinstance(self.mentions, tuple) \
                or len(self.mentions) > 32 \
                or tuple(sorted(set(self.mentions))) != self.mentions \
                or not all(valid_fid(value) for value in self.mentions):
            raise ValueError("notification trigger")


__all__ = ("NotificationTrigger",)
