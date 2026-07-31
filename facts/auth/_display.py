"""Shared byte bound for human-readable authority labels."""

from core.limits import valid_bounded_text

MAX_DISPLAY_BYTES = 255


def display(value):
    if not valid_bounded_text(value, MAX_DISPLAY_BYTES):
        raise ValueError("authority display text")
    return value
