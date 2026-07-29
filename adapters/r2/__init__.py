"""Cloudflare R2 adapters."""

from .worker import R2BindingStore

__all__ = ("R2BindingStore", "R2S3Config", "R2S3Store")


def __getattr__(name):
    """Keep the host-only S3 compatibility graph out of Python Workers."""
    if name in {"R2S3Config", "R2S3Store"}:
        from .s3 import R2S3Config, R2S3Store
        globals().update({
            "R2S3Config": R2S3Config,
            "R2S3Store": R2S3Store,
        })
        return globals()[name]
    raise AttributeError(name)
