"""Cloudflare binding adapter for the shared RepositoryApplier.

The runtime owns only binding/configuration translation and scheduling.  Both
R2 buckets are exposed through the provider-neutral object-store contract;
all validation, immutable promotion, root CAS, reconciliation,
and F10 retirement remain in ``core.repository_applier``.
"""
import asyncio
from dataclasses import dataclass

from adapters.r2.worker import R2BindingStore
from core.repository_applier import RepositoryApplier
from core.shape import valid_fid


_inflight = None
_next_kind = "internal"


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
    canonical: object
    ingress: object
    canonical_prefix: str

    @classmethod
    def from_env(cls, env):
        if _text(env, "POC16_DEPLOYMENT_ROLE") != "applier":
            raise ValueError("repository applier role binding")
        workspace = _text(env, "WORKSPACE")
        if not valid_fid(workspace):
            raise ValueError("WORKSPACE binding")
        expected = f"ingress/v1/workspaces/{workspace}"
        if _text(env, "INGRESS_PREFIX").strip("/") != expected:
            raise ValueError("INGRESS_PREFIX binding")
        canonical_prefix = _text(
            env, "CANONICAL_PREFIX").strip("/")
        if not canonical_prefix:
            raise ValueError("CANONICAL_PREFIX binding")
        canonical, ingress = getattr(env, "CANONICAL"), getattr(
            env, "INGRESS")
        if canonical is ingress:
            raise ValueError("canonical and ingress bindings must differ")
        return cls(
            workspace,
            canonical,
            ingress,
            canonical_prefix,
        )


async def _drain_once(env):
    """Consume at most one fair backlog unit in one bounded hosted turn."""
    global _next_kind
    settings = Settings.from_env(env)
    canonical = R2BindingStore(
        settings.canonical, settings.canonical_prefix)
    ingress = R2BindingStore(settings.ingress)
    applier = RepositoryApplier(settings.workspace, canonical)
    internal = staged = ()
    if _next_kind == "internal":
        internal = await applier.turn(limit=1)
        if internal:
            _next_kind = "staged"
        else:
            staged = await applier.drain_staged(ingress, limit=1)
            _next_kind = "internal"
    else:
        staged = await applier.drain_staged(ingress, limit=1)
        if staged:
            _next_kind = "internal"
        else:
            internal = await applier.turn(limit=1)
            _next_kind = "staged"
    return internal, staged


def _clear_flight(task):
    global _inflight
    if _inflight is task:
        _inflight = None
    # A cancelled sole waiter must not leave an unobserved task exception.
    try:
        task.exception()
    except asyncio.CancelledError:
        pass


async def drain(env):
    """Join the one live isolate drain without granting it cancellation."""
    global _inflight
    if _inflight is None:
        _inflight = asyncio.create_task(_drain_once(env))
        _inflight.add_done_callback(_clear_flight)
    return await asyncio.shield(_inflight)


__all__ = ("Settings", "drain")
