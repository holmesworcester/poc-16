"""Cloudflare binding adapter for the shared RepositoryApplier.

The runtime owns only binding/configuration translation and scheduling.  Both
R2 buckets are exposed through the provider-neutral object-store contract;
all validation, immutable promotion, root CAS, reconciliation,
and F10 retirement remain in ``core.repository_applier``.
"""
from dataclasses import dataclass

from adapters.r2.worker import R2BindingStore
from core.repository_applier import RepositoryApplier
from core.shape import valid_fid


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


async def drain(env):
    """Drain retained internal work, then one isolated-ingress snapshot."""
    settings = Settings.from_env(env)
    canonical = R2BindingStore(
        settings.canonical, settings.canonical_prefix)
    ingress = R2BindingStore(settings.ingress)
    applier = RepositoryApplier(settings.workspace, canonical)
    internal = await applier.turn()
    staged = await applier.drain_staged(ingress)
    return internal, staged


__all__ = ("Settings", "drain")
