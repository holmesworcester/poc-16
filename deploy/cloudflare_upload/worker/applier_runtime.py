"""Cloudflare bindings for one exact shared RepositoryApplier call."""
from dataclasses import dataclass

from adapters.r2.worker import R2BindingStore
from core.repository_applier import RepositoryApplier
from core.shape import valid_fid
from core.staged_intent import parse_staging_key


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
        canonical_prefix = _text(env, "CANONICAL_PREFIX").strip("/")
        if not canonical_prefix:
            raise ValueError("CANONICAL_PREFIX binding")
        canonical = getattr(env, "CANONICAL")
        ingress = getattr(env, "INGRESS")
        if canonical is ingress:
            raise ValueError("canonical and ingress bindings must differ")
        return cls(workspace, canonical, ingress, canonical_prefix)


async def apply(env, key, digest):
    """Apply exactly one private-RPC-named immutable ingress pile."""
    settings = Settings.from_env(env)
    address = parse_staging_key(key)
    if address.workspace != settings.workspace \
            or address.object_class != "pile" \
            or address.digest != digest:
        raise ValueError("repository applier source binding")
    canonical = R2BindingStore(
        settings.canonical, settings.canonical_prefix)
    ingress = R2BindingStore(settings.ingress)
    return await RepositoryApplier(
        settings.workspace, canonical,
    ).apply_exact(ingress, key, digest)


__all__ = ("Settings", "apply")
