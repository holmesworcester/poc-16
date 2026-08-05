"""Cross-community service authority and external-effect reconciliation.

The two ordinary :class:`AccessGate` decisions are the complete authority
input.  This module never applies facts or mutates repository state; a narrow
provider adapter may only realize or revoke the resulting external grant.
"""
from dataclasses import dataclass
import inspect
from itertools import islice

import facts

from core.close import decode_signed_pile
from core.crypto import h
from core.fact import canon
from core.limits import (
    MAX_ATOM_VALUE_BYTES,
    PayloadTooLarge,
    valid_bounded_text,
)
from core.shape import valid_fid


MAX_SERVICE_GRANTS = 256


@dataclass(frozen=True, slots=True)
class ServiceGrant:
    workspace: str
    operations: str
    device: str
    owner: str
    binding: str
    provider: str
    capability: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.operations, self.device, self.owner,
                self.binding)) \
                or self.provider not in facts.auth.service_binding.PROVIDERS \
                or not valid_bounded_text(
                    self.capability, MAX_ATOM_VALUE_BYTES):
            raise ValueError("service grant")

    @property
    def fingerprint(self):
        return h(canon([
            "poc16-service-grant-v1",
            self.workspace,
            self.operations,
            self.device,
            self.owner,
            self.binding,
            self.provider,
            self.capability,
        ]))


@dataclass(frozen=True, slots=True)
class InstalledCapability:
    binding: str
    fingerprint: str
    handle: str

    def __post_init__(self):
        if not valid_fid(self.binding) or not valid_fid(self.fingerprint) \
                or not valid_bounded_text(
                    self.handle, MAX_ATOM_VALUE_BYTES):
            raise ValueError("installed service capability")


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    current: tuple[InstalledCapability, ...]
    revoked: tuple[InstalledCapability, ...]
    ensured: tuple[InstalledCapability, ...]


def _one_request(pile, tag, trusted_now, purpose):
    looked = facts.lookup_request(pile, trusted_now, purpose=purpose)
    selected = tuple(fact for fact in pile.facts if fact.t == tag)
    if looked is None or len(selected) != 1:
        return None
    return looked[0], selected[0]


async def authorize_service(
        target_gate, operations_gate, target_proof, operations_proof,
        trusted_now):
    """Require the same live principal at both independently pinned gates."""
    if target_gate.workspace == operations_gate.workspace:
        raise ValueError("service communities must be distinct")
    try:
        target_pile = decode_signed_pile(
            target_proof, workspace=target_gate.workspace)
        operations_pile = decode_signed_pile(
            operations_proof, workspace=operations_gate.workspace)
        target = _one_request(
            target_pile, facts.auth.service_request.TAG,
            trusted_now, facts.auth.service_request.PURPOSE)
        operations = _one_request(
            operations_pile, facts.auth.request.TAG,
            trusted_now, "service")
        if target is None or operations is None:
            return None
        target_identity, request = target
        operations_identity, _operations_request = operations
        body = request.body
        if body["operations"] != operations_gate.workspace \
                or (target_identity.device, target_identity.owner) != (
                    operations_identity.device, operations_identity.owner):
            return None
    except (KeyError, TypeError, ValueError):
        return None

    target_decision = await target_gate.authorize_access(
        target_proof,
        trusted_now,
        purpose=facts.auth.service_request.PURPOSE,
    )
    if target_decision is None:
        return None
    operations_decision = await operations_gate.authorize_access(
        operations_proof, trusted_now, purpose="service")
    if operations_decision is None \
            or target_decision[0] != operations_decision[0]:
        return None
    return ServiceGrant(
        target_gate.workspace,
        operations_gate.workspace,
        target_identity.device,
        target_identity.owner,
        body["binding"],
        body["provider"],
        body["capability"],
    )


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


def _bounded(values, label):
    try:
        values = tuple(islice(iter(values), MAX_SERVICE_GRANTS + 1))
    except TypeError as error:
        raise TypeError(label) from error
    if len(values) > MAX_SERVICE_GRANTS:
        raise PayloadTooLarge(f"too many {label}")
    return values


class CapabilityReconciler:
    """Converge a provider's capabilities onto exact current DAG grants.

    The adapter owns only ``inventory``, ``revoke``, and ``ensure``. Stale or
    changed credentials are revoked before any replacement is created, so a
    failed turn cannot widen authority. Every completed turn is idempotent.
    """

    def __init__(self, adapter):
        for method in ("inventory", "revoke", "ensure"):
            if not callable(getattr(adapter, method, None)):
                raise TypeError("service capability adapter")
        self.adapter = adapter

    async def reconcile(self, desired):
        grants = _bounded(desired, "desired service grants")
        if not all(isinstance(grant, ServiceGrant) for grant in grants):
            raise TypeError("desired service grant")
        by_binding = {grant.binding: grant for grant in grants}
        if len(by_binding) != len(grants):
            raise ValueError("duplicate desired service binding")

        installed = _bounded(
            await _maybe_await(self.adapter.inventory()),
            "installed service capabilities",
        )
        if not all(isinstance(row, InstalledCapability) for row in installed):
            raise TypeError("installed service capability")
        current = {row.binding: row for row in installed}
        if len(current) != len(installed):
            raise ValueError("duplicate installed service binding")

        revoked = []
        for binding, row in sorted(current.items()):
            grant = by_binding.get(binding)
            if grant is not None and row.fingerprint == grant.fingerprint:
                continue
            await _maybe_await(self.adapter.revoke(row))
            revoked.append(row)
            current.pop(binding)

        ensured = []
        for binding, grant in sorted(by_binding.items()):
            if binding in current:
                continue
            row = await _maybe_await(self.adapter.ensure(grant))
            if not isinstance(row, InstalledCapability) \
                    or (row.binding, row.fingerprint) != (
                        binding, grant.fingerprint):
                raise ValueError("provider ensured the wrong capability")
            current[binding] = row
            ensured.append(row)

        ordered = tuple(current[key] for key in sorted(current))
        return ReconcileResult(ordered, tuple(revoked), tuple(ensured))


__all__ = (
    "CapabilityReconciler",
    "InstalledCapability",
    "MAX_SERVICE_GRANTS",
    "ReconcileResult",
    "ServiceGrant",
    "authorize_service",
)
