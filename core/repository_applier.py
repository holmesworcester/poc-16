"""The sole exact-pile to repository-root state transition.

``RepositoryApplier`` is database-free and provider-neutral.  Its caller
names one create-only source object.  The applier exact-reads and validates
that complete closed pile, establishes immutable fact and Merkle objects,
advances the one mutable root by CAS, and returns. It never discovers or
deletes work. Inline Bao slices are ordinary facts, so there is no secondary
object-completion path. Retrying the same immutable source is idempotent
because the authenticated repository is a monotone set.
"""
from dataclasses import dataclass

import facts

from .close import ClosedPileEvaluator, check_pile_bounds
from .crypto import h
from .fact import encode
from .ingress import (
    InvalidPile,
    KernelRejected,
    PermanentIngressRejection,
    ingress_key,
    parse_ingress_key,
)
from .limits import (
    InvalidEncoding,
    MAX_BUFFERED_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from .object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    STALE,
    Applied,
    OutcomeUnknown,
    REPOSITORY_ROOT_KEYS,
    Versioned,
    async_store,
    ensure_object_async,
)
from .repository_snapshot import extend_snapshot_awaited
from .shape import valid_fid


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """One typed exact-source outcome."""

    status: str
    root: bytes | None
    admitted: tuple = ()


class RepositoryApplier:
    """One database-free receiving engine over an object-store CAS register."""

    def __init__(
            self, workspace, store, *, root_key="root",
            evaluate=None, accept_fact=None):
        if not valid_fid(workspace):
            raise ValueError("repository workspace")
        if root_key not in REPOSITORY_ROOT_KEYS:
            raise ValueError("repository root key")
        if evaluate is not None and not callable(evaluate):
            raise TypeError("repository evaluator")
        if accept_fact is not None and not callable(accept_fact):
            raise TypeError("repository fact policy")
        self.workspace = workspace
        self.store = async_store(store)
        self.root_key = root_key
        self._evaluate = evaluate or (
            lambda raw: ClosedPileEvaluator(workspace).evaluate(raw).judgment)
        self._accept_fact = accept_fact

    @staticmethod
    async def _get_bounded(store, key, maximum):
        value = await store.get_bounded(key, maximum)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > maximum):
            raise PayloadTooLarge("repository read exceeds byte limit")
        return value

    async def _put_exact(self, store, key, raw):
        """Create one immutable source and reconcile an unknown response."""
        unknown = None
        for _ in range(2):
            try:
                result = await store.put_if_absent(key, raw)
            except OutcomeUnknown as error:
                unknown = error
            else:
                if result not in {CREATED, EXISTS}:
                    raise TypeError("immutable create result")
            incumbent = await self._get_bounded(
                store, key, max(1, len(raw)))
            if incumbent == raw:
                return
            if incumbent is not None:
                raise ValueError("immutable value conflict")
        raise unknown or OSError("immutable value was not preserved")

    async def _stage(self, member, raw):
        """Store raw receiving bytes before they can influence publication."""
        if not isinstance(raw, bytes):
            raise TypeError("exact ingress bytes required")
        if len(raw) > MAX_BUFFERED_PILE_BYTES:
            raise InvalidPile("pile too large")
        if not valid_fid(member):
            raise ValueError("ingress member")
        try:
            check_pile_bounds(raw)
        except (InvalidEncoding, PayloadTooLarge) as error:
            raise InvalidPile(str(error) or "pile encoding") from error
        payload = h(raw)
        source = ingress_key(
            self.workspace, payload[:32], member, payload)
        await self._put_exact(self.store, source, raw)
        return source

    async def receive_pile(self, member, raw):
        """Persist one HTTP/P2P body, then apply only its exact stored bytes."""
        source = await self._stage(member, raw)
        return await self.apply_exact(self.store, source, h(raw))

    async def _extend_snapshot(self, root_bytes, facts_by_fid):
        """Compile through one awaited page path and immediate immutables."""
        async def fetch(oid):
            return await self._get_bounded(
                self.store,
                "obj/" + oid,
                MAX_REPOSITORY_OBJECT_BYTES,
            )

        async def establish(raw):
            oid = h(raw)
            await ensure_object_async(self.store, oid, raw)
            return oid

        return await extend_snapshot_awaited(
            self.workspace,
            root_bytes,
            facts_by_fid,
            fetch,
            establish,
        )

    def _validated_facts(self, raw):
        """Return the durable subset of one database-free closed-pile turn."""
        judgment = self._evaluate(raw)
        if not judgment.ok:
            if judgment.failure is not None:
                raise judgment.failure
            raise KernelRejected("ingress rejected")

        facts_by_fid, durable = {}, []
        for receipt in judgment.valids:
            family = facts.family_for(receipt.fact.t)
            if self._accept_fact is not None \
                    and not self._accept_fact(receipt.fact):
                raise KernelRejected("fact is outside repository policy")
            if family is None or not family.DURABLE:
                continue
            fid = receipt.fact.fid
            durable.append(fid)
            old = facts_by_fid.setdefault(fid, receipt.fact)
            if encode(old) != encode(receipt.fact):
                raise ValueError("repository fact conflict")
        return facts_by_fid, tuple(sorted(set(durable)))

    async def apply_exact(self, source_store, source, payload):
        """Apply one caller-named create-only object with its key digest."""
        source_store = async_store(source_store)
        try:
            address = parse_ingress_key(source)
        except ValueError as error:
            raise ValueError("exact ingress address") from error
        if not valid_fid(payload) or address.workspace != self.workspace \
                or address.digest != payload:
            raise ValueError("exact ingress address")
        try:
            raw = await self._get_bounded(
                source_store, source, MAX_BUFFERED_PILE_BYTES)
        except PayloadTooLarge:
            return ApplyResult("rejected", None)
        if raw is None:
            return ApplyResult("retryable", None)
        if h(raw) != payload:
            return ApplyResult("rejected", None)

        try:
            facts_by_fid, admitted = self._validated_facts(raw)
        except PermanentIngressRejection:
            return ApplyResult("rejected", None)

        versioned = await self.store.read_versioned(self.root_key)
        if versioned is ABSENT:
            base_root, base_token = None, ABSENT
        elif isinstance(versioned, Versioned):
            base_root, base_token = versioned.value, versioned.token
        else:
            raise TypeError("versioned root read")
        if base_root is None and facts_by_fid \
                and self.workspace not in facts_by_fid:
            return ApplyResult("retryable", None)

        compiled = await self._extend_snapshot(base_root, facts_by_fid)
        if compiled.root is not None \
                and not set(admitted) <= set(compiled.fact_oids):
            raise ValueError("repository application omitted admission")
        if compiled.root is None:
            return ApplyResult("noop", None, admitted)
        if compiled.root == base_root:
            current = await self.store.read_versioned(self.root_key)
            if not isinstance(current, Versioned) \
                    or current.token != base_token \
                    or current.value != base_root:
                return ApplyResult("retryable", base_root, admitted)
            return ApplyResult("noop", compiled.root, admitted)

        try:
            result = await self.store.cas(
                self.root_key, base_token, compiled.root)
        except OutcomeUnknown:
            current = await self.store.read_versioned(self.root_key)
            if isinstance(current, Versioned) \
                    and current.value == compiled.root:
                return ApplyResult("applied", compiled.root, admitted)
            return ApplyResult("retryable", base_root, admitted)
        if result is STALE:
            return ApplyResult("retryable", base_root, admitted)
        if not isinstance(result, Applied):
            raise TypeError("root CAS result")
        return ApplyResult("applied", compiled.root, admitted)


__all__ = (
    "ApplyResult",
    "RepositoryApplier",
)
