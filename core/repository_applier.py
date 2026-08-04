"""Database-free closed-pile projection into one authenticated CAS root.

Ordinary content lives in per-writer trees.  This smaller engine remains for
the shared authority/removal projection: it receives exact bytes already in
hand, validates one complete closed pile, joins its durable authority facts,
and advances ``authority``.  It has no ingress namespace, queue, discovery,
deletion, or workspace-global content root.
"""
from dataclasses import dataclass

import facts

from .close import ClosedPileEvaluator, check_pile_bounds
from .crypto import h
from .fact import encode
from .limits import (
    InvalidEncoding,
    MAX_BUFFERED_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from .object_store import (
    ABSENT,
    AUTHORITY_ROOT_KEY,
    STALE,
    Applied,
    OutcomeUnknown,
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
    """One database-free authority projection over its fixed CAS register."""

    def __init__(
            self, workspace, store, *, root_key,
            evaluate=None, accept_fact=None):
        if not valid_fid(workspace):
            raise ValueError("repository workspace")
        if root_key != AUTHORITY_ROOT_KEY:
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

    async def apply_pile(self, raw):
        """Apply one exact in-hand pile without manufacturing ingress state."""
        if not isinstance(raw, bytes) or len(raw) > MAX_BUFFERED_PILE_BYTES:
            return ApplyResult("rejected", None)
        try:
            check_pile_bounds(raw)
            facts_by_fid, admitted = self._validated_facts(raw)
        except (InvalidEncoding, PayloadTooLarge, ValueError):
            return ApplyResult("rejected", None)
        return await self._apply_validated(facts_by_fid, admitted)

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
            raise ValueError(
                str(judgment.failure) if judgment.failure is not None
                else "closed pile rejected")

        facts_by_fid, durable = {}, []
        for receipt in judgment.valids:
            family = facts.family_for(receipt.fact.t)
            if self._accept_fact is not None \
                    and not self._accept_fact(receipt.fact):
                raise ValueError("fact is outside repository policy")
            if family is None or not family.DURABLE:
                continue
            fid = receipt.fact.fid
            durable.append(fid)
            old = facts_by_fid.setdefault(fid, receipt.fact)
            if encode(old) != encode(receipt.fact):
                raise ValueError("repository fact conflict")
        return facts_by_fid, tuple(sorted(set(durable)))

    async def _apply_validated(self, facts_by_fid, admitted):
        """Join one already-judged durable set through the authority CAS."""
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

        # A directory slot records the content hash of the exact authority
        # view used to authorize it.  Preserve root bytes under that address
        # before advertising them through the mutable register, just as the
        # compiler preserves every page the root names.  Provider version
        # tokens remain separate opaque CAS capabilities.
        await ensure_object_async(
            self.store, h(compiled.root), compiled.root)

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
            raise TypeError("authority CAS result")
        return ApplyResult("applied", compiled.root, admitted)


__all__ = (
    "ApplyResult",
    "RepositoryApplier",
)
