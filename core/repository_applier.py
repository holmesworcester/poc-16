"""The sole exact-pile to repository-root state transition.

``RepositoryApplier`` is database-free and provider-neutral.  Its caller
names one create-only source object.  The applier exact-reads and validates
that complete closed pile, establishes immutable fact and Merkle objects,
advances the one mutable root by CAS, and returns. It never discovers or
deletes work. Inline Bao slices are ordinary facts, so there is no secondary
object-completion path. Retrying the same immutable source is idempotent
because the authenticated repository is a monotone set.
"""
from dataclasses import dataclass, field
import inspect

import facts

from .close import check_pile_bounds, decode_pile
from .crypto import h
from .fact import canon, encode
from .ingress import (
    KernelRejected,
    PermanentIngressRejection,
    check_source,
    pile_source,
)
from .kernel import drain
from .limits import (
    MAX_PILE_BYTES,
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
    Versioned,
    ensure_object_async,
)
from .repository_snapshot import extend_snapshot_awaited
from .shape import valid_fid


class RepositoryAnchorPending(RuntimeError):
    """A valid closed pile arrived before the workspace genesis."""


class SyncStoreAdapter:
    """Awaited adapter for one already-conforming synchronous store."""

    def __init__(self, store):
        self.store = store

    async def get_bounded(self, key, max_bytes):
        value = self.store.get_bounded(key, max_bytes)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > max_bytes):
            raise PayloadTooLarge("repository read exceeds byte limit")
        return value

    async def read_versioned(self, key):
        return self.store.read_versioned(key)

    async def put_if_absent(self, key, value):
        return self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return self.store.cas(key, token, value)


def async_store(store):
    """Return one awaited store without introducing provider branches."""
    method = getattr(type(store), "get_bounded", None)
    return store if inspect.iscoroutinefunction(method) \
        else SyncStoreAdapter(store)


@dataclass(frozen=True, slots=True)
class ApplyProposal:
    """Prepared root pinned to one exact source and root-version read."""

    workspace: str
    source: str
    payload: str
    base_root: bytes | None
    base_token: object
    root: bytes | None
    admitted: tuple
    issuer: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """One typed exact-source outcome."""

    status: str
    root: bytes | None
    admitted: tuple = ()


class RepositoryApplier:
    """One database-free receiving engine over an object-store CAS register."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("repository workspace")
        self.workspace = workspace
        self.store = async_store(store)
        self._issuer = object()

    @staticmethod
    async def _get_bounded(store, key, maximum):
        value = await store.get_bounded(key, maximum)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > maximum):
            raise PayloadTooLarge("repository read exceeds byte limit")
        return value

    async def _put_exact(self, store, key, raw):
        """Create one immutable value and reconcile an unknown response."""
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

    async def stage(self, member, raw):
        """Create one local exact source; discovery is the caller's job."""
        if not isinstance(raw, bytes):
            raise TypeError("exact ingress bytes required")
        check_pile_bounds(raw)
        generation = h(canon({
            "uploader": member,
            "payload": h(raw),
            "workspace": self.workspace,
        }))
        source = pile_source(member, raw, generation)
        await self._put_exact(self.store, source, raw)
        return source

    async def receive_pile(self, member, raw):
        """Create and immediately apply one local exact source."""
        source = await self.stage(member, raw)
        return await self._apply_exact(
            self.store, source, h(raw), raw=raw)

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

    async def propose(self, source, payload, raw):
        """Validate one whole pile and prepare its source-bound root."""
        stream = decode_pile(raw, self.workspace)
        judgment = drain(tuple(stream), self.workspace)
        if not judgment.ok:
            if judgment.failure is not None:
                raise judgment.failure
            raise KernelRejected("ingress rejected")

        versioned = await self.store.read_versioned("root")
        if versioned is ABSENT:
            base_root, base_token = None, ABSENT
        elif isinstance(versioned, Versioned):
            base_root, base_token = versioned.value, versioned.token
        else:
            raise TypeError("versioned root read")

        facts_by_fid, durable = {}, []
        for receipt in judgment.valids:
            family = facts.family_for(receipt.fact.t)
            if family is None or not family.DURABLE:
                continue
            fid = receipt.fact.fid
            durable.append(fid)
            old = facts_by_fid.setdefault(fid, receipt.fact)
            if encode(old) != encode(receipt.fact):
                raise ValueError("repository fact conflict")

        if base_root is None and facts_by_fid \
                and self.workspace not in facts_by_fid:
            raise RepositoryAnchorPending(
                "repository anchor fact is not available yet")

        compiled = await self._extend_snapshot(base_root, facts_by_fid)
        admitted = tuple(sorted(set(durable)))
        if compiled.root is not None \
                and not set(admitted) <= set(compiled.fact_oids):
            raise ValueError("repository proposal omitted admission")
        return ApplyProposal(
            self.workspace,
            source,
            payload,
            base_root,
            base_token,
            compiled.root,
            admitted,
            self._issuer,
        )

    async def commit(self, source, payload, proposal):
        """CAS only the exact source-bound proposal's prepared root."""
        if not isinstance(proposal, ApplyProposal) \
                or proposal.workspace != self.workspace \
                or proposal.source != source \
                or proposal.payload != payload \
                or proposal.issuer is not self._issuer:
            raise ValueError("repository apply proposal binding")
        if proposal.root is None:
            return ApplyResult("rootless", None, proposal.admitted)

        if proposal.root == proposal.base_root:
            current = await self.store.read_versioned("root")
            if not isinstance(current, Versioned) \
                    or current.token != proposal.base_token \
                    or current.value != proposal.base_root:
                return ApplyResult(
                    "retryable", proposal.base_root, proposal.admitted)
            return ApplyResult("noop", proposal.root, proposal.admitted)

        try:
            result = await self.store.cas(
                "root", proposal.base_token, proposal.root)
        except OutcomeUnknown:
            current = await self.store.read_versioned("root")
            if isinstance(current, Versioned) \
                    and current.value == proposal.root:
                return ApplyResult(
                    "confirmed", proposal.root, proposal.admitted)
            return ApplyResult(
                "retryable", proposal.base_root, proposal.admitted)
        if result is STALE:
            return ApplyResult(
                "retryable", proposal.base_root, proposal.admitted)
        if not isinstance(result, Applied):
            raise TypeError("root CAS result")
        return ApplyResult("applied", proposal.root, proposal.admitted)

    async def apply_exact(self, source_store, source, payload):
        """Apply one caller-named create-only object with its key digest."""
        return await self._apply_exact(source_store, source, payload)

    async def _apply_exact(
            self, source_store, source, payload, *, raw=None):
        source_store = async_store(source_store)
        if not isinstance(source, str) or not source or not valid_fid(payload):
            raise ValueError("exact ingress address")
        if raw is None:
            try:
                raw = await self._get_bounded(
                    source_store, source, MAX_PILE_BYTES)
            except PayloadTooLarge:
                return ApplyResult("rejected", None)
        if raw is None:
            return ApplyResult("retryable", None)
        if h(raw) != payload:
            return ApplyResult("rejected", None)

        try:
            proposal = await self.propose(source, payload, raw)
        except RepositoryAnchorPending:
            return ApplyResult("retryable", None)
        except PermanentIngressRejection:
            return ApplyResult("rejected", None)
        return await self.commit(source, payload, proposal)

    async def apply(self, source):
        """Apply one local exact source through the identical transition."""
        return await self.apply_exact(
            self.store, source, check_source(source).payload)


__all__ = (
    "ApplyProposal",
    "ApplyResult",
    "RepositoryAnchorPending",
    "RepositoryApplier",
    "async_store",
)
