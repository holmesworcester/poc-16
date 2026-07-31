"""The sole exact-pile to repository-root state transition.

``RepositoryApplier`` is database-free and provider-neutral.  It consumes one
internal, generation-bound closed pile, validates that unit atomically, unions
every durable result with the validated facts pinned by one root read, invokes
the pure repository compiler, establishes every immutable object, advances
the one mutable root by CAS, and only then grants exact retirement authority.

Synchronous filesystem/S3 stores are adapted to this asynchronous surface.
Cloudflare's native R2 binding implements the same awaited methods directly.
"""
from dataclasses import dataclass, field
import inspect

import facts

from .close import decode_pile
from .crypto import h
from .ingress import (
    KernelRejected,
    PermanentIngressRejection,
    check_source,
    decode_rejection_record,
    encode_rejection_record,
    pile_source,
)
from .kernel import drain
from .object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    STALE,
    Applied,
    OutcomeUnknown,
    StoreError,
    Versioned,
    ListPage,
    ensure_object_async,
    retire_exact_async,
)
from .repository_snapshot import compile_snapshot
from .validated_set import reconstruct
from .shape import valid_fid
from .staged_intent import (
    InvalidStagedObject,
    confirm_staged_object,
    decode_staged_pile,
    staging_key,
    staging_prefix,
)
from .fact import canon, encode
from .limits import (
    MAX_OBJECT_BYTES,
    MAX_PILE_BYTES,
    MAX_REJECTION_RECORD_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)

_MAX_DISCOVERY_CURSOR_BYTES = 16 * 1024
_MAX_OPERATION_RECORD_BYTES = 4 * 1024
_STAGED_OBJECT_BATCH = PAGE_BATCH


@dataclass(frozen=True, slots=True)
class _Evidence:
    """One exact operational value bound to one provider-neutral key."""

    key: str
    raw: bytes


def _decode_evidence(raw, label, fields):
    """Decode one bounded canonical record with an explicit exact schema."""
    value = decode_json(raw, _MAX_DISCOVERY_CURSOR_BYTES, label)
    if not isinstance(value, dict) or set(value) != set(fields) \
            or canon(value) != raw:
        raise ValueError(label)
    return value


class _ObjectMiss(Exception):
    def __init__(self, oid):
        super().__init__(oid)
        self.oid = oid


class RepositoryAnchorPending(RuntimeError):
    """A valid closed pile arrived before the workspace genesis."""


class SyncStoreAdapter:
    """Awaited adapter for one already-conforming synchronous store."""

    def __init__(self, store):
        self.store = store

    async def get_bounded(self, key, max_bytes):
        return self.store.get_bounded(key, max_bytes)

    async def read_versioned(self, key):
        return self.store.read_versioned(key)

    async def put(self, key, value):
        return self.store.put(key, value)

    async def put_if_absent(self, key, value):
        return self.store.put_if_absent(key, value)

    async def cas(self, key, token, value):
        return self.store.cas(key, token, value)

    async def list_page(self, prefix, cursor, limit):
        return self.store.list_page(prefix, cursor, limit)

    async def delete(self, key):
        return self.store.delete(key)


def async_store(store):
    """Return one awaited store without introducing provider branches."""
    method = getattr(type(store), "get_bounded", None)
    return store if inspect.iscoroutinefunction(method) \
        else SyncStoreAdapter(store)


@dataclass(frozen=True, slots=True)
class ApplyProposal:
    """Pure result pinned to the exact root/token read by this turn."""

    workspace: str
    payload: str
    base_root: bytes | None
    base_token: object
    root: bytes | None
    outbox: tuple
    admitted: tuple
    valids: tuple
    issuer: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, eq=False)
class _RetirementReceipt:
    workspace: str
    source: str
    payload: str
    generation: str
    outcome: str
    issuer: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, eq=False)
class ApplyReceipt(_RetirementReceipt):
    """Unforgeable one-use F10 authority for a published generation."""

    base_root: bytes | None
    root: bytes
    admitted: tuple


@dataclass(frozen=True, slots=True, eq=False)
class RejectionReceipt(_RetirementReceipt):
    """Unforgeable one-use F10 authority for a rejected generation."""

    record: bytes


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """One typed turn outcome; retryable outcomes retain exact work."""

    status: str
    root: bytes | None
    admitted: tuple = ()
    retired: bool = False
    rejection: RejectionReceipt | None = None
    valids: tuple = ()


@dataclass(frozen=True, slots=True)
class StagedApplyResult:
    """One isolated staging marker translated through the canonical engine."""

    key: str
    source: str | None
    result: ApplyResult
    promoted: tuple = ()
    unavailable: tuple = ()
    poisoned: tuple = ()


@dataclass(frozen=True, slots=True)
class TurnItem:
    """One independently attempted internal generation."""

    source: str
    result: ApplyResult | None = None
    error: Exception | None = None

    def __post_init__(self):
        if not isinstance(self.source, str) \
                or (self.result is None) == (self.error is None):
            raise TypeError("repository turn item")


class RepositoryApplier:
    """One database-free receiving engine over an object-store CAS register."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("repository workspace")
        self.workspace = workspace
        self.store = async_store(store)
        self._issuer = object()
        self._receipts = {}

    def _generation_evidence(self, actor, raw, origin):
        record = canon({
            "actor": actor,
            "kind": "internal-generation-v1",
            "origin": origin,
            "payload": h(raw),
            "workspace": self.workspace,
        })
        generation = h(record)
        return (
            pile_source(actor, raw, generation),
            _Evidence("applier/generation/" + generation, record),
        )

    async def _generation(self, source, raw=None):
        binding = check_source(source, raw)
        reservation = await self._get_bounded(
            self.store,
            "applier/generation/" + binding.generation,
            _MAX_OPERATION_RECORD_BYTES,
        )
        if reservation is None:
            raise ValueError("internal generation is not reserved")
        value = _decode_evidence(
            reservation, "internal generation",
            {"actor", "kind", "origin", "payload", "workspace"})
        if value["actor"] != binding.member \
                or value["kind"] != "internal-generation-v1" \
                or not isinstance(value["origin"], str) \
                or value["payload"] != binding.payload \
                or value["workspace"] != self.workspace \
                or h(reservation) != binding.generation:
            raise ValueError("internal generation reservation")
        record = await self._get_bounded(
            self.store,
            "applier/spent/" + binding.generation,
            _MAX_OPERATION_RECORD_BYTES,
        )
        if record is None:
            return binding, None
        value = _decode_evidence(
            record, "internal generation spend",
            {"kind", "outcome", "proof"},
        )
        if value["kind"] != "internal-generation-spend-v1" \
                or value["outcome"] not in {
                    "applied", "confirmed", "noop", "rejected"} \
                or not valid_fid(value["proof"]):
            raise ValueError("internal generation spend")
        if value["outcome"] == "rejected":
            rejection = await self._get_bounded(
                self.store,
                "failed/meta/" + value["proof"],
                MAX_REJECTION_RECORD_BYTES,
            )
            if rejection is None or h(rejection) != value["proof"]:
                raise ValueError("internal generation spend")
            try:
                decode_rejection_record(
                    rejection,
                    workspace=self.workspace,
                    source=source,
                    payload=binding.payload,
                    generation=binding.generation,
                )
            except ValueError as error:
                raise ValueError("internal generation spend") from error
        return binding, value

    async def _terminal_result(self, source):
        try:
            _, spent = await self._generation(source)
        except ValueError:
            return None
        return None if spent is None else ApplyResult(
            spent["outcome"], None, retired=True)

    async def _stage(self, member, raw, origin):
        """Recover one stable logical delivery, creating its source at most once."""
        source, reservation = self._generation_evidence(member, raw, origin)
        await self._put_evidence(reservation)
        _, spent = await self._generation(source, raw)
        if spent is None:
            await self._put_evidence(_Evidence(source, raw))
        return source

    async def stage(self, member, raw):
        """Idempotently create one reserved generation for exact logical work."""
        if not isinstance(raw, bytes):
            raise TypeError("exact ingress bytes required")
        if len(raw) > MAX_PILE_BYTES:
            raise PayloadTooLarge("pile exceeds byte limit")
        return await self._stage(member, raw, "")

    async def admit_object(self, oid, raw):
        """Verify and establish one inbound detached canonical object."""
        return await ensure_object_async(self.store, oid, raw)

    async def receive_pile(self, member, raw):
        """Reserve and apply the exact logical delivery from an HTTP gate."""
        return await self._attempt(await self.stage(member, raw))

    async def _attempt(self, source):
        """Isolate one retained generation from every other ingress unit."""
        try:
            result = await self.apply(source)
        except Exception as error:
            return TurnItem(source, error=error)
        return TurnItem(source, result=result)

    def _cursor_key(self, kind):
        if kind not in {"internal", "staged"}:
            raise ValueError("repository discovery kind")
        return f"applier/cursor/{kind}"

    async def _load_discovery_cursor(self, kind):
        key = self._cursor_key(kind)
        raw = await self._get_bounded(
            self.store, key, _MAX_DISCOVERY_CURSOR_BYTES)
        if raw is None:
            return None
        value = _decode_evidence(
            raw, "repository discovery cursor",
            {"cursor", "kind", "workspace"})
        if value["kind"] != kind \
                or value["workspace"] != self.workspace \
                or not isinstance(value["cursor"], str):
            raise ValueError("repository discovery cursor")
        return value["cursor"] or None

    async def _save_discovery_cursor(self, kind, cursor):
        if cursor is not None and (
                not isinstance(cursor, str) or not cursor
                or len(cursor.encode("utf-8")) >
                _MAX_DISCOVERY_CURSOR_BYTES // 2):
            raise ValueError("repository discovery cursor")
        raw = canon({
            "cursor": cursor or "",
            "kind": kind,
            "workspace": self.workspace,
        })
        await self._put_hint(_Evidence(self._cursor_key(kind), raw))

    async def _discovery_page(self, store, kind, prefix, limit):
        if type(limit) is not int or not 0 < limit <= PAGE_BATCH:
            raise ValueError("repository discovery page limit")
        cursor = await self._load_discovery_cursor(kind)
        page = await store.list_page(prefix, cursor, limit)
        if not isinstance(page, ListPage):
            raise TypeError("repository discovery page")
        return page

    def _marker_receipt(self, kind, key, raw):
        record = canon({
            "key": key,
            "kind": f"staged-{kind}-v1",
            "payload": h(raw),
            "workspace": self.workspace,
        })
        return _Evidence(f"staged/{kind}/{h(record)}", record)

    def _object_receipt(self, kind, intent, oid):
        record = canon({
            "kind": f"staged-object-{kind}-v1",
            "marker": intent.key,
            "object": oid,
            "payload": h(intent.raw),
            "workspace": self.workspace,
        })
        return _Evidence(
            f"staged/object-{kind}/{h(record)}", record)

    def _page_receipt(self, intent, page, pages):
        record = canon({
            "kind": "staged-object-page-v1",
            "marker": intent.key,
            "page": page,
            "pages": pages,
            "payload": h(intent.raw),
            "workspace": self.workspace,
        })
        return _Evidence(f"staged/object-page/{h(record)}", record)

    def _staged_object_cursor_key(self, intent):
        binding = canon({
            "kind": "staged-object-cursor-v1",
            "marker": intent.key,
            "payload": h(intent.raw),
            "workspace": self.workspace,
        })
        return f"staged/object-cursor/{h(binding)}"

    async def _load_staged_object_cursor(self, intent, pages):
        if pages < 1:
            return None
        key = self._staged_object_cursor_key(intent)
        raw = await self._get_bounded(
            self.store, key, _MAX_DISCOVERY_CURSOR_BYTES)
        if raw is None:
            return 0
        value = _decode_evidence(
            raw, "staged object cursor",
            {"kind", "marker", "page", "pages", "payload", "workspace"})
        if value["kind"] != "staged-object-cursor-v1" \
                or value["marker"] != intent.key \
                or value["pages"] != pages \
                or value["payload"] != h(intent.raw) \
                or value["workspace"] != self.workspace \
                or type(value["page"]) is not int \
                or not 0 <= value["page"] < pages:
            raise ValueError("staged object cursor")
        return value["page"]

    async def _save_staged_object_cursor(
            self, intent, page, pages):
        if type(page) is not int or type(pages) is not int \
                or not 0 <= page < pages:
            raise ValueError("staged object cursor")
        raw = canon({
            "kind": "staged-object-cursor-v1",
            "marker": intent.key,
            "page": page,
            "pages": pages,
            "payload": h(intent.raw),
            "workspace": self.workspace,
        })
        await self._put_hint(_Evidence(
            self._staged_object_cursor_key(intent), raw))

    async def _next_staged_object_page(
            self, intent, start, pages):
        """Find one unfinished page; every scan is bounded by 256 receipts."""
        for offset in range(pages):
            page = (start + offset) % pages
            if not await self._has_evidence(
                    self._page_receipt(intent, page, pages)):
                return page
        return None

    async def _staged_source(self, intent):
        """Use the marker itself as the stable delivery identity."""
        return await self._stage(intent.member, intent.raw, intent.key)

    @staticmethod
    async def _get_bounded(store, key, maximum):
        value = await store.get_bounded(key, maximum)
        if value is not None and (
                not isinstance(value, bytes) or len(value) > maximum):
            raise PayloadTooLarge("repository read exceeds byte limit")
        return value

    async def apply_staged(self, ingress_store, key):
        """Translate one direct-upload marker into the same internal path.

        The untrusted staging namespace is never a second repository.  The
        exact marker is always fetched from ingress, bound to its stable
        reserved generation, and committed first.  Only afterward are
        same-session detached objects promoted independently.  Slow, absent,
        poisoned, or failed object reads therefore cannot block valid facts.

        The client-writable marker is deliberately not deleted here.  Its
        lifecycle policy is independent of F10, which governs only the exact
        internal generation reserved below.  Immutable operational receipts
        prevent retained markers from creating generations forever and leave
        missing attachments as separately retryable completion work.
        """
        ingress = async_store(ingress_store)
        raw = await self._get_bounded(ingress, key, MAX_PILE_BYTES)
        if raw is None:
            return None
        receipts = {
            state: self._marker_receipt(state, key, raw)
            for state in ("admitted", "done", "rejected")
        }
        if await self._has_evidence(
                receipts["rejected"]):
            return StagedApplyResult(
                key,
                None,
                ApplyResult("rejected-staging", None),
            )
        if await self._has_evidence(
                receipts["done"]):
            return StagedApplyResult(
                key,
                None,
                ApplyResult("admitted", None),
            )
        try:
            intent = decode_staged_pile(self.workspace, key, raw)
        except PermanentIngressRejection:
            await self._put_evidence(receipts["rejected"])
            return StagedApplyResult(
                key,
                None,
                ApplyResult("rejected-staging", None),
            )
        admitted = await self._has_evidence(receipts["admitted"])
        source = None
        if admitted:
            result = ApplyResult("admitted", None)
        else:
            source = await self._staged_source(intent)
            result = await self.apply(source, retire=False)
            if result.status == "rejected":
                await self._put_evidence(receipts["rejected"])
                retired = result.retired
                if result.rejection is not None:
                    retired = await self.retire_rejection(
                        source, intent.raw, result.rejection)
                return StagedApplyResult(
                    key,
                    source,
                    ApplyResult(
                        "rejected-staging",
                        None,
                        retired=retired,
                        rejection=result.rejection,
                    ),
                )
            if result.status not in {"applied", "confirmed", "noop"}:
                return StagedApplyResult(key, source, result)
            await self._put_evidence(receipts["admitted"])
            receipt = self._receipts.get(source)
            retired = result.retired
            if receipt is not None:
                retired = await self.retire(
                    source, intent.raw, receipt)
            result = ApplyResult(
                result.status,
                result.root,
                result.admitted,
                retired,
                valids=result.valids,
            )

        promoted, unavailable, poisoned = [], [], []
        pages = (
            len(intent.blob_refs) + _STAGED_OBJECT_BATCH - 1
        ) // _STAGED_OBJECT_BATCH
        if pages == 0:
            await self._put_evidence(receipts["done"])
            return StagedApplyResult(
                key, source, result, (), (), ())

        cursor = await self._load_staged_object_cursor(intent, pages)
        page = await self._next_staged_object_page(
            intent, cursor, pages)
        if page is None:
            await self._put_evidence(receipts["done"])
            return StagedApplyResult(
                key, source, result, (), (), ())

        start = page * _STAGED_OBJECT_BATCH
        stop = min(
            start + _STAGED_OBJECT_BATCH,
            len(intent.blob_refs),
        )
        for oid in intent.blob_refs[start:stop]:
            object_key = staging_key(
                intent.workspace,
                intent.member,
                intent.session,
                "obj",
                oid,
            )
            promoted_receipt = self._object_receipt(
                "promoted", intent, oid)
            poisoned_receipt = self._object_receipt(
                "poisoned", intent, oid)
            if await self._has_evidence(promoted_receipt) \
                    or await self._has_evidence(poisoned_receipt):
                continue
            try:
                value = await self._get_bounded(
                    ingress, object_key, MAX_OBJECT_BYTES)
            except PayloadTooLarge:
                await self._put_evidence(poisoned_receipt)
                poisoned.append(object_key)
                continue
            except (OSError, StoreError):
                unavailable.append(object_key)
                continue
            if value is None:
                unavailable.append(object_key)
                continue
            try:
                confirm_staged_object(intent, object_key, value)
            except InvalidStagedObject:
                await self._put_evidence(poisoned_receipt)
                poisoned.append(object_key)
                continue
            try:
                await self.admit_object(oid, value)
            except (OSError, StoreError):
                unavailable.append(object_key)
                continue
            await self._put_evidence(promoted_receipt)
            promoted.append(oid)

        if not unavailable:
            await self._put_evidence(
                self._page_receipt(intent, page, pages))
        following = await self._next_staged_object_page(
            intent, (page + 1) % pages, pages)
        if following is None:
            await self._put_evidence(receipts["done"])
        else:
            # This cursor is a fairness hint, never completion authority.
            # Concurrent regressions only duplicate bounded work because
            # immutable page receipts remain the source of truth.
            await self._save_staged_object_cursor(
                intent, following, pages)
        return StagedApplyResult(
            key,
            source,
            result,
            tuple(promoted),
            tuple(unavailable),
            tuple(poisoned),
        )

    async def drain_staged(self, ingress_store, *, limit=PAGE_BATCH):
        """Process one bounded discovery snapshot without cross-item wedges."""
        ingress = async_store(ingress_store)
        outcomes = []
        prefix = staging_prefix(self.workspace, "pile")
        page = await self._discovery_page(
            ingress, "staged", prefix, limit)
        for key in page.keys:
            try:
                outcomes.append((key, await self.apply_staged(ingress, key)))
            except Exception as error:
                outcomes.append((key, error))
        await self._save_discovery_cursor("staged", page.cursor)
        return tuple(outcomes)

    async def _load_validated(self, root_bytes):
        if root_bytes is None:
            return None
        objects = {}

        def fetch(oid):
            if oid not in objects:
                raise _ObjectMiss(oid)
            return objects[oid]

        while True:
            try:
                validated = reconstruct(root_bytes, fetch)
            except _ObjectMiss as miss:
                objects[miss.oid] = await self._get_bounded(
                    self.store,
                    "obj/" + miss.oid,
                    MAX_REPOSITORY_OBJECT_BYTES,
                )
                continue
            if validated.workspace != self.workspace:
                raise ValueError("repository root workspace")
            return validated

    async def propose(self, raw):
        """Derive one proposal without mutating canonical repository state."""
        # Reject untrusted bytes before they can force traversal of the
        # authenticated validated-fact tree. Only a valid kernel judgment
        # earns reads beyond the exact pile itself.
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
        validated = await self._load_validated(base_root)

        pending = {}

        def emit(value):
            oid = h(value)
            incumbent = pending.setdefault(oid, value)
            if incumbent != value:
                raise ValueError("repository object hash collision")
            return oid

        facts_by_fid = {} if validated is None else dict(validated.facts)
        durable, durable_receipts = [], []
        for receipt in judgment.valids:
            family = facts.family_for(receipt.fact.t)
            if family is None or not family.DURABLE:
                continue
            fid = receipt.fact.fid
            durable.append(fid)
            durable_receipts.append(receipt)
            incumbent = facts_by_fid.get(fid)
            if incumbent is not None \
                    and encode(incumbent) != encode(receipt.fact):
                raise ValueError("repository fact conflict")
            facts_by_fid[fid] = receipt.fact

        if facts_by_fid and self.workspace not in facts_by_fid:
            raise RepositoryAnchorPending(
                "repository anchor fact is not available yet")
        compiled = compile_snapshot(self.workspace, facts_by_fid)
        for oid, value in compiled.outbox:
            emit(value)
        admitted = tuple(sorted(set(durable)))
        if compiled.root is not None \
                and not set(admitted) <= set(compiled.objects):
            raise ValueError("repository proposal omitted admission")
        return ApplyProposal(
            self.workspace,
            h(raw),
            base_root,
            base_token,
            compiled.root,
            tuple(sorted(pending.items())),
            admitted,
            tuple(durable_receipts),
            self._issuer,
        )

    async def _establish_outbox(self, outbox):
        for oid, raw in outbox:
            await ensure_object_async(self.store, oid, raw)

    async def commit(self, source, raw, proposal):
        """Interpret one pure proposal and mint F10 authority on exact success."""
        incumbent = await self._get_bounded(
            self.store, source, MAX_PILE_BYTES)
        if incumbent != raw:
            terminal = await self._terminal_result(source)
            if terminal is not None:
                return terminal
            raise ValueError(
                "repository source is not a present exact generation")
        binding, _ = await self._generation(source, raw)
        if not isinstance(proposal, ApplyProposal):
            raise TypeError("repository apply proposal")
        if proposal.workspace != self.workspace \
                or proposal.payload != h(raw) \
                or proposal.issuer is not self._issuer:
            raise ValueError("repository apply proposal binding")
        if proposal.root is None:
            return ApplyResult(
                "rootless", None, proposal.admitted,
                valids=proposal.valids)

        await self._establish_outbox(proposal.outbox)
        if proposal.root == proposal.base_root:
            current = await self.store.read_versioned("root")
            if not isinstance(current, Versioned) \
                    or current.token != proposal.base_token \
                    or current.value != proposal.base_root:
                return ApplyResult(
                    "stale", proposal.base_root, proposal.admitted,
                    valids=proposal.valids)
            outcome = "noop"
        else:
            try:
                result = await self.store.cas(
                    "root", proposal.base_token, proposal.root)
            except OutcomeUnknown:
                current = await self.store.read_versioned("root")
                if isinstance(current, Versioned) \
                        and current.value == proposal.root:
                    outcome = "confirmed"
                elif (
                        current is ABSENT
                        and proposal.base_root is None
                        or isinstance(current, Versioned)
                        and current.value == proposal.base_root
                        and current.token == proposal.base_token):
                    raise
                else:
                    return ApplyResult(
                        "stale", proposal.base_root, proposal.admitted,
                        valids=proposal.valids)
            else:
                if result is STALE:
                    return ApplyResult(
                        "stale", proposal.base_root, proposal.admitted,
                        valids=proposal.valids)
                if not isinstance(result, Applied):
                    raise TypeError("root CAS result")
                outcome = "applied"

        receipt = ApplyReceipt(
            workspace=self.workspace,
            source=source,
            payload=h(raw),
            generation=binding.generation,
            outcome=outcome,
            issuer=self._issuer,
            base_root=proposal.base_root,
            root=proposal.root,
            admitted=proposal.admitted,
        )
        self._receipts[source] = receipt
        return ApplyResult(
            outcome, proposal.root, proposal.admitted,
            valids=proposal.valids)

    def _retirement_evidence(self, receipt):
        rejected = isinstance(receipt, RejectionReceipt)
        proof = h(receipt.record) if rejected else h(canon([
            receipt.workspace,
            receipt.source,
            receipt.payload,
            receipt.generation,
            receipt.outcome,
            "" if receipt.base_root is None else h(receipt.base_root),
            h(receipt.root),
            h(canon(list(receipt.admitted))),
        ]))
        record = canon({
            "kind": "internal-generation-spend-v1",
            "outcome": receipt.outcome,
            "proof": proof,
        })
        return _Evidence("applier/spent/" + receipt.generation, record)

    async def _claim_spend(self, receipt):
        """Linearize the sole delete grant; ambiguity never grants deletion."""
        evidence = self._retirement_evidence(receipt)
        try:
            result = await self.store.put_if_absent(
                evidence.key, evidence.raw)
        except OutcomeUnknown:
            result = None
        incumbent = await self._read_evidence(evidence)
        if incumbent is not None and incumbent != evidence.raw:
            # Another legitimate applier may have committed a different exact
            # success outcome for the same logical delivery.  It owns the sole
            # delete; this caller must only observe terminal state.
            _, spent = await self._generation(receipt.source)
            if spent is None:
                raise ValueError("internal generation spend")
        elif result is CREATED and incumbent != evidence.raw:
            raise OSError("generation spend disappeared")
        return result is CREATED and incumbent == evidence.raw

    async def _spend_and_retire(self, source, raw, receipt):
        """Use a definite fresh spend as the sole proof-facing delete grant."""
        self._receipts.pop(source, None)
        if not await self._claim_spend(receipt):
            return await self._get_bounded(
                self.store, source, MAX_PILE_BYTES) is None
        return await retire_exact_async(self.store, source, raw)

    async def _owned_receipt(
            self, source, raw, receipt, kind, outcomes, label):
        binding, _ = await self._generation(source, raw)
        if not isinstance(receipt, kind) \
                or self._receipts.get(source) is not receipt \
                or receipt.issuer is not self._issuer \
                or receipt.workspace != self.workspace \
                or receipt.source != source \
                or receipt.payload != h(raw) \
                or receipt.generation != binding.generation \
                or receipt.outcome not in outcomes:
            raise ValueError(label)

    async def retire(self, source, raw, receipt):
        """Consume one exact F10 capability and retire only its generation."""
        await self._owned_receipt(
            source, raw, receipt, ApplyReceipt,
            {"applied", "confirmed", "noop"},
            "repository retirement receipt")
        return await self._spend_and_retire(source, raw, receipt)

    async def _read_evidence(self, evidence):
        return await self._get_bounded(
            self.store, evidence.key, max(1, len(evidence.raw)))

    async def _has_evidence(self, evidence):
        incumbent = await self._read_evidence(evidence)
        if incumbent is not None and incumbent != evidence.raw:
            raise ValueError("operational evidence conflict")
        return incumbent is not None

    async def _put_hint(self, evidence):
        try:
            await self.store.put(evidence.key, evidence.raw)
        except OutcomeUnknown:
            if await self._read_evidence(evidence) != evidence.raw:
                raise

    async def _put_evidence(self, evidence):
        unknown = None
        for _ in range(2):
            try:
                result = await self.store.put_if_absent(
                    evidence.key, evidence.raw)
            except OutcomeUnknown as error:
                unknown = error
            else:
                if result not in {CREATED, EXISTS}:
                    raise TypeError("evidence create result")
            incumbent = await self._read_evidence(evidence)
            if incumbent == evidence.raw:
                return
            if incumbent is not None:
                raise ValueError("operational evidence conflict")
        raise unknown or OSError("operational evidence was not preserved")

    async def _reject(self, source, raw, error, *, retire=True):
        """Persist exact typed permanent-rejection evidence, then retire."""
        incumbent = await self._get_bounded(
            self.store, source, MAX_PILE_BYTES)
        if incumbent != raw:
            terminal = await self._terminal_result(source)
            if terminal is not None:
                return terminal
            raise ValueError(
                "repository source is not a present exact generation")
        binding, _ = await self._generation(source, raw)
        payload = h(raw)
        record = encode_rejection_record(
            error, self.workspace, source, raw)
        receipt = RejectionReceipt(
            workspace=self.workspace,
            source=source,
            payload=payload,
            generation=binding.generation,
            outcome="rejected",
            issuer=self._issuer,
            record=record,
        )
        await self._put_evidence(
            _Evidence("failed/pile/" + payload, raw))
        await self._put_evidence(
            _Evidence("failed/meta/" + h(record), record))
        self._receipts[source] = receipt
        retired = await self.retire_rejection(
            source, raw, receipt) if retire else False
        return ApplyResult(
            "rejected", None, (), retired, receipt, ())

    async def retire_rejection(self, source, raw, receipt):
        """Retire exact rejected work only after rechecking its evidence."""
        await self._owned_receipt(
            source, raw, receipt, RejectionReceipt, {"rejected"},
            "durable rejection witness")
        try:
            value = decode_rejection_record(
                receipt.record,
                workspace=self.workspace,
                source=source,
                payload=h(raw),
                generation=receipt.generation,
            )
        except ValueError as error:
            raise ValueError("durable rejection witness") from error
        pile_evidence = await self._get_bounded(
            self.store,
            value["pile"],
            max(1, len(raw)),
        )
        meta_evidence = await self._get_bounded(
            self.store,
            "failed/meta/" + h(receipt.record),
            MAX_REJECTION_RECORD_BYTES,
        )
        if pile_evidence != raw or meta_evidence != receipt.record:
            raise ValueError("durable rejection witness")
        return await self._spend_and_retire(source, raw, receipt)

    async def apply(self, source, *, retire=True):
        """Run one present exact internal generation through the transition."""
        raw = await self._get_bounded(
            self.store, source, MAX_PILE_BYTES)
        if raw is None:
            return await self._terminal_result(source) \
                or ApplyResult("missing", None)
        _, spent = await self._generation(source, raw)
        if spent is not None:
            return ApplyResult(spent["outcome"], None)
        receipt = self._receipts.get(source)
        if retire and receipt is not None:
            if isinstance(receipt, RejectionReceipt):
                retired = await self.retire_rejection(
                    source, raw, receipt)
                return ApplyResult(
                    "rejected", None, (), retired, receipt, ())
            retired = await self.retire(source, raw, receipt)
            return ApplyResult(
                receipt.outcome,
                receipt.root,
                receipt.admitted,
                retired,
            )
        try:
            proposal = await self.propose(raw)
        except PermanentIngressRejection as error:
            return await self._reject(
                source, raw, error, retire=retire)
        result = await self.commit(source, raw, proposal)
        if not retire or result.status not in {"applied", "confirmed", "noop"}:
            return result
        receipt = self._receipts.get(source)
        if receipt is None:
            return result
        retired = await self.retire(source, raw, receipt)
        return ApplyResult(
            result.status, result.root, result.admitted, retired,
            valids=result.valids)

    async def turn(self, *, limit=PAGE_BATCH):
        """Drain one bounded page; each exact pile remains independent."""
        results = []
        page = await self._discovery_page(
            self.store, "internal", "pile/", limit)
        for source in page.keys:
            results.append(await self._attempt(source))
        await self._save_discovery_cursor("internal", page.cursor)
        return tuple(results)
