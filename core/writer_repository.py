"""Per-device writer publication and shared forest reconciliation.

The cloud composition uses :class:`OpaqueHeadGate` and never constructs or
validates writer content. A consuming peer uses :class:`RepositoryMirror` with
one :class:`FactConsumer`. Both store the same immutable objects and stable
per-device slots through the same object-store contract.
"""
from dataclasses import dataclass
import hashlib
import inspect

import facts

from . import merkle_map
from .close import (
    ClosedPileEvaluator,
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from .crypto import h
from .fact import canon, encode
from .limits import (
    MAX_CONTROL_APPLY_ATTEMPTS,
    MAX_HEAD_CONTROL_PILES,
    MAX_OWNER_CONTROL_COMMIT_ATTEMPTS,
    MAX_SEMANTIC_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PAGE_BATCH,
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
    VersionToken,
    async_store,
    ensure_object_async,
)
from .shape import valid_fid
from .writer_head import (
    HeadSlot,
    WriterBinding,
    decode_head,
    decode_slot,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    head_slot_prefix,
    make_head,
    parse_head_slot_key,
    require_bound_head,
    validate_advance,
    writer_store_binding,
)
from .writer_tree import (
    EMPTY_TREE,
    append_piles_awaited,
    leaf_key,
    reachable_staged_pages,
    validate_extension_awaited,
    writer_tree_seed,
)


@dataclass(frozen=True, slots=True)
class PreparedUpdate:
    """Immutable objects for one final tree root and one signed head."""

    workspace: str
    device: str
    base_head: str | None
    piles: tuple
    pile_oids: tuple[str, ...]
    head: object
    objects: tuple[tuple[str, bytes], ...]

    @property
    def head_oid(self):
        return head_oid(self.head)


@dataclass(frozen=True, slots=True)
class HeadGrant:
    """Typed result of one discarded current-removal evaluation."""

    workspace: str
    device: str
    base_head: str | None
    head: str
    removal_root: str

    def __post_init__(self):
        if not all(valid_fid(value) for value in (
                self.workspace, self.device,
                self.head, self.removal_root)) \
                or self.base_head is not None \
                and not valid_fid(self.base_head):
            raise ValueError("head grant")


@dataclass(frozen=True, slots=True)
class SlotResult:
    status: str
    slot: HeadSlot

    def __post_init__(self):
        if self.status not in {"applied", "noop", "retryable", "conflict"} \
                or not isinstance(self.slot, HeadSlot):
            raise ValueError("head slot result")


def _reconcile_head_cas(opened, grant, proposed, exact_status):
    """Classify one failed/unknown CAS from an exact register reread."""
    if exact_status not in {"applied", "noop"}:
        raise ValueError("head reconciliation status")
    if opened is ABSENT:
        status = "retryable" if grant.base_head is None else "conflict"
        return SlotResult(status, proposed)
    if not isinstance(opened, Versioned):
        raise TypeError("writer slot read")
    current = decode_slot_at(
        head_slot_key(grant.workspace, grant.device), opened.value)
    if opened.value == encode_slot(proposed):
        return SlotResult(exact_status, current)
    if current.head == grant.head:
        return SlotResult(
            "noop" if current.permit == proposed.permit else "conflict",
            current,
        )
    if current.head == grant.base_head:
        return SlotResult("retryable", proposed)
    return SlotResult("conflict", current)


@dataclass(frozen=True, slots=True)
class MirrorResult:
    listed: int
    changed: int
    piles: int
    facts: int
    errors: tuple


@dataclass(frozen=True, slots=True)
class OwnerPublishResult:
    """One owner-confined cloud publication attempt."""

    status: str
    head: str | None
    objects: int
    piles: int

    def __post_init__(self):
        if self.status not in {
                "applied", "noop", "retryable", "conflict"} \
                or self.head is not None and not valid_fid(self.head) \
                or type(self.objects) is not int or self.objects < 0 \
                or type(self.piles) is not int or self.piles < 0:
            raise ValueError("owner publication result")


@dataclass(frozen=True, slots=True)
class ValidatedBatch:
    """One fully judged candidate suffix, still free of residence effects."""

    piles: tuple[str, ...]
    facts: tuple[tuple[str, bytes], ...]
    control_piles: tuple[str, ...] = ()

    def __post_init__(self):
        if any(not valid_fid(oid) for oid in self.piles) \
                or any(not valid_fid(fid) or not isinstance(raw, bytes)
                       for fid, raw in self.facts) \
                or tuple(sorted(set(self.control_piles))) \
                != self.control_piles:
            raise ValueError("validated consumer batch")


async def _maybe_await(value):
    return await value if inspect.isawaitable(value) else value


async def _retry_pause(_attempt):
    """Yield fairly when a runtime does not inject its own backoff policy."""
    from asyncio import sleep

    await sleep(0)


def _mirror_permit_oid(
        workspace, device, base_head, head, updates):
    """Name one locally reconstructable mirror control transition."""
    return h(canon([
        "poc16-mirror-control-permit-v2",
        workspace,
        device,
        "" if base_head is None else base_head,
        head,
        updates,
    ]))


async def _object(store, oid, maximum=MAX_REPOSITORY_OBJECT_BYTES):
    if not valid_fid(oid):
        raise ValueError("repository object oid")
    raw = await store.get_bounded("obj/" + oid, maximum)
    if not isinstance(raw, bytes) or len(raw) > maximum or h(raw) != oid:
        raise ValueError("repository object integrity")
    return raw


async def _copy_pile_object(
        store, oid, write, maximum=MAX_SEMANTIC_PILE_BYTES):
    """Copy one pile through the required streaming data plane."""
    if not valid_fid(oid) or not callable(write) \
            or type(maximum) is not int \
            or not 0 < maximum <= MAX_SEMANTIC_PILE_BYTES:
        raise ValueError("repository pile copy")
    copied = await _maybe_await(
        store.copy_pile_object(oid, maximum, write))
    if copied is None:
        return None
    if type(copied) is not int or not 0 <= copied <= maximum:
        raise ValueError("repository pile copy result")
    return copied


async def _pile_object(store, oid, maximum=MAX_SEMANTIC_PILE_BYTES):
    value = bytearray()
    copied = await _copy_pile_object(
        store, oid, value.extend, maximum)
    raw = None if copied is None else bytes(value)
    if raw is None or copied != len(raw) or h(raw) != oid:
        raise ValueError("repository pile integrity")
    return raw


async def control_extension(
        store, binding, base_head_oid, proposed_head_oid):
    """Open one signed head pair and prove its bounded control-tree suffix.

    Hosted gates deliberately do not inspect ordinary pile bytes.  The
    writer-signed secondary tree is therefore the exact, cheap declaration of
    control piles that must use the fenced permit path for this transition.
    """
    if not isinstance(binding, WriterBinding) \
            or base_head_oid is not None and not valid_fid(base_head_oid) \
            or not valid_fid(proposed_head_oid):
        raise ValueError("control extension binding")
    store = async_store(store)
    candidate_raw = await _object(store, proposed_head_oid)
    candidate = require_bound_head(decode_head(candidate_raw), binding)
    if base_head_oid is None:
        accepted, accepted_control = None, EMPTY_TREE
    else:
        accepted_raw = await _object(store, base_head_oid)
        accepted = require_bound_head(decode_head(accepted_raw), binding)
        validate_advance(accepted, candidate, binding)
        accepted_control = accepted.control
    delta = candidate.control.count - accepted_control.count
    if not 0 <= delta <= MAX_HEAD_CONTROL_PILES:
        raise PayloadTooLarge("too many control piles in one head advance")

    async def fetch(oid):
        return await _object(store, oid)

    additions = await validate_extension_awaited(
        accepted_control,
        candidate.control,
        binding.workspace,
        binding.device,
        fetch,
        fetch,
    )
    return candidate, tuple(oid for _key, oid in additions)


async def open_accepted_pile(
        store, workspace, device, sequence,
        *, max_bytes=MAX_SEMANTIC_PILE_BYTES):
    """Open one original pile through the recipient's current accepted head."""
    if type(max_bytes) is not int \
            or not 0 < max_bytes <= MAX_SEMANTIC_PILE_BYTES:
        raise ValueError("accepted pile byte limit")
    leaf = leaf_key(sequence)
    store = async_store(store)
    key = head_slot_key(workspace, device)
    opened = await store.read_versioned(key)
    if not isinstance(opened, Versioned):
        raise ValueError("accepted writer slot is missing")
    slot = decode_slot_at(key, opened.value)
    head_raw = await _object(store, slot.head)
    decoded = decode_head(head_raw)
    head = require_bound_head(decoded, WriterBinding(
        workspace,
        device,
        decoded.owner,
        writer_store_binding(workspace, device),
    ))
    if head_oid(head_raw) != slot.head or sequence > head.sequence:
        raise ValueError("accepted writer head integrity")

    async def fetch(oid):
        return await _object(store, oid)

    answers, _pages = await merkle_map.get_many_awaited(
        head.tree.root,
        writer_tree_seed(workspace, device),
        (leaf,),
        fetch,
        max_page_depth=head.tree.depth,
        expected_count=head.tree.count,
        expected_depth=head.tree.depth,
    )
    pile_oid = answers[leaf]
    if not valid_fid(pile_oid):
        raise ValueError("accepted writer leaf is missing")
    raw = await _pile_object(store, pile_oid, max_bytes)
    decode_signed_pile(raw, workspace=workspace, writer=device)
    return raw


async def _same_pile_object(store, oid, expected_bytes):
    digest = hashlib.sha256()
    copied = await _copy_pile_object(store, oid, digest.update)
    return copied == expected_bytes and digest.hexdigest() == oid


async def ensure_pile_async(store, oid, raw):
    """Establish one large immutable pile and verify every collision."""
    if not isinstance(raw, bytes) \
            or len(raw) > MAX_SEMANTIC_PILE_BYTES \
            or not valid_fid(oid) or h(raw) != oid:
        raise ValueError("immutable pile address")
    store = async_store(store)
    unknown = None
    for _ in range(2):
        try:
            result = await store.put_if_absent("obj/" + oid, raw)
        except OutcomeUnknown as error:
            unknown = error
            continue
        if result is CREATED:
            return CREATED
        if result is not EXISTS:
            raise TypeError("conditional-create result")
        try:
            matches = await _same_pile_object(store, oid, len(raw))
        except PayloadTooLarge as error:
            raise ValueError("immutable pile conflict") from error
        if not matches:
            raise ValueError("immutable pile conflict")
        return EXISTS
    try:
        if await _same_pile_object(store, oid, len(raw)):
            return EXISTS
    except PayloadTooLarge:
        pass
    raise unknown or OSError("immutable pile was not preserved")


async def _objects(store, oids, maximum=MAX_REPOSITORY_OBJECT_BYTES):
    """Fetch a pile set through an optional bounded batch capability."""
    oids = tuple(oids)
    if maximum > MAX_REPOSITORY_OBJECT_BYTES:
        return tuple([
            await _pile_object(store, oid) for oid in oids
        ])
    get_many = getattr(store, "get_many", None)
    if not callable(get_many):
        return tuple([
            await _object(store, oid, maximum) for oid in oids
        ])
    values = await _maybe_await(get_many(
        tuple("obj/" + oid for oid in oids)))
    if not isinstance(values, (tuple, list)) or len(values) != len(oids):
        raise ValueError("repository object batch")
    return tuple(
        _checked_object(oid, raw, maximum)
        for oid, raw in zip(oids, values)
    )


def _checked_object(oid, raw, maximum):
    if not isinstance(raw, bytes) or len(raw) > maximum or h(raw) != oid:
        raise ValueError("repository object integrity")
    return raw


async def _writer_piles(source, workspace, device, rows):
    """Fetch tree-selected rows through one optional source optimizer.

    The capability receives only the exact rows proved by ``WriterTree``.
    Results are independently OID-checked here, so a physical layout cannot
    substitute, add, or reorder logical history.  Sources without the
    capability retain the ordinary loose-object batch path.
    """
    rows = tuple(rows)
    fetch = getattr(source, "fetch_writer_piles", None)
    values = NotImplemented if not callable(fetch) else await _maybe_await(
        fetch(workspace, device, rows))
    if values is NotImplemented:
        values = await _objects(
            source, (oid for _key, oid in rows),
            MAX_SEMANTIC_PILE_BYTES)
    if not isinstance(values, (tuple, list)) or len(values) != len(rows):
        raise ValueError("repository pile fetch")
    checked = []
    for (_key, oid), raw in zip(rows, values):
        if not isinstance(raw, bytes) \
                or len(raw) > MAX_SEMANTIC_PILE_BYTES \
                or h(raw) != oid:
            raise ValueError("repository object integrity")
        checked.append(raw)
    return tuple(checked)


def _require_writer_proof(evaluated, writer, owner):
    """Require one pile to carry the exact member/device writer binding."""
    valids, _current_stream = facts.semantic_evaluation(
        evaluated.judgment, evaluated.pile.facts)
    offers = {
        offer
        for valid in valids
        for offer in valid.fact.offers()
    }
    if ("member", owner, owner) not in offers or (
            writer != owner
            and ("device_key", writer, owner) not in offers):
        raise ValueError("writer is not proved by its closure")


class WriterLog:
    """Build signed piles and one final path-copied device-tree update.

    This is writer-side work. Hosted storage never invokes it: a cloud writer
    prepares locally, uploads :attr:`PreparedUpdate.objects`, then submits only
    a current-removal proof and proposed head OID to :class:`OpaqueHeadGate`.
    """

    def __init__(
            self, workspace, device, owner, store_binding, secret, store):
        if not all(valid_fid(value) for value in (
                workspace, device, owner, store_binding)):
            raise ValueError("writer log binding")
        self.workspace = workspace
        self.device = device
        self.owner = owner
        self.store_binding = store_binding
        self.secret = secret
        self.store = async_store(store)
        self.binding = WriterBinding(
            workspace, device, owner, store_binding)
        self.evaluator = ClosedPileEvaluator(workspace)

    async def _base(self):
        key = head_slot_key(self.workspace, self.device)
        versioned = await self.store.read_versioned(key)
        if versioned is ABSENT:
            return None, EMPTY_TREE
        if not isinstance(versioned, Versioned):
            raise TypeError("writer slot read")
        slot = decode_slot_at(key, versioned.value)
        if slot is None:
            raise ValueError("writer transition is pending")
        raw = await _object(self.store, slot.head)
        head = require_bound_head(decode_head(raw), self.binding)
        if head_oid(raw) != slot.head:
            raise ValueError("writer head slot integrity")
        return head, head.tree

    async def prepare(self, closures):
        """Validate and batch one or more closures under one final head."""
        closures = tuple(tuple(closure) for closure in closures)
        if not closures:
            raise ValueError("writer update needs a closed pile")
        base_head, base_tree = await self._base()
        pending = {}
        signed = []
        control_oids = []
        for closure in closures:
            pile = make_signed_pile(
                self.secret,
                self.workspace,
                self.device,
                closure,
            )
            raw = encode_signed_pile(pile)
            evaluated = self.evaluator.evaluate(raw, writer=self.device)
            _require_writer_proof(
                evaluated, self.device, self.owner)
            oid = signed_pile_oid(raw)
            try:
                updates = facts.removal_state_updates(
                    evaluated.judgment, evaluated.pile.facts)
            except ValueError:
                if facts.has_control_action_sink(
                        evaluated.judgment, evaluated.pile.facts):
                    raise ValueError(
                        "control material needs one control-only sink")
            else:
                if updates:
                    control_oids.append(oid)
            pending[oid] = raw
            signed.append(pile)

        async def fetch(oid):
            if oid in pending:
                return pending[oid]
            return await _object(self.store, oid)

        async def emit(raw):
            oid = h(raw)
            pending.setdefault(oid, raw)
            return oid

        pile_oids = tuple(signed_pile_oid(pile) for pile in signed)
        tree = await append_piles_awaited(
            base_tree,
            self.workspace,
            self.device,
            pile_oids,
            fetch,
            emit,
        )
        control = EMPTY_TREE if base_head is None else base_head.control
        if control_oids:
            control = await append_piles_awaited(
                control,
                self.workspace,
                self.device,
                tuple(control_oids),
                fetch,
                emit,
            )
        # The generic bounded updater yields every intermediate path-copy
        # page.  A writer can batch locally and establish only the pages its
        # final signed head can reach, avoiding immediate cloud orphans.
        keep = set(pile_oids) | set(reachable_staged_pages(
            tree, self.workspace, self.device, pending)) | set(
                reachable_staged_pages(
                    control, self.workspace, self.device, pending))
        pending = {
            oid: raw for oid, raw in pending.items()
            if oid in keep
        }
        head = make_head(
            self.secret,
            self.workspace,
            self.device,
            self.owner,
            tree.count,
            tree,
            self.store_binding,
            control,
        )
        raw_head = encode_head(head)
        pending[head_oid(raw_head)] = raw_head
        return PreparedUpdate(
            self.workspace,
            self.device,
            None if base_head is None else head_oid(base_head),
            tuple(signed),
            pile_oids,
            head,
            tuple(pending.items()),
        )

    async def establish(self, prepared, store=None):
        """Upload all immutables before any slot can advertise the head."""
        if not isinstance(prepared, PreparedUpdate) \
                or prepared.workspace != self.workspace \
                or prepared.device != self.device:
            raise ValueError("prepared writer update")
        target = self.store if store is None else async_store(store)
        pile_oids = set(prepared.pile_oids)
        for oid, raw in prepared.objects:
            if oid in pile_oids:
                await ensure_pile_async(target, oid, raw)
            else:
                await ensure_object_async(target, oid, raw)
        return prepared.head_oid


class OpaqueHeadGate:
    """Authorize one exact owner slot and CAS it without reading content."""

    def __init__(self, store, authorize):
        if not callable(authorize):
            raise TypeError("head authority gate")
        self.store = async_store(store)
        self.authorize = authorize

    async def advance(self, proof_raw, proposed_head, trusted_now):
        if not valid_fid(proposed_head):
            raise ValueError("proposed writer head")
        if type(trusted_now) is not int or trusted_now < 0:
            raise ValueError("trusted head time")
        grant = await _maybe_await(
            self.authorize(proof_raw, proposed_head, trusted_now))
        return await self.advance_grant(grant, proposed_head)

    async def advance_grant(self, grant, proposed_head=None):
        """CAS one ordinary already-typed grant."""
        proposed_head = grant.head \
            if isinstance(grant, HeadGrant) and proposed_head is None \
            else proposed_head
        if not isinstance(grant, HeadGrant) or grant.head != proposed_head:
            raise ValueError("authority decision did not bind proposed head")
        if not await self.store.has("obj/" + proposed_head):
            raise ValueError("proposed writer head object is missing")
        slot = HeadSlot(
            grant.workspace,
            grant.device,
            grant.head,
            grant.removal_root,
        )
        return await self._advance_slot(grant, slot)

    async def control_replay(self, grant, permit_oid):
        """Acknowledge only an exact already-finalized control transition."""
        if not isinstance(grant, HeadGrant) or not valid_fid(permit_oid):
            raise ValueError("control head replay")
        key = head_slot_key(grant.workspace, grant.device)
        opened = await self.store.read_versioned(key)
        if opened is ABSENT:
            return None
        if not isinstance(opened, Versioned):
            raise TypeError("writer slot read")
        current = decode_slot_at(key, opened.value)
        if current.head != grant.head:
            return None
        return SlotResult(
            "noop" if current.permit == permit_oid else "conflict",
            current,
        )

    async def advance_control(self, grant, permit_oid, removal_root):
        """CAS one final control slot after its ACI effects are durable."""
        if not isinstance(grant, HeadGrant) or not valid_fid(permit_oid) \
                or not valid_fid(removal_root):
            raise ValueError("control head advance")
        if not await self.store.has("obj/" + grant.head):
            raise ValueError("proposed writer head object is missing")
        return await self._advance_slot(grant, HeadSlot(
            grant.workspace,
            grant.device,
            grant.head,
            removal_root,
            permit_oid,
        ))

    async def _advance_slot(self, grant, slot):
        """Perform the sole base-guarded writer-slot CAS and reconcile it."""
        key = head_slot_key(grant.workspace, grant.device)
        raw = encode_slot(slot)
        opened = await self.store.read_versioned(key)
        if opened is ABSENT:
            if grant.base_head is not None:
                return SlotResult("conflict", slot)
            token = ABSENT
        elif isinstance(opened, Versioned):
            if opened.value == raw:
                return SlotResult("noop", slot)
            current = decode_slot_at(key, opened.value)
            # The same immutable head is already the exact successful turn.
            # A later removal-root advance must not turn a lost-response retry
            # into a conflict or rewrite the root recorded at acceptance.
            if current.head == grant.head:
                return SlotResult(
                    "noop" if current.permit == slot.permit else "conflict",
                    current,
                )
            if current.head != grant.base_head:
                return SlotResult("conflict", current)
            token = opened.token
        else:
            raise TypeError("writer slot read")
        try:
            result = await self.store.cas(key, token, raw)
        except OutcomeUnknown:
            return _reconcile_head_cas(
                await self.store.read_versioned(key),
                grant,
                slot,
                "applied",
            )
        if result is STALE:
            return _reconcile_head_cas(
                await self.store.read_versioned(key),
                grant,
                slot,
                "noop",
            )
        if not isinstance(result, Applied):
            raise TypeError("writer slot CAS")
        return SlotResult("applied", slot)


class OwnerPublisher:
    """Copy one local writer suffix, then advertise it through its owner gate.

    The target does not validate writer content.  This writer-side helper
    compares the two signed Merkle roots, establishes only the immutable
    candidate pages and closed piles needed by the suffix, establishes the
    signed head last, and finally submits a discarded current-access proof. It
    never lists or mutates another writer's slot.
    """

    def __init__(
            self, workspace, device, binding, source, target,
            make_proof, issue_permit, commit_permit, advance,
            retry_pause=None):
        if not valid_fid(workspace) or not valid_fid(device) \
                or not isinstance(binding, WriterBinding) \
                or (binding.workspace, binding.device) != (
                    workspace, device) \
                or not callable(make_proof) \
                or not callable(issue_permit) \
                or not callable(commit_permit) \
                or not callable(advance) \
                or (retry_pause is not None and not callable(retry_pause)):
            raise ValueError("owner publisher")
        self.workspace = workspace
        self.device = device
        self.binding = binding
        self.source = async_store(source)
        self.target = async_store(target)
        self.make_proof = make_proof
        self.issue_permit = issue_permit
        self.commit_permit = commit_permit
        self.advance = advance
        self.retry_pause = retry_pause or _retry_pause
        self.evaluator = ClosedPileEvaluator(workspace)

    async def publish(self):
        key = head_slot_key(self.workspace, self.device)
        local_opened = await self.source.read_versioned(key)
        if local_opened is ABSENT:
            return OwnerPublishResult("noop", None, 0, 0)
        if not isinstance(local_opened, Versioned):
            raise TypeError("local writer slot read")
        local_slot = decode_slot_at(key, local_opened.value)
        candidate_raw = await _object(self.source, local_slot.head)
        candidate = require_bound_head(
            decode_head(candidate_raw), self.binding)
        if head_oid(candidate_raw) != local_slot.head:
            raise ValueError("local writer head integrity")

        remote_opened = await self.target.read_versioned(key)
        if remote_opened is ABSENT:
            base_head, accepted_tree, accepted_control = (
                None, EMPTY_TREE, EMPTY_TREE)
        elif isinstance(remote_opened, Versioned):
            remote_slot = decode_slot_at(key, remote_opened.value)
            if remote_slot.head == local_slot.head:
                return OwnerPublishResult(
                    "noop", local_slot.head, 0, 0)
            else:
                accepted_raw = await _object(self.target, remote_slot.head)
                accepted = require_bound_head(
                    decode_head(accepted_raw), self.binding)
                if head_oid(accepted_raw) != remote_slot.head:
                    raise ValueError("remote writer head integrity")
                validate_advance(accepted, candidate, self.binding)
                base_head, accepted_tree, accepted_control = (
                    remote_slot.head, accepted.tree, accepted.control)
        else:
            raise TypeError("remote writer slot read")

        pages = {}

        async def candidate_fetch(oid):
            raw = await _object(self.source, oid)
            pages.setdefault(oid, raw)
            return raw

        async def accepted_fetch(oid):
            return await _object(self.target, oid)

        additions = await validate_extension_awaited(
            accepted_tree,
            candidate.tree,
            self.workspace,
            self.device,
            candidate_fetch,
            accepted_fetch,
        )
        control_delta = candidate.control.count - accepted_control.count
        if not 0 <= control_delta <= MAX_HEAD_CONTROL_PILES:
            raise PayloadTooLarge(
                "too many control piles in one head advance")
        declared_controls = tuple(
            oid for _key, oid in await validate_extension_awaited(
                accepted_control,
                candidate.control,
                self.workspace,
                self.device,
                candidate_fetch,
                accepted_fetch,
            )
        )
        for oid, raw in sorted(pages.items()):
            await ensure_object_async(self.target, oid, raw)
        added_piles = []
        for _leaf, oid in additions:
            raw = await _pile_object(self.source, oid)
            await ensure_pile_async(self.target, oid, raw)
            added_piles.append((oid, raw))
        # A head can be visible only after every object it names is durable.
        await ensure_object_async(
            self.target, local_slot.head, candidate_raw)

        # One recipient-issued exact permit evaluates every state-affecting
        # pile while this writer is current. Commit carries only that bounded
        # capability, applies its rows, then performs one final slot CAS.
        control_piles = []
        for oid, raw in added_piles:
            evaluated = self.evaluator.evaluate(raw, writer=self.device)
            try:
                updates = facts.removal_state_updates(
                    evaluated.judgment, evaluated.pile.facts)
            except ValueError:
                if facts.has_control_action_sink(
                        evaluated.judgment, evaluated.pile.facts):
                    raise ValueError(
                        "control material needs one control-only sink")
                continue
            if updates:
                control_piles.append((oid, raw))

        if tuple(oid for oid, _raw in control_piles) != declared_controls:
            raise ValueError("writer head control declaration")

        proof = await _maybe_await(
            self.make_proof(base_head, local_slot.head))
        if not isinstance(proof, bytes):
            raise TypeError("owner head proof")
        if control_piles:
            control_piles = tuple(raw for _oid, raw in control_piles)
            permit = await _maybe_await(self.issue_permit(
                proof, local_slot.head, control_piles))
            if not isinstance(permit, bytes):
                raise TypeError("owner control-head permit")
            for attempt in range(MAX_OWNER_CONTROL_COMMIT_ATTEMPTS):
                outcome = await _maybe_await(self.commit_permit(
                    permit, local_slot.head))
                status = getattr(outcome, "status", outcome)
                if status != "retryable":
                    break
                if attempt + 1 < MAX_OWNER_CONTROL_COMMIT_ATTEMPTS:
                    await _maybe_await(self.retry_pause(attempt))
        else:
            outcome = await _maybe_await(
                self.advance(proof, local_slot.head))
        status = getattr(outcome, "status", outcome)
        if status not in {"applied", "noop", "retryable", "conflict"}:
            raise ValueError("owner head advance result")
        return OwnerPublishResult(
            status,
            local_slot.head,
            len(pages) + 1,
            len(additions),
        )


class FactConsumer:
    """Shared closed-pile evaluator over a replaceable monotone state sink."""

    def __init__(self, workspace, state=None):
        self.workspace = workspace
        self.evaluator = ClosedPileEvaluator(workspace)
        if state is not None and not all(
                callable(getattr(state, method, None))
                for method in (
                    "commit", "fact_bytes", "fact_ids",
                    "projected_head")):
            raise TypeError("fact consumer state")
        self.state = state
        self._facts = {} if state is None else None
        self._piles = set() if state is None else None
        self._heads = {} if state is None else None

    def prepare_batch(self, values, *, owner=None):
        """Validate a candidate suffix without making any of it resident.

        A writer head is accepted as one unit.  If its fifth new pile is bad,
        the first four must not leak into the consumer merely because they
        happened to be visited first.
        """
        staged_facts = {}
        staged_piles = set()
        batch_facts, batch_piles, control_piles = {}, [], []
        for raw, writer in values:
            oid = h(raw)
            if oid in staged_piles:
                continue
            known = self.state is None and oid in self._piles
            evaluated = self.evaluator.evaluate(raw, writer=writer)
            if owner is not None:
                _require_writer_proof(evaluated, writer, owner)
            try:
                updates = facts.removal_state_updates(
                    evaluated.judgment, evaluated.pile.facts)
            except ValueError:
                if facts.has_control_action_sink(
                        evaluated.judgment, evaluated.pile.facts):
                    raise ValueError(
                        "control material needs one control-only sink")
            else:
                if updates:
                    control_piles.append(oid)
            if known:
                staged_piles.add(oid)
                continue
            for valid in evaluated.judgment.valids:
                family = facts.family_for(valid.fact.t)
                if family is None or not family.DURABLE:
                    continue
                fid, body = valid.fact.fid, encode(valid.fact)
                incumbent = staged_facts.get(fid)
                if incumbent is None:
                    incumbent = self.fact_bytes(fid)
                if incumbent is not None and incumbent != body:
                    raise ValueError("validated fact identity conflict")
                if incumbent is None:
                    staged_facts[fid] = body
                    batch_facts[fid] = body
            staged_piles.add(oid)
            batch_piles.append(oid)
        return ValidatedBatch(
            tuple(batch_piles),
            tuple(sorted(batch_facts.items())),
            tuple(sorted(control_piles)),
        )

    def commit(self, batch, *, device, head):
        """Atomically join one accepted head's already-validated suffix."""
        if not isinstance(batch, ValidatedBatch) \
                or not valid_fid(device) or not valid_fid(head):
            raise ValueError("consumer commit")
        if self.state is not None:
            return self.state.commit(
                batch, device=device, head=head)
        staged_facts = dict(self._facts)
        additions = []
        for fid, body in batch.facts:
            incumbent = staged_facts.get(fid)
            if incumbent is not None and incumbent != body:
                raise ValueError("validated fact identity conflict")
            if incumbent is None:
                staged_facts[fid] = body
                additions.append(fid)
        self._facts = staged_facts
        self._piles = self._piles | set(batch.piles)
        self._heads = {**self._heads, device: head}
        return tuple(additions)

    def consume_batch(self, values, *, device=None, head=None):
        """Convenience for a caller that already owns the commit boundary."""
        values = tuple(values)
        if device is None:
            writers = {writer for _raw, writer in values}
            if len(writers) != 1:
                raise ValueError("consumer writer")
            device = next(iter(writers))
        if head is None:
            head = h(canon([
                "poc16-standalone-consumer-batch-v1",
                tuple(h(raw) for raw, _writer in values),
            ]))
        return self.commit(
            self.prepare_batch(values), device=device, head=head)

    def consume(self, raw, *, writer):
        return self.consume_batch(((raw, writer),))

    def projected_head(self, device):
        return self._heads.get(device) if self.state is None \
            else self.state.projected_head(device)

    def fact_ids(self):
        return tuple(sorted(self._facts)) if self.state is None \
            else tuple(sorted(self.state.fact_ids()))

    def fact_bytes(self, fid):
        return self._facts.get(fid) if self.state is None \
            else self.state.fact_bytes(fid)

    def has_pile(self, oid):
        return self.state is None and oid in self._piles


class RepositoryMirror:
    """Mirror and optionally consume every changed device tree with RBSR."""

    def __init__(
            self, workspace, store, binding_for, consumer,
            *, current_binding_for=None, control_state=None,
            observe_controls=False):
        consumer_ok = consumer is None or (
            getattr(consumer, "workspace", None) == workspace
            and all(callable(getattr(consumer, method, None))
                    for method in (
                        "prepare_batch", "commit", "projected_head"))
        )
        if not valid_fid(workspace) or not callable(binding_for) \
                or not consumer_ok \
                or current_binding_for is not None \
                and not callable(current_binding_for) \
                or control_state is not None and not all(callable(
                    getattr(control_state, method, None))
                    for method in ("plan_control", "apply_plan")) \
                or type(observe_controls) is not bool \
                or control_state is not None and observe_controls:
            raise ValueError("repository mirror")
        self.workspace = workspace
        self.store = async_store(store)
        self.binding_for = binding_for
        self.current_binding_for = current_binding_for or binding_for
        self.consumer = consumer
        if control_state is None and not observe_controls \
                and consumer is not None:
            from .removal_state import RecipientRemovalState

            control_state = RecipientRemovalState(workspace, self.store)
        self.control_state = control_state
        self.observe_controls = observe_controls

    def _control_plan(self, batch, device, pile_values):
        """Evaluate peer control sinks as independently bounded local turns."""
        if batch is None or not batch.control_piles:
            return None
        if self.control_state is None:
            # Explicit read-only scanners and relays observe a source whose
            # recipient already fenced these effects. They never expose their
            # target store as an access gate. Every accepting FullPeer supplies
            # recipient-owned state instead.
            return None
        control = set(batch.control_piles)
        by_oid = {
            oid: raw for oid, raw in pile_values if oid in control
        }
        raws = tuple(by_oid[oid] for oid in sorted(by_oid))
        if set(by_oid) != control:
            raise ValueError("recipient control pile set")
        return tuple(
            self.control_state.plan_control((raw,), device)
            for raw in raws
        )

    async def _repair_local_slot(self, key, opened):
        """Replay a lagging projection from one already-final writer slot."""
        piles = fact_count = 0
        if not isinstance(opened, Versioned):
            return opened, piles, fact_count, False, True
        visible = decode_slot_at(key, opened.value)
        if self.consumer is not None and visible is not None \
                and self.consumer.projected_head(visible.device) \
                != visible.head:
            got_piles, got_facts = await self._replay_slot(key, opened)
            piles += got_piles
            fact_count += got_facts
        return opened, piles, fact_count, False, True

    async def _binding(
            self, workspace, device, removal_root, head, *, current=False):
        resolver = self.current_binding_for if current else self.binding_for
        value = resolver(
            workspace, device, removal_root, head)
        return await _maybe_await(value)

    async def _local_head(self, key, binding, opened=None):
        if opened is None:
            opened = await self.store.read_versioned(key)
        if opened is ABSENT:
            return opened, None
        if not isinstance(opened, Versioned):
            raise TypeError("writer slot read")
        slot = decode_slot_at(key, opened.value)
        raw = await _object(self.store, slot.head)
        return opened, require_bound_head(decode_head(raw), binding)

    async def _sync_slot(self, source, key, opened=None):
        workspace, device = parse_head_slot_key(key)
        if workspace != self.workspace:
            raise ValueError("writer slot workspace")
        opened = await source.read_versioned(key) \
            if opened is None else opened
        local_opened = await self.store.read_versioned(key)
        (local_opened, recovered_piles, recovered_facts,
         recovered_head, complete) = await self._repair_local_slot(
             key, local_opened)
        if not complete:
            raise ValueError("concurrent recipient control application")
        if opened is ABSENT:
            # LIST and the bundled slot read are not one transaction. A key
            # may disappear from a lagging directory view; retry it on the
            # next scan instead of diagnosing repository corruption.
            return recovered_piles, recovered_facts, recovered_head
        if not isinstance(opened, Versioned):
            raise ValueError("listed writer slot disappeared")
        slot = decode_slot_at(key, opened.value)
        source_slot_raw = encode_slot(slot)
        if isinstance(local_opened, Versioned):
            # Directory slots carry recipient-owned removal roots and permit
            # identities.  The portable synchronization top is the signed
            # writer head, so equal head OIDs are an exact no-op even when
            # those local audit fields differ.  This check must precede any
            # object fetch so unchanged reverse sync remains a zero-request
            # operation after the directory read phase.
            local_visible = decode_slot_at(key, local_opened.value)
            if local_visible.head == slot.head:
                if self.consumer is None \
                        or self.consumer.projected_head(device) == slot.head:
                    return (
                        recovered_piles,
                        recovered_facts,
                        recovered_head,
                    )
                piles, facts = await self._replay_slot(key, local_opened)
                return (
                    recovered_piles + piles,
                    recovered_facts + facts,
                    recovered_head,
                )
        source_cache = {}

        async def source_fetch(oid):
            raw = source_cache.get(oid)
            if raw is None:
                raw = await _object(source, oid)
                source_cache[oid] = raw
            await ensure_object_async(self.store, oid, raw)
            return raw

        async def local_fetch(oid):
            return await _object(self.store, oid)

        candidate_raw = await source_fetch(slot.head)
        decoded_candidate = decode_head(candidate_raw)
        binding = await self._binding(
            workspace, device, slot.removal_root, decoded_candidate,
            current=True)
        bootstrapping = binding is None
        if bootstrapping:
            # A newly joined writer's first independently closed pile is also
            # its portable identity proof. Verify the untrusted head's
            # own signature and deterministic store address first; semantic
            # membership is still required below before the slot can commit.
            binding = WriterBinding(
                workspace,
                device,
                decoded_candidate.owner,
                writer_store_binding(workspace, device),
            )
        if not isinstance(binding, WriterBinding):
            raise ValueError("unknown writer binding")
        candidate = require_bound_head(decoded_candidate, binding)
        if head_oid(candidate_raw) != slot.head:
            raise ValueError("writer head slot integrity")
        local_slot, accepted = await self._local_head(
            key, binding, local_opened)
        if bootstrapping and accepted is not None:
            raise ValueError("unknown accepted writer binding")
        if accepted is not None:
            # Directory views need not be simultaneous.  Seeing an older
            # signed head from a lagging peer is ordinary two-way sync, not a
            # request to roll the local slot back; leave it unchanged so the
            # reverse pass can advertise the newer accepted head.
            if candidate.sequence < accepted.sequence:
                return (
                    recovered_piles,
                    recovered_facts,
                    recovered_head,
                )
            delta = validate_advance(accepted, candidate, binding)
            if delta == 0:
                return (
                    recovered_piles,
                    recovered_facts,
                    recovered_head,
                )
            accepted_tree = accepted.tree
        else:
            accepted_tree = EMPTY_TREE

        additions = await validate_extension_awaited(
            accepted_tree,
            candidate.tree,
            workspace,
            device,
            source_fetch,
            local_fetch,
        )
        accepted_control = EMPTY_TREE if accepted is None \
            else accepted.control
        control_delta = candidate.control.count - accepted_control.count
        if not 0 <= control_delta <= MAX_HEAD_CONTROL_PILES:
            raise PayloadTooLarge(
                "too many control piles in one head advance")
        declared_controls = tuple(sorted({
            oid for _key, oid in await validate_extension_awaited(
                accepted_control,
                candidate.control,
                workspace,
                device,
                source_fetch,
                local_fetch,
            )
        }))
        pile_oids = tuple(pile_oid for _leaf, pile_oid in additions)
        # Do not publish a candidate pile into the local object store before
        # the complete candidate suffix passes semantic judgment.  A peer may
        # batch these immutable reads; each returned body is still checked by
        # OID and then evaluated as its own complete signed pile.
        pile_values = tuple(zip(
            pile_oids,
            await _writer_piles(
                source, workspace, device, additions),
        ))
        batch = None if self.consumer is None \
            else self.consumer.prepare_batch(
                ((raw, device) for _oid, raw in pile_values),
                owner=candidate.owner,
            )
        observed_controls = declared_controls \
            if batch is None and self.observe_controls \
            else () if batch is None else batch.control_piles
        if observed_controls != declared_controls:
            raise ValueError("writer head control declaration")
        if declared_controls and self.control_state is None \
                and not self.observe_controls:
            raise ValueError("recipient control state is required")
        if bootstrapping:
            # No auxiliary pre-sync may make an incoming head
            # valid.  The consumer just proved the exact member/device binding
            # from every independently closed pile in the candidate suffix.
            if self.consumer is None:
                raise ValueError("unknown writer binding")
        for pile_oid, raw in pile_values:
            await ensure_pile_async(self.store, pile_oid, raw)

        plans = self._control_plan(batch, device, pile_values)
        changed = True
        if plans is not None:
            base_head = None if accepted is None else head_oid(accepted)
            permit_oid = _mirror_permit_oid(
                workspace,
                device,
                base_head,
                slot.head,
                tuple(plan.updates for plan in plans),
            )
            gate = OpaqueHeadGate(self.store, lambda *_args: None)
            applied = None
            for plan in plans:
                for _attempt in range(MAX_CONTROL_APPLY_ATTEMPTS):
                    applied = await _maybe_await(
                        self.control_state.apply_plan(plan))
                    if getattr(applied, "status", None) != "retryable":
                        break
                if applied is None or applied.status == "retryable" \
                        or applied.status not in {"applied", "noop"} \
                        or not valid_fid(applied.root_oid):
                    raise ValueError(
                        "concurrent recipient control application")
            outcome = await gate.advance_control(HeadGrant(
                workspace,
                device,
                base_head,
                slot.head,
                slot.removal_root,
            ), permit_oid, applied.root_oid)
            if outcome.status not in {"applied", "noop"}:
                raise ValueError("concurrent local writer-slot update")
            changed = outcome.status == "applied"
        else:
            token = ABSENT if local_slot is ABSENT else local_slot.token
            result = await self.store.cas(key, token, source_slot_raw)
            if result is STALE:
                raise ValueError("concurrent local writer-slot update")
            if not isinstance(result, Applied):
                raise TypeError("writer slot CAS")
        fact_count = 0 if self.consumer is None else len(
            self.consumer.commit(
                batch, device=device, head=slot.head))
        return (
            recovered_piles + len(additions),
            recovered_facts + fact_count,
            recovered_head or changed,
        )

    async def _replay_slot(self, key, opened=None):
        """Repair SQL from one slot whose acceptance is already durable.

        The local slot is the admission certificate.  Rebuild must not need
        a historical authority root (or current membership) to replay content
        that this repository already accepted.
        """
        if self.consumer is None:
            return 0, 0
        workspace, device = parse_head_slot_key(key)
        if workspace != self.workspace:
            raise ValueError("writer slot workspace")
        opened = await self.store.read_versioned(key) \
            if opened is None else opened
        if not isinstance(opened, Versioned):
            raise ValueError("accepted writer slot disappeared")
        slot = decode_slot_at(key, opened.value)
        candidate_raw = await _object(self.store, slot.head)
        decoded_candidate = decode_head(candidate_raw)
        # The slot was installed only after this exact immutable head passed
        # the normal authority and extension checks.  Its signed binding is
        # therefore part of the durable accepted value; reconstruction uses
        # the protocol-derived store address and must not consult mutable
        # present-day authority.
        binding = WriterBinding(
            workspace,
            device,
            decoded_candidate.owner,
            writer_store_binding(workspace, device),
        )
        candidate = require_bound_head(decoded_candidate, binding)
        if head_oid(candidate_raw) != slot.head:
            raise ValueError("writer head slot integrity")

        previous_oid = self.consumer.projected_head(device)
        if previous_oid is None:
            accepted_tree = EMPTY_TREE
        else:
            previous_raw = await _object(self.store, previous_oid)
            previous = require_bound_head(
                decode_head(previous_raw), binding)
            validate_advance(previous, candidate, binding)
            accepted_tree = previous.tree

        async def fetch(oid):
            return await _object(self.store, oid)

        additions = await validate_extension_awaited(
            accepted_tree,
            candidate.tree,
            workspace,
            device,
            fetch,
            fetch,
        )
        pile_values = []
        for _leaf, pile_oid in additions:
            pile_values.append((
                pile_oid, await _pile_object(self.store, pile_oid)))
        batch = self.consumer.prepare_batch(
            ((raw, device) for _oid, raw in pile_values),
            owner=candidate.owner,
        )
        # The accepted slot already certifies that recipient control effects
        # preceded visibility. Projection rebuild replays SQL only.
        facts = self.consumer.commit(
            batch, device=device, head=slot.head)
        return len(additions), len(facts)

    async def replay_local(self, *, page_limit=256):
        """Replay every lagging projection from final local slots."""
        if self.consumer is None:
            return MirrorResult(0, 0, 0, 0, ())
        prefix = head_slot_prefix(self.workspace)
        cursor = None
        listed = changed = piles = fact_count = 0
        errors = []
        while True:
            page = await self.store.list_page(prefix, cursor, page_limit)
            listed += len(page.keys)
            for key in page.keys:
                try:
                    workspace, device = parse_head_slot_key(key)
                    opened = await self.store.read_versioned(key)
                    if not isinstance(opened, Versioned):
                        raise ValueError("accepted writer slot disappeared")
                    prior = self.consumer.projected_head(device)
                    (opened, got_piles, got_facts,
                     accepted, complete) = await self._repair_local_slot(
                         key, opened)
                    if not complete:
                        raise ValueError(
                            "concurrent recipient control application")
                    piles += got_piles
                    fact_count += got_facts
                    changed += int(
                        accepted
                        or self.consumer.projected_head(device) != prior)
                except ValueError as error:
                    errors.append((key, str(error)))
            if page.cursor is None:
                break
            cursor = page.cursor
        return MirrorResult(
            listed, changed, piles, fact_count, tuple(errors))

    async def accept_slot(self, raw):
        """Validate one staged P2P candidate through the normal mirror path.

        Immutable objects already arrived through create-only PUTs.  This
        transient source substitutes only the proposed slot bytes; all object
        reads and the final accepted-slot CAS still use this mirror's store.
        """
        slot = decode_slot(raw)
        key = head_slot_key(slot.workspace, slot.device)
        target = self.store

        class CandidateSource:
            async def get_bounded(self, candidate_key, maximum):
                return await target.get_bounded(candidate_key, maximum)

            async def copy_pile_object(self, oid, maximum, write):
                return await target.copy_pile_object(oid, maximum, write)

            async def read_versioned(self, candidate_key):
                if candidate_key == key:
                    return Versioned(raw, VersionToken(h(raw)))
                return await target.read_versioned(candidate_key)

            async def put_if_absent(self, candidate_key, value):
                return await target.put_if_absent(candidate_key, value)

            async def cas(self, candidate_key, token, value):
                return await target.cas(candidate_key, token, value)

            async def list_page(self, prefix, cursor=None, limit=256):
                return await target.list_page(prefix, cursor, limit)

        piles, fact_count, changed = await self._sync_slot(
            CandidateSource(), key)
        return MirrorResult(
            1, int(changed), piles, fact_count, ())

    @staticmethod
    async def _open_slots(source, keys):
        """Open one bounded directory page as a single read phase.

        Sources may collapse the phase into one provider/HTTP batch.  The
        fallback starts every independent slot read before processing any
        writer, so network latency is one bounded wave rather than one RTT
        per workspace member.  Applying and projecting the returned slots
        remains deliberately serialized below.
        """
        keys = tuple(keys)
        read_many = getattr(source, "read_many_versioned", None)
        if callable(read_many):
            opened = await _maybe_await(read_many(keys))
        else:
            from asyncio import gather

            opened = await gather(*(
                source.read_versioned(key) for key in keys),
                return_exceptions=True)
        if not isinstance(opened, (tuple, list)) \
                or len(opened) != len(keys):
            raise ValueError("writer slot batch")
        return tuple(opened)

    async def sync_from(self, source_store, *, page_limit=256):
        if type(page_limit) is not int \
                or not 0 < page_limit <= PAGE_BATCH:
            raise ValueError("writer directory page limit")
        source = async_store(source_store)
        prefix = head_slot_prefix(self.workspace)
        cursor = None
        listed = changed = piles = fact_count = 0
        errors = []
        while True:
            page = await source.list_page(prefix, cursor, page_limit)
            if len(page.keys) > page_limit:
                raise ValueError("writer directory page overflow")
            listed += len(page.keys)
            # Head discovery is one bounded read wave.  Do not run complete
            # `_sync_slot` calls concurrently: the optional projection sink
            # is one transactionally ordered local state machine.
            opened_page = await self._open_slots(source, page.keys)
            for key, opened in zip(page.keys, opened_page):
                try:
                    if isinstance(opened, BaseException):
                        raise opened
                    got_piles, got_facts, did_change = await self._sync_slot(
                        source, key, opened)
                    piles += got_piles
                    fact_count += got_facts
                    changed += int(did_change)
                except ValueError as error:
                    errors.append((key, str(error)))
            if page.cursor is None:
                break
            cursor = page.cursor
        return MirrorResult(
            listed, changed, piles, fact_count, tuple(errors))


__all__ = (
    "FactConsumer",
    "HeadGrant",
    "MirrorResult",
    "OpaqueHeadGate",
    "OwnerPublishResult",
    "OwnerPublisher",
    "PreparedUpdate",
    "RepositoryMirror",
    "SlotResult",
    "ValidatedBatch",
    "WriterLog",
    "open_accepted_pile",
)
