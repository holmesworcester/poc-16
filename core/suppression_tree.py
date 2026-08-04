"""Private authenticated point map for suppression and removal state.

The logical map is ``suppression id -> CLEAR | ACTIVE(action_fid)``.  Its
keys are SHA-256 hashes bound to one workspace and format domain.  A compact
binary Patricia tree gives a history-independent shape with exactly one
value per leaf and at most ``2n - 1`` nodes.  Inclusion proofs disclose only
the requested key hash/value and one opaque sibling commitment per branch.

The mutable root lives at ``removal`` and immutable nodes live at
``removal-node/<sha256>``.  These keys are deliberately outside ``obj/`` and
``pack/``: only the authority engine receives the backing-store capability.
Ordinary HTTP reads, direct-object grants, and public object LISTs therefore
cannot turn a root commitment into a traversal capability.
"""

from dataclasses import dataclass, field

from .crypto import h
from .fact import canon
from .indexes import checked_suppression_slot
from .limits import (
    MAX_REMOVAL_NODE_BYTES,
    MAX_REMOVAL_PROOF_BYTES,
    MAX_REMOVAL_PROOF_STEPS,
    MAX_REMOVAL_ROOT_BYTES,
    MAX_REMOVAL_UPDATES,
    MAX_SUPPRESSION_ID_BYTES,
    PayloadTooLarge,
    decode_json,
    valid_bounded_text,
)
from .object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    REMOVAL_NODE_PREFIX,
    REMOVAL_ROOT_KEY,
    STALE,
    Applied,
    OutcomeUnknown,
    Versioned,
    VersionToken,
    async_store,
)
from .shape import valid_fid


KEY_FORMAT = "poc16-private-suppression-key-v1"
NODE_FORMAT = "poc16-private-suppression-node-v1"
ROOT_FORMAT = "poc16-private-suppression-root-v1"
PROOF_FORMAT = "poc16-private-suppression-proof-v1"
KEY_BITS = 256
MAX_MAP_ROWS = (1 << 53) - 1

if KEY_BITS != MAX_REMOVAL_PROOF_STEPS:
    raise RuntimeError("private suppression proof geometry")


@dataclass(frozen=True, slots=True)
class Root:
    workspace: str
    root: str
    count: int


@dataclass(frozen=True, slots=True)
class Built:
    """One root proposal and its newly required private immutable nodes."""

    root: bytes
    nodes: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class ApplyResult:
    """One exact private-root CAS outcome."""

    status: str
    root: bytes | None


@dataclass(frozen=True, slots=True)
class _Leaf:
    key: str
    value: dict


@dataclass(frozen=True, slots=True)
class _Branch:
    bit: int
    left: str
    right: str


@dataclass(frozen=True, slots=True)
class _Frame:
    node: _Branch
    right: bool
    oid: str


@dataclass(frozen=True, slots=True)
class _Proof:
    root: str
    key: str
    value: dict
    path: tuple[tuple[int, str], ...]


def _suppression_id(sid):
    if not valid_bounded_text(sid, MAX_SUPPRESSION_ID_BYTES):
        raise ValueError("suppression id")
    return sid


def logical_key(workspace, sid):
    """Hash one logical id in an exact workspace and format domain."""
    if not valid_fid(workspace):
        raise ValueError("suppression workspace")
    return h(canon([KEY_FORMAT, workspace, _suppression_id(sid)]))


def private_node_key(oid):
    """Return the internal-only content address for one removal node."""
    if not valid_fid(oid):
        raise ValueError("private suppression node id")
    return REMOVAL_NODE_PREFIX + oid


def _slot(value):
    return dict(checked_suppression_slot(value))


def join_slots(left, right):
    """ACI join for one self-contained current suppression cell.

    ``None`` is absence, CLEAR reserves a known cell, and an ACTIVE action is
    irreversible. Concurrent actions converge on their minimum immutable fid
    without fetching or retaining either action fact merely to rank a retry.
    """
    if left is None and right is None:
        return None
    if left is None:
        return _slot(right)
    if right is None:
        return _slot(left)
    left, right = _slot(left), _slot(right)
    if left["state"] == "clear":
        return right
    if right["state"] == "clear":
        return left
    return {
        "action": min(left["action"], right["action"]),
        "state": "active",
    }


def _leaf_raw(workspace, key, value):
    if not valid_fid(workspace) or not valid_fid(key):
        raise ValueError("private suppression leaf")
    return _node_raw({
        "format": NODE_FORMAT,
        "key": key,
        "kind": "leaf",
        "value": _slot(value),
        "workspace": workspace,
    })


def _branch_raw(workspace, bit, left, right):
    if not valid_fid(workspace) \
            or type(bit) is not int or not 0 <= bit < KEY_BITS \
            or not valid_fid(left) or not valid_fid(right) or left == right:
        raise ValueError("private suppression branch")
    return _node_raw({
        "bit": bit,
        "format": NODE_FORMAT,
        "kind": "branch",
        "left": left,
        "right": right,
        "workspace": workspace,
    })


def _node_raw(document):
    raw = canon(document)
    if len(raw) > MAX_REMOVAL_NODE_BYTES:
        raise PayloadTooLarge("private suppression node too large")
    return raw


def _decode_node(raw, workspace):
    value = decode_json(raw, MAX_REMOVAL_NODE_BYTES, "suppression node")
    if not isinstance(value, dict) or canon(value) != raw \
            or value.get("format") != NODE_FORMAT \
            or value.get("workspace") != workspace:
        raise ValueError("private suppression node")
    if value.get("kind") == "leaf" and set(value) == {
            "format", "key", "kind", "value", "workspace"} \
            and raw == _leaf_raw(
                workspace, value.get("key"), value.get("value")):
        return _Leaf(value["key"], value["value"])
    if value.get("kind") == "branch" and set(value) == {
            "bit", "format", "kind", "left", "right", "workspace"}:
        if raw != _branch_raw(
                workspace, value["bit"], value["left"], value["right"]):
            raise ValueError("private suppression branch")
        return _Branch(value["bit"], value["left"], value["right"])
    raise ValueError("private suppression node")


def _opened_node(oid, raw, workspace):
    if not isinstance(raw, bytes) or h(raw) != oid:
        raise ValueError("private suppression node integrity")
    node = _decode_node(raw, workspace)
    if node is None:
        raise ValueError("private suppression node")
    return node


def encode_root(workspace, root="", count=0):
    """Encode the exact small value stored in the private root CAS cell."""
    if not valid_fid(workspace) or not isinstance(root, str) \
            or root and not valid_fid(root) \
            or type(count) is not int or not 0 <= count <= MAX_MAP_ROWS \
            or bool(root) != bool(count):
        raise ValueError("private suppression root")
    raw = canon({
        "count": count,
        "format": ROOT_FORMAT,
        "root": root,
        "workspace": workspace,
    })
    if len(raw) > MAX_REMOVAL_ROOT_BYTES:
        raise PayloadTooLarge("private suppression root too large")
    return raw


def decode_root(raw, workspace=None):
    """Decode one canonical private root and optionally bind its workspace."""
    value = decode_json(raw, MAX_REMOVAL_ROOT_BYTES, "suppression root")
    if not isinstance(value, dict) or set(value) != {
            "count", "format", "root", "workspace"} \
            or value.get("format") != ROOT_FORMAT \
            or not valid_fid(value.get("workspace")) \
            or workspace is not None and value["workspace"] != workspace:
        raise ValueError("private suppression root")
    checked = encode_root(value["workspace"], value["root"], value["count"])
    if checked != raw:
        raise ValueError("private suppression root")
    return Root(value["workspace"], value["root"], value["count"])


def _proof_document(root_oid, key, value, path):
    if not valid_fid(root_oid) or not valid_fid(key):
        raise ValueError("private suppression proof")
    path = tuple(path)
    if len(path) > MAX_REMOVAL_PROOF_STEPS:
        raise PayloadTooLarge("private suppression proof path")
    previous = -1
    checked = []
    for bit, sibling in path:
        if type(bit) is not int or not previous < bit < KEY_BITS \
                or not valid_fid(sibling):
            raise ValueError("private suppression proof path")
        checked.append([bit, sibling])
        previous = bit
    return {
        "format": PROOF_FORMAT,
        "key": key,
        "path": checked,
        "root": root_oid,
        "value": _slot(value),
    }


def _encode_proof(root_oid, key, value, path):
    raw = canon(_proof_document(root_oid, key, value, path))
    if len(raw) > MAX_REMOVAL_PROOF_BYTES:
        raise PayloadTooLarge("private suppression proof too large")
    return raw


def _decode_proof(raw):
    value = decode_json(raw, MAX_REMOVAL_PROOF_BYTES, "suppression proof")
    if not isinstance(value, dict) or set(value) != {
            "format", "key", "path", "root", "value"} \
            or value.get("format") != PROOF_FORMAT \
            or not isinstance(value.get("path"), list):
        raise ValueError("private suppression proof")
    try:
        path = tuple(
            tuple(frame) if isinstance(frame, list) else frame
            for frame in value["path"]
        )
        checked = _proof_document(
            value["root"], value["key"], value["value"], path)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("private suppression proof") from error
    if checked != value or canon(value) != raw:
        raise ValueError("private suppression proof")
    return _Proof(
        value["root"], value["key"], _slot(value["value"]), path)


def _bit(key, index):
    nibble = int(key[index // 4], 16)
    return (nibble >> (3 - index % 4)) & 1


def _different_bit(left, right):
    if left == right:
        raise ValueError("duplicate private suppression key")
    return KEY_BITS - (int(left, 16) ^ int(right, 16)).bit_length()


def _materialize(workspace, rows, maximum=None):
    if isinstance(rows, dict):
        rows = rows.items()
    try:
        rows = tuple(rows)
    except TypeError as error:
        raise ValueError("private suppression rows") from error
    if maximum is not None and len(rows) > maximum:
        raise PayloadTooLarge("too many private suppression updates")
    by_sid, keys = {}, {}
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            raise ValueError("private suppression row")
        sid, value = row
        sid = _suppression_id(sid)
        key = logical_key(workspace, sid)
        incumbent_sid = keys.setdefault(key, sid)
        if incumbent_sid != sid:
            raise ValueError("suppression key collision")
        by_sid[sid] = join_slots(by_sid.get(sid), value)
    return tuple(sorted(
        (logical_key(workspace, sid), value)
        for sid, value in by_sid.items()
    ))


def _collector():
    pending = {}

    def emit(raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_REMOVAL_NODE_BYTES:
            raise ValueError("private suppression node bytes")
        oid = h(raw)
        incumbent = pending.setdefault(oid, raw)
        if incumbent != raw:
            raise ValueError("private suppression node collision")
        return oid

    return pending, emit


def _build(workspace, rows):
    """Build the canonical history-independent private tree from rows."""
    if not valid_fid(workspace):
        raise ValueError("suppression workspace")
    checked = _materialize(workspace, rows)
    pending, emit = _collector()

    def subtree(start, stop):
        if stop - start == 1:
            key, value = checked[start]
            return emit(_leaf_raw(workspace, key, value))
        bit = _different_bit(checked[start][0], checked[stop - 1][0])
        middle = start + 1
        while middle < stop and _bit(checked[middle][0], bit) == 0:
            middle += 1
        if middle == start or middle == stop:
            raise ValueError("private suppression partition")
        left = subtree(start, middle)
        right = subtree(middle, stop)
        return emit(_branch_raw(workspace, bit, left, right))

    root = "" if not checked else subtree(0, len(checked))
    return Built(
        encode_root(workspace, root, len(checked)),
        tuple(sorted(pending.items())),
    )


async def _walk(root, workspace, key, count, fetch):
    path, current, previous = [], root, -1
    while True:
        raw = await fetch(current)
        node = _opened_node(current, raw, workspace)
        if isinstance(node, _Leaf):
            if len(path) >= count:
                raise ValueError("private suppression root count")
            return tuple(path), node, current
        if len(path) >= MAX_REMOVAL_PROOF_STEPS or len(path) >= count \
                or node.bit <= previous:
            raise ValueError("private suppression path")
        right = bool(_bit(key, node.bit))
        path.append(_Frame(node, right, current))
        current = node.right if right else node.left
        previous = node.bit


def _rewrite(workspace, key, value, root_oid, walked, emit):
    path, leaf, leaf_oid = walked
    if leaf.key == key:
        value = join_slots(leaf.value, value)
        if leaf.value == value:
            return root_oid, False
        current = emit(_leaf_raw(workspace, key, value))
        prefix = path
        added = False
    else:
        bit = _different_bit(key, leaf.key)
        insert = next(
            (index for index, frame in enumerate(path)
             if frame.node.bit > bit),
            len(path),
        )
        existing = path[insert].oid if insert < len(path) else leaf_oid
        fresh = emit(_leaf_raw(workspace, key, value))
        if _bit(key, bit) == _bit(leaf.key, bit):
            raise ValueError("private suppression insertion")
        left, right = (fresh, existing) if _bit(key, bit) == 0 \
            else (existing, fresh)
        current = emit(_branch_raw(workspace, bit, left, right))
        prefix = path[:insert]
        added = True

    for frame in reversed(prefix):
        node = frame.node
        left, right = (node.left, current) if frame.right \
            else (current, node.right)
        current = emit(_branch_raw(
            workspace, node.bit, left, right))
    return current, added


async def _update(workspace, root_bytes, changes, fetch):
    """Path-copy one bounded deterministic batch against a pinned root."""
    root = decode_root(root_bytes, workspace)
    checked = _materialize(workspace, changes, MAX_REMOVAL_UPDATES)
    pending, emit = _collector()
    current, count = root.root, root.count

    async def available(oid):
        return pending[oid] if oid in pending else await fetch(oid)

    for key, value in checked:
        if not current:
            current = emit(_leaf_raw(workspace, key, value))
            count = 1
            continue
        current, added = _rewrite(
            workspace, key, value, current,
            await _walk(
                current, workspace, key, count, available),
            emit,
        )
        count += int(added)
    return Built(
        encode_root(workspace, current, count),
        tuple(sorted(pending.items())),
    )


async def _prove(root_bytes, sid, fetch):
    """Return one non-enumerating inclusion proof, or ``None`` if absent."""
    root = decode_root(root_bytes)
    key = logical_key(root.workspace, sid)
    if not root.root:
        return None
    path, leaf, _ = await _walk(
        root.root, root.workspace, key, root.count, fetch)
    if leaf.key != key:
        return None
    siblings = tuple(
        (frame.node.bit,
         frame.node.left if frame.right else frame.node.right)
        for frame in path
    )
    return _encode_proof(h(root_bytes), key, leaf.value, siblings)


def verify(root_bytes, workspace, sid, proof_bytes):
    """Verify exactly one value against one caller-pinned private root."""
    root = decode_root(root_bytes, workspace)
    proof = _decode_proof(proof_bytes)
    key = logical_key(workspace, sid)
    if not root.root or proof.root != h(root_bytes) or proof.key != key \
            or len(proof.path) >= root.count:
        raise ValueError("private suppression proof binding")
    current = h(_leaf_raw(workspace, key, proof.value))
    for bit, sibling in reversed(proof.path):
        left, right = (current, sibling) if _bit(key, bit) == 0 \
            else (sibling, current)
        current = h(_branch_raw(workspace, bit, left, right))
    if current != root.root:
        raise ValueError("private suppression proof root")
    return _slot(proof.value)


async def _ensure_node(store, oid, raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_REMOVAL_NODE_BYTES \
            or h(raw) != oid:
        raise ValueError("private suppression node address")
    key = private_node_key(oid)
    unknown = None
    for _ in range(2):
        try:
            result = await store.put_if_absent(key, raw)
        except OutcomeUnknown as error:
            unknown = error
            incumbent = await store.get_bounded(key, MAX_REMOVAL_NODE_BYTES)
            if incumbent == raw:
                return EXISTS
            if incumbent is not None:
                raise ValueError("private suppression node conflict") \
                    from error
            continue
        if result is CREATED:
            return CREATED
        if result is not EXISTS:
            raise TypeError("private node conditional-create result")
        incumbent = await store.get_bounded(key, MAX_REMOVAL_NODE_BYTES)
        if incumbent != raw:
            raise ValueError("private suppression node conflict")
        return EXISTS
    raise unknown


@dataclass(frozen=True, slots=True)
class SuppressionPin:
    """One exact root read and its private point-proof capability."""

    workspace: str
    root_bytes: bytes
    root_oid: str
    version: VersionToken
    _store: object = field(repr=False, compare=False)

    def __post_init__(self):
        decode_root(self.root_bytes, self.workspace)
        if self.root_oid != h(self.root_bytes) \
                or not isinstance(self.version, VersionToken):
            raise ValueError("private suppression pin")
        object.__setattr__(self, "_store", async_store(self._store))

    async def proof(self, sid):
        async def fetch(oid):
            return await self._store.get_bounded(
                private_node_key(oid), MAX_REMOVAL_NODE_BYTES)

        return await _prove(self.root_bytes, sid, fetch)

    def verify(self, sid, proof_bytes):
        return verify(self.root_bytes, self.workspace, sid, proof_bytes)


class SuppressionTree:
    """The sole private-store/CAS owner for recipient suppression state."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("suppression workspace")
        self.workspace = workspace
        self.store = async_store(store)

    async def pin(self):
        opened = await self.store.read_versioned(REMOVAL_ROOT_KEY)
        if opened is ABSENT:
            return None
        if not isinstance(opened, Versioned):
            raise TypeError("private suppression root read")
        decode_root(opened.value, self.workspace)
        return SuppressionPin(
            self.workspace,
            opened.value,
            h(opened.value),
            opened.token,
            self.store,
        )

    async def apply(self, changes):
        """Convenience turn that pins current state, then calls ``apply_at``."""
        pin = await self.pin()
        return await self.apply_at(ABSENT if pin is None else pin, changes)

    async def apply_at(self, pin, changes):
        """Join changes only if ``pin`` is still the exact current root.

        Authority validation can read through one :class:`SuppressionPin` and
        pass that same pin here. A concurrent removal then makes this turn
        retryable; it can never be silently rebased onto authority the caller
        did not validate.
        """
        if isinstance(changes, dict):
            changes = tuple(changes.items())
        else:
            try:
                changes = tuple(changes)
            except TypeError as error:
                raise ValueError("private suppression updates") from error
        if len(changes) > MAX_REMOVAL_UPDATES:
            raise PayloadTooLarge("too many private suppression updates")
        if pin is ABSENT:
            base_root, token = None, ABSENT
        elif isinstance(pin, SuppressionPin) \
                and pin.workspace == self.workspace \
                and pin._store is self.store:
            base_root, token = pin.root_bytes, pin.version
        else:
            raise ValueError("foreign private suppression pin")

        current = await self.store.read_versioned(REMOVAL_ROOT_KEY)
        exact = current is ABSENT if pin is ABSENT else (
            isinstance(current, Versioned)
            and current.token == token and current.value == base_root)
        if not exact:
            return ApplyResult("retryable", base_root)
        if not changes:
            return ApplyResult("noop", base_root)

        async def fetch(oid):
            return await self.store.get_bounded(
                private_node_key(oid), MAX_REMOVAL_NODE_BYTES)

        built = _build(self.workspace, changes) if base_root is None \
            else await _update(
                self.workspace, base_root, changes, fetch)
        for oid, raw in built.nodes:
            await _ensure_node(self.store, oid, raw)

        if built.root == base_root:
            current = await self.store.read_versioned(REMOVAL_ROOT_KEY)
            if not isinstance(current, Versioned) \
                    or current.token != token or current.value != base_root:
                return ApplyResult("retryable", base_root)
            return ApplyResult("noop", built.root)
        try:
            result = await self.store.cas(
                REMOVAL_ROOT_KEY, token, built.root)
        except OutcomeUnknown:
            current = await self.store.read_versioned(REMOVAL_ROOT_KEY)
            if isinstance(current, Versioned) \
                    and current.value == built.root:
                return ApplyResult("applied", built.root)
            return ApplyResult("retryable", base_root)
        if result is STALE:
            return ApplyResult("retryable", base_root)
        if not isinstance(result, Applied):
            raise TypeError("private suppression CAS result")
        return ApplyResult("applied", built.root)


__all__ = (
    "ApplyResult",
    "SuppressionPin",
    "SuppressionTree",
    "join_slots",
    "verify",
)
