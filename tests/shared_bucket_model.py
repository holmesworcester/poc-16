"""Executable small-state model for concurrent shared-bucket publication.

The model deliberately has only three durable structures:

    O : oid -> immutable bytes       a grow-only map
    R : one opaque composite root    an atomic CAS register
    H : successful roots             the observable commit history

A snapshot has independent manifest and index objects over the same immutable
leaves.  That is enough structure to expose missing objects, split root
generations, destructive writes, stale publication bases, and mixed reads
without reproducing the production tree implementation.
"""
from collections import deque
from dataclasses import dataclass, replace
import json

from core.crypto import h
from core.fact import canon
from core.shape import valid_fid


def _leaf(token):
    return canon({"kind": "leaf", "token": token})


def _branch(kind, children):
    return canon({"children": list(children), "kind": kind})


def _root(manifest_oid, index_oid):
    return canon({"index": index_oid, "manifest": manifest_oid})


@dataclass(frozen=True)
class Bundle:
    root: bytes
    objects: tuple


def compile_bundle(tokens):
    """Compile one logical token set into a deterministic closed snapshot."""
    leaves = tuple((h(raw), raw) for raw in map(_leaf, sorted(tokens)))
    children = tuple(oid for oid, _ in leaves)
    manifest = _branch("manifest", children)
    index = _branch("index", children)
    objects = leaves + ((h(manifest), manifest), (h(index), index))
    return Bundle(_root(h(manifest), h(index)), objects)


def branch_children(root, name, objects):
    """Fetch and validate one branch through one exact root value."""
    root_value = json.loads(root)
    if not isinstance(root_value, dict) or set(root_value) != {
            "index", "manifest"}:
        raise ValueError("root shape")
    oid = root_value[name]
    if not valid_fid(oid) or oid not in objects or h(objects[oid]) != oid:
        raise ValueError("root closure")
    value = json.loads(objects[oid])
    if value.get("kind") != name or set(value) != {"children", "kind"} \
            or not isinstance(value["children"], list):
        raise ValueError("branch shape")
    return tuple(value["children"])


def leaf_tokens(children, objects):
    """Decode one hash-checked logical leaf set."""
    tokens = []
    for oid in children:
        if not valid_fid(oid) or oid not in objects or h(objects[oid]) != oid:
            raise ValueError("leaf closure")
        value = json.loads(objects[oid])
        if set(value) != {"kind", "token"} or value["kind"] != "leaf" \
                or not isinstance(value["token"], str):
            raise ValueError("leaf shape")
        tokens.append(value["token"])
    if tokens != sorted(set(tokens)):
        raise ValueError("logical token order")
    return frozenset(tokens)


def snapshot_tokens(root, objects):
    """Validate and decode one complete composite snapshot."""
    branches = [
        branch_children(root, name, objects)
        for name in ("manifest", "index")
    ]
    if branches[0] != branches[1]:
        raise ValueError("split root generation")
    return leaf_tokens(branches[0], objects)


@dataclass(frozen=True)
class Writer:
    name: str
    token: str
    phase: str = "ready"
    base: bytes | None = None
    expected: str | None = None
    bundle: Bundle | None = None
    offset: int = 0
    crashes_left: int = 1


@dataclass(frozen=True)
class Reader:
    phase: str = "ready"
    pinned: bytes | None = None
    used_etags: tuple = ()
    manifest: tuple = ()
    result: frozenset | None = None
    error: str | None = None


@dataclass(frozen=True)
class State:
    objects: tuple
    root: bytes
    history: tuple
    commits: tuple
    writers: tuple
    reader: Reader

    def object_map(self):
        return dict(self.objects)


@dataclass(frozen=True)
class Protocol:
    """Mutation switches are used to prove that the laws are non-vacuous."""

    root_before_objects: bool = False
    split_root: bool = False
    reader_repins: bool = False
    non_atomic_cas: bool = False
    overwrite_object: bool = False


@dataclass(frozen=True)
class Action:
    actor: str
    verb: str

    def __str__(self):
        return f"{self.actor}.{self.verb}"


@dataclass(frozen=True)
class Counterexample:
    law: str
    schedule: tuple


@dataclass(frozen=True)
class Exploration:
    states: int
    terminals: tuple
    counterexample: Counterexample | None


def initial_state():
    bundle = compile_bundle({"base"})
    return State(
        tuple(sorted(bundle.objects)),
        bundle.root,
        (bundle.root,),
        (),
        (Writer("A", "a"), Writer("B", "b")),
        Reader(),
    )


def _replace_writer(state, changed):
    writers = tuple(
        changed if writer.name == changed.name else writer
        for writer in state.writers
    )
    return replace(state, writers=writers)


def enabled(state, *, crashes=False):
    actions = []
    for writer in state.writers:
        verb = {
            "ready": "read",
            "built": "build",
            "put": "put",
            "cas": "cas",
            "check": "check",
            "swap": "swap",
            "retry": "retry",
            "ack": "ack",
            "crashed": "restart",
        }.get(writer.phase)
        if verb:
            actions.append(Action(writer.name, verb))
        if crashes and writer.crashes_left and writer.phase not in {
                "done", "crashed", "ready"}:
            actions.append(Action(writer.name, "crash"))
    if state.reader.phase == "ready":
        actions.append(Action("R", "open"))
    elif state.reader.phase == "open":
        actions.append(Action("R", "manifest"))
    elif state.reader.phase == "index":
        actions.append(Action("R", "index"))
    return tuple(actions)


def step(state, action, protocol=Protocol()):
    """Apply one atomic model action."""
    if action.actor == "R":
        if action.verb == "open" and state.reader.phase == "ready":
            return replace(
                state, reader=Reader("open", pinned=state.root))
        if action.verb == "manifest" and state.reader.phase == "open":
            try:
                children = branch_children(
                    state.reader.pinned, "manifest", state.object_map())
                error = None
            except ValueError as exc:
                children, error = (), str(exc)
            reader = Reader(
                "index" if error is None else "done",
                state.reader.pinned,
                (h(state.reader.pinned),),
                children,
                None,
                error,
            )
            return replace(state, reader=reader)
        if action.verb == "index" and state.reader.phase == "index":
            raw = state.root if protocol.reader_repins \
                else state.reader.pinned
            try:
                children = branch_children(
                    raw, "index", state.object_map())
                result = leaf_tokens(children, state.object_map())
                error = None
            except ValueError as exc:
                result, error = None, str(exc)
            reader = Reader(
                "done",
                state.reader.pinned,
                state.reader.used_etags + (h(raw),),
                state.reader.manifest,
                result,
                error,
            )
            return replace(state, reader=reader)
        raise ValueError(f"disabled action {action}")

    writer = next(
        candidate for candidate in state.writers
        if candidate.name == action.actor)
    objects = state.object_map()

    if action.verb == "read" and writer.phase == "ready":
        current = snapshot_tokens(state.root, objects)
        if writer.token in current:
            changed = replace(writer, phase="ack")
        else:
            changed = replace(
                writer, phase="built", base=state.root,
                expected=h(state.root))
        return _replace_writer(state, changed)

    if action.verb == "build" and writer.phase == "built":
        tokens = snapshot_tokens(writer.base, objects) | {writer.token}
        bundle = compile_bundle(tokens)
        phase = "cas" if protocol.root_before_objects else "put"
        return _replace_writer(
            state, replace(writer, phase=phase, bundle=bundle, offset=0))

    if action.verb == "put" and writer.phase == "put":
        oid, raw = writer.bundle.objects[writer.offset]
        previous = objects.get(oid)
        if previous is not None and previous != raw:
            raise ValueError("immutable object clobber")
        if protocol.overwrite_object and previous is not None:
            objects[oid] = b"destructive overwrite"
        else:
            objects.setdefault(oid, raw)
        offset = writer.offset + 1
        if offset == len(writer.bundle.objects):
            phase = "check" if protocol.non_atomic_cas else "cas"
        else:
            phase = "put"
        return _replace_writer(
            replace(state, objects=tuple(sorted(objects.items()))),
            replace(writer, phase=phase, offset=offset),
        )

    if action.verb == "cas" and writer.phase == "cas":
        if h(state.root) != writer.expected:
            return _replace_writer(
                state, replace(
                    writer, phase="retry", base=None, expected=None,
                    bundle=None, offset=0))
        root = writer.bundle.root
        if protocol.split_root:
            candidate = json.loads(root)
            current = json.loads(state.root)
            root = _root(candidate["manifest"], current["index"])
        changed = replace(writer, phase="ack")
        return _replace_writer(
            replace(
                state, root=root, history=state.history + (root,),
                commits=state.commits + ((writer.expected, root),)),
            changed,
        )

    if action.verb == "check" and writer.phase == "check":
        phase = "swap" if h(state.root) == writer.expected else "retry"
        return _replace_writer(state, replace(writer, phase=phase))

    if action.verb == "swap" and writer.phase == "swap":
        root = writer.bundle.root
        return _replace_writer(
            replace(
                state, root=root, history=state.history + (root,),
                commits=state.commits + ((writer.expected, root),)),
            replace(writer, phase="ack"),
        )

    if action.verb == "retry" and writer.phase == "retry":
        return _replace_writer(state, replace(writer, phase="ready"))

    if action.verb == "ack" and writer.phase == "ack":
        return _replace_writer(state, replace(writer, phase="done"))

    if action.verb == "crash" and writer.crashes_left \
            and writer.phase not in {"done", "crashed", "ready"}:
        return _replace_writer(
            state,
            replace(
                writer, phase="crashed", base=None, expected=None,
                bundle=None, offset=0, crashes_left=writer.crashes_left - 1),
        )

    if action.verb == "restart" and writer.phase == "crashed":
        return _replace_writer(state, replace(writer, phase="ready"))

    raise ValueError(f"disabled action {action}")


def violation(before, after, action):
    """Return the first violated safety law, if any."""
    old, new = before.object_map(), after.object_map()
    if any(h(raw) != oid for oid, raw in new.items()):
        return "object-address integrity"
    if any(new.get(oid) != raw for oid, raw in old.items()):
        return "object map is not grow-only"
    if after.root != before.root and action.verb not in {"cas", "swap"}:
        return "root changed outside CAS"
    if len(after.history) != len(before.history) \
            and action.verb not in {"cas", "swap"}:
        return "commit history changed outside CAS"
    # Snapshot token sets only grow and publishers do not emit no-op roots, so
    # this bounded protocol has neither ABA nor a legitimate second X -> X CAS.
    expected = [etag for etag, _ in after.commits]
    if len(expected) != len(set(expected)):
        return "two root writes accepted the same CAS precondition"
    try:
        for root in after.history:
            snapshot_tokens(root, new)
    except ValueError as exc:
        return f"published snapshot is invalid: {exc}"
    reader = after.reader
    if reader.phase == "done":
        if reader.error is not None:
            return None  # malformed or missing data fails closed
        if len(set(reader.used_etags)) != 1:
            return "reader mixed root generations"
        if reader.manifest != branch_children(
                reader.pinned, "manifest", new):
            return "reader manifest has no pinned-root explanation"
        if reader.result != snapshot_tokens(reader.pinned, new):
            return "reader result has no pinned-root explanation"
    return None


def terminal(state):
    return state.reader.phase == "done" and all(
        writer.phase in {"done", "crashed"} for writer in state.writers)


def explore(protocol=Protocol(), *, crashes=False, max_states=100_000):
    """Breadth-first exploration; any counterexample schedule is minimal."""
    start = initial_state()
    queue = deque(((start, ()),))
    seen = {start}
    terminals = []
    while queue:
        state, schedule = queue.popleft()
        if terminal(state):
            terminals.append(state)
            continue
        for action in enabled(state, crashes=crashes):
            successor = step(state, action, protocol)
            trace = schedule + (str(action),)
            failed = violation(state, successor, action)
            if failed:
                return Exploration(
                    len(seen), tuple(terminals),
                    Counterexample(failed, trace))
            if successor not in seen:
                seen.add(successor)
                if len(seen) > max_states:
                    raise AssertionError("shared-bucket model state budget")
                queue.append((successor, trace))
    return Exploration(len(seen), tuple(terminals), None)


def drive(state, actor, protocol=Protocol()):
    """Fairly finish one writer from any restartable state."""
    while True:
        writer = next(item for item in state.writers if item.name == actor)
        if writer.phase == "done":
            return state
        action = next(
            item for item in enabled(state)
            if item.actor == actor)
        state = step(state, action, protocol)
