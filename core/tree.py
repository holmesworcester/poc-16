"""One deterministic, sans-I/O Merkle-tree engine.

Binary and flat compatibility packings keep closed piles at their leaves.
Production fat trees factor every fact into one settle-node payload: the
deepest node covering its own key and every dependent key.  A root-to-node
path is therefore closed, while a full preorder stream stores every fact once.
Drivers provide ``fetch(oid)`` and ``emit(bytes) -> oid``; this module knows
nothing about files, HTTP, or R2.
"""
import json
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from heapq import heapify, heappop, heappush

from .close import close, decode_pile, encode_pile
from .crypto import h
from .shape import FACT


@dataclass(frozen=True)
class View:
    """A subtree summary.

    ``fp`` covers in-range keys only; ``oid`` covers the node bytes and its
    settle payload. A leaf has ``level == 0`` and no children. Decoded children
    are summaries; fetching their oid resolves keys and placement metadata.
    """
    fp: str
    oid: str
    sep: str
    n: int
    children: tuple
    keys: tuple = ()
    level: int = 0
    kind: str = "leaf"
    mark: int = 0                 # flat root: number of promoted fence leaves
    config: str = ""
    pay: str = ""                 # fat tree: content-addressed payload pile
    pn: int = 0
    spans: tuple | None = None    # (fid, low key, high key); blanks mean self


@dataclass(frozen=True)
class Packing:
    """Physical arrangement. ``fanout=0`` is the inlined flat spine."""
    fanout: int
    kind: str = "fat"


BINARY = Packing(2, "binary")
FLAT = Packing(0, "flat")
FAT = Packing(64, "fat")


def fat(fanout=64):
    if not isinstance(fanout, int) or fanout < 2:
        raise ValueError("fat-tree fanout must be at least two")
    return Packing(fanout, "fat")


def config(packing, shape):
    """Tree-format identity; configuration changes force a full rebuild."""
    version = 2 if packing.kind == "fat" else 1
    return f"{version}:{packing.kind}:{packing.fanout}:{shape.cut()}"


def _fat_config_version(value, mark):
    if not isinstance(value, str):
        raise ValueError("tree config")
    parts = value.split(":")
    if len(parts) != 4 or parts[0] not in ("1", "2") \
            or parts[1] != "fat":
        raise ValueError("tree config")
    try:
        fanout, cut = int(parts[2]), int(parts[3])
    except ValueError as exc:
        raise ValueError("tree config") from exc
    if fanout != mark or fanout < 2 or cut < 1:
        raise ValueError("tree config")
    return int(parts[0])


@dataclass(frozen=True)
class Root:
    """Root metadata needed by stateless readers and mint."""
    view: View
    anchor: str
    globals_: frozenset


def _summary(view):
    out = {
        "f": view.fp, "k": view.kind, "l": view.level, "n": view.n,
        "m": view.mark, "o": view.oid, "s": view.sep, "x": view.config,
    }
    if view.config.startswith("2:fat:"):
        out.update({"p": view.pay, "q": view.pn})
    return out


def _from_summary(obj):
    return View(
        obj["f"], obj["o"], obj["s"], obj["n"], (),
        level=obj.get("l", 0), kind=obj.get("k", "leaf"),
        mark=obj.get("m", 0), config=obj.get("x", ""),
        pay=obj.get("p", ""), pn=obj.get("q", 0),
    )


def _root_tree(view):
    children = (
        [_root_tree(child) for child in view.children]
        if view.kind == "binary" else
        [_summary(child) for child in view.children]
    )
    return {**_summary(view), "c": children, "m": view.mark}


def _from_root_tree(obj):
    children = tuple(
        _from_root_tree(child) if obj["k"] == "binary"
        else _from_summary(child)
        for child in obj.get("c", ())
    )
    return View(
        obj["f"], obj["o"], obj["s"], obj["n"], children,
        level=obj["l"], kind=obj["k"], mark=obj.get("m", 0),
        config=obj.get("x", ""),
        pay=obj.get("p", ""), pn=obj.get("q", 0),
    )


def _wire_span(span):
    fid, lo, hi = span
    return [fid] if not lo else [fid, lo, hi]


def _span(row):
    if not isinstance(row, list) or len(row) not in (1, 3):
        raise ValueError("tree span")
    if not all(isinstance(value, str) for value in row) or not row[0]:
        raise ValueError("tree span")
    if len(row) == 1:
        return row[0], "", ""
    if not row[1] or not row[2] or row[1] > row[2]:
        raise ValueError("tree span")
    return tuple(row)


def _node_bytes(view):
    from .fact import canon
    body = {
        "c": [_summary(child) for child in view.children],
        "f": view.fp, "k": view.kind, "l": view.level,
        "m": view.mark, "n": view.n, "s": view.sep,
        "a": [_wire_span(span) for span in view.spans or ()],
        "p": view.pay, "q": view.pn, "v": 2, "x": view.config,
    }
    if view.level == 0:
        body["y"] = list(view.keys)
    return canon(body)


def _legacy_branch_bytes(view):
    from .fact import canon
    def summary(child):
        return {
            "f": child.fp, "k": child.kind, "l": child.level,
            "m": child.mark, "n": child.n, "o": child.oid,
            "s": child.sep, "x": child.config,
        }
    return canon({
        "c": [summary(child) for child in view.children],
        "f": view.fp, "k": view.kind, "l": view.level,
        "m": view.mark, "n": view.n, "s": view.sep,
        "v": 1, "x": view.config,
    })


def _validate_branch(view):
    children = view.children
    if not children or view.kind != "fat" \
            or view.mark < 2 or not view.config \
            or view.n != sum(child.n for child in children) \
            or view.sep != children[-1].sep \
            or view.fp != _fp("fat", view.level, children) \
            or any(child.level != view.level - 1 for child in children) \
            or any(child.n <= 0 or not child.sep for child in children) \
            or any(left.sep >= right.sep
                   for left, right in zip(children, children[1:])) \
            or any(child.level and child.config != view.config
                   for child in children):
        raise ValueError("tree node shape")


def _validate_node(view):
    if not view.config.startswith("2:fat:") \
            or view.pn != len(view.spans or ()) \
            or bool(view.pay) != bool(view.pn) \
            or len({row[0] for row in view.spans or ()}) != view.pn:
        raise ValueError("tree node shape")
    if view.level == 0:
        if view.kind != "leaf" or view.children \
                or len(view.keys) != view.n \
                or tuple(sorted(set(view.keys))) != view.keys \
                or (view.keys[-1] if view.keys else "") != view.sep:
            raise ValueError("tree node shape")
    else:
        _validate_branch(view)


def _decode_branch(raw, oid=None):
    obj = json.loads(raw)
    version = obj.get("v")
    if version not in (1, 2) or not isinstance(obj.get("c"), list):
        raise ValueError("tree node")
    view = View(
        obj["f"], oid or h(raw), obj["s"], obj["n"],
        tuple(_from_summary(child) for child in obj["c"]),
        level=obj["l"], kind=obj["k"], mark=obj.get("m", 0),
        config=obj.get("x", ""),
        keys=tuple(obj.get("y", ())), pay=obj.get("p", ""),
        pn=obj.get("q", 0),
        spans=tuple(_span(row) for row in obj.get("a", ()))
        if version == 2 else None,
    )
    if oid is not None and h(raw) != oid:
        raise ValueError("tree node integrity")
    if _fat_config_version(view.config, view.mark) != version:
        raise ValueError("tree config")
    (_validate_node if version == 2 else _validate_branch)(view)
    return view


def encode_root(root):
    """Encode root metadata; FLAT intentionally preserves today's manifest."""
    from .fact import canon

    view = root.view
    if view.kind == "flat":
        fences = [
            {"fp": child.fp, "hi": child.sep, "n": child.n,
             "pile": child.oid}
            for child in view.children[:view.mark]
        ]
        tails = view.children[view.mark:]
        tail = (
            {"fp": tails[0].fp, "n": tails[0].n, "pile": tails[0].oid}
            if tails else
            {"fp": FACT.fingerprint([]), "n": 0, "pile": None}
        )
        return canon({
            "anchor": root.anchor, "fences": fences,
            "globals": sorted([list(row) for row in root.globals_]),
            "tail": tail,
        })
    return canon({
        "anchor": root.anchor,
        "globals": sorted([list(row) for row in root.globals_]),
        "tree": _root_tree(view),
        "v": 1,
    })


def decode_root(raw):
    """Decode either the engine root or the legacy-compatible flat manifest."""
    obj = json.loads(raw)
    globals_ = frozenset(tuple(row) for row in obj.get("globals", ()))
    if "tree" not in obj:
        children = [
            View(fence["fp"], fence["pile"], fence["hi"], fence["n"], ())
            for fence in obj.get("fences", ())
        ]
        tail = obj.get("tail", {})
        if tail.get("pile"):
            children.append(View(
                tail["fp"], tail["pile"], "~", tail["n"], ()))
        view = _flat_view(children, len(obj.get("fences", ())))
        return Root(view, obj["anchor"], globals_)
    view = _from_root_tree(obj["tree"])
    if view.kind == "fat":
        version = _fat_config_version(view.config, view.mark)
        if view.level:
            _validate_branch(view)
            if version == 1 and h(_legacy_branch_bytes(view)) != view.oid:
                raise ValueError("tree root integrity")
        elif view.n or view.children or view.fp != h(b"") \
                or view.oid != h(b"") or view.sep \
                or view.pay or view.pn:
            raise ValueError("tree node shape")
    return Root(view, obj["anchor"], globals_)


def _emit(raw, emit):
    oid = h(raw)
    got = emit(raw)
    if got not in (None, oid, "obj/" + oid):
        raise ValueError("emit returned the wrong object id")
    return oid


def _empty(kind="leaf", shape=FACT):
    return View(shape.fingerprint([]), h(b""), "", 0, (), kind=kind)


def _leaf_views(
        keys, shape, packing, fact_of, deps_of, emit, memo=None):
    keys = sorted(set(keys))
    if not keys:
        return [], 0
    fids = [shape.fid_of(key) for key in keys]
    cuts = shape.cuts(fids)
    leaves, lo = [], 0
    for hi in cuts + ([len(keys)] if not cuts or cuts[-1] < len(keys) else []):
        chunk = keys[lo:hi]
        fp, cached = shape.fingerprint(chunk), \
            memo.get(chunk[-1]) if memo and hi in cuts else None
        if cached and cached["fp"] == fp and cached["n"] == len(chunk):
            oid = cached["pile"]
        else:
            pile = close(
                [fact_of(shape.fid_of(key)) for key in chunk],
                deps_of, fact_of,
            )
            oid = _emit(encode_pile(pile), emit)
        leaves.append(View(
            fp, oid, chunk[-1], len(chunk), (), tuple(chunk),
        ))
        lo = hi
    return leaves, len(cuts)


def _fp(kind, level, children):
    body = "|".join(f"{child.n}:{child.fp}" for child in children)
    return h(f"F|{kind}|{level}|{body}".encode())


def _binary_view(leaves, shape):
    if not leaves:
        return _empty("binary", shape)

    def rec(items):
        if len(items) == 1:
            return items[0]
        best = max(
            range(len(items) - 1),
            key=lambda index: shape.priority(
                shape.fid_of(items[index].sep)),
        )
        left, right = rec(items[:best + 1]), rec(items[best + 1:])
        oid = h(
            ("N|" + left.sep + "|" + left.oid + "|" + right.oid).encode())
        return View(
            _fp("binary", max(left.level, right.level) + 1, (left, right)),
            oid, right.sep, left.n + right.n, (left, right),
            level=max(left.level, right.level) + 1, kind="binary",
        )

    return rec(leaves)


def _flat_view(leaves, mark, shape=FACT):
    if not leaves:
        return View(
            shape.fingerprint([]), h(b""), "", 0, (),
            kind="flat", mark=0,
        )
    return View(
        _fp("flat", 1, leaves), h(
            ("FLAT|" + "|".join(child.oid for child in leaves)).encode()),
        leaves[-1].sep, sum(child.n for child in leaves), tuple(leaves),
        level=1, kind="flat", mark=mark,
    )


def _fat_boundary(child, level, packing, shape):
    # Shape.boundary samples a 32-bit prefix; higher tiers promote nothing.
    threshold = shape.cut() * packing.fanout ** level
    return threshold <= 2 ** 32 and shape.boundary(
        shape.fid_of(child.sep), threshold)


@dataclass
class _Draft:
    fp: str
    sep: str
    n: int
    children: tuple
    keys: tuple
    level: int
    base: View | None = None


def _chunks(keys, shape):
    keys = sorted(set(keys))
    cuts = shape.cuts([shape.fid_of(key) for key in keys])
    ends = cuts + (
        [len(keys)] if keys and (not cuts or cuts[-1] < len(keys)) else [])
    return [tuple(keys[lo:hi]) for lo, hi in zip([0] + ends, ends)]


def _draft_leaf(keys, shape, base=None):
    return _Draft(
        shape.fingerprint(keys), keys[-1], len(keys), (), tuple(keys), 0,
        base,
    )


def _draft_node(children, level, base=None):
    return _Draft(
        _fp("fat", level, children), children[-1].sep,
        sum(child.n for child in children), tuple(children), (), level, base,
    )


def _fat_groups(children, level, packing, shape):
    groups, group = [], []
    for child in children:
        group.append(child)
        if _fat_boundary(child, level, packing, shape):
            groups.append(group)
            group = []
    if group:
        groups.append(group)
    return groups


def _fat_shape(keys, packing, shape):
    nodes = [_draft_leaf(chunk, shape) for chunk in _chunks(keys, shape)]
    level = 1
    while True:
        nodes = [
            _draft_node(tuple(group), level)
            for group in _fat_groups(nodes, level, packing, shape)
        ]
        if len(nodes) == 1:
            return nodes[0]
        level += 1


def _closure_spans(fids, positions, deps_of):
    """Return exact stable key bounds for every transitive need span."""
    spans = {fid: [positions[fid], positions[fid]] for fid in fids}
    pending = {fid: 0 for fid in fids}
    for fid in fids:
        for dep in deps_of(fid):
            if dep not in pending:
                raise ValueError("tree closure")
            pending[dep] += 1
    ready = [fid for fid in fids if pending[fid] == 0]
    seen = 0
    while ready:
        fid = ready.pop()
        seen += 1
        lo, hi = spans[fid]
        for dep in deps_of(fid):
            target = spans[dep]
            if lo < target[0]:
                target[0] = lo
            if hi > target[1]:
                target[1] = hi
            pending[dep] -= 1
            if pending[dep] == 0:
                ready.append(dep)
    if seen != len(fids):
        raise ValueError("dependency DAG has a cycle")
    return {
        fid: (fid, "", "")
        if lo == hi == positions[fid] else (fid, lo, hi)
        for fid, (lo, hi) in spans.items()
    }


def _settle(root, span, key_of):
    node = root
    fid, low, high = span
    if not low:
        low = high = key_of(fid)
    while node.level:
        highs = [child.sep for child in node.children]
        left, right = bisect_left(highs, low), bisect_left(highs, high)
        if left != right:
            break
        node = node.children[left]
    return node


def _payload_order(fids, deps_of):
    inside, followers = set(fids), {}
    pending = {}
    for fid in inside:
        dependencies = [dep for dep in deps_of(fid) if dep in inside]
        pending[fid] = len(dependencies)
        for dep in dependencies:
            followers.setdefault(dep, []).append(fid)
    ready = [fid for fid in inside if not pending[fid]]
    heapify(ready)
    ordered = []
    while ready:
        fid = heappop(ready)
        ordered.append(fid)
        for follower in followers.get(fid, ()):
            pending[follower] -= 1
            if not pending[follower]:
                heappush(ready, follower)
    if len(ordered) != len(inside):
        raise ValueError("dependency DAG has a cycle")
    return ordered


def _finish_fat(
        node, assigned, moving, packing, shape, deps_of, emit, fetch=None):
    if isinstance(node, View):
        if assigned.get(id(node)):
            raise ValueError("settled into an unchanged node")
        return node

    children = tuple(
        _finish_fat(
            child, assigned, moving, packing, shape, deps_of, emit, fetch)
        for child in node.children
    )
    additions = assigned.get(id(node), ())
    base = node.base
    removed = base is not None and any(
        span[0] in moving for span in base.spans or ())
    if base is not None and not additions and not removed:
        pay, pn, spans = base.pay, base.pn, base.spans
    else:
        facts, records = {}, {}
        if base is not None:
            for fact, span in zip(_payload(base, fetch), base.spans or ()):
                if fact.fid not in moving:
                    facts[fact.fid], records[fact.fid] = fact, span
        for fact, span in additions:
            facts[fact.fid], records[fact.fid] = fact, span
        order = _payload_order(facts, deps_of)
        spans = tuple(records[fid] for fid in order)
        raw = encode_pile([facts[fid] for fid in order])
        pay = h(raw) if order else ""
        if order and (base is None or pay != base.pay):
            _emit(raw, emit)
        pn = len(order)

    kind = "leaf" if node.level == 0 else "fat"
    view = View(
        node.fp, "", node.sep, node.n, children, node.keys,
        level=node.level, kind=kind, mark=packing.fanout,
        config=config(packing, shape), pay=pay, pn=pn, spans=spans,
    )
    raw = _node_bytes(view)
    oid = h(raw)
    if base is not None and oid == base.oid:
        return base
    return View(
        view.fp, _emit(raw, emit), view.sep, view.n, view.children, view.keys,
        level=view.level, kind=view.kind, mark=view.mark, config=view.config,
        pay=view.pay, pn=view.pn, spans=view.spans,
    )


def _fat_view(keys, packing, shape, fact_of, deps_of, emit):
    keys = sorted(set(keys))
    if not keys:
        return View(
            shape.fingerprint([]), h(b""), "", 0, (),
            kind="fat", mark=packing.fanout, config=config(packing, shape),
            spans=(),
        )
    deps, facts = {}, {}

    def dependencies(fid):
        if fid not in deps:
            deps[fid] = tuple(deps_of(fid))
        return deps[fid]

    def fact(fid):
        if fid not in facts:
            facts[fid] = fact_of(fid)
        return facts[fid]

    root = _fat_shape(keys, packing, shape)
    fids = [shape.fid_of(key) for key in keys]
    positions = dict(zip(fids, keys))
    spans = _closure_spans(fids, positions, dependencies)
    assigned = {}
    for fid, span in spans.items():
        target = _settle(root, span, positions.__getitem__)
        assigned.setdefault(id(target), []).append((fact(fid), span))
    return _finish_fat(
        root, assigned, set(), packing, shape, dependencies, emit)


def build(keys, shape, packing, fact_of, deps_of, emit, memo=None):
    """Build one packing as a pure function of ``keys``."""
    if packing.kind == "fat":
        return _fat_view(
            keys, packing, shape, fact_of, deps_of, emit)
    leaves, mark = _leaf_views(
        keys, shape, packing, fact_of, deps_of, emit, memo)
    if packing.kind == "binary":
        return _binary_view(leaves, shape)
    return _flat_view(leaves, mark, shape)


def _resolved(view, fetch):
    if not view.n:
        return view
    current = view.config.startswith("2:fat:")
    if (current and view.spans is not None) \
            or (not current and (view.level == 0 or view.children)):
        return view
    raw = fetch(view.oid)
    if raw is None:
        raise KeyError(view.oid)
    resolved = _decode_branch(raw, view.oid)
    if _summary(resolved) != _summary(view):
        raise ValueError("tree child summary")
    return resolved


def _read_leaf(view, lo, hi, shape, fetch):
    if view.config.startswith("2:fat:"):
        raise ValueError("fat leaves require their ancestor path")
    if view.n == 0:
        return (), []
    raw = fetch(view.oid)
    if raw is None:
        raise KeyError(view.oid)
    if h(raw) != view.oid:
        raise ValueError("leaf integrity")
    facts, _ = decode_pile(raw)
    keys = sorted(
        shape.key(fact) for fact in facts
        if lo < shape.key(fact) <= hi
    )
    if len(keys) != view.n or shape.fingerprint(keys) != view.fp:
        raise ValueError("leaf summary")
    return facts, keys


def _leaf_keys(view, lo, hi, shape, fetch, use_warm=True):
    if view.config.startswith("2:fat:"):
        try:
            view = _resolved(view, fetch)
        except ValueError as exc:
            if "integrity" in str(exc):
                raise ValueError("leaf integrity") from exc
            if "summary" in str(exc):
                raise ValueError("leaf summary") from exc
            raise
        keys = list(view.keys)
        if len(keys) != view.n or shape.fingerprint(keys) != view.fp \
                or any(not lo < key <= hi for key in keys):
            raise ValueError("leaf summary")
        return keys
    if use_warm and view.keys:
        keys = list(view.keys)
        if len(keys) != view.n or shape.fingerprint(keys) != view.fp:
            raise ValueError("leaf summary")
        return keys
    return _read_leaf(view, lo, hi, shape, fetch)[1]


def _walk_leaves(view, fetch, lo="", hi="~"):
    if view.level == 0:
        yield lo, hi, view
        return
    view = _resolved(view, fetch)
    lower = lo
    for child in view.children:
        upper = min(hi, child.sep)
        yield from _walk_leaves(child, fetch, lower, upper)
        lower = upper


def leaf_keys(view, fetch, shape=FACT, use_warm=True):
    """Return all in-range keys, never closure copies."""
    out = []
    for lo, hi, leaf in _walk_leaves(view, fetch):
        out.extend(_leaf_keys(
            leaf, lo, hi, shape, fetch, use_warm))
    return out


def leaf_ranges(view, fetch):
    """Yield ``(lo, hi, leaf)`` summaries in key order."""
    yield from _walk_leaves(view, fetch)


def range_keys(leaf, lo, hi, shape, fetch):
    """Read one leaf's in-range keys, excluding its closure copies."""
    return _leaf_keys(leaf, lo, hi, shape, fetch)


def leaf_facts(leaf, lo, hi, shape, fetch):
    """Read a legacy closed leaf pile.

    Fat-tree closure lives on the root path; use :func:`range_facts`.
    """
    return _read_leaf(leaf, lo, hi, shape, fetch)[0]


def _payload(view, fetch):
    view = _resolved(view, fetch)
    if not view.pn:
        return ()
    raw = fetch(view.pay)
    if raw is None or h(raw) != view.pay:
        raise ValueError("payload integrity")
    stream, _ = decode_pile(raw)
    if len(stream) != view.pn \
            or tuple(fact.fid for fact in stream) != tuple(
                span[0] for span in view.spans or ()):
        raise ValueError("payload summary")
    return tuple(stream)


def _validate_fact_keys(stream, keys, shape, *, exact):
    """Check payload facts against the explicit keys committed by leaves."""
    actual = {shape.key(fact) for fact in stream}
    expected = set(keys)
    mismatch = actual != expected if exact else not expected <= actual
    if len(actual) != len(stream) or mismatch:
        raise ValueError("tree fact set")


def facts(view, fetch, shape=FACT):
    """Return the whole committed fact set once, in closed preorder."""
    if not view.n:
        return ()
    if not view.config.startswith("2:fat:"):
        return tuple(
            fact
            for lo, hi, leaf in leaf_ranges(view, fetch)
            for fact in leaf_facts(leaf, lo, hi, shape, fetch)
        )
    out, keys = [], []

    def rec(node, lo, hi):
        node = _resolved(node, fetch)
        out.extend(_payload(node, fetch))
        if not node.level:
            keys.extend(_leaf_keys(node, lo, hi, shape, fetch))
            return
        lower = lo
        for child in node.children:
            upper = min(hi, child.sep)
            rec(child, lower, upper)
            lower = upper

    rec(view, "", view.sep)
    _validate_fact_keys(out, keys, shape, exact=True)
    return tuple(out)


def range_facts(view, ranges, fetch, shape=FACT):
    """Return one closed, deduplicated stream for ``(lo, hi]`` ranges.

    Ancestor payloads are included once, which is the hoisted range tax.
    """
    if isinstance(ranges, tuple) and len(ranges) == 2 \
            and all(isinstance(value, str) for value in ranges):
        ranges = (ranges,)
    ranges = tuple(
        (lo, hi) for lo, hi in ranges if lo < hi)
    if not ranges or not view.n:
        return ()
    if not view.config.startswith("2:fat:"):
        out, seen = [], set()
        for lo, hi, leaf in leaf_ranges(view, fetch):
            if any(max(lo, start) < min(hi, stop)
                   for start, stop in ranges):
                for fact in leaf_facts(leaf, lo, hi, shape, fetch):
                    if fact.fid not in seen:
                        seen.add(fact.fid)
                        out.append(fact)
        return tuple(out)

    out, keys = [], []

    def intersects(lo, hi):
        return any(max(lo, start) < min(hi, stop)
                   for start, stop in ranges)

    def rec(node, lo, hi):
        if not intersects(lo, hi):
            return
        node = _resolved(node, fetch)
        out.extend(_payload(node, fetch))
        if not node.level:
            keys.extend(_leaf_keys(node, lo, hi, shape, fetch))
            return
        lower = lo
        for child in node.children:
            upper = min(hi, child.sep)
            rec(child, lower, upper)
            lower = upper

    rec(view, "", view.sep)
    _validate_fact_keys(out, keys, shape, exact=False)
    return tuple(out)


def key_facts(view, keys, fetch, shape=FACT):
    """Return one closed path union for the leaves to which ``keys`` route."""
    keys = tuple(sorted(set(keys)))
    if not keys or not view.n:
        return ()
    if not view.config.startswith("2:fat:"):
        out, seen = [], set()
        leaves = list(leaf_ranges(view, fetch))
        highs = [hi for _, hi, _ in leaves]
        wanted = {
            min(bisect_left(highs, key), len(leaves) - 1)
            for key in keys
        }
        for index, (lo, hi, leaf) in enumerate(leaves):
            if index in wanted:
                for fact in leaf_facts(leaf, lo, hi, shape, fetch):
                    if fact.fid not in seen:
                        seen.add(fact.fid)
                        out.append(fact)
        return tuple(out)

    out, leaf_keys = [], []

    def rec(node, routed, lo, hi):
        node = _resolved(node, fetch)
        out.extend(_payload(node, fetch))
        if not node.level:
            leaf_keys.extend(_leaf_keys(node, lo, hi, shape, fetch))
            return
        lower = lo
        for child, child_keys in zip(
                node.children, _route(node.children, routed)):
            upper = min(hi, child.sep)
            if child_keys:
                rec(child, child_keys, lower, upper)
            lower = upper

    rec(view, keys, "", view.sep)
    _validate_fact_keys(out, leaf_keys, shape, exact=False)
    return tuple(out)


def _fold_binary(
        view, delta, shape, fact_of, deps_of, fetch, emit, lo="",
        use_warm=True):
    if not delta:
        return view
    view = _resolved(view, fetch)
    if view.level == 0:
        old = _leaf_keys(
            view, lo, view.sep or "~", shape, fetch, use_warm)
        leaves, _ = _leaf_views(
            old + delta, shape, BINARY, fact_of, deps_of, emit)
        return _binary_view(leaves, shape)
    left, right = view.children
    separator = left.sep
    promotions = [
        shape.priority(shape.fid_of(key)) for key in delta
        if shape.boundary(shape.fid_of(key))
    ]
    if delta[-1] > view.sep \
            and shape.boundary(shape.fid_of(view.sep)):
        promotions.append(shape.priority(shape.fid_of(view.sep)))
    promoted = max(promotions, default=-1)
    if promoted > shape.priority(shape.fid_of(separator)):
        old = leaf_keys(view, fetch, shape, use_warm)
        leaves, _ = _leaf_views(
            old + delta, shape, BINARY, fact_of, deps_of, emit)
        return _binary_view(leaves, shape)
    cut = bisect_left(delta, separator)
    if cut < len(delta) and delta[cut] == separator:
        cut += 1
    left_delta, right_delta = delta[:cut], delta[cut:]
    new_left = _fold_binary(
        left, left_delta, shape, fact_of, deps_of, fetch, emit, lo,
        use_warm)
    new_right = _fold_binary(
        right, right_delta, shape, fact_of, deps_of, fetch, emit,
        separator, use_warm)
    if new_left is left and new_right is right:
        return view
    level = max(new_left.level, new_right.level) + 1
    oid = h(
        ("N|" + new_left.sep + "|" + new_left.oid + "|"
         + new_right.oid).encode())
    return View(
        _fp("binary", level, (new_left, new_right)), oid,
        new_right.sep, new_left.n + new_right.n, (new_left, new_right),
        level=level, kind="binary",
    )


def _route(children, delta):
    routed = [[] for _ in children]
    highs = [child.sep for child in children]
    for key in delta:
        routed[min(bisect_left(highs, key), len(children) - 1)].append(key)
    return routed


def _fold_flat(
        view, delta, shape, fact_of, deps_of, fetch, emit,
        use_warm=True):
    if not view.children:
        return build(delta, shape, FLAT, fact_of, deps_of, emit)
    routed, leaves, lo = _route(view.children, delta), [], ""
    marks = 0
    for index, (child, additions) in enumerate(zip(view.children, routed)):
        if additions:
            old = _leaf_keys(
                child, lo, child.sep, shape, fetch, use_warm)
            fresh, fresh_mark = _leaf_views(
                old + additions, shape, FLAT, fact_of, deps_of, emit)
            leaves.extend(fresh)
            marks += fresh_mark
        else:
            leaves.append(child)
            marks += index < view.mark
        lo = child.sep
    return _flat_view(leaves, marks, shape)


def _fold_fat(
        view, delta, shape, packing, fact_of, deps_of, fetch, emit):
    """Path-copy an additive update, rehoming only changed closure spans."""
    objects, resolved, payloads = {}, {}, {}

    def cached(oid):
        if oid not in objects:
            objects[oid] = fetch(oid)
        return objects[oid]

    def load(node):
        if node.spans is not None:
            return node
        if node.oid not in resolved:
            resolved[node.oid] = _resolved(node, cached)
        return resolved[node.oid]

    facts_by_fid, deps = {}, {}

    def fact(fid):
        if fid not in facts_by_fid:
            facts_by_fid[fid] = fact_of(fid)
        return facts_by_fid[fid]

    def key_of(fid):
        return shape.key(fact(fid))

    def dependencies(fid):
        if fid not in deps:
            deps[fid] = tuple(deps_of(fid))
        return deps[fid]

    locations = {}

    def locate(fid):
        if fid in locations:
            return locations[fid]
        key, node, path = key_of(fid), view, []
        while True:
            node = load(node)
            path.append(node)
            record = next(
                (span for span in node.spans or () if span[0] == fid),
                None,
            )
            if record is not None or node.level == 0:
                locations[fid] = (record, tuple(path), node)
                return locations[fid]
            highs = [child.sep for child in node.children]
            node = node.children[
                min(bisect_left(highs, key), len(highs) - 1)]

    delta_by_fid = {shape.fid_of(key): key for key in delta}
    old = {fid: locate(fid) for fid in delta_by_fid}
    new = [fid for fid in delta_by_fid if old[fid][0] is None]
    if not new:
        return view

    spans = {}

    def current_span(fid):
        if fid not in spans:
            if fid in delta_by_fid and locate(fid)[0] is None:
                spans[fid] = [key_of(fid), key_of(fid)]
            else:
                record = locate(fid)[0]
                if record is None:
                    raise ValueError("tree closure")
                spans[fid] = list(record[1:]) if record[1] else [
                    key_of(fid), key_of(fid)]
        return spans[fid]

    # Each new dependent position expands every transitive dependency span.
    for origin in new:
        stack, seen = [origin], set()
        while stack:
            fid = stack.pop()
            if fid in seen:
                continue
            seen.add(fid)
            span = current_span(fid)
            if key_of(origin) < span[0]:
                span[0] = key_of(origin)
            if key_of(origin) > span[1]:
                span[1] = key_of(origin)
            stack.extend(dependencies(fid))

    def record_for(fid, span):
        own = key_of(fid)
        return (fid, "", "") if span == [own, own] \
            else (fid, span[0], span[1])

    moving = {
        fid for fid, span in spans.items()
        if locate(fid)[0] is not None
        and record_for(fid, span) != locate(fid)[0]
    }
    dirty = {
        node.oid
        for fid in moving
        for node in locate(fid)[1]
    }
    rehome = {
        fid: (fact(fid), record_for(fid, span))
        for fid, span in spans.items()
        if fid in moving or fid in new
    }

    def payload(node):
        if node.pay not in payloads:
            payloads[node.pay] = _payload(node, cached)
        return payloads[node.pay]

    def float_payload(node):
        for item, span in zip(payload(node), node.spans or ()):
            rehome.setdefault(item.fid, (item, span))

    def same_partition(children, old_children):
        return len(children) == len(old_children) and all(
            (child.level, child.sep) == (prior.level, prior.sep)
            for child, prior in zip(children, old_children)
        )

    def edit(node, additions, lo):
        node = load(node)
        if node.level == 0:
            keys = _leaf_keys(
                node, lo, node.sep or "~", shape, cached)
            drafts = [
                _draft_leaf(chunk, shape)
                for chunk in _chunks(keys + additions, shape)
            ]
            if len(drafts) == 1 and drafts[0].sep == node.sep:
                drafts[0].base = node
            else:
                float_payload(node)
            return drafts

        routed, children, lower = _route(node.children, additions), [], lo
        for child, child_delta in zip(node.children, routed):
            if child_delta or child.oid in dirty:
                children.extend(edit(child, child_delta, lower))
            else:
                children.append(child)
            lower = child.sep
        groups = _fat_groups(
            children, node.level, packing, shape)
        if len(groups) == 1 and same_partition(
                groups[0], node.children):
            return [_draft_node(tuple(groups[0]), node.level, node)]
        float_payload(node)
        return [
            _draft_node(tuple(group), node.level)
            for group in groups
        ]

    roots = edit(view, delta, "")
    level = view.level + 1
    while len(roots) > 1:
        roots = [
            _draft_node(tuple(group), level)
            for group in _fat_groups(roots, level, packing, shape)
        ]
        level += 1
    root = roots[0]
    assigned = {}
    for item, span in rehome.values():
        target = _settle(root, span, key_of)
        assigned.setdefault(id(target), []).append((item, span))
    return _finish_fat(
        root, assigned, moving, packing, shape, dependencies, emit, cached)


def fold(
        view, delta, shape, packing, fact_of, deps_of, fetch, emit, *,
        fetch_warm=False):
    """Blind additive update; untouched subtrees are neither read nor emitted."""
    if view.kind == "fat" and view.config != config(packing, shape):
        raise ValueError("tree config")
    delta = sorted(set(delta))
    if not delta:
        return view
    if view.n == 0:
        return build(delta, shape, packing, fact_of, deps_of, emit)
    if packing.kind == "binary":
        return _fold_binary(
            view, delta, shape, fact_of, deps_of, fetch, emit,
            use_warm=not fetch_warm)
    if packing.kind == "flat":
        return _fold_flat(
            view, delta, shape, fact_of, deps_of, fetch, emit,
            not fetch_warm)
    return _fold_fat(
        view, delta, shape, packing, fact_of, deps_of, fetch, emit)


def diff(
        mine, theirs, shape, fetch_mine, fetch_theirs, *,
        fetch_warm=False):
    """Yield differing leaf ranges as ``(lo, hi, my_keys, their_leaf)``."""
    left_nodes, right_nodes, left_keys, right_keys = {}, {}, {}, {}

    def resolve(view, fetch, cache):
        if not view.n:
            return view
        current = view.config.startswith("2:fat:")
        if (current and view.spans is not None) \
                or (not current and (view.level == 0 or view.children)):
            return view
        if view.oid not in cache:
            cache[view.oid] = _resolved(view, fetch)
        return cache[view.oid]

    def parts(view, lo, hi, fetch, cache):
        view = resolve(view, fetch, cache)
        if view.level == 0:
            return [(lo, hi, view)]
        out, lower = [], lo
        for child in view.children:
            upper = min(hi, child.sep)
            out.append((lower, upper, child))
            lower = upper
        return out

    def keys(view, lo, hi, fetch, cache):
        token = (view.oid, lo, hi)
        if token not in cache:
            cache[token] = _leaf_keys(
                view, lo, hi, shape, fetch, not fetch_warm)
        return cache[token]

    def rec(left, left_lo, left_hi, right, right_lo, right_hi):
        lo, hi = max(left_lo, right_lo), min(left_hi, right_hi)
        if lo >= hi:
            return
        if left.fp == right.fp and left.n == right.n:
            return
        if left.level == right.level == 0:
            mine = keys(
                left, left_lo, left_hi, fetch_mine, left_keys)
            theirs = keys(
                right, right_lo, right_hi, fetch_theirs, right_keys)
            mine = mine[
                bisect_right(mine, lo):bisect_right(mine, hi)]
            theirs = theirs[
                bisect_right(theirs, lo):bisect_right(theirs, hi)]
            if mine != theirs:
                remote = right if (lo, hi) == (right_lo, right_hi) \
                    else View(
                        shape.fingerprint(theirs), right.oid,
                        hi, len(theirs), (),
                        tuple(theirs),
                    )
                yield lo, hi, tuple(mine), remote
            return
        if left_lo == right_lo and left_hi == right_hi \
                and left.level == right.level:
            left_parts = parts(
                left, left_lo, left_hi, fetch_mine, left_nodes)
            right_parts = parts(
                right, right_lo, right_hi, fetch_theirs, right_nodes)
            i = j = 0
            while i < len(left_parts) and j < len(right_parts):
                llo, lhi, lview = left_parts[i]
                rlo, rhi, rview = right_parts[j]
                yield from rec(
                    lview, llo, lhi, rview, rlo, rhi)
                if lhi <= rhi:
                    i += 1
                if rhi <= lhi:
                    j += 1
            return
        left_contains = left_lo <= right_lo and right_hi <= left_hi
        right_contains = right_lo <= left_lo and left_hi <= right_hi
        if left.level == 0:
            split_left = False
        elif right.level == 0:
            split_left = True
        elif left_contains != right_contains:
            split_left = left_contains
        else:
            split_left = left.level >= right.level
        if split_left:
            for llo, lhi, lview in parts(
                    left, left_lo, left_hi, fetch_mine, left_nodes):
                yield from rec(
                    lview, llo, lhi, right, right_lo, right_hi)
        else:
            for rlo, rhi, rview in parts(
                    right, right_lo, right_hi, fetch_theirs, right_nodes):
                yield from rec(
                    left, left_lo, left_hi, rview, rlo, rhi)

    mine = resolve(mine, fetch_mine, left_nodes)
    theirs = resolve(theirs, fetch_theirs, right_nodes)
    left_hi, right_hi = mine.sep, theirs.sep
    if left_hi and right_hi:
        yield from rec(mine, "", left_hi, theirs, "", right_hi)
    empty = _empty(shape=shape)
    if left_hi < right_hi:
        yield from rec(empty, left_hi, right_hi, theirs, "", right_hi)
    elif right_hi < left_hi:
        yield from rec(mine, "", left_hi, empty, right_hi, left_hi)


def _canonical_graph(units):
    """Return union facts and deps resolved against the whole union."""
    items = {
        fact.fid: fact
        for unit in units
        for fact in unit
    }
    import facts as families
    if all(
            not fact.refs() and families.handler_for(fact.t) is None
            for fact in items.values()):
        return items, {fid: () for fid in items}
    if any(
            (handler := families.handler_for(fact.t)) is None
            or not handler.DURABLE
            for fact in items.values()):
        raise ValueError("merge closure")

    anchors = [
        fact.fid for fact in items.values()
        if fact.t in ("workspace", "genesis")
    ]
    if not anchors:
        raise ValueError("merge closure")

    import sqlite3
    from .kernel import SCHEMA, drain, resolve_deps, unresolved_facts

    db = sqlite3.connect(":memory:")
    try:
        db.executescript(SCHEMA)
        db.executemany(
            "INSERT INTO facts VALUES(?,?,?)",
            ((fact.fid, fact.ts, fact.t) for fact in items.values()),
        )
        db.executemany(
            "INSERT INTO offers VALUES(?,?,?,?)",
            ((*offer, fact.fid)
             for fact in items.values() for offer in fact.offers()),
        )
        if unresolved_facts(db, items.get):
            raise ValueError("merge closure")
        deps = {
            fid: tuple(resolved)
            for fid, fact in items.items()
            if (resolved := resolve_deps(fact, db)) is not None
        }
        if len(deps) != len(items):
            raise ValueError("merge closure")
    finally:
        db.close()

    ordered = close(items.values(), deps.__getitem__, items.__getitem__)
    result = drain(ordered, min(anchors))
    if not result.ok or len(result.valids) != len(items):
        raise ValueError("merge closure")
    return items, {
        valid.fact.fid: valid.deps for valid in result.valids
    }


def _may_rewire(fact):
    """Whether adding ``fact`` can change union-wide canonical dependencies."""
    if fact.offers():
        return True
    import facts as families
    handler = families.handler_for(fact.t)
    if handler is None:
        return False
    try:
        return bool(tuple(handler.needs(fact)))
    except Exception:
        return True


def validate_view(view, shape, packing, fetch):
    """Return facts only when closure and physical placement are canonical."""
    stream = facts(view, fetch, shape)
    if len({fact.fid for fact in stream}) != view.n:
        raise ValueError("tree fact set")
    items, deps = _canonical_graph((stream,))
    if view.config.startswith("2:fat:"):
        canonical = build(
            [shape.key(fact) for fact in items.values()],
            shape, packing, items.__getitem__, deps.__getitem__, h,
        )
        if canonical.oid != view.oid:
            raise ValueError("tree placement")
    else:
        for lo, hi, leaf in leaf_ranges(view, fetch):
            _canonical_graph((
                leaf_facts(leaf, lo, hi, shape, fetch),
            ))
    return stream


def merge(a, b, shape, packing, fetch, emit, *, prevalidated=False):
    """Join two roots, folding a fixed-dependency delta or rebuilding.

    Untrusted semantic roots are validated by default. ``prevalidated=True``
    preserves the bounded path when both inputs already passed their
    publication trust boundary; incorporated deltas are still checked.
    """
    expected = config(packing, shape)

    def is_current(view):
        return view.kind == "fat" and view.config == expected

    if a.n and a.config.startswith("2:fat:") and a.spans is None:
        a = _resolved(a, fetch)
    if b.n and b.config.startswith("2:fat:") and b.spans is None:
        b = _resolved(b, fetch)
    if packing.kind == "fat":
        if not is_current(a):
            if is_current(b):
                a, b = b, a
            else:
                raise ValueError("tree config")
    elif any(
            view.kind == "fat" and view.config != expected
            for view in (a, b)):
        raise ValueError("tree config")

    cache, items, deps = {}, {}, {}
    streams = {}

    def cached(oid):
        if oid not in cache:
            raw = cache[oid] = fetch(oid)
            if raw is not None:
                try:
                    stream = decode_pile(raw)[0]
                except Exception:
                    pass
                else:
                    items.update((fact.fid, fact) for fact in stream)
        return cache[oid]

    def validate_root(view):
        identity = (view.fp, view.oid, view.n, view.config)
        if identity not in streams:
            streams[identity] = validate_view(
                view, shape, packing, cached)
        return streams[identity]

    if not prevalidated:
        validate_root(a)
        validate_root(b)
    if a.fp == b.fp and a.n == b.n and a.oid == b.oid:
        return a
    if not a.n:
        if packing.kind != "fat" or is_current(b):
            return b
    if not b.n:
        return a

    def rebuild():
        streams = (
            validate_root(a),
            validate_root(b),
        )
        all_items, all_deps = _canonical_graph(streams)
        staged = {}

        def stage(raw):
            oid = h(raw)
            staged.setdefault(oid, raw)
            return oid

        merged = build(
            [shape.key(fact) for fact in all_items.values()],
            shape, packing, all_items.__getitem__,
            all_deps.__getitem__, stage,
        )
        for raw in staged.values():
            _emit(raw, emit)
        return merged

    if a.fp == b.fp and a.n == b.n:
        return rebuild()

    changes = list(diff(
        a, b, shape, cached, cached, fetch_warm=True))
    delta, ranges = set(), []
    for lo, hi, mine, remote in changes:
        theirs = set(_leaf_keys(remote, lo, hi, shape, cached))
        missing = theirs - set(mine)
        if missing:
            delta.update(missing)
            ranges.append((lo, hi))
    if not delta:
        return a

    units = (
        key_facts(a, delta, cached, shape),
        range_facts(b, ranges, cached, shape),
    )
    items.update(
        (fact.fid, fact) for unit in units for fact in unit)
    delta_fids = {shape.fid_of(key) for key in delta}
    if any(_may_rewire(items[fid]) for fid in delta_fids):
        return rebuild()
    for unit in units:
        _canonical_graph((unit,))
    canonical_items, canonical_deps = _canonical_graph(units)
    items.update(canonical_items)
    deps.update(canonical_deps)

    def fact_of(fid):
        try:
            return items[fid]
        except KeyError as exc:
            raise ValueError("merge closure") from exc

    def deps_of(fid):
        if fid not in deps:
            import facts as families
            item = items.get(fid)
            if item is not None and not item.refs() \
                    and families.handler_for(item.t) is None:
                deps[fid] = ()
            else:
                raise ValueError("merge closure")
        return deps[fid]

    staged = {}

    def stage(raw):
        oid = h(raw)
        staged.setdefault(oid, raw)
        return oid

    merged = fold(
        a, delta, shape, packing, fact_of, deps_of, cached, stage,
        fetch_warm=True)
    for raw in staged.values():
        _emit(raw, emit)
    return merged


def verify(root, pad, fact_of, fetch, base_hashes=None, base_phs=None):
    """Verify a hoisted tree once, carrying ``pad`` down each changed path.

    Callers may retain a common ancestor in the same pad while invoking this
    on consecutive child ranges; shared context is then judged only once.
    """
    st = {
        "judged": set(), "judge_ops": 0, "ctx_ops": 0,
        "skipped": 0, "ok": True,
    }

    def payload(node):
        if fetch is None or not node["pay"]:
            return [fact_of(fid) for fid in node["pay"]]
        raw = fetch(node["ph"])
        if raw is None or h(raw) != node["ph"]:
            raise ValueError("payload integrity")
        stream, _ = decode_pile(raw)
        if len(stream) != node["n"] \
                or tuple(fact.fid for fact in stream) != tuple(node["pay"]):
            raise ValueError("payload summary")
        return stream

    def rec(node):
        if base_hashes is not None and node["hash"] in base_hashes:
            st["skipped"] += 1
            return True
        stream = payload(node)
        accepted = ()
        try:
            if base_phs is not None and node["ph"] in base_phs:
                accepted = pad.context(stream)
                st["ctx_ops"] += len(accepted)
            else:
                ok, accepted = pad.judge(stream)
                st["judge_ops"] += len(accepted)
                st["judged"].update(accepted)
                if not ok:
                    st["ok"] = False
                    return False
            return node["leaf"] or (
                rec(node["L"]) and rec(node["R"]))
        finally:
            pad.pop(accepted)

    st["ok"] = rec(root) and st["ok"]
    return st


def live_oids(view, fetch=None):
    """Return reachable node and settle-payload object ids.

    A decoded fat tree needs ``fetch`` to walk below its child summaries.
    """
    if not view.n:
        return set()
    out = {view.oid}
    if view.config.startswith("2:fat:"):
        resolved = _resolved(view, fetch)
        if resolved.pay:
            out.add(resolved.pay)
        for child in resolved.children:
            out.update(live_oids(child, fetch))
        return out
    if view.level == 0:
        return out
    resolved = view if view.children else (
        _resolved(view, fetch) if fetch is not None else view)
    for child in resolved.children:
        out.update(live_oids(child, fetch))
    return out
