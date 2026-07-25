"""One deterministic, sans-I/O Merkle-tree engine.

The logical leaves are content-defined closed piles. ``Packing`` changes only
their arrangement: the binary prototype, the legacy flat manifest, or a
shallow content-defined fat tree. The flat packing is retained for legacy
byte checks; production uses fat nodes. Drivers provide ``fetch(oid)`` and
``emit(bytes) -> oid``; this module knows nothing about files, HTTP, or R2.
"""
import json
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from .close import close, decode_pile, encode_pile
from .crypto import h
from .shape import FACT


@dataclass(frozen=True)
class View:
    """A subtree summary.

    ``fp`` covers in-range keys only; ``oid`` covers stored bytes, including
    closure. A leaf has ``level == 0`` and no children. Decoded branch children
    are summaries; fetching their oid resolves the next level lazily.
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
    return f"1:{packing.kind}:{packing.fanout}:{shape.cut()}"


@dataclass(frozen=True)
class Root:
    """Root metadata needed by stateless readers and mint."""
    view: View
    anchor: str
    globals_: frozenset


def _summary(view):
    return {
        "f": view.fp, "k": view.kind, "l": view.level, "n": view.n,
        "m": view.mark, "o": view.oid, "s": view.sep, "x": view.config,
    }


def _from_summary(obj):
    return View(
        obj["f"], obj["o"], obj["s"], obj["n"], (),
        level=obj.get("l", 0), kind=obj.get("k", "leaf"),
        mark=obj.get("m", 0), config=obj.get("x", ""),
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
    )


def _branch_bytes(view):
    from .fact import canon
    return canon({
        "c": [_summary(child) for child in view.children],
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
            or any(child.level and child.config != view.config
                   for child in children):
        raise ValueError("tree node shape")


def _decode_branch(raw, oid=None):
    obj = json.loads(raw)
    if obj.get("v") != 1 or not isinstance(obj.get("c"), list):
        raise ValueError("tree node")
    view = View(
        obj["f"], oid or h(raw), obj["s"], obj["n"],
        tuple(_from_summary(child) for child in obj["c"]),
        level=obj["l"], kind=obj["k"], mark=obj.get("m", 0),
        config=obj.get("x", ""),
    )
    if oid is not None and h(raw) != oid:
        raise ValueError("tree node integrity")
    _validate_branch(view)
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
    if view.kind == "fat" and view.level:
        _validate_branch(view)
        if h(_branch_bytes(view)) != view.oid:
            raise ValueError("tree root integrity")
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


def _fat_node(children, level, packing, shape, emit):
    view = View(
        _fp("fat", level, children), "", children[-1].sep,
        sum(child.n for child in children), tuple(children),
        level=level, kind="fat", mark=packing.fanout,
        config=config(packing, shape),
    )
    raw = _branch_bytes(view)
    return View(
        view.fp, _emit(raw, emit), view.sep, view.n, view.children,
        level=level, kind="fat", mark=view.mark, config=view.config,
    )


def _pack_fat(children, level, packing, shape, emit):
    groups, group = [], []
    for child in children:
        group.append(child)
        if _fat_boundary(child, level, packing, shape):
            groups.append(group)
            group = []
    if group:
        groups.append(group)
    return [
        _fat_node(tuple(group), level, packing, shape, emit)
        for group in groups
    ]


def _fat_view(leaves, packing, shape, emit):
    if not leaves:
        return View(
            shape.fingerprint([]), h(b""), "", 0, (),
            kind="fat", mark=packing.fanout,
            config=config(packing, shape),
        )
    nodes, level = leaves, 1
    while True:
        nodes = _pack_fat(nodes, level, packing, shape, emit)
        if len(nodes) == 1:
            return nodes[0]
        level += 1


def build(keys, shape, packing, fact_of, deps_of, emit, memo=None):
    """Build one packing as a pure function of ``keys``."""
    leaves, mark = _leaf_views(
        keys, shape, packing, fact_of, deps_of, emit, memo)
    if packing.kind == "binary":
        return _binary_view(leaves, shape)
    if packing.kind == "flat":
        return _flat_view(leaves, mark, shape)
    return _fat_view(leaves, packing, shape, emit)


def _resolved(view, fetch):
    if view.level == 0 or view.children:
        return view
    raw = fetch(view.oid)
    if raw is None:
        raise KeyError(view.oid)
    resolved = _decode_branch(raw, view.oid)
    if _summary(resolved) != _summary(view):
        raise ValueError("tree child summary")
    return resolved


def _read_leaf(view, lo, hi, shape, fetch):
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
    if use_warm and view.keys:
        keys = list(view.keys)
        if len(keys) != view.n or shape.fingerprint(keys) != view.fp:
            raise ValueError("leaf summary")
        return keys
    return _read_leaf(view, lo, hi, shape, fetch)[1]


def _walk_leaves(view, fetch, lo="", hi="~"):
    view = _resolved(view, fetch)
    if view.level == 0:
        yield lo, hi, view
        return
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
    """Read one closed leaf pile after validating its object and summary."""
    return _read_leaf(leaf, lo, hi, shape, fetch)[0]


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
        view, delta, shape, packing, fact_of, deps_of, fetch, emit,
        lo="", use_warm=True):
    view = _resolved(view, fetch)
    if view.level == 0:
        old = _leaf_keys(
            view, lo, view.sep or "~", shape, fetch, use_warm)
        leaves, _ = _leaf_views(
            old + delta, shape, packing, fact_of, deps_of, emit)
        return leaves
    routed, children, lower = _route(view.children, delta), [], lo
    changed = False
    for child, additions in zip(view.children, routed):
        if additions:
            children.extend(_fold_fat(
                child, additions, shape, packing, fact_of, deps_of,
                fetch, emit, lower, use_warm,
            ))
            changed = True
        else:
            children.append(child)
        lower = child.sep
    if not changed:
        return [view]
    packed = _pack_fat(children, view.level, packing, shape, emit)
    if len(packed) == 1 and packed[0].oid == view.oid:
        return [view]
    return packed


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
    nodes = _fold_fat(
        view, delta, shape, packing, fact_of, deps_of, fetch, emit,
        use_warm=not fetch_warm)
    level = view.level + 1
    while len(nodes) > 1:
        nodes = _pack_fat(nodes, level, packing, shape, emit)
        level += 1
    return nodes[0]


def diff(
        mine, theirs, shape, fetch_mine, fetch_theirs, *,
        fetch_warm=False):
    """Yield differing leaf ranges as ``(lo, hi, my_keys, their_leaf)``."""
    left_nodes, right_nodes, left_keys, right_keys = {}, {}, {}, {}

    def resolve(view, fetch, cache):
        if view.level == 0 or view.children:
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

    left_hi, right_hi = mine.sep, theirs.sep
    if left_hi and right_hi:
        yield from rec(mine, "", left_hi, theirs, "", right_hi)
    empty = _empty(shape=shape)
    if left_hi < right_hi:
        yield from rec(empty, left_hi, right_hi, theirs, "", right_hi)
    elif right_hi < left_hi:
        yield from rec(mine, "", left_hi, empty, right_hi, left_hi)


def merge(a, b, shape, packing, fetch, emit):
    """Join two roots by folding only ``b - a`` into ``a``."""
    expected = config(packing, shape)
    if any(view.kind == "fat" and view.config != expected for view in (a, b)):
        raise ValueError("tree config")
    if a.fp == b.fp and a.n == b.n:
        return a
    if not a.n:
        return b
    if not b.n:
        return a

    cache, facts, streams, deps, processed = {}, {}, {}, {}, set()

    def cached(oid):
        if oid not in cache:
            raw = cache[oid] = fetch(oid)
            if raw is not None and "facts" in json.loads(raw):
                stream = decode_pile(raw)[0]
                streams[oid] = stream
                facts.update((fact.fid, fact) for fact in stream)
        return cache[oid]

    changes = list(diff(
        a, b, shape, cached, cached, fetch_warm=True))
    delta = set()
    for lo, hi, mine, remote in changes:
        theirs = set(_leaf_keys(remote, lo, hi, shape, cached))
        delta.update(theirs - set(mine))
    if not delta:
        return a

    def resolve_streams():
        anchors = [
            fact.fid for fact in facts.values()
            if fact.t in ("workspace", "genesis")
        ]
        if not anchors:
            from . import facts as families
            if any(
                    fact.refs() or families.handler_for(fact.t) is not None
                    for fact in facts.values()):
                raise ValueError("merge closure")
            deps.update((fid, ()) for fid in facts)
            processed.update(streams)
            return
        from .kernel import drain
        anchor = min(anchors)
        for oid, stream in streams.items():
            if oid in processed:
                continue
            result = drain(stream, anchor)
            if not result.ok:
                raise ValueError("merge closure")
            deps.update(
                (valid.fact.fid, valid.deps) for valid in result.valids)
            processed.add(oid)

    def fact_of(fid):
        return facts[fid]

    def deps_of(fid):
        if fid not in deps:
            resolve_streams()
        if fid not in deps:
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
    """Return reachable node and pile object ids.

    A decoded fat tree needs ``fetch`` to walk below its child summaries.
    """
    out = {view.oid} if view.n else set()
    if view.level == 0:
        return out
    resolved = view if view.children else (
        _resolved(view, fetch) if fetch is not None else view)
    for child in resolved.children:
        out.update(live_oids(child, fetch))
    return out
