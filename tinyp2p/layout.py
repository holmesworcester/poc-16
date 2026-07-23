"""layout(): the pure layout function — the treap as math, not state.

The canonical arrangement is a pure function of the valid set: keys sort,
content-defined boundaries (priority from the fid hash) cut pages, the suffix
after the last boundary is the tail, and every range gets an annex that makes
range + annex a closed pile. Same set ⇒ same pages, fences, tail, manifest —
on every node. Promotion, straggler mini-folds, and full rebuild are all this
one function; incrementality falls out of content addressing (unchanged
ranges hash to objects the store already has, so a commit PUTs only what
changed).

**Incremental compute.** With `memo` (the prior manifest's fences, keyed by
`hi`) a promoted range whose `(hi, fp)` is unchanged is reused verbatim — its
page and annex bytes are not recomputed and its facts are never loaded. This
is byte-identical to a full recompute whenever dep resolution is stable, i.e.
every offer address the set resolves has a single provider (so `min-src`
cannot shift). The caller (`Node.commit`) guarantees that by disabling the
memo on any turn that adds a shadowing offer, so `fp`-equality ⇒ identical
page *and* annex: a page depends only on its range's fids (immutable, key
order), an annex only on those fids plus their resolved deps (now fixed).
The residual O(n) is the key scan and per-range fingerprint — cheap, body-free;
eliminating it needs a persistent fence tree (byte-format work, out of scope).
"""
from .close import close, encode_pile
from .crypto import h

CUT = 8          # warm/fine density: a fact is a fine boundary iff prio % CUT == 0
COLD_CUT = None  # if set, everything older than the guard watermark seals into
                 # coarse cold pages of ~COLD_CUT facts; the recent window stays fine
GUARD = 256      # B_t: keep at least this many recent facts in the fine warm zone


def boundary(fid, cut=None):
    return int(fid[:8], 16) % (cut or CUT) == 0


def _cut_positions(fids):
    """Boundary positions that partition the sorted run into leaves.

    One fine density (CUT) unless COLD_CUT is set — then the split is the last
    coarse boundary at or before len-GUARD: below it, history seals into big
    cold pages cut at COLD_CUT (each amortizes its membership annex over
    ~COLD_CUT facts, so catchup redundancy → 1); above it, the recent GUARD+
    window stays fine (CUT), so a write re-cuts only a small warm page. Pure in
    the set — split is a function of the fids alone — so RBSR/history-
    independence and leaves-are-piles are untouched. When len-GUARD crosses a
    coarse boundary the newly-sealed cold page is written once (the compaction:
    each fact ends up written ~twice over its life, warm then cold)."""
    if not COLD_CUT:
        return [i + 1 for i, fid in enumerate(fids) if boundary(fid)]
    n = len(fids)
    cold = [i + 1 for i, fid in enumerate(fids) if boundary(fid, COLD_CUT)]
    split = 0
    for c in cold:
        if c <= n - GUARD:
            split = c
        else:
            break
    return [c for c in cold if c <= split] + \
           [i + 1 for i, fid in enumerate(fids) if i + 1 > split and boundary(fid)]


def fingerprint(keys):
    return h("|".join(keys).encode())


def prefix_set(fids_in_key_order, deps_of):
    """The annex: out-of-range closure plus in-range skew-inversion copies.

    Smallest set P such that P is dep-closed (a prefix must be self-closed)
    and annex ∪ range streams valid: every dep of a range fact is either
    behind it in key order or copied into the prefix.
    """
    pos = {fid: i for i, fid in enumerate(fids_in_key_order)}
    P = set()

    def add(fid):
        if fid in P:
            return
        P.add(fid)
        for d in deps_of(fid):
            add(d)  # deps of prefix members join the prefix, in-range or not

    for i, fid in enumerate(fids_in_key_order):
        for d in deps_of(fid):
            if d not in pos:
                add(d)  # out-of-range dep
            elif pos[d] > i:
                add(d)  # in-range skew inversion: dep keyed after its dependent
    return P


def layout(keys, fact_of, deps_of, anchor, globals_, memo=None):
    """keys: sorted '<ts>:<fid>' strings of the whole valid set.
    memo: {hi: prior fence dict} to reuse unchanged promoted ranges, or None
    for a full recompute. Returns (manifest_bytes, {objkey: bytes}) —
    everything content-addressed; only recomputed ranges appear in objects.
    """
    from .fact import canon  # local import to avoid cycle
    fids = [k.split(":", 1)[1] for k in keys]
    cuts = _cut_positions(fids)
    tailstart = cuts[-1] if cuts else 0
    objects, fences = {}, []

    def emit_range(kslice, fslice, fp):
        """One range: page object (key order) + annex object (closed prefix)."""
        pb = encode_pile([fact_of(fid) for fid in fslice])
        objects["obj/" + h(pb)] = pb
        pre = prefix_set(fslice, deps_of)
        ah = None
        if pre:
            ab = encode_pile(close([fact_of(fid) for fid in pre], deps_of, fact_of))
            ah = h(ab)
            objects["obj/" + ah] = ab
        return {"fp": fp, "n": len(kslice), "page": h(pb), "annex": ah}

    lo = 0
    for cut in cuts:
        if cut > tailstart:
            break
        kslice, hi = keys[lo:cut], keys[cut - 1]
        fp = fingerprint(kslice)
        cached = memo.get(hi) if memo else None
        if cached and cached["fp"] == fp and cached["n"] == len(kslice):
            fences.append(cached)  # reuse: identical key set ⇒ identical bytes
        else:
            f = emit_range(kslice, fids[lo:cut], fp)
            f["hi"] = hi
            fences.append(f)
        lo = cut
    if tailstart < len(keys):  # the tail is small and always recomputed
        tail = emit_range(keys[tailstart:], fids[tailstart:], fingerprint(keys[tailstart:]))
    else:
        tail = {"fp": fingerprint([]), "n": 0, "page": None, "annex": None}
    manifest = canon({"anchor": anchor, "fences": fences, "tail": tail,
                      "globals": sorted([list(row) for row in globals_])})
    return manifest, objects
