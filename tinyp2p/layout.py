"""layout(): the pure layout function — the treap as math, not state.

The canonical arrangement is a pure function of the valid set: keys sort,
content-defined boundaries (priority from the fid hash) cut the run into
leaves, and the suffix after the last boundary is the tail. Each leaf is one
**pile** — its in-range leaves plus their closure, `close`-d into a
topo-sorted (deps-first) self-contained object. Same set ⇒ same leaves,
fences, tail, manifest — on every node. Promotion, straggler mini-folds, and
full rebuild are all this one function; incrementality falls out of content
addressing (unchanged leaves hash to objects the store already has, so a
commit PUTs only what changed).

Sizing counts only the in-range leaves (`n`); the closure a leaf drags in is
attached, not counted. There is no separate "annex" object and no skew copies:
because the pile is topo-sorted, every dependency precedes its dependent by
construction, so `close(in-range leaves)` already streams valid from an empty
kernel. The fingerprint (`fp`) is over the in-range leaves in key order only —
the closure lives in the pile but outside the fingerprinted set, so copies
never perturb the diff algebra.

**Incremental compute.** With `memo` (the prior manifest's fences, keyed by
`hi`) a promoted leaf whose `(hi, fp)` is unchanged is reused verbatim — its
pile bytes are not recomputed and its facts are never loaded. This is
byte-identical to a full recompute whenever canonical proof winners are
stable. The caller (`Node.commit`) guarantees that by disabling the memo on
any turn that adds a shadowing offer, so `fp`-equality ⇒ identical pile: a
pile depends only on its in-range fids (immutable, key order) plus their
resolved deps (now fixed). The residual O(n) is the key scan and per-leaf
fingerprint — cheap, body-free; eliminating it needs a persistent fence tree
(byte-format work, out of scope).
"""
from .close import close, encode_pile
from .crypto import h

CUT = 8          # warm/fine density: a fact is a fine boundary iff prio % CUT == 0
COLD_CUT = 4096  # everything older than the guard watermark seals into coarse
                 # cold pages of ~COLD_CUT facts (~1.5 MB); the recent window
                 # stays fine. 4096 is the calibrated one-size-fits-most target:
                 # it buries the membership annex (which saturates at the ~Dunbar
                 # active-writer core, not at total members) under ~15% redundancy
                 # flat from 100 to 10,000 members. See MODEL.md "Leaf Sizing".
GUARD = 256      # B_t: keep at least this many recent facts in the fine warm zone


def boundary(fid, cut=None):
    return int(fid[:8], 16) % (cut or CUT) == 0


def _cut_positions(fids):
    """Boundary positions that partition the sorted run into leaves.

    One fine density (CUT) unless COLD_CUT is set — then the split is the last
    coarse boundary at or before len-GUARD: below it, history seals into big
    cold pages cut at COLD_CUT (each amortizes its shared closure over
    ~COLD_CUT in-range leaves, so catchup duplication → 1); above it, the recent GUARD+
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
        """One leaf pile: the in-range leaves plus their closure, `close`-d
        into a single topo-sorted (deps-first) self-contained object."""
        pile = close([fact_of(fid) for fid in fslice], deps_of, fact_of)
        pb = encode_pile(pile)
        objects["obj/" + h(pb)] = pb
        return {"fp": fp, "n": len(kslice), "pile": h(pb)}

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
        tail = {"fp": fingerprint([]), "n": 0, "pile": None}
    manifest = canon({"anchor": anchor, "fences": fences, "tail": tail,
                      "globals": sorted([list(row) for row in globals_])})
    return manifest, objects
