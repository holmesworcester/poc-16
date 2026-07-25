# Blind incremental tree update — cost analysis + prototype

**Status (2026-07-25): absorbed by the engine.** The cost floor and
measurements remain the design record; `tinyp2p/tree.py` now implements the
sans-I/O fold once for binary, flat-compatibility, and production fat
packings. `tinyp2p/treap.py` is a golden compatibility façade, not a second
production engine.

Branch `treap-merkle-prototype`. Prototype: `tinyp2p/treap.py`; measurement:
`bench/bench_treap.py`. This note shows, with a cost model and a lower-bound
argument backed by measurement, that folding incoming piles into the tree
touches the **minimum possible** set of store objects and runs at complexity
proportional to *what changed*, not to the workspace — and where the memory /
store-I/O balance falls in a λ (ephemeral, memory-bounded) runtime.

---

## 1. Cost model

The store is a dumb content-addressed object store: a leaf pile or the root
manifest is one object; the only operations are `GET` (read) and `PUT` (write),
each a network round-trip with a per-request cost `c_io` plus bytes. The runtime
is an ephemeral function instance with RAM budget `M` and no state between
invocations unless the container is warm. The scarce resources, in order, are:
**store round-trips**, then **RAM**, then compute (closures + hashing).

| symbol | meaning |
|---|---|
| `n` | facts in the workspace |
| `B` | new facts folded in one operation (from incoming piles) |
| `L` | expected leaf size (facts/leaf) — `CUT` fine, `COLD_CUT` coarse |
| `P` | leaves `= n / L` |
| `A` | **distinct leaves the `B` new keys land in** |
| `annex(L)` | closure a single `L`-leaf carries (membership etc.) |
| `c_io` | cost of one store round-trip (GET or PUT) |

The layout is history-independent: a key's leaf, and the whole tree shape, are
pure functions of each key's own hash (`boundary(fid)`, and the treap priority
over boundaries). So `A` is **not a choice** — it is fixed by where the `B`
keys' hashes place them:

```
A(B, P) = P · (1 − (1 − 1/P)^B) ≈ P · (1 − e^(−B/P)) ≈ min(B, P)   (scattered B)
```

For `B ≪ P` a scattered batch lands in `A ≈ B` distinct leaves; as `B → P` it
saturates at `A → P` (every leaf touched once).

---

## 2. Lower bound — what any correct fold must read and write

Three facts force a floor, independent of data structure:

1. **A changed leaf must be rewritten.** Leaves are content-addressed and
   self-contained: change the in-range set and the bytes change, so the hash
   changes, so it is a *new object*. Hence `writes ≥ A` (plus one extra write
   per boundary key in `B` that splits a leaf `1 → 2`).
2. **A changed leaf must be read to be re-closed.** Re-closing needs the leaf's
   existing facts; absent a warm cache they come from its pile. Hence
   `reads ≥ A` — minus any facts already in hand (the incoming pile, §6).
3. **The commit point must move.** The root/manifest must reference the new leaf
   hashes, so `writes ≥ 1` more (the manifest).

**Floor:** `reads ≥ A + locate`, `writes ≥ A + manifest`. Nothing correct beats
`A` leaf-touches, because the `B` facts genuinely occupy `A` distinct
self-contained leaves.

---

## 3. The treap meets the floor

`update()` (treap.py) descends routing the new keys, rebuilds only the leaves
they hit (grow, or split at the boundary), rebuilds a subtree only when a new
boundary key out-ranks the separator above it (a bounded treap "rotate-up"), and
returns every untouched subtree **verbatim, without reading it**. Its costs:

```
reads   = A            leaves  + O(log P)  spine descent    (or 1 root, if inlined)
writes  = A + splits   leaves  + spine
spine   = O(A · log(P/A))  internal-node updates
```

Leaf I/O is exactly `A` (+ splits) — **the floor**. The `spine` term is the
Merkle price of moving `A` scattered leaf hashes up to the root; it is packed
into store objects two ways, and this is the *only* design freedom:

- **Inlined root** (like the flat list today): one manifest object, so the
  spine is **1 PUT** of `O(P)` bytes. Best when `P` is small (≤ ~10⁴): one
  round-trip.
- **Chunked spine** (prolly/MST): the spine is itself content-addressed, so an
  update rewrites `O(A·log(P/A)/c)` small objects of `O(log P)` bytes total.
  Best when `P` is large enough that an `O(P)`-byte root is too big to rewrite.

The flat fence list *also* reaches the `A`-leaf floor **if** you fold via the
fence list (locate by bisect over `hi`, read the `A` hit leaves). But the
`layout()` on `main` does **not** — it takes the *entire* key sequence and
re-fingerprints *every* leaf each commit. In a warm process with a local index
that rescan is cheap; in a **cold λ with no index it is `O(P)` reads** (you must
read every leaf to reconstruct the key set) before you can locate anything. The
treap needs only the spine + the `A` hit leaves — **`O(A + log P)` reads vs
`O(P)`**. That is the read-scope minimization, and it is structural: the tree
lets you find the changed leaves without materialising the whole set.

---

## 4. Complexity of the operation

```
locate      O(B · log P)
re-close    O( A · (L + annex(L)) )        -- only the touched leaves
spine hash  O( A · log(P/A) )
-----------------------------------------------------------------
fold total  O( B·log P + A·(L + annex) )   ∝ what changed
full build  O( P · (L + annex) ) = O( n + P·annex )   ∝ the whole workspace
```

The ratio is `A/P` — the fraction of leaves the batch disturbs. For a fold that
is `≪` a rebuild whenever `A ≪ P`.

---

## 5. The scratchpad — incoming piles as durable working memory

Incoming piles are already in the store, durable, and destined to be consumed.
That has two consequences that push the fold *below* the §2 floor in
amortized terms:

- **Deferred writes.** Before you rewrite a re-closed leaf, its content —
  `old-leaf ∪ new-facts` — is *already durable*: the old leaf is in the store,
  the new facts are in the incoming piles. So the re-closed leaf need not be
  written immediately to avoid data loss. **Incoming is the write-ahead log.**
  Serve `canonical leaves ∪ un-distilled incoming`; a requester fetches the
  facts from whichever holds them. Distil (re-close, write, delete incoming)
  lazily. This is "boiling down incoming": the tree is the slowly-distilled
  form of the incoming stream.

- **Amortization.** Distil once per `B_acc` accumulated facts. Amortized store
  ops per fact:

  ```
  ops/fact = ( A(B_acc) + manifest ) / B_acc
           = P(1 − e^(−B_acc/P))/B_acc  +  manifest/B_acc
  ```

  Both terms **decrease in `B_acc`**: the leaf term falls from ≈1 (at `B_acc ≪ P`)
  toward `P/B_acc` (collisions — a leaf hit twice is still written once), and the
  manifest term `→ 0`. Bigger accumulation ⇒ cheaper per fact.

The catch would normally be RAM: holding `B_acc` facts in memory caps
`B_acc ≤ M`. But streaming the incoming piles *from the store* makes the batch
external, so:

```
RAM = O(L + spine window)      -- one leaf being re-closed + the descent path
                               -- INDEPENDENT of B_acc
```

**The scratchpad decouples amortization from RAM.** Without it, `B_acc ≤ M`;
with it, `B_acc` can grow to `≈ P` (each leaf touched ~once, written once) at
`O(L)` memory. That is the whole win of "use incoming as scratch."

---

## 6. The λ optimum — memory vs store I/O

Per-fact cost, all resources:

```
Φ(L, B_acc) =  c_io · (A(B_acc) + manifest)/B_acc     -- fold round-trips (§5)
            +  c_close · (L + annex(L))                -- re-close a touched leaf
            +  c_mem  · M · τ                          -- RAM · time
            +  c_io   · (1 + annex(L)/L)               -- catchup redundancy
```

Two independent minimizations:

- **In `B_acc`:** monotically decreasing until compute/latency (or the
  invocation window) caps it ⇒ **distil at `B_acc ≈ P`**, and — because of §5 —
  do it at `O(L)` RAM by streaming incoming, *not* by buying `M = B_acc`.

- **In `L`:** the re-close / write-amp term `(L + annex)` pulls **small** (a
  one-fact change rewrites a whole `L`-leaf); the redundancy `1 + annex/L` and
  object count `P = n/L` pull **large**. Interior optimum `L*` = the leaf-sizing
  target `B*` from MODEL.md, now with per-request I/O folded in. Small `L` makes
  incremental folds cheap; large `L` makes catchup cheap — the treap can carry a
  consolidated pile at internal levels too (base case: the root *is* a pile) to
  get both, at the price of storing piles at more than one level. (Left for
  later; the prototype carries piles only at leaves.)

---

## 7. Measured (`bench/bench_treap.py`, flat mode so treap leaves == flat leaves)

100 members, 3 simulated years, fold batch = 250 scattered old-ts msgs
(B = 500 facts). `leaves=` treap leaves byte-identical to the flat layout;
`incr=` blind update's leaf **and** spine hashes identical to a full rebuild.

| facts | P | full build (treap / flat) | fold time | rd | wr | spine | leaves= | incr= |
|--:|--:|--:|--:|--:|--:|--:|:--:|:--:|
| 4 999 | 631 | 0.26s / 0.33s | 0.21s | 163 | 217 | 469 | y | y |
| 19 999 | 2 449 | 1.09s / 1.40s | 0.29s | 222 | 283 | 1 014 | y | y |
| 49 999 | 6 215 | 2.79s / 3.59s | 0.30s | 239 | 289 | 1 403 | y | y |
| 99 999 | 12 469 | 5.69s / 7.32s | 0.38s | 241 | 296 | 1 710 | y | y |

- **Full build is `O(n)`** (0.26 → 5.69s): the "rebuild the whole tree" cost.
- **Fold is ≈ flat in `n`** (0.21 → 0.38s): governed by `B`, not the workspace.
- **Leaf I/O saturates with `B`** (rd/wr → ~241/296 for B=500) — the `A` floor,
  independent of `n`.
- **Spine grows as `A·log(P/A)`** (469 → 1 710 while `P` grows 20×) — the log
  Merkle term, small.
- **Fold-vs-rebuild advantage grows with `n`:** 1.25× at 5k → **15× at 100k**,
  because the fold is `O(B)` while the rebuild is `O(n)`.

(These are warm-process compute numbers — the store-I/O advantage of §3, `O(A)`
vs `O(P)` reads on a cold instance, is *not* visible here because the bench
holds a local index; the `rd`/`wr` columns are the store object-touch counts,
which are what a cold λ would pay.)

---

## 8. The mint question, answered

> ingest all incoming piles and rebuild the tree on mint, before returning?

- **Rebuild-on-mint (full):** `O(n·(1 + annex/L))` closures — **5.7s at 100k**,
  and it grows with the workspace. Fine for a cold start or a small workspace;
  too slow to sit synchronously on a hot mint path at scale.
- **Fold-on-mint (incremental):** `O(B·log P + A·(L+annex))` — **≈0.3s for a
  500-fact batch, essentially independent of `n`**. This is affordable on the
  mint path.

So: **maintain the tree, don't rebuild it.** On mint, both sides fold their
`O(B)` incoming before serving / requesting — the responder distils incoming and
serves a fresh tree, the requester distils its own incoming before it walks. A
full `O(n)` rebuild is reserved for a genuinely cold instance with no tree at
all. With the §5 scratchpad, the fold's writes amortize toward the `A(B_acc)/B_acc`
floor and RAM stays `O(L)` regardless of how much incoming has piled up.
