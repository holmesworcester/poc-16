# The multi-level pile — hoisting closure up the tree

**Status (2026-07-25): landed for production `T_fact`.** `core/tree.py` stores
one content-addressed payload per settle node, walks a full fact tree with every
fact once, and assembles deduplicated closed path unions for range sync.
`kernel.Scratchpad` owns verify-once path context; `core/hoist.py` remains only
the binary compatibility/measurement façade. This is `poc-16-808.9`.
Secondary indexes whose validity closure contains unindexed facts require the
adapter tracked by `poc-16-yez.15`.

Companion to `TREAP_PROTOTYPE.md`. The prototype stores a **closed pile at every
leaf**: leaf `ℓ`'s object carries `C(ℓ) = closure(K(ℓ))`, its in-range facts plus
their full dependency closure. A fact needed by `k` leaves is therefore stored
`k` times — the redundancy tax (`ρ ≈ 3×` flat, measured). `COLD_CUT` fights it by
making leaves big enough to amortise the shared closure over more facts.

This note does it **structurally** instead: store each closure fact **once**, at
the node where the branches that need it meet, so the closure is *factored* up the
tree. The result:

- every **root-to-node path is a closed set** (not just leaves) — you can validate
  as you descend;
- full-sync download and verification drop to **one copy of each fact** (`ρ → 1`);
- for **full sync** the multiplicative redundancy collapses to `1×`; for **range
  sync** it becomes a *flat shared-core tax* (≈ 4×members) that can **lose** to
  leaf-only piles for small pulls unless the key order is dependency-aligned — an
  earlier draft claimed an `O(log n)` tax here; it is measured and corrected in
  A.4–A.5.

Part A works out how the tree is built deterministically with minimal steps.
Part B works out the "fancy" version: validation down branching paths.

---

## 0. Setup

Facts form a DAG: `deps(f)` are the facts `f` needs to validate (its refs +
resolved family/membership needs — `resolve_deps`). `closure(S)` is the least
superset of `S` closed under `deps`; a pile is **closed** iff `closure(pile)=pile`.

The treap is a **binary search tree over the keys** (`layout`/`treap.py`): left =
keys `≤ sep`, right = keys `> sep`, shape fixed by each key's own hash (boundary +
priority). So node `v` owns a **contiguous key interval** `K(v)`, and for any set
of leaves the **LCA is the node whose interval is the tightest one covering their
key range** — the BST property we lean on throughout.

| symbol | meaning |
|---|---|
| `V` | all facts; `\|V\|` distinct facts in the workspace |
| `E` | dependency edges, `\|E\| = Σ_f \|deps(f)\|` |
| `P` | leaves |
| `K(v)` | in-range keys under node `v` (a contiguous interval) |
| `C(v)` | `= closure(K(v))`, everything needed to validate `v`'s subtree |
| `N(f)` | leaves whose closure contains `f` `= {ℓ : f ∈ C(ℓ)}` |
| `pos(f)` | `f`'s own position in key order (every fact is a key of one leaf) |
| `span(f)` | `[min, max] pos` over `{f} ∪ {g : g depends on f}` |
| `settle(f)` | the node where `f`'s bytes are stored |

`C` is **monotone up the tree**: `C(child) ⊆ C(parent)`, because
`C(parent) = closure(K(child) ∪ K(sibling)) ⊇ closure(K(child))`. Closure only
grows with range. This one fact drives everything below.

---

# Part A — building the multi-level pile

## A.1 The placement rule (three equivalent forms)

**(Local — what you asked for.)** Bottom-up: *a dep in the closure of **both**
children is moved to the parent; repeat up the tree.* A dep needed on only one
side stays on that side.

**(Global — LCA.)** `settle(f) = LCA( N(f) )` — the deepest node whose subtree
contains every leaf that needs `f`.

**(Computable — interval.)** `settle(f) =` the **deepest node whose key interval
covers `span(f)`**.

**These three are the same rule.** Local ⇒ global: `f` rises out of a subtree `a`
exactly while it is *also* needed outside `a` (i.e. `f ∈ C(a)` and `f ∈ C(sibling)`
so it is "common to both children" of `a`'s parent); it stops at the first node
whose sibling does **not** need it — which is precisely `LCA(N(f))`. Global ⇒
interval: because the tree is a BST, `LCA` of a leaf-set is `LCA(min-key-leaf,
max-key-leaf)`, and `pos(f) ∈ span(f)` always (a fact is in its own closure), so
the covering node is an ancestor of `f`'s own leaf too. ∎

Two facts settle at a leaf iff `N(f)` is that single leaf (needed nowhere else).
Everything shared rises to the meeting point of the branches that need it; the
genesis membership, needed almost everywhere, rises to the root.

## A.2 The theorem — every path is a closure

> **Claim.** For every node `v`, `pathUnion(v) := ⋃_{u ⪯ v} store(u)` is
> dependency-closed. (`u ⪯ v` = `u` on the root→`v` path.)

**Lemma (deps rise at least as high).** If `g ∈ deps(f)` then `settle(g)` is an
ancestor-or-self of `settle(f)`.
*Proof.* Everything that depends on `f` also depends on `g` (through `f`), and `f`
itself depends on `g`, so `{f} ∪ dependents(f) ⊆ dependents(g)`. Hence
`span(f) ⊆ span(g)`. In a BST the deepest node covering a larger interval is an
ancestor-or-self of the one covering a nested interval (the descent for the
smaller interval refines the larger one along the same path). So
`settle(g) ⪰ settle(f)`. ∎

**Proof of claim.** Take `f ∈ pathUnion(v)`: `f` settled at some `u ⪯ v`. For any
`g ∈ deps(f)`, the lemma puts `settle(g)` at an ancestor-or-self of `u`, hence
`⪯ v`, so `g ∈ pathUnion(v)`. Thus `pathUnion(v)` is closed. ∎

In particular `pathUnion(ℓ) ⊇ C(ℓ) ⊇ K(ℓ)`: the accumulated path validates the
leaf. Determinism is inherited — `span` is a function of (key order, deps) and
`settle` of the treap shape, both deterministic — so the multi-level tree is a
pure function of the fact set (history-independent; R1–R3 hold).

## A.3 The build — minimal steps

Each fact is **closed and serialised exactly once**, against the redundant
`Σ_f |N(f)|` of the leaf-only build.

```
1. shape         treap(keys)                              # BST-treap, as today  — O(V)
2. spans         one reverse-topo pass over the DAG:      # dependents before deps
                   span[f] = [pos(f), pos(f)]
                   for f in reverse_topo:                 # f after all that depend on it
                     for g in deps(f): span[g] ∪= span[f] # interval merge
                                                          #                       — O(V + E)
3. settle        for each f, descend from root while span[f]
                   fits inside one child; stop = settle[f]#                       — O(V·log P)
4. payloads      store[v] = { f : settle[f] = v }         #                       — O(V)
                 node.hash = h( encode(store[v]) | L.hash | R.hash )
```

- **Step 2 is linear** (`|E| = O(V)` here: a fact deps on a handful of others).
- **Total serialisation/hashing is `|V|`, not `ρ|V|`.** The leaf-only build
  re-`close()`s every shared fact once per needing leaf (`Σ_ℓ |C(ℓ)| = Σ_f |N(f)|`).
  So the multi-level build is **`ρ×` less work** as well as `ρ×` less storage —
  it pays the closure cost once globally instead of once per leaf.

**Lower bound.** You must read every dep edge to know the closure structure
(`≥ E`) and write every distinct fact once (`≥ |V|`). The build hits both:
`O(V + E)` up to the `log P` placement descent. Nothing correct stores a fact
fewer than once, so `|V|` object-volume is the floor — the leaf-only scheme sits a
factor `ρ` above it.

## A.4 What it costs — full-sync wins, a flat shared-core tax on range sync

| | leaf-only pile | multi-level pile |
|---|---|---|
| stored fact-copies | `Σ_f N(f) = ρ·\|V\|` | `\|V\|` (once each) |
| full-sync download | `ρ×` | **`1×`** (the floor) |
| range sync (subtree of `s` leaves) | `s` piles, each carrying its full closure | subtree facts `+` the **hoisted shared-core** (≈ 4×members), **flat in `s`** |
| single-leaf random fetch | 1 object | the root→leaf path |
| redundancy form | **multiplicative** `ρ` | **additive, = the shared-core size** (not `O(log n)`) |

Two residuals — and the first is bigger than the earlier draft admitted
(measured in A.5):

- **Over-inclusion is not small.** A fact settles at `LCA(N(f))`, which rides
  *every* leaf under that node — tight only when `N(f)` is **contiguous in key
  order**. Under the shipped **timestamp** order it is badly non-contiguous: each
  member posts across the whole 3-year window, so that member's membership is
  needed by ~1% of leaves *scattered end to end* → `LCA(N(f)) = root` → it rides
  nearly all paths. The shared core (≈ 4×members: workspace root + per-user
  user_invite/user/signatures) hoists to the root and over-includes ~92% of the
  paths it rides — only the *workspace root* is genuinely near-universal. So
  the range-sync tax is a **flat ≈ 4×members**, independent of subtree size, and
  it makes multi-level
  **lose to leaf-only for small range syncs** — *under the shipped timestamp
  order*. A.5 now measures actual depth-1, shallow-wide, random, and length-99
  delegation trees. A delegation-DFS order turns the semantic-subtree overhead
  into a path cost (about four auth facts per ancestor, plus a small
  hash-boundary residual): an order artifact bounded by depth, not members.
- **Single-leaf access is now a path, not an object.** Sync walks paths anyway, so
  it is free there; only random single-leaf fetch pays the depth.

## A.5 Measured — the redundancy hoisting removes

`bench/bench_hoist.py`, flat leaves (`CUT=8`, `COLD_CUT=None`), 100 members / 3y:

| facts | leaves | avg facts/leaf | `ρ` (leaf-only) | own-leaf % | facts→root | max `N(f)` | full-sync saving |
|--:|--:|--:|--:|--:|--:|--:|--:|
| 4 999 | 649 | 22.8 | **2.96×** | 86.1% | 5 | 595 (92% of leaves) | **66.2%** |
| 49 999 | 6 251 | 24.6 | **3.08×** | 93.1% | 1 | 5 752 (92% of leaves) | **67.5%** |

`ρ` reproduces RESULTS.md §3's flat 3.1×. The shape of the win: **86–93% of facts
are needed by their own leaf only** and never move; a **tiny shared core** (led by
the workspace membership, in ~92% of all leaves) is what inflates the total to `3×`.
Hoisting moves only that core and deletes **two-thirds** of the *full-sync*
stored/shipped/verified volume — `ρ → 1`. But the moved core is exactly the
**range-sync tax** of A.4, and it is *not* small — measured next.

This is why hoisting makes `COLD_CUT` page-inflation unnecessary *for full-sync
redundancy*: big cold pages exist only to amortise this shared core, and the
multi-level pile amortises it structurally. (Large leaves would still help
object-count / round-trip count — a separate axis.)

### Range-sync tax and real delegation depth (`bench/bench_order.py`, 49,999)

The shared core hoists to the root, so a range syncer pulling a small subtree pays
it in full — but **how big that core is depends on key order and actual delegation
depth**. The benchmark now bulk-builds the same 100-user fact set in four shapes,
with messages uniform over three years and flat leaves (`COLD_CUT=None`):
the numeric seed deterministically derives the root time and every Ed25519
identity, so repeated runs reproduce the same fact ids, treap boundaries, and
tax measurements (only the wall-clock timing columns vary). Topology and
content use separate deterministic RNG streams, so the random tree's parent
draws cannot change message authors or timestamps relative to the other shapes.

| shape | realized depth histogram (depth:users) | min / median / max |
|---|---|---:|
| star | `0:1, 1:99` | 0 / 1 / 1 |
| shallow-wide (8 inviters) | `0:1, 1:8, 2:91` | 0 / 2 / 2 |
| random recursive | `0:1, 1:7, 2:11, 3:19, 4:19, 5:25, 6:14, 7:3, 8:1` | 0 / 4 / 8 |
| chain | every depth `0…99:1` | 0 / 49.5 / 99 |

The tree is reconstructed via **users**, never the ephemeral invitee key:
`user -> referenced user_invite -> invite signer`. Each invite and its signature
are then re-homed onto the user it admitted. `mean tax` is the mean ancestor
payload above a layout leaf; `≥50%` counts facts whose settle node rides at least
half the leaves. `crossover` is the first observed hash-shaped layout subtree
where multi-level ships no more than leaf-only, so it is boundary-sample-sensitive:

| shape | order | leaf-only `ρ` | mean tax | facts ≥50% | crossover (leaves) |
|---|---|--:|--:|--:|--:|
| star | timestamp | 3.09× | 398.9 | 397 | 14 |
|  | author | 1.64× | 137.6 | 135 | 7 |
|  | **delegation DFS** | **1.64×** | **35.7** | **13** | **2** |
| shallow-wide | timestamp | 4.34× | 398.8 | 397 | 7 |
|  | author | 2.07× | 181.0 | 179 | 13 |
|  | **delegation DFS** | **2.06×** | **48.1** | **25** | **3** |
| random | timestamp | 6.69× | 398.8 | 397 | 4 |
|  | author | 3.06× | 244.4 | 255 | 5 |
|  | **delegation DFS** | **3.04×** | **86.8** | **69** | **2** |
| chain | timestamp | 34.81× | 398.8 | 397 | 1 |
|  | author | 24.30× | 393.3 | 395 | 1 |
|  | **delegation DFS** | **24.20×** | **274.7** | **213** | **1** |

The new depth test pulls the key range containing one *semantic delegation
subtree*. Here `tax = ML facts fetched − that subtree's own facts`, so it counts
both ancestor context and unrelated facts dragged in by scatter:

| shape / target | depth | users | timestamp tax | author tax | **DFS tax** |
|---|--:|--:|--:|--:|--:|
| star leaf | 1 | 1 | 49,119 | 16,615 | **24** |
| shallow-wide leaf | 2 | 1 | 48,627 | 17,213 | **43** |
| shallow-wide branch | 1 | 12 | 43,995 | 41,091 | **69** |
| random leaf | 8 | 1 | 49,505 | 42,035 | **92** |
| random branch | 4 | 10 | 45,067 | 41,222 | **114** |
| chain suffix | 99 | 1 | 49,424 | 14,422 | **401** |
| chain suffix | 90 | 10 | 45,154 | 38,775 | **361** |
| chain suffix | 50 | 50 | 25,112 | 24,657 | **197** |

What the numbers say:

- **Timestamp tax is still the flat control.** Every shape has mean tax ≈399
  and 397 facts riding at least half the leaves: the `1 + 4×99` workspace/user
  auth core, scattered by three years of content. This reproduces the old star
  result and confirms depth does not rescue a time order.
- **DFS makes semantic-subtree tax path-bounded.** On the deliberately clean
  chain the prediction is visible directly: depth 99 costs 401
  (`≈4×99 + 1`), depth 90 costs 361, and depth 50 costs 197. The remaining
  tens-of-facts wobble is the hash-derived leaf boundary covering neighboring
  facts, not an `N` term. The same fixed boundary residual dominates the much
  shorter wide/random paths (for example 43 at depth 2 and 92 at depth 8).
- **It matters most in the realistic shallow-wide case, not only the stress
  chain.** Wide mean tax falls 399→48 (8.3×) and random falls 399→87 (4.6×);
  they beat flat author grouping by 3.8× and 2.8× respectively. In the adversarial chain,
  `depth = Θ(N)`, so the worst-case asymptotic advantage necessarily vanishes
  and mean tax falls only 399→275. Even there the aligned semantic suffix avoids
  scatter: the deepest one-user pull pays 401 rather than 49,424.
- **Real depth raises leaf-only closure cost.** Chain `ρ=24.20×` even under DFS
  because a deep author's *actual required authority path* is long; this is not
  ordering over-inclusion. Multi-level full sync remains exactly `1×`, so
  verify-once/ship-once becomes more valuable as honest closure depth grows.
- **Treap-shape residual remains.** DFS makes semantic spans contiguous, but a
  hash-random boundary can cover neighboring facts. Aligning boundaries to the
  delegation hierarchy could remove that last fixed residual; it is not needed
  for the `O(members) -> O(depth)` result.

With three devices per user, flat device-author grouping and user grouping
finally diverge. On a 4,999-fact random seed, roster-aware user DFS lowers
leaf-only `ρ` **4.13×→3.58×**, mean tax **862→108**, and facts riding ≥50% of
leaves **815→55**; every sampled user subtree has no greater tax. This is why
the keychain/device layer matters to ordering rather than merely vocabulary.

**Robust regardless of order:** full-sync `= |V|` (the floor), verify-once `= |V|`
judge-ops, incremental fold `= O(touched)` (§A.6, B.1). The key-order question
governs only the range-sync tax — an `N`-scale catastrophe under timestamp
scatter and a depth-scale path cost under delegation order.

**What this means for the headline claim.** In the star, a good key order lowers
*leaf-only* `ρ` too (3.09→1.64), while multi-level's full-sync cost is
order-**invariant** (always `|V|`). So much of the old "two-thirds saved" headline
was timestamp scatter. In a deep chain, however, aligned leaf-only remains
24.20× because the required authority paths themselves are long; multi-level
still ships and verifies each fact once. Hoisting's durable payoff is therefore
the **closed-path / verify-once** property (§A.2, B.1), with the redundancy gain
ranging from modest on a shallow aligned star to enormous on honest deep
closures.

## A.6 Incremental fold (blind, bounded ripple)

Folding `B` new facts has two effects:

1. **Shape** — new keys grow/split their landing leaves and bounded-rotate, exactly
   as `treap.update`: `A` leaves + spine, `O(B)`.
2. **Re-hoist** — a new fact at position `p` depending on old fact `g` adds `p` to
   `span(g)`; if `p` falls outside `g`'s current interval, `settle(g)` **rises** to
   `LCA(old settle(g), p)` (bytes move up one payload to another). This ripples
   only through the **closure of the new facts**, never the whole tree.

Why it stays cheap:

- **Append** (new facts at the tip, depending on recent facts): the touched deps
  live near the tip; rises are short.
- **Widely-shared deps are already near the root** — adding one more dependent to
  the workspace membership does not move it (it already covers the tree). The facts
  expensive to move are exactly the ones already high, which almost never move.

So the fold touches `A` leaves + spine + `{deps of the batch that actually rise}` —
still `∝ what changed`, `n`-independent for append, and **blind**: rising `g` needs
only its current `settle` node (found by descent) and the new position, so you
rewrite the nodes on the affected paths, not the tree.

The production encoding records each payload fact's exact stable low/high key
bounds in its node (the common self-only case is encoded as just its fid).
`fold` follows the new batch's transitive deps, expands only those bounds,
removes the facts whose bounds changed, path-copies the affected structural
spines, and settles them again. A leaf or fat group split similarly rehomes only
the payload of the node whose interval changed. This metadata is what makes a
sans-I/O two-root merge history-independent on the bounded path when both roots
already passed publication validation and dependency edges are fixed. An
untrusted root must reproduce the byte-identical canonical settle placement
before any identity/empty shortcut; checking only its full fact set would miss
an invalid partial path. A concurrent provider/consumer delta can rewire the
union-wide canonical dependency graph; production detects that case and
performs a full canonical rebuild rather than publishing a history-dependent
root. `poc-16-jbg.3` owns amortizing that fallback.

---

# Part B — the fancy version: validation down branching paths

Because every path is closed (A.2), you can verify **as you descend**, and each
fact is verified **exactly once** — at its settle node, on behalf of every leaf
below it.

## B.1 Verify-once

```
verify(v, ctx):                      # ctx = verified pathUnion(parent), closed
  ctx' = ctx ∪ store[v]
  for f in store[v]:                 # deps(f) ⊆ ctx' since pathUnion(v) is closed
     check_sig_and_membership(f, against ctx')
  for child in (L, R): verify(child, ctx')
```

- **Work `= O(|V|)` verifications** (each fact once), against the leaf-only
  `O(Σ_f N(f)) = O(ρ|V|)` — every leaf there re-verifies its whole closure from an
  empty kernel (RESULTS.md: "leaves judge alone"), re-checking the shared core once
  per leaf. Hoisting pays the Ed25519 floor **once**. Since RESULTS.md finds crypto
  *is* the floor, this is the same `ρ→1` win on CPU as on bytes.
- **Memory `= O(depth · payload)`** — only the current path's contexts are live;
  pop on backtrack. Streamable, `n`-independent.
- **Incremental sync verifies changed nodes only.** A diff pulls the nodes whose
  *payload* changed (distinct from nodes whose *hash* changed — the Merkle spine
  moves to the root, but an unchanged payload is re-used from cache). Each changed
  payload is checked against its already-verified ancestor context. Verify-work
  `= O(changed facts)`; the shared core, verified once, is never re-checked.

## B.2 Two modes, and when they coincide

- **Branch validation (fancy).** Verify at each node during descent, as above.
  Best for streaming / incremental sync: `O(depth)` memory, verify-once,
  changed-nodes-only.
- **Accumulate-to-leaf.** Pull a whole path, union the payloads (`pathUnion(ℓ)`,
  a closed superset of `C(ℓ)`), verify the leaf's facts there. Simpler mental
  model; correct because the path is closed.

They **coincide when you cache the verified ancestor context**: accumulate-to-leaf
*without* caching re-verifies each ancestor's facts once per leaf and regresses to
`O(ρ|V|)`; *with* caching it is the branch version with the checks deferred to the
leaf boundary. The verify-once win is the caching, not the timing.

## B.3 Download-as-you-diff, validated

Combining A.2 + B.1 gives the property you were after: a range-scoped syncer walks
root→(its leaves), and

1. every prefix it has pulled is already a **closed, validating** set (A.2), so it
   never holds an unvalidatable fragment;
2. it verifies each pulled fact **once** (B.1), shared context included, and
3. it pulls each shared fact **once** (A.4) instead of once per leaf.

The closure it needs is *delivered by the path itself* — which is exactly why the
node hash is over pile **bytes**: a change anywhere in a settled payload moves that
node's hash and re-invites the pull, and the closure rides down with it.

---

## Summary

- The local rule **"hoist a dep shared by both children to the parent, repeat"**
  equals `settle(f) = LCA(N(f)) =` deepest node covering `span(f)` — deterministic,
  history-independent, computable in `O(V + E)` + an `O(log P)` placement descent.
- It makes **every root-to-node path a closed set**, so you can download and
  validate as you descend.
- For **full sync** it stores/ships/verifies **each fact once** (`ρ ≈ 3× → 1×`,
  measured 66–68% saved) — the floor, order-independent — and makes `COLD_CUT`
  page-inflation unnecessary for *full-sync* redundancy.
- For **range sync** the cost is a **shared-core tax**, *not* the `O(log n)` an
  earlier draft claimed — and it is **an artifact of key order, not intrinsic**.
  Under the shipped **timestamp** order it is a flat ≈ 4×members and multi-level
  loses to leaf-only for small pulls. A **delegation-aligned** order (invite tree
  via users, each invite+signature re-homed onto the member it admitted) changes
  semantic-subtree overhead from member-bounded to **path-bounded**: star mean
  tax 399→36, shallow-wide 399→48, random 399→87, and a length-99 chain 399→275.
  On that chain, depth-99/90/50 suffixes cost 401/361/197 extra facts—about four
  auth facts per ancestor—rather than 49k/45k/25k under timestamp scatter.
  Measured in A.5.
- Folds stay **blind and bounded** (`A` leaves + spine + the batch's rising deps;
  append-cheap).
- The fancy version verifies **once per fact** at `O(depth)` memory and, on a diff,
  **only the changed payloads** — the same `ρ→1` win on the Ed25519 floor.

Net: the wins that hold unconditionally are **full-sync `ρ→1`, verify-once, and
`O(touched)` incremental fold**. The **range-sync** story is order-dependent and, for
small pulls, a loss — surfaced by the prototype (`core/hoist.py`,
`bench/bench_hoist_sync.py`, `bench/bench_order.py`), which is now built and
measured rather than assumed.
