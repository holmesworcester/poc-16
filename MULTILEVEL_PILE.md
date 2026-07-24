# The multi-level pile — hoisting closure up the tree

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
  nearly all paths. The shared core (≈ 4×members: genesis + per-member
  invite/join/sigs) hoists to the root and over-includes ~92% of the paths it
  rides — only *genesis* is genuinely near-universal. So the range-sync tax is a
  **flat ≈ 4×members**, independent of subtree size, and it makes multi-level
  **lose to leaf-only for small range syncs** (below a crossover of a few dozen
  leaves) — *under the shipped timestamp order*. A.5 measures how a
  dependency-aligned key order collapses this ~10× (tax 397→37, crossover ~40→~11
  leaves): the tax is an order artifact, not an intrinsic cost.
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
the genesis membership, in ~92% of all leaves) is what inflates the total to `3×`.
Hoisting moves only that core and deletes **two-thirds** of the *full-sync*
stored/shipped/verified volume — `ρ → 1`. But the moved core is exactly the
**range-sync tax** of A.4, and it is *not* small — measured next.

This is why hoisting makes `COLD_CUT` page-inflation unnecessary *for full-sync
redundancy*: big cold pages exist only to amortise this shared core, and the
multi-level pile amortises it structurally. (Large leaves would still help
object-count / round-trip count — a separate axis.)

### Range-sync tax and the key-order question (`bench/bench_order.py`, 50k)

The shared core hoists to the root, so a range syncer pulling a small subtree pays
it in full — but **how big that core is depends entirely on the key order**. The
tightness rule is the same one that governs applicability/global facts: a fact
settles tightly only when the leaves that need it are **contiguous in key order**,
and closure follows **authorship + delegation**, not time. Three orders over the
*same* facts — timestamp (shipped); author-contiguous (group by signer); and
delegation-DFS (the invite tree built via **joins**, with each invite and its sig
re-homed onto the member it admitted). `tax` = mean facts on a leaf's ancestor
path; `≥50%` = facts settling across ≥ half the leaves (the "genuinely global"
count); crossover = subtree size past which multi-level ships less than leaf-only:

| order | leaf-only `ρ` | tax (mean/leaf) | facts ≥50% | ML beats leaf-only from | 1-leaf ML cost |
|---|--:|--:|--:|--:|--:|
| timestamp (shipped) | 3.08× | **399** | 397 (= 4×members) | ~40 leaves | 397 |
| author-contiguous | 1.63× | 184 | 169 | ~13 leaves | 72 |
| **delegation-DFS** | 1.62× | **37** | **21** (~9 real) | **~11 leaves** | **11** |

What the numbers say (and the two things the earlier drafts got wrong):

- **The timestamp tax is real and flat.** ≈ 397 facts (= 4×members) hoist above
  *every* leaf, because each member posts across the whole window so its membership
  is needed by ~1% of leaves scattered end to end → `LCA = root`. A 1-leaf sync
  costs 397 vs leaf-only's 5. The original A.4 "`O(log n)` path tax" was wrong.
- **Dependency-aligned order collapses the tax ~10×.** Grouping by **author**
  already halves leaf-only `ρ` (3.08→1.63) and drops the tax to ~184 — but it
  leaves **invites + invite-sigs high** (169 facts still ≥50%): an invite is signed
  by the *inviter* yet needed by the *invitee*'s block, so author-order can't
  co-locate it. Building the **delegation tree** (via joins — the invite names an
  ephemeral key, so the member↔invite link is the join's ref) and re-homing each
  invite and its sig onto the admitted member collapses the tax to **~37**, with
  only **~9 facts genuinely global** (led by genesis). `LO/ML` crosses 1 at **~11
  leaves** and a below-crossover 1-leaf pull wastes only **11** facts, not 397.
  (The `ts` *secondary* key matters too: it co-locates each msg with its
  same-timestamp sig, lowering leaf-only `ρ` on its own — the whole sort key, not
  just its primary, shapes the blocks.)
- **Caveat — the fixture is a depth-1 delegation star.** `add_member` always
  invites via genesis, so every member is one hop from the root; here
  "beneficiary grouping" and "DFS of the delegation tree" coincide and cannot be
  told apart. Deep, chained delegation (A invites B invites C) is *untested* — it
  is where DFS-preorder should matter beyond simple beneficiary grouping, and it
  needs a chained-invite seed to measure.
- **A small residual remains, from the tree *shape*.** Over-inclusion falls
  3.08→**69%** under delegation order but not to zero: the treap shape is
  hash-random, so a semantically-contiguous span can still settle at an `LCA` node
  covering some extra leaves. Truly tight hoisting would additionally align the
  *boundaries* to the delegation hierarchy — a further step, not needed for the
  ~10× the order alone buys.

*(An earlier revision of this section reported delegation ≈ author with a ~92%
over-inclusion "floor"; that was a bug — the delegation tree was built from the
invite's ephemeral invitee key, which never matches the member's operating key, so
invites never co-located. Rebuilt via joins, delegation order behaves as above.)*

**Robust regardless of order:** full-sync `= |V|` (the floor), verify-once `= |V|`
judge-ops, incremental fold `= O(touched)` (§A.6, B.1). The key-order question
governs only the range-sync tax — a catastrophe under timestamp order, a ~dozen-leaf
crossover with a tiny penalty under delegation order.

**What this means for the headline claim.** A good key order lowers *leaf-only*
`ρ` too (3.08→1.63), while multi-level's full-sync cost is order-**invariant**
(always `|V|`). So hoisting's redundancy *advantage* over leaf-only shrinks from
**67.5%** (under the shipped `ts` order) to **~38%** (aligned) — much of the
headline "two-thirds saved" is the timestamp order inflating *leaf-only* to `3×`,
not an intrinsic property of hoisting. Fix the order and leaf-only is already
~1.6×. Hoisting's **durable, order-independent** payoff is therefore not raw byte
redundancy but the **closed-path / verify-once** property (§A.2, B.1):
validate-as-you-descend, judge each fact exactly once. That is the win to lead
with; the redundancy number is real but is largely a symptom of key order.

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
  the genesis membership does not move it (it already covers the tree). The facts
  expensive to move are exactly the ones already high, which almost never move.

So the fold touches `A` leaves + spine + `{deps of the batch that actually rise}` —
still `∝ what changed`, `n`-independent for append, and **blind**: rising `g` needs
only its current `settle` node (found by descent) and the new position, so you
rewrite the nodes on the affected paths, not the tree.

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
  **loses to leaf-only for small pulls** (1-leaf ~40–80× worse, crossover ~40
  leaves). A **delegation-aligned** order (invite tree via joins, each invite+sig
  re-homed onto the member it admitted) collapses it ~10× — tax 397→**37**, only
  ~9 facts genuinely global, crossover **~11 leaves**, a below-crossover pull
  wasting ~11 facts not 397. Aligning also halves leaf-only `ρ` (so ML's full-sync
  edge narrows to ~1.6×). Measured in A.5.
- Folds stay **blind and bounded** (`A` leaves + spine + the batch's rising deps;
  append-cheap).
- The fancy version verifies **once per fact** at `O(depth)` memory and, on a diff,
  **only the changed payloads** — the same `ρ→1` win on the Ed25519 floor.

Net: the wins that hold unconditionally are **full-sync `ρ→1`, verify-once, and
`O(touched)` incremental fold**. The **range-sync** story is order-dependent and, for
small pulls, a loss — surfaced by the prototype (`tinyp2p/hoist.py`,
`bench/bench_hoist_sync.py`, `bench/bench_order.py`), which is now built and
measured rather than assumed.
