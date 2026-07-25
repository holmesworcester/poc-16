# Global 1:N deletion closure — the suppression-key treap

**Status:** plan (2026-07-24). Tracked by bead epic — see `bd dep tree` for the
epic that names this doc. Handoff for another agent; do not implement from memory,
read this + `DESIGN.md` (Open Questions, and the Closure Walk §P3) + `MODEL.md`
(Closure) first.

This plan resolves the multi-target-deletion Open Question in `DESIGN.md`
(the paragraph beginning *"Set-valued verdicts break parallel validation"*).
That paragraph concludes multi-target deletion "composes only under **full state
awareness, not closure alone**: a singleton serial pass … parallel peer validation
cannot [do it] without the retry loop," and that "POC-16 builds only the
single-target, closure-local path." **This plan removes the serial pass.** The
1:N join becomes a *second closure augmentation* — a range walk in a second
content-addressed treap — structurally identical to the dep-ref closure (P3),
just keyed by a predicate attribute instead of a backward hash pointer.

---

## 0. The gap

- **Single-target delete** (already the built path): the delete names its one
  victim by dep-ref; the ordinary dep-ref closure walk (P3, `closure_sync`) drags
  the victim into the pile. Closure-local. Done.
- **Multi-target / 1:N delete** (this plan): deleting a channel `X` suppresses
  **every** fact, present and future, with attribute `chan = X`. The N victims are
  not named by hash — they match a **predicate** (the *death key* `chan = X`). In
  the primary treap they are keyed by `ts:fid`, so they scatter across key space;
  an arbitrary range sync `closure_sync(Q)` misses every victim outside `Q`. A
  projector that never sees them wrongly shows deleted facts as live.

`DESIGN.md` already reserves the machinery: negative knowledge (POC-13's
`SuppressIf`) "stays out of the grammar by design — it is globals' job, and it
returns with deletion"; the suppress-if set is "the second occupant of the
globals slot." This plan says **how** the out-of-range victims reach the closure.

## 1. The idea — a second treap keyed by the suppression key

Keep the primary treap (`T_fact`, key `ts:fid`) exactly as it is. Add one more
content-addressed Merkle treap over the *same fact set*, differing only in its
**key function**:

| treap    | key                    | walk yields                              |
|----------|------------------------|------------------------------------------|
| `T_fact` | `ts:fid`               | range `Q` + dep-ref closure (existing P3) |
| `T_supp` | `suppkey \|\| ts:fid`  | **all facts sharing a death key, contiguous** |

`suppkey` is the fact's suppression attribute (the death-key domain, e.g.
`chan=X`). Facts with no suppression attribute are absent from `T_supp`. A
deletion fact is indexed under the death key it carries. So under key prefix `K`
sit, adjacent: the deletion fact(s) for `K` **and** every victim with attribute
`K`. **The 1:N join is now a contiguous range in `T_supp`** — surfacing the
out-of-range victims is a range walk, the *same* one-sided RBSR machinery
(`walk.py` / `treap.py`) already built, against a dumb store. No database join,
no serial full-state pass.

`T_supp` is a pure function of the set, exactly like `T_fact` (content-defined
chunking + treap priority ⇒ history-independent; a new victim under `K` perturbs
only `K`'s root-to-leaf path). So it is **built and maintained by the existing
`treap.build` / `treap.update`, and diffed/walked by the existing RBSR** — this
is the *"update the tree whenever we have new suppression keys"* requirement:
maintenance is just the blind incremental `update`, no new code path.

## 2. When the pass runs — a closure post-pass

The surfacing pass runs on the **validated, dep-closed** set, **after** the
primary closure walk and **before** materialize/project. `closure_sync(Q)` gains
a second phase:

```
close_deletions(closure):                       # after the dep-ref closure of Q
  Ks = { deathkey(f) for f in closure if is_deletion(f) }   # death keys present
  for K in Ks:
    victims = supp_walk(T_supp, prefix=K)        # one-sided RBSR range walk
    closure |= victims                           # pull ALL matches, incl. out-of-range
  return closure                                 # now deletion-closed as well as dep-closed
```

**Why after dep-closure, before project** (this is the "interesting question:
when should the pass be", answered):

- **After validation** — only *validated* deletions get to suppress. The pass
  consumes the kernel's output, never feeds its input, so the **globals-blind
  rule holds**: no persistent-family handler reads the suppression set during
  validity judgment (that would make verdicts time-dependent and break
  order-independence). Suppression stays a **projection-time verdict**, exactly
  as `DESIGN.md` mandates ("anything needing negative or global knowledge stays a
  projection-time verdict — never a validation input").
- **Before project** — `project` must never surface a fact the closure now knows
  is suppressed. The pass hands `project` a set closed under *both* relations; the
  deterministic fold applies the suppression locally, no further fetches.

## 3. One synced index, three call sites, two directions

`T_supp` is a **first-class synced tree** — a second root per workspace beside
`T_fact`, **not** something each node derives locally. Local derivation can only
see the facts a node already has; **syncing the index is *how* out-of-range facts
surface**. Every consumer runs the *same* `T_supp` augmentation at its own call
site:

- **Sync walk** — reconcile `T_supp`'s root like `T_fact`'s; pulling a differing
  leaf pulls the co-resident deletion+targets, so ordinary sync surfaces matches.
- **Kernel / validation** — resolve a **suppression closure edge**: for a fact
  with a suppression key, look up the head of its `K`-group; a deletion marker
  there means the deletion is part of that fact's closure and rides along. It is a
  **closure edge, not a validity input** — the fact stays valid, only *flagged*
  suppressed — so validity stays globals-blind and parallel drain stays safe. This
  is the exact sense in which "the kernel must check the tree to know the closure."
- **Projection** — the same head-of-group check masks suppressed facts.

**Tag-ordered key** makes both directions cheap. Key `T_supp` by
`suppkey ‖ tag ‖ ts:fid` with deletions `tag=0` (sort to the group head) and
targets `tag=1`:

- *target → deletion* (projection-critical, N:1): seek the group head — **one
  leaf**. This is your "offer and need collide in one sorted leaf": the head
  marker is the offer every target checks.
- *deletion → all targets* (blast radius / the out-of-range proof, 1:N):
  range-scan the group — **O(matches)**.

**One mechanism covers both time directions.** A *future* target just lands in
the `K`-group and the next projection sees the head marker — so `T_supp` closes
past **and** future. The globals suppress-if slot is **subsumed**; keep it only as
an optional hot-death-key cache, never for correctness.

## 3a. Matching under concurrency — nothing to match at write time

Deletions and their targets arrive and get written concurrently (different piles,
different writers/lambdas). They still match, with **no coordination**, because
matching is the read-time closure edge above, not a write-time event:

- **Suppression is a projection-time verdict** (locked): "T is suppressed" ⟺ "a
  validated deletion for T's key exists" — a pure function of the set. Concurrent
  `D` and `T` need not see each other; they need only end up in the same tree.
- **`T_supp` is a CvRDT.** Two concurrent writers ⇒ two roots ⇒ the two-root merge
  (FaaS epic) is a set-union of leaves ⇒ the `K`-group holds both. Any later walk
  over `K` sees the match. A match is lost only if a *write* is lost, and the
  store never drops an accepted pile (a dropped root = re-work, not data).
- **The only cost of concurrency is latency-to-visibility** — a target may project
  as live until the next reconcile. Staleness, self-healing; not a data race.

So the four candidate mechanisms rank as:

- **Read-time closure edge + CvRDT convergence (§3)** — the default. No lock, no
  retry, no scan.
- **Optimistic retry / lease (opt-in only)** — for an *authoritative* linearizable
  "is X deleted?" that must never return a stale live answer: the per-workspace
  Durable-Object / CAS path the FaaS epic already defines. Never the default.
- **Scan (backstop only)** — the generational sweep already planned (amortized,
  over a grace window): the net guaranteeing eventual visibility, not the hot path.
- **Default lock/queue — rejected.** It reintroduces the per-workspace
  serialization bottleneck the FaaS epic just removed (the DO path in disguise).

## 3b. Where the walk fires, what rides with it, what it writes

Aligns with the `E = V∖S` frame in `SIMPLIFY.md` §3–§5 (the 808 engine epic);
suppression **masks after judgment** at three places only — gate, closure edge
(`resolve_supp`), pump — never the kernel, never the tree.

- **The walk fires per suppression-participant, at merge/serve — not per pile,
  not at projection.** Projection is a pure fold over a delivery log
  `log(seq, ±fid)` and does **zero** tree walking. The `T_supp` walk happens at
  **merge** (per newly-admitted fact with a `suppkey`: one head-of-group check;
  per newly-admitted deletion: surface held targets → emit `−fid`) and at
  **serve** (`closure_sync` surfaces *out-of-range* victims for a peer). A plain
  fact with no suppression attribute costs nothing.
- **Cost adds up as O(S·log N), paid once, monotone.** Each participant's status
  is decided once at ingest — same class as `resolve_deps` — and a not-yet-
  suppressed target flips at most once (a single `−fid` append, never a re-scan).
  Memoize against the K-subtree hash: steady state is a hash-compare. The only
  1:N cost (a hot death key's full blast radius) is paid solely by a node that
  holds/serves the whole target set, once; scoped projectors never pay it.
- **A discovery writes to the closure — as a `±fid` log row, paid once.** The
  append lands in the **local delivery log** (`log(seq, ±fid)` in `idx.db`), **not
  in any leaf pile** — piles are immutable/content-addressed and the target's bytes
  never change (suppression hides it, it stays a member). The pump consumes the row
  as `DELETE … WHERE src = ?` exactly-once. When a deletion `D` lands it does two
  *tree* inserts (into `T_fact` under its own key, into `T_supp` under `K`), each an
  O(log N) path-copy; the per-target flip is one *log* append each — the log and
  `app.db` are both derived/rebuildable, so the flip mutates no canonical state.
  **S itself never lives in `app.db`** — it lives in `T_supp`/the root; rebuild
  recomputes S first, folds E, fires zero retractions. Optionally also persist surfaced out-of-range victims locally to
  avoid re-surfacing (the read-time-walk vs embed-annex tradeoff, §6). Monotone ⇒
  either write is safe.
- **A deletion carries its own validity closure.** `valid(D) = pred(D,
  closure(D))` — its authority chain (admin cert / membership / signatures). A
  `T_supp` leaf carrying D is a **closed pile** (same `close()`): D **plus**
  `closure(D)`, self-validating on arrival, exactly like a `T_fact` leaf. Only a
  D that arrived with its own closure enters S (`S(D) = targets of *valid*
  suppression facts`). Validity-closure (may D delete) stays separate from the
  suppression relation (what D deletes).
- **`T_supp` hoists — for free, as the engine's second instance.** D's authority
  closure is *shared* closure (one admin deletes many channels), so the ρ≈3×
  leaf-duplication tax hits `T_supp` too. Because `T_supp` is the same engine
  (`tree.py`/`shape.py`) keyed differently, it inherits hoisting; and closure
  facts are content-addressed, so `T_fact` and `T_supp` reference **one shared
  hoisted closure pool** (only index nodes are extra, ~×2). Production `T_supp`
  must ride the hoisting engine (808.2 / jbg.1), **not** the flat per-leaf-closure
  prototype (`layout` + per-leaf `close()`, ρ≈3× measured — `MULTILEVEL_PILE.md`);
  the yez.6 proof may run on the prototype (SIMPLIFY §3), production must not.

## 4. Why there is no serial pass (the advance on the Open Question)

`DESIGN.md` worried multi-target needs "full state awareness … a singleton serial
pass … which the cloud node hosts naturally (single-writer per workspace under
the lease/CAS) but parallel peer validation cannot without the retry loop." The
suppression treap dissolves that:

- **Surfacing needs no full state.** A peer holding only `T_supp` (a dumb Merkle
  tree in the store) enumerates the *complete* victim set for `K` by a pruned
  range walk, cost **O(matches + walk depth)**, not O(set size). No SQLite, no
  join, no scan.
- **The residual order question is projection-time, not validation-time.**
  "Did delete `D` land before victim `V`?" doesn't matter: deletion is forever ⇒
  suppression is a **grow-only set** ⇒ order-free. Keeping suppression a
  projection-time monotone verdict (as the model already requires) means **no
  globals CAS on the persistent path** — parallel drain is untouched. The
  optimistic-retry loop `DESIGN.md` feared only appears if suppression were a
  *validation* verdict; it isn't. The aux treap is the whole addition.

This also composes cleanly with the just-landed non-serialized / CvRDT direction
(the FaaS epic): `T_supp` is another state-based-CRDT tree, its root another
32-byte hash, converging under Strong Eventual Consistency by the same argument.

## 5. The proof — surface out-of-range victims by tree traversal, no database

The centerpiece deliverable. A synthetic seed + bench/property test, **pure treap
traversal, zero SQL**, mirroring `bench/bench_sync.py` and the `hoist` prototype:

1. **Seed.** `M` facts carrying `chan` attributes over a few channels. Place a
   subset of `chan=X` facts at timestamps deliberately **outside** a chosen range
   `Q`, scattered across key space. Author one deletion fact `D`, death key
   `chan=X`, placed *inside* `Q` (or dragged in by `Q`'s dep-closure).
2. **Build both treaps** with `treap.build`: `T_fact` (key `ts:fid`) and `T_supp`
   (key `chan||ts:fid`), sharing the same `fact_of` / `deps_of`.
3. **Primary closure.** Run `closure_sync(Q)` against `T_fact`. **Assert it yields
   `D` but MISSES the out-of-range `chan=X` victims** — the bug the pass fixes.
   Surfacing this miss is half the proof.
4. **Surfacing pass.** For each death key present (`chan=X`),
   `supp_walk(T_supp, prefix="chan=X")` — a one-sided RBSR range walk that prunes
   by fingerprint and pulls only the differing leaf piles. Merge into the closure.
5. **Assert:**
   - (a) surfaced set **==** the true set of all `chan=X` facts (ground truth
     computed directly from the seed);
   - (b) obtained by **treap node fetches only** — an instrumented counting store
     asserts **zero** `idx`/SQL calls and fetch count `= O(matches + depth)`, not
     O(M);
   - (c) the merged closure is deletion-closed: `project(closure)` shows every
     `chan=X` fact suppressed, in-range and out-of-range alike;
   - (d) history-independence: build `T_supp` from a shuffled insert order ⇒
     byte-identical root (reuse the treap byte-identity check).
   - (e) **concurrency convergence (CvRDT):** write `D` and its target `T` as two
     *separate* roots (concurrent writers), merge the roots, and assert the merged
     `K`-group matches them regardless of order — and that projecting `T` *before*
     the merge shows it live, *after* shows it suppressed (staleness self-heals, no
     lost match). This is the "how do they match under concurrent writes" answer,
     demonstrated: no lock, no retry, no scan.
6. **Bench (mirrors `bench_sync`):** vary `M` and the out-of-range fraction;
   report rounds / node-fetches / bytes for the surfacing walk vs. a naive
   "pull the whole set" baseline; show the walk cost tracks match-count, not set
   size, and report `T_supp`'s storage / write-amp overhead (~×2 index nodes;
   leaves dedup by content).

This is the literal proof the task asks for: *out-of-range deletion-offering
facts surfaced into the closure by tree traversal alone, no database.*

## 6. Open sub-questions (log, don't block)

- **Death-key domain:** which attribute(s) are death-key-eligible; can one fact
  carry several? (multiple aux treaps, one per predicate domain, vs one treap
  keyed by `(domain, value)`). Start with one domain (`chan`).
- **Envelope exposure:** the death key must live in the **clear envelope** (like
  dep-refs) so `T_supp` builds from envelopes without decrypting bodies. Confirm
  the suppression attribute is envelope-visible, or add an envelope offer for it.
  Ties to the clear-envelope / dep-refs split. **Phase-0 resolution:** content
  facts carry one inert `["supp", "chan", value, "target"]` atom. This is an
  explicit wire-shape cutover: accepting old markerless `msg`/`file` shapes
  would also let newly signed facts bypass deletion. Preserving immutable
  pre-cutover content therefore requires a separately versioned migration.
- **Embed-annex placement:** MODEL.md superseded the standalone closure object
  with pile-embedded annexes; decide whether `T_supp` victims embed in the pile
  annex at promotion, or stay a read-time walk. The proof uses the read-time walk;
  embedding is an optimization.
- **GC interaction:** a suppressed victim is still a *fact* (membership is
  forever); suppression hides it at projection, it is **not** collected. Confirm
  `T_supp` never drives GC.
- **Authoritative mode (opt-in):** a linearizable "is X deleted?" that must never
  return a stale-live answer takes the per-workspace Durable-Object / CAS lease
  (the FaaS epic's opt-in path) — optimistic retry / lease live *here only*, never
  in the default. Design the read-mode selector (fast-eventual vs authoritative).
- **DESIGN.md update:** on green, rewrite the multi-target-deletion Open Question
  to record this resolution (serial pass → suppression-key treap augmentation,
  matched read-time as a CvRDT closure edge — no default serialization).
