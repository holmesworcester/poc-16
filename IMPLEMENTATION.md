# tinyp2p — the POC-16 implementation

A working build of [DESIGN.md](DESIGN.md) in ~2,000 lines of Python (stdlib +
pynacl), proving the semantics before any byte-format or Rust work. Alice,
bob, and carol run real daemons, join by invite link, converge continuously,
move multi-MB files, survive stragglers, eviction, and restarts —
`tests/test_blackbox.py` drives all of it through the CLI seam.

## The map

| DESIGN.md | module | notes |
|---|---|---|
| canonical fact value | `fact.py` | family-neutral JSON envelope and codec; fid = sha256 |
| auth and content families | `facts/auth/`, `facts/content/` | one module per wire family; exact shape, needs, bool validation, mode effects, materialization, commands, and queries |
| the kernel | `kernel.py` | family-routed streaming judge; separate `validate → bool`, `drain → Judgment`, and `evaluate → bool` paths; `Valid` constructed here only |
| close(), the unit codec | `close.py` | completion-order serializer; one codec for every pile — ingress, leaf, tail, request, invite |
| treap, leaf piles, fences, manifest | `layout.py` | **one pure function of the set**; each leaf = `close` of its in-range leaves (no annex); promotion, mini-fold, and rebuild are the same code path; incrementality = content addressing |
| ObjectStore | `store.py` | mem + fs drivers; CAS by etag; `obj/` holds every immutable object |
| the engine, turn-based runtime | `node.py` | `turn()` = drain → judge (parallel) → merge facts/globals → spill → commit → routed materialize → retire; the only mutator |
| the walk | `walk.py` | conditional root GET, fingerprint pruning, pull the peer's leaf pile verbatim into own ingress, reactive per-range push; responder drains on receipt |
| command façade | `cmds.py` | stable control API pointing into family-owned commands and queries |
| seven verbs + gate + cadence | `daemon.py` | responder half (zero sync logic) + initiator half (`Syncer`); mint = one kernel call in evaluate mode |
| CLI | `cli.py` | drives a daemon over its control plane — the black-box seam |

Everything enters through a pile: local commands, pulled units, and pushed
piles all land in `pile/<member>/<hash>` and go through the same `turn()`.
Independent piles validate in parallel (each kernel call gets its own
`:memory:` scratchpad); handlers and projectors only ever
`INSERT OR IGNORE` by id, so replays and races are harmless by construction.
This holds *because validity is globals-blind* — a pure function of each
pile's closure. An operation whose verdict depends on a global that can change
concurrently (e.g. set-valued deletion — deleting a whole channel, not one
named target) is **not** race-safe here: it needs optimistic
rollback-and-retry on the globals, or a serial singleton with full state
awareness rather than closure alone. See DESIGN.md → Open Questions
("set-valued verdicts break parallel validation").

## The POC-16 fact contract

The POC-13 family boundary survives, but its projector contract does not fit a
closed-pile kernel. Every concrete module under `facts/auth/` or
`facts/content/` therefore has these sections, in this order:

- **SHAPE** constructs the exact canonical fact. Existing short fact tags are
  preserved, so this packaging refactor does not rename stored facts.
- **NEEDS** declares normalized offer addresses. The generic resolver combines
  them with envelope refs and chooses the canonical minimum-fid provider.
- **VALIDATE** is exactly `validate(fact, context) -> bool`. Context contains
  only the immutable in-pile offer table and workspace anchor; globals, the
  node, projection databases, and waiting are unavailable.
- **MODE** declares durability, immutable-object refs, and drain-only global
  rows. An optional `evaluate(fact, globals) -> bool` is permitted only on an
  ephemeral family. Today `auth.removal` emits `("removal", pk)` during drain,
  and `auth.request` consumes committed removal rows during evaluate.
- **MATERIALIZE** receives a kernel-minted `Valid`, so it only writes the read
  model; it repeats no validity or scope policy.
- **COMMANDS** owns local authoring. Workspace create/accept also call the
  core's keyring seam because the locally trusted anchor cannot be derived from
  the store being checked.
- **QUERIES** reads the family's materialized rows.

There is deliberately no connection scope: access requests are ephemeral auth
facts, while HTTP remains transport. `facts/__init__.py` is the root route;
`fact.py`, `kernel.py`, `node.py`, `layout.py`, `walk.py`, and `cmds.py` remain
at package root and dispatch inward. `tests/test_fact_contract.py` pins the
source shape and routing boundary.

The three kernel entry points share one internal forward pass. Inputs are
already canonical-topological closed piles, so none sorts: `validate` returns
only a boolean for trustless consumers, `drain` additionally exposes `Valid`
values and new monotone global rows, and `evaluate` applies ephemeral gates but
returns only a boolean. The index stores globals generically as `(name, value)`
rows and the manifest publishes their canonical sorted records; neither the
node nor layout knows what `removal` means.

## Treap leaves are piles — the confirmation

The property the design left unproven: piles can be added to the treap so
that **every leaf stays a closed pile** — a set of facts whose in-range and
out-of-range needs are all present in the fetched unit — and the treap can
be rebuilt along the same lines.

Four invariants carry it:

- **I1 — the set is dep-closed.** A fact enters only via a closed pile that
  the kernel accepted whole, so its full closure merges with it (or was
  already in). Induction over drains: the index is always dep-closed.
- **I2 — dep edges are canonical.** Edges are *recomputed from the set*
  (`resolve_deps` against the cumulative offers table, min-src tiebreak),
  never remembered from validation history. Two nodes with the same set
  derive the same edges, whatever order things arrived in.
- **I3 — topo-sort makes each leaf a closed pile.** A leaf is `close` of its
  in-range leaves: those leaves plus their full recursive closure, emitted
  deps-first. Every dependency therefore precedes its dependent, so the pile
  satisfies the seen-set rule from an empty scratchpad — no separate annex
  object, no skew copies to construct. The out-of-range closure rides in the
  pile but sits outside the fingerprinted set (which is over the in-range
  leaves only), so copies never perturb the diff algebra.
- **I4 — layout is a pure function.** `layout(keys, deps)` recomputes leaf
  piles, fences, tail, and manifest from nothing but the set. Same set ⇒
  same bytes, on every node.

The four mutation paths are then one argument:

- **Drain/merge** preserves I1 (piles are closed); I2–I4 are recomputed.
- **Promotion** is not an operation: a new boundary fact simply changes
  where the pure function cuts. Nothing to get wrong.
- **Straggler mini-fold**: an old-ts fact lands in some promoted chunk; only
  that chunk's leaf-pile bytes change (boundary-ness is a per-fact
  property, so all other cuts are stable), and its closure already arrived
  in its own pile.
- **Rebuild** replays the store's own units through the kernel — each unit
  is independently judgeable (I3), so any order works — reproducing the same
  set, hence (I4) the identical root.

**Incremental updates, not full rebuild.** Three things stay cheap as the set
grows. *Validation* is incremental — a turn kernels only the new piles and
merges by id; the whole set is never re-judged (`rebuild()` re-validates only
on an index wipe, never on the pile path). *Writes* are incremental via
content addressing — a commit PUTs only objects the store lacks
(`test_efficient_updates`: one post writes ≤ 8 objects against a 60-fact
store). And *layout compute* is now incremental too: `commit()` passes the
prior manifest's fences to `layout()` as a memo, and any promoted range whose
`(hi, fp)` is unchanged is reused verbatim — its facts are never loaded, its
pile never rebuilt (`test_incremental_reuses_work`: a post into a
promoted store touches under half the facts). This is byte-identical to a full
recompute because a leaf pile depends only on its in-range fids and their
resolved deps, which are fixed *as long as every
offer address has one provider* (so `min-src` cannot move). The one way that
breaks — a duplicate `member`/`admin`/`author` offer (a re-join or re-sign) —
is caught by a shadow guard (`Node._shadows`) that drops the memo for that
turn and recomputes fully. `test_incremental_equals_full` asserts
incremental == full at every step across promotions, a straggler, a new
member, and an eviction; `test_shadow_guard_keeps_identity` exercises the
guard. The residual O(n) is the body-free key scan and per-range fingerprint;
removing that needs a persistent fence tree (byte-format work, out of scope).

Tested in `tests/test_props.py`: `test_leaves_are_piles` (every published
unit passes the kernel from empty), `test_history_independence` (random pile
groupings × random orders × random turn batching ⇒ byte-identical roots),
`test_rebuild`, `test_straggler_minifold`, `test_incremental_equals_full`,
`test_incremental_reuses_work`, `test_shadow_guard_keeps_identity`.

**Litter, never poison.** The design's "a hostile writer can litter but never
poison" is enforced at two layers: `from_json` validates atom shape at the
decode door (a malformed atom rejects the whole unit there), and the kernel's
per-fact judgment is wrapped so that *any* exception — a missing body field, a
crashing validator — becomes a whole-unit reject rather than an escaped error.
Either way the drain retires the pile, so a hash-consistent but malformed pile
cannot wedge a workspace (`test_poison_pile_is_litter_not_poison`,
`test_poison_alongside_honest`). This was the one critical defect the
adversarial review surfaced; the fix keeps the kernel the sole security
boundary — a judge that crashes on a hostile exhibit is a broken judge.

## Deviations from DESIGN.md (all scale/packaging, no semantics)

- **JSON units instead of packed byte runs.** Fixed-size records, 8 KB
  slices, delta-coded 28 B fences, and body heaps are byte-economy for 10^6
  facts; units here are canonical-JSON objects. Fences still carry
  (hi, fp, count, pile) and pruning still works range-by-range.
- **Fence hierarchy depth 1** — the manifest holds the single fence run;
  2–3-level runs are a 10^5+ concern.
- **Whole-leaf fetch**: with whole-object units there are no record slices, so
  the walk fetches each differing leaf's pile whole; intra-leaf slicing is the
  deferred, reversible optimization (a `Range` GET within the immutable
  object). The push is **reactive per range** — `close` the leaves the peer
  lacks and PUT, the mirror of the pull — and the responder **drains on
  receipt**, so there is no poke on the p2p path.
- **`page/`+`blob/` collapse to `obj/`** (one immutable content-addressed
  namespace); the `/page/{hash}` route serves them all.
- **Needs are family-declared functions**, not explicit atoms — a fact
  cannot name its own fid, so "authored-by my pk" and "author is a member"
  are declared beside the family and resolved generically by `resolve_deps`.
  Offers, refs, and the matching rule are as
  designed (addresses, never values).
- **Bodies are plaintext** — epochs/body encryption are out of scope; the
  crypto that carries auth *is* real (Ed25519 sig facts, sealed-box grants,
  secretbox invite blobs, KDF'd link seeds).
- **Tail guard couples to cut density by default** (tail = everything after
  the last boundary); the tiered layout (`layout.COLD_CUT`) restores the
  design's decoupled B_t guard — history seals into coarse cold leaves below a
  GUARD-deep watermark while the recent window stays fine (`bench/RESULTS.md`).
- **Drain-on-receipt at root, poke, and PUT** — the design's "a peer drains
  before answering any verb" is realized at the walk's entry point (root GET),
  on poke, and on the PUT that delivers a pushed pile (so a peer push needs no
  poke); `page` objects are immutable and `list` is unused by the walk.
- Not built (per the staged plan): S3 driver + presigned flow, iroh
  connector, GC/invite-TTL purge, the personal meta-workspace, deletion.

**Known gap for the designer to rule on (removal ⇒ invite redemption).**
DESIGN.md promises an invite blob is "evaluated fresh at mint (inviting admin
since removed ⇒ refused)." Here invites are redeemed as *drained join facts*,
and drains are globals-blind by design (history-independence), so a join whose
inviting admin was removed after the invite was minted still confers
membership, and that fresh member then mints normally. The only reachable
trigger in this PoC is a founder self-eviction (the founder is the sole admin —
there is no admin-promotion command), so it is minor. The faithful fix gates
the *mint*, not the drain: refuse a grant when the requester's entitling edge
traces through a removed key. That is a real policy choice — immediate-inviter
only (refuse just the removed admin's direct invitees) vs. full-chain (removal
cascades to everyone downstream) — which the design should settle before it is
coded, so it is left as a flagged gap rather than a unilateral choice.

## Running it

```
python3 -m tinyp2p daemon /tmp/alice --port 7100 &
python3 -m tinyp2p --node http://127.0.0.1:7100 create alice     # -> ws id
python3 -m tinyp2p --node http://127.0.0.1:7100 invite --ws <ws> # -> link
# on bob's machine/daemon:
python3 -m tinyp2p --node http://127.0.0.1:7101 join <link> bob
python3 -m tinyp2p --node http://127.0.0.1:7101 post --ws <ws> "hello"
python3 -m tinyp2p --node http://127.0.0.1:7100 msgs --ws <ws>
python3 -m tinyp2p --node http://127.0.0.1:7101 send --ws <ws> ./photo.jpg
```

`pytest tests/` runs everything; `tests/test_blackbox.py` is the
three-daemon scenario (~10 s).
