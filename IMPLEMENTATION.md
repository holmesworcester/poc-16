# tinyp2p — the POC-16 implementation

A working build of [DESIGN.md](DESIGN.md) in ~1,400 lines of Python (stdlib +
pynacl), proving the semantics before any byte-format or Rust work. Alice,
bob, and carol run real daemons, join by invite link, converge continuously,
move multi-MB files, survive stragglers, eviction, and restarts —
`tests/test_blackbox.py` drives all of it through the CLI seam.

## The map

| DESIGN.md | module | notes |
|---|---|---|
| facts, atoms, authors | `fact.py` | canonical JSON envelope; fid = sha256; the authors are the construction chokepoint |
| the kernel | `kernel.py` | one streaming judge, own SQLite scratchpad per invocation, seen-set rule, all-or-nothing; `Valid` constructed here only |
| close(), the unit codec | `close.py` | completion-order serializer; one codec for pile/page/annex/tail/request/invite |
| treap, pages, fences, annexes, manifest | `layout.py` | **one pure function of the set**; promotion, mini-fold, and rebuild are the same code path; incrementality = content addressing |
| ObjectStore | `store.py` | mem + fs drivers; CAS by etag; `obj/` holds every immutable object |
| the engine, turn-based runtime | `node.py` | `turn()` = drain → judge (parallel) → merge → spill → commit → materialize → retire; the only mutator |
| the walk, push tail | `walk.py` | conditional root GET, fingerprint pruning, pull closed units into own ingress, collect-then-close push + poke |
| commands ⇒ facts | `cmds.py` | create/invite/join/post/send/evict; each closes a pile into its own ingress and kicks the syncer |
| seven verbs + gate + cadence | `daemon.py` | responder half (zero sync logic) + initiator half (`Syncer`); mint = one kernel call in evaluate mode |
| CLI | `cli.py` | drives a daemon over its control plane — the black-box seam |

Everything enters through a pile: local commands, pulled units, and pushed
piles all land in `pile/<member>/<hash>` and go through the same `turn()`.
Independent piles validate in parallel (each kernel call gets its own
`:memory:` scratchpad); handlers and projectors only ever
`INSERT OR IGNORE` by id, so replays and races are harmless by construction.

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
- **I3 — the annex restores the stream invariant.** `prefix_set(R)` takes
  every out-of-range dep (transitively), every in-range dep of a prefix
  member (a prefix precedes the whole range, so those must be copied), and
  every in-range skew inversion (a dep keyed after its dependent); the
  result is dep-closed by construction and `close()` serializes it
  deps-first. Hence annex ++ key-ordered(range) always satisfies the
  seen-set rule from an empty scratchpad.
- **I4 — layout is a pure function.** `layout(keys, deps)` recomputes pages,
  fences, annexes, tail, and manifest from nothing but the set. Same set ⇒
  same bytes, on every node.

The four mutation paths are then one argument:

- **Drain/merge** preserves I1 (piles are closed); I2–I4 are recomputed.
- **Promotion** is not an operation: a new boundary fact simply changes
  where the pure function cuts. Nothing to get wrong.
- **Straggler mini-fold**: an old-ts fact lands in some promoted chunk; only
  that chunk's page and annex bytes change (boundary-ness is a per-fact
  property, so all other cuts are stable), and its closure already arrived
  in its own pile.
- **Rebuild** replays the store's own units through the kernel — each unit
  is independently judgeable (I3), so any order works — reproducing the same
  set, hence (I4) the identical root.

Efficiency of updates is the content addressing: recompute is O(n) at toy
scale (the pure function *is* the spec), but writes are O(changed chunks) —
unchanged pages hash to objects the store already has. `test_efficient_updates`
pins it: one post writes ≤ 8 objects against a 60-fact store. The
incremental-compute version is a mechanical memoization (page bytes depend
only on the range; annex bytes only on range + closure) precisely *because*
the function is pure.

Tested in `tests/test_props.py`: `test_leaves_are_piles` (every published
unit passes the kernel from empty), `test_history_independence` (random pile
groupings × random orders × random turn batching ⇒ byte-identical roots),
`test_rebuild`, `test_straggler_minifold`.

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
  (hi, fp, count, page, annex) and pruning still works range-by-range.
- **Fence hierarchy depth 1** — the manifest holds the single fence run;
  2–3-level runs are a 10^5+ concern.
- **Exact/bulk walk modes collapse**: with whole-object units there are no
  record slices, so both modes fetch the range's closed unit; the push tail
  is exactly the design's collect-then-close (one `close()`, one pile, poke).
- **`page/`+`blob/` collapse to `obj/`** (one immutable content-addressed
  namespace); the `/page/{hash}` route serves them all.
- **Needs are family-declared functions**, not explicit atoms — a fact
  cannot name its own fid, so "authored-by my pk" and "author is a member"
  live in `resolve_deps`. Offers, refs, and the matching rule are as
  designed (addresses, never values).
- **Bodies are plaintext** — epochs/body encryption are out of scope; the
  crypto that carries auth *is* real (Ed25519 sig facts, sealed-box grants,
  secretbox invite blobs, KDF'd link seeds).
- **Tail guard window couples to page cadence** (tail = everything after the
  last boundary fact); the design's decoupled B_t cap is a scale knob.
- **Drain-on-read on root and poke only** — the design's "a peer drains
  before answering any verb" narrows to the walk's entry point; `page`
  objects are immutable and `list` is unused by the walk.
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
