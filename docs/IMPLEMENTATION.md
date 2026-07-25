# tinyp2p — the POC-16 implementation

A working build of [DESIGN.md](../DESIGN.md) in ~2,000 lines of Python (stdlib +
pynacl), proving the core semantics before lower-level optimization. Alice,
bob, and carol run real daemons, join by invite link, converge continuously,
move multi-MB files, survive stragglers, eviction, and restarts —
`tests/test_blackbox.py` drives all of it through the CLI seam.
The optional Bao attachment binding is vendored under `native/bao_py` and
installed with `python3 -m pip install ./native/bao_py`; `core/bao.py` loads it
only when attachment I/O crosses that seam.

## The map

| DESIGN.md | module | notes |
|---|---|---|
| canonical fact value | `core/fact.py` | family-neutral JSON envelope and codec; fid = sha256 |
| auth and content families | `facts/auth/`, `facts/content/` | one module per wire family; exact shape, needs, bool validation, mode effects, materialization, commands, and queries |
| the kernel | `core/kernel.py` | family-routed streaming judge; separate `validate → bool`, `drain → Judgment`, and `evaluate → bool` paths; `Valid` constructed here only |
| close(), the unit codec | `core/close.py` | completion-order serializer; one codec for ingress, settle payload, request, and invite piles |
| fat Merkle tree + settle payloads | `core/tree.py` | one pure `build`/`fold`/`diff`/`merge` engine; every fact stored once, every root-to-node path closed; binary/flat packings are compatibility fixtures |
| ObjectStore | `core/store.py` | mem + fs drivers; CAS by etag; `obj/` holds every immutable object |
| the engine, turn-based runtime | `core/node.py` | `turn()` = drain → judge (parallel) → merge facts/globals → spill → commit → routed materialize → retire; the only mutator |
| the walk | `core/sync.py` | conditional root GET, fingerprint pruning, one deduplicated closed path union into ingress, reactive per-range push; responder drains on receipt |
| command façade | `core/cmds.py` | stable control API pointing into family-owned commands and queries |
| seven verbs + gate + cadence | `core/daemon.py` | responder half (zero sync logic) + initiator half (`Syncer`); mint = one kernel call in evaluate mode |
| CLI | `core/cli.py` | drives a daemon over its control plane — the black-box seam |

Everything enters through a pile: local commands, pulled units, and pushed
piles all land in `pile/<member>/<hash>` and go through the same `turn()`.
Independent piles validate in parallel (each kernel call gets its own
`:memory:` scratchpad). The same index transaction that admits facts appends
their dependency-ordered ids to a delivery log and invalidates the root stamp.
After the root CAS, the app pump applies pending rows and advances its cursor
in one transaction, so closure replays and pile retries are projection no-ops.
A crash with an index ahead of the root rebuilds from that root before
retrying its retained pile; a crash after publication resumes the cursor. A
caught turn failure performs that same resynchronization before releasing the
workspace lock, so a live daemon cannot authorize from unpublished index or
global rows. Stamp writes roll back as one SQLite transaction, and bulk
builders use the same dirty-index boundary as live merge.
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

- **SHAPE** constructs the exact canonical fact. Chained auth adopts the
  poc-13 names (`workspace`, `signature`, `user_invite`, `user`); read-only
  legacy handlers keep persisted `genesis`, `sig`, `invite`, and `join` facts
  judgeable during upgrade and rebuild, while every new command emits only the
  current tags.
- **NEEDS** declares normalized offer addresses. The generic resolver combines
  them with envelope refs and chooses the canonical provider by shortest
  finite authority proof, then source id.
- **VALIDATE** is exactly `validate(fact, context) -> bool`. Context contains
  only the immutable in-pile offer table and workspace anchor; globals, the
  node, projection databases, and waiting are unavailable.
- **MODE** declares durability, immutable-object refs, and drain-only global
  rows. An optional `evaluate(fact, globals, context) -> bool` is confined to
  ephemeral families, so it never changes stable validation or drain.
  `auth.removal` emits `("removal", pk)` during drain; `auth.request` rejects
  both that key and any request closure carrying a signature from a removed
  issuer, so access cannot be laundered through a fresh user, device, or admin
  key.
- **MATERIALIZE** receives a kernel-minted `Valid` and inserts rows keyed by
  that fact's `src`; it repeats no validity, scope, or suppression policy.
  Aggregate-shaped `members` and `devices` are views over retained candidates,
  so removing a source exposes its runner-up without a family repair path.
  The pump performs the only retraction: delete that `src` from the tables the
  family declares.
- **COMMANDS** owns local authoring. Workspace create/accept also call the
  core's keyring seam because the locally trusted anchor cannot be derived from
  the store being checked.
- **QUERIES** reads the family's materialized rows.

There is deliberately no connection scope: access requests are ephemeral auth
facts, while HTTP remains transport. `facts/__init__.py` is the root route;
the family-neutral modules live under `core/` and dispatch to the sibling
`facts/` package. `tests/test_fact_contract.py` pins the source shape and
routing boundary.

The three kernel entry points share one internal forward pass. Inputs are
already canonical-topological closed piles, so none sorts: `validate` returns
only a boolean for trustless consumers, `drain` additionally exposes `Valid`
values and new monotone global rows, and `evaluate` applies ephemeral gates but
returns only a boolean. At mint, the generic evaluator also requires the
committed canonical provider at every already-known address to satisfy that
need's exact co-offers; genuinely new addresses remain self-bootstrapping.
Equivalent providers may differ while honest peers converge, but a caller
cannot omit an incompatible winning conflict and revive a quarantined
authority closure. The committed index never enters family validators.
The index stores globals generically as `(name, value)` rows and the root
publishes their canonical sorted records; neither the node nor layout knows
what `removal` means. Rebuild and stateless authority accept a published root
only when every committed fact belongs to a known durable family and a fresh
drain derives exactly those global records. The live daemon synchronizes its
root-stamped index before minting, so a root-only metadata rewrite fails closed
instead of consulting an older valid index.

## Fat-tree paths are piles

The production `T_fact` invariant is stronger and cheaper than the old
closed-leaf layout: each fact is serialized once at the lowest fat node
covering its own key and all dependent keys. Dependencies therefore settle at
an ancestor or the same node as their dependents, so every root-to-node payload
union is a topological closed set. A full preorder is also closed and contains
exactly the canonical set—no repeated auth annex.

`fp` fingerprints only in-range keys and remains the diff identity. Node `oid`
commits structural bytes, child summaries, and a separate content-addressed
payload hash, so moving closure never invents a set difference. Leaves store
their explicit keys; readers obtain closure through `range_facts(root, ranges)`
rather than opening a bare leaf. Full rebuild and stateless mint use
`facts(root)`, which streams each payload once.

Incremental `fold` stores compact stable span bounds with each payload fact.
A new batch expands only its transitive dependencies' spans; facts that rise
are removed from their old payload and settled again while affected spines are
path-copied. Leaf or fat-group splits rehome only the payload whose physical
interval changed. `test_incremental_equals_full` checks every incremental root
against a full rebuild across promotions, stragglers, membership, and eviction;
the read/write-floor tests ensure no sibling scan.

Two-root `merge` validates untrusted roots before its identity/empty shortcuts:
it derives the canonical dependency graph and rebuilds the expected v2 view in
memory, so the supplied settle placement must be byte-identical and every
partial path is closed. A caller that already crossed that publication boundary
marks both inputs prevalidated and retains the bounded fold when added facts
have neither offers nor declared needs. Either can change a canonical provider
edge outside the differing tree ranges. Those merges therefore load both
committed sets, rebuild proof ranks against the union, validate the resulting
topological stream, and stage a full deterministic build. This is deliberately
the simple correct fallback; append-only-root amortization/provider summaries
remain `poc-16-jbg.3`.

Admission canonicalizes kernel-valid facts dependency-first at `Node.merge`.
That single boundary protects live delivery, retry, restart, sync, two-root
merge, and rebuild from a hoisted preorder placing an independent retraction
before its projection source. The boundary matrix in `test_pump.py` pins this.
Production placement tests additionally pin one-copy storage, closed paths,
`fp`/`oid` separation, dependency rehoming, and path-union sync.

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
The closure serializer uses an explicit DFS stack, so the same rule remains
usable for delegation chains deeper than Python's call-stack limit.

## Deviations from DESIGN.md (all scale/packaging, no semantics)

- **Canonical JSON objects instead of packed byte runs.** Structural fat nodes
  and settle payloads are whole immutable objects. Fixed-size records, byte
  slices, delta-coded fences, body heaps, and intra-object `Range` GETs remain
  deferred byte/round-trip optimizations; the Merkle and closed-path semantics
  do not depend on them.
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
- **The legacy flat compatibility packing retains its tail guard.** Production
  fat trees use monotone content cuts so incremental folds never erase an old
  boundary.
- **Drain-on-receipt at root, poke, and PUT** — the design's "a peer drains
  before answering any verb" is realized at the walk's entry point (root GET),
  on poke, and on the PUT that delivers a pushed pile (so a peer push needs no
  poke); `page` objects are immutable and `list` is unused by the walk.
- Not built (per the staged plan): S3 driver + presigned flow, iroh
  connector, GC/invite-TTL purge, the personal meta-workspace, deletion.

**Deferred revocation boundary.** Request evaluation now rejects a removed
requester and any presented membership closure signed by a removed issuer, so
a freshly delegated user, device, or admin cannot launder a mint. Durable
facts remain globals-blind, however: an active peer can still relay facts
signed by an evicted identity. Read-model removal is now order-independent,
but those broader remove-wins semantics are tracked in `poc-16-gxz` and
`poc-16-up4`, gated by the global suppression-tree review in
`poc-16-yez.9`; they are intentionally not claimed as solved here.

## Running it

```
python3 -m core daemon /tmp/alice --port 7100 &
python3 -m core --node http://127.0.0.1:7100 create alice     # -> ws id
python3 -m core --node http://127.0.0.1:7100 invite --ws <ws> # -> link
# on bob's machine/daemon:
python3 -m core --node http://127.0.0.1:7101 join <link> bob
python3 -m core --node http://127.0.0.1:7101 post --ws <ws> "hello"
python3 -m core --node http://127.0.0.1:7100 msgs --ws <ws>
python3 -m core --node http://127.0.0.1:7101 send --ws <ws> ./photo.jpg
```

`pytest tests/` runs everything; `tests/test_blackbox.py` is the
three-daemon scenario (~10 s).
