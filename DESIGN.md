# Passive-Store Reconciliation — POC-16 Design

Design of record; no code yet. The staged plan is at the end, and every
number here is an estimate until `bench/` replaces it. [MODEL.md](MODEL.md)
carries the performance model and the loop math behind the numbers.

POC-16 asks one question: **can range-based set reconciliation run against a
counterpart that executes no code?** The counterpart is a dumb object store
(S3, a peer's disk behind five HTTP routes, a static file host) holding a
materialized summary of the validated set. The active side does the whole
reconciliation itself by fetching immutable pages. If it works, a cloud node
stops being a sync participant and becomes an artifact peers sync against —
which dissolves the POC-13 cloud blocker (sync coverage == residency).

Lineage: POC-13 built interactive RBSR and proved liveness by cadence.
POC-14 kept the blind store but retired RBSR for head-spidering. POC-16 is
the unexplored quadrant: RBSR semantics over a blind store, as a
**one-sided walk**. It reuses POC-13's treap and cadence rule, POC-14's
blind-store discipline, POC-10's authenticator split, and POC-8's KDF-tree
encryption (all stores hold ciphertext).

## What POC-16 Must Prove

**P1 — efficient sync from the treap.** A client with an arbitrary subset
converges in O(d · log n) transfer and O(log_B n) sequential rounds.
Litmus: 10^6 facts, 10^2 recent-clustered diff ⇒ ≤ 4 rounds, ≤ low
hundreds of KB; a fully scattered diff stays ~1 MB via slice fetches
(MODEL.md).

**P2 — efficient compaction.** An engine takes `(raw pile, valid treap)` to
`(valid new treap)` — signatures, membership, 5–10 dep lookups per fact.
Litmus: ≥ 300 facts/s in a warm 1 GB Lambda against real S3; thousands/s
against a local store.

Everything else is scaffolding around these two.

## The Store

**Facts.** Content-addressed, self-certifying (signature and chain refs in
the payload — the compaction engine is the only validator), bodies encrypted.
Reconciliation key is `(ts, fid)`. **Dependency references must carry the
full `(ts, fid)`** — a bare fid is unresolvable without a secondary index we
refuse to pay for. This is a fact-format constraint.

**Treap.** The validated set lives in a treap keyed `(ts, fid)`, priority
from the fid hash — history-independent, so the same set gives the same
shape, fingerprints, and pages on every node. That is what makes one-sided
comparison possible: aligned subtrees, plain Merkle fingerprints, no
boundary negotiation. No homomorphic sums — they exist to compare unaligned
ranges (useless here) and invite Wagner's attack.

**Pages.** The treap is cut deterministically into fat immutable
content-addressed pages (64–256 KB, thousands of entries). Interior record:
`(range, fingerprint, count, child refs)`. Leaf record: `(ts, fid, author,
seq, auth digest)` — existence and validation without fetching bodies.
Paging is load-bearing: node-per-object storage means ~20 sequential GETs
per lookup and sinks the design. Paged depth is 2–3. Interior records also
carry k sub-fingerprints per child (and the manifest carries the root's
own), so a walker ranged-GETs 8 KB slices instead of whole pages —
load-bearing for scattered diffs (MODEL.md).

**Manifest.** The one mutable object: root page, auth snapshot, generation.
Changes only by CAS (S3 conditional PUT / SQLite transaction / atomic
rename). Everything it references is immutable, so one conditional GET
revalidates a node's whole cached world, and readers get snapshot isolation
free. Unreferenced pages are GC'd after a grace period.

**Pile.** `pile/<member>/<hash>` — write path and quarantine. Puts are
content-addressed, hence idempotent; the member prefix comes from the grant,
so attribution, rate limits, and blame are the same code in every world.
The pile is the WAL: a put is durable and visible (readers scan tree +
pile), so the put response is the writer's confirmation. Treap = validated,
pile = quarantine; fingerprints only ever cover validated facts, so a
hostile writer can litter but never poison. Clients validate pulled pile
entries like any wire input.

**ObjectStore trait.** Every node stores through one S3-shaped trait:

```text
get(key)  put_if_absent(key, bytes)  list(prefix)
cas(key, etag, bytes)   # manifest only
delete(key)             # GC, pile retirement
```

Layout: `root`, `page/<hash>`, `blob/<hash>`, `pile/<member>/<hash>`.
Drivers: s3 (also R2/MinIO/Garage), sqlite (peer default), fs, mem (tests).
One named asymmetry: in the cloud the store *is* the server (presigned,
no daemon in the byte path); in a peer the daemon fronts the store.

## The Walk (P1)

```text
manifest <- conditional GET root      # unchanged ⇒ done
compare(local, remote):
  equal fingerprint  -> prune
  huge count gap     -> bulk fetch / bulk push the range
  else               -> fetch page, recurse unequal children
then: scan pile; pull what I lack; push what it lacks into its pile
```

The count heuristic is advisory (adds and deletes cancel); depth is capped.

The walk computes the *symmetric* difference, so push is the tail of the
same walk: **one dial converges both sides; the responder runs zero sync
logic.** Eager delivery still exists — put your own new facts into known
piles at write time — and the walk is the anti-entropy backstop (the Dynamo
split).

Round trips: interactive negentropy descends two levels per round trip, the
one-sided walk one — bought back by fat fanout (256-way pages match 16-way
interactive round-for-round) and parallel subtree fetches. 2–3 sequential
rounds at 10^6 facts.

## The Engine (P2)

One body of code; only the trigger and store driver differ by deployment.

```text
auth  <- manifest.auth_snapshot          # O(members), one object
deps  <- batch's (ts, fid) refs, sorted
have  <- merge-join deps vs leaf pages   # after intra-batch + recent window
admit <- sig valid ∧ author live ∧ deps in have
park  <- missing deps stay in pile
emit pages -> CAS manifest -> delete covered pile entries
```

**Publish then delete** — an item is briefly in both pile and treap (dedup
makes that harmless), never in neither.

Trigger: cloud S3→SQS(batch window)→Lambda; peer in-process debounce. A
lease keeps compaction single-flight for cache locality; the CAS keeps it
safe regardless.

Auth state is materialized, never re-derived: the snapshot (member keys,
chain heads, epochs) is a small object referenced by the manifest, rewritten
each compaction. Validation is a shallow check against it (POC-10 split);
no chain walks. Revocation is enforced here: an evicted member's grant can
litter the pile until expiry, but the next compaction rejects the facts.

Performance: merge-join, not per-fact lookups; resolve intra-batch and
recent-window first. A messaging dep graph is a tiny universally-hot auth
core plus cold message leaves — steady state resolves almost everything from
memory. Estimates: GET 10–30 ms, ~100 in flight ⇒ 3–5k GET/s; Ed25519
~50–100 µs, never the bottleneck; ~500–1,000 facts/s point-lookup,
thousands merge-join. Memory beats lookups: Lambda RAM bills only while
executing (+1 GB ≈ $0.05/day at a 1-min/2-s cadence ≈ 120k GETs), the hot
set is tens of MB, and immutable pages mean the cache needs no invalidation
— the single-flight compactor wrote the current pages itself last run.

## Auth

Two layers, never mixed. **Integrity**: payload sigchains, checked only by
the engine, gating only the treap — the same boundary in every deployment.
**Transport**: the mint. Prove control of a sigchain-certified device key,
get a grant `{member, scope, expiry}` — presigned URLs in the cloud, a
bearer/signed-URL capability from a peer daemon. To the client a grant is an
opaque request decorator: the only per-backend seam. Renewal is re-mint.
Over iroh the mint feels vestigial (the channel proved the key) but stays —
it is load-bearing in the cloud world and keeping it keeps the worlds
isomorphic. Transport identity is never an integrity input.

## Protocol and Transports

| verb | route | cloud | peer daemon |
|---|---|---|---|
| mint | `POST /mint` | Lambda URL | handshake endpoint |
| root | `GET /root` | S3 conditional GET | serve manifest |
| page | `GET /page/{hash}` (+ blob) | S3 GET | serve blob |
| put | `PUT /pile/{member}/{hash}` | presigned PUT | grant-checked append |
| list | `GET /pile/` | S3 LIST | list pile |

HTTP is the protocol: ETag revalidation on root, h2/h3 streams for parallel
page fetches, and any static HTTPS host is a read-only replica with zero
code. Peers may offer long-poll on `/root` as a liveness hint; cadence
remains the correctness mechanism (POC-13's rule).

Two dialers behind one client, picked by URL scheme: `https://` (WebPKI —
S3, Lambda, mirrors) and `iroh://<node-id>` (h3 over iroh; the node id is
the key, so dialing authenticates; hole-punching and relays included). iroh
is dumb pipes only — no iroh-docs/blobs/gossip, bao stays retired — and
pre-1.0, so the connector module is its containment boundary.

Every node = a **responder half** (five verbs over its store, zero sync
logic) + optional **initiator half** (walk on cadence + eager push). Roles
are per-session, fixed by dial direction. Any peer may dial — news-driven
sends stay fast, and the pair gets the better of the two cadences.
Simultaneous opens: lower node id survives. Always-on public nodes never
initiate.

## Node State and SQLite

The store is the sole source of truth; **every SQLite is a derived
projection stamped with the manifest generation it reflects**; the commit
point is always the manifest CAS. Any node can delete its SQLite and
rebuild from its store.

- The auth snapshot is a manifest-referenced object, not a local file — the
  Lambda wakes, conditional-GETs the manifest, fetches the snapshot on cache
  miss, works, publishes. No EFS, no /tmp durability.
- Engine processing state is ephemeral SQLite by connection string:
  `:memory:` in the Lambda, on-disk temp where RAM is tight. Discarded
  after every run.
- A peer's persistent SQLite holds two separate schemas: the sqlite
  ObjectStore driver (canonical layout) and the app read model (API
  queries), projected from the treap, rebuilt by replay when its generation
  trails.

## Deployments

| | store | serving | compacts | initiates |
|---|---|---|---|---|
| cloud node | s3 | presigned (store is server) | S3→SQS→Lambda | never |
| peer | sqlite | daemon | debounce | cadence + news |
| home server | sqlite or s3 | daemon | debounce | never |
| static mirror | any HTTPS host | files | no | never |

## Staged Plan

Proofs first; no transport work until both numbers exist.

1. **Core** — treap, deterministic page cut, codec; trait with mem + sqlite
   drivers; manifest CAS. Property test: same set ⇒ same page hashes.
2. **P1 bench** — divergence sweep, measure rounds/bytes vs O(d · log n).
3. **P2 bench** — messaging-shaped synthetic pile; engine vs sqlite store,
   then vs real S3 from a warm Lambda; pin facts/s and $/M; pick page size.
4. **Protocol** — daemon (five routes) + the one HTTP client with grant
   decorators + s3 driver/presigned flow; conformance suite green against
   daemon and S3+Lambda.
5. **iroh** — h3-over-iroh connector; same conformance suite.
6. **Auth** — real sigchain validation, snapshot format, eviction test,
   mint over both transports.

## Open Questions

- Orphan policy: pile facts whose deps never arrive need a TTL; re-ask
  POC-13's eviction lessons here.
- Deletion: tombstones weaken the count heuristic; content confidentiality
  via key destruction (POC-14), but the reconciliation-visible shape of a
  delete is undesigned.
- Page cut: needs a precise deterministic definition that keeps small diffs
  ⇒ few changed pages (candidate: cut at treap priority thresholds).
- Fresh log: a validated, deduped, CAS'd staging tier between pile and
  treap — validate on a fast cadence, fold into the treap at ~one leaf
  page. MODEL.md's math favors it strongly (~9× reader cost, ~200× less
  page churn); adopting it rewrites The Pile and The Engine and adds a
  second mutable object.
- Multi-group on one bucket; blob attachments (`blob/<hash>`, POC-13 branch
  findings, hash-list slices not bao); bulk join wants leaf-aligned body
  bundles (MODEL.md — fresh join is request-bound, not byte-bound).
