# Passive-Store Reconciliation — POC-16 Design

Design of record; no code yet. The staged plan is at the end, and every
number here is an estimate until `bench/` replaces it. [MODEL.md](MODEL.md)
carries the performance model and the loop math behind the numbers.

POC-16 asks one question: **can range-based set reconciliation run against a
counterpart that executes no code?** The counterpart is a dumb object store
(S3, a peer's disk behind seven HTTP routes, a static file host) holding a
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

**P2 — efficient engine.** Two loops. *Validate* takes `(raw piles, WAL,
valid treap)` to `(valid new WAL)` on request — signatures,
membership, 5–10 dep lookups per fact. *Fold* takes a full WAL into the
treap. Litmus: ≥ 300 facts/s validated in a warm 1 GB Lambda against real
S3; thousands/s against a local store.

Everything else is scaffolding around these two.

## The Store

**Facts.** Content-addressed, self-certifying (signature and chain refs in
the payload — the engine is the only validator), bodies encrypted.
Reconciliation key is `(ts, fid)`. **Dependency references must carry the
full `(ts, fid)`** — a bare fid is unresolvable without a secondary index we
refuse to pay for. This is a fact-format constraint.

**Treap.** The canonical structure is a treap keyed `(ts, fid)`, priority
from the fid hash — history-independent, so the same set gives the same
shape, fingerprints, and pages on every node. That is what makes one-sided
comparison possible: aligned ranges, plain Merkle fingerprints, no
boundary negotiation. It is math, not layout — on disk it is realized as
the sorted run + fence hierarchy below. No homomorphic sums — they exist
to compare unaligned ranges (useless here) and invite Wagner's attack.

**Pages and fences.** The validated set serializes as one key-sorted run
of fixed-size leaf records `(ts, fid, author, seq, auth digest)` —
existence and validation without fetching bodies — cut deterministically
into fat immutable content-addressed pages (64–256 KB), addressable in
8 KB slices by ranged GET. Above it sit **fence runs**: one fence per
slice, `(separator key, fingerprint, count, page ref)`, suffix-truncated
and delta-coded (~28 B), itself sorted, cut, and fingerprinted by the same
rule; the top run (a few KB) rides inside the manifest. The treap never
exists as a pointer structure — priorities are only the cut function, and
the fence hierarchy is its fingerprint aggregation. Retrieval is one
uniform operation: binary-search cached fences, then **any key range is
one contiguous ranged GET per level** (fixed-size sorted records make
offsets arithmetic) — walk descent, dep probes, and bulk fetches are all
instances. Fences are load-bearing: node-per-object storage (~20
sequential GETs per lookup) or whole-page fetches on scattered diffs would
sink the design. Run depth is 2–3 (MODEL.md).

**Manifest.** The root mutable object: root page, auth snapshot,
generation. Changes only by CAS (S3 conditional PUT / SQLite transaction /
atomic rename). Everything it references is immutable, so one conditional
GET revalidates a node's whole cached world, and readers get snapshot
isolation free. Unreferenced pages are GC'd after a grace period. The WAL
index below is the only other mutable object.

**Pile.** `pile/<member>/<hash>` — ingress and quarantine. Puts are
content-addressed, hence idempotent; the member prefix comes from the grant,
so attribution, rate limits, and blame are the same code in every world. A
put is durable, so the put response is the writer's confirmation. Only the
engine reads raw piles: a hostile writer can litter but never poison, and
litter costs readers zero bandwidth.

**WAL.** `wal` — the validated log: admitted-but-unfolded facts as one
CAS'd, deduped, `(ts, fid)`-sorted index (capped at one leaf page's worth,
~128 KB) plus body bundles `walblob/<gen>`. This is what readers poll for
news: one conditional GET, no LIST, no litter. Treap = folded history,
WAL = validated news, pile = quarantine; fingerprints only ever cover the
treap. The WAL is literally the next leaf page accumulating in public —
its size cap and the fold threshold coincide.

**ObjectStore trait.** Every node stores through one S3-shaped trait:

```text
get(key)  put_if_absent(key, bytes)  list(prefix)
cas(key, etag, bytes)   # manifest only
delete(key)             # GC, pile retirement
```

Layout: `root`, `wal`, `page/<hash>`, `blob/<hash>`, `walblob/<gen>`,
`pile/<member>/<hash>`.
Drivers: s3 (also R2/MinIO/Garage), sqlite (peer default), fs, mem (tests).
One named asymmetry: in the cloud the store *is* the server (presigned,
no daemon in the byte path); in a peer the daemon fronts the store.

## The Walk (P1)

```text
manifest <- conditional GET root      # unchanged ⇒ wal check only; top fences inline
compare(local, remote) per fence:
  equal fingerprint  -> prune
  huge count gap     -> bulk fetch / bulk push (any range = contiguous GETs)
  else               -> ranged GET the covered fence/leaf slices, recurse
then: conditional GET wal; pull unseen entries (bundle GETs);
      push what it lacks into its pile
```

The count heuristic is advisory (adds and deletes cancel); depth is capped.

The walk computes the *symmetric* difference, so push is the tail of the
same walk: **one dial converges both sides; the responder runs zero sync
logic.** Eager delivery still exists — put your own new facts into known
piles at write time, then poke — and the walk is the anti-entropy backstop
(the Dynamo split).

Round trips: interactive negentropy descends two levels per round trip, the
one-sided walk one — bought back by fat fanout (256-way pages match 16-way
interactive round-for-round) and parallel subtree fetches. 2–3 sequential
rounds at 10^6 facts.

## The Engine (P2)

One body of code, two loops; only the trigger and store driver differ by
deployment.

```text
validate:                  # on request — peers drain before serving /wal; cloud on POST /poke
  auth  <- manifest.auth_snapshot ∪ WAL    # O(members), one object
  facts <- LIST + GET piles
  deps  <- sorted (ts, fid) refs; resolve intra-batch, then WAL,
           then merge-join vs leaf slices
  admit <- sig valid ∧ author live ∧ deps resolved
  park  <- missing deps stay in pile
  put bodies + bundle -> CAS wal (append, dedup) -> delete promoted pile keys

fold:                      # when |wal| ≥ ~one leaf page, or age ≥ τ_max
  emit pages + fences from wal             # the wal IS the next leaf page
  CAS manifest -> CAS wal (drop folded)
```

**Publish then swap** at every promotion — a fact is briefly in two tiers
(dedup by fid makes that harmless), never in none.

Trigger: **on request, in both worlds** — the engine has no timers and no
event plumbing. A peer drains its piles before answering `/wal`; the
request pauses (milliseconds) so the requester always gets the latest. The
cloud store cannot compute on read, so the request is explicit: `POST
/poke` on the mint Lambda — writers poke after pushing, walkers poke on a
slow backstop cadence, a writer that dies before poking is caught by
cadence (POC-13's rule). Arrival triggers (S3 events) are rejected on
isomorphism grounds: most ObjectStore drivers (sqlite, fs, MinIO, a static
host) cannot signal on put, so the engine's trigger must live in the
protocol, not the backend. A lease keeps the engine single-flight for
cache locality — concurrent pokes coalesce — and the CASes keep it safe
regardless.

Auth state is materialized, never re-derived: the snapshot (member keys,
chain heads, epochs) is a small object referenced by the manifest, rewritten
at each fold; between folds the live auth state is snapshot ∪ WAL.
Validation is a shallow check against it (POC-10 split); no chain walks.
Revocation is enforced here: an evicted member's grant can litter the pile
until expiry, but the next validation rejects the facts.

Performance: merge-join, not per-fact lookups; resolve intra-batch and
the WAL first. A messaging dep graph is a tiny universally-hot auth
core plus cold message leaves — steady state resolves almost everything from
memory. Estimates: GET 10–30 ms, ~100 in flight ⇒ 3–5k GET/s; Ed25519
~50–100 µs, never the bottleneck; ~500–1,000 facts/s point-lookup,
thousands merge-join. Memory beats lookups: Lambda RAM bills only while
executing (+1 GB ≈ $0.05/day at a 1-min/2-s cadence ≈ 120k GETs), the hot
set is tens of MB, and immutable pages mean the cache needs no invalidation
— the single-flight engine wrote the current pages itself last run.

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
| poke | `POST /poke` | mint Lambda | implicit (drain-on-read) |
| root | `GET /root` | S3 conditional GET | serve manifest |
| wal | `GET /wal` (+ bundles) | S3 conditional GET | drain piles, then serve |
| page | `GET /page/{hash}` (+ blob) | S3 GET | serve blob |
| put | `PUT /pile/{member}/{hash}` | presigned PUT | grant-checked append |
| list | `GET /pile/` | S3 LIST | list pile |

HTTP is the protocol: ETag revalidation on root, h2/h3 streams for parallel
page fetches, and any static HTTPS host is a read-only replica with zero
code. Peers may offer long-poll on `/wal` as a liveness hint; cadence
remains the correctness mechanism (POC-13's rule).

Two dialers behind one client, picked by URL scheme: `https://` (WebPKI —
S3, Lambda, mirrors) and `iroh://<node-id>` (h3 over iroh; the node id is
the key, so dialing authenticates; hole-punching and relays included). iroh
is dumb pipes only — no iroh-docs/blobs/gossip, bao stays retired — and
pre-1.0, so the connector module is its containment boundary.

Every node = a **responder half** (seven verbs over its store, zero sync
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

| | store | serving | engine | initiates |
|---|---|---|---|---|
| cloud node | s3 | presigned (store is server) | Lambda on poke | never |
| peer | sqlite | daemon | on request | cadence + news |
| home server | sqlite or s3 | daemon | on request | never |
| static mirror | any HTTPS host | files | no | never |

## Staged Plan

Proofs first; no transport work until both numbers exist.

1. **Core** — leaf run + fence runs, deterministic cut, codec; trait with
   mem + sqlite drivers; manifest + WAL CAS. Property test: same set ⇒
   same page hashes.
2. **P1 bench** — divergence sweep, measure rounds/bytes vs O(d · log n).
3. **P2 bench** — messaging-shaped synthetic pile; engine vs sqlite store,
   then vs real S3 from a warm Lambda; pin facts/s and $/M; pick page size.
4. **Protocol** — daemon (seven routes) + the one HTTP client with grant
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
- Multi-group on one bucket; blob attachments (`blob/<hash>`, POC-13 branch
  findings, hash-list slices not bao); bulk join wants leaf-aligned body
  bundles (MODEL.md — fresh join is request-bound, not byte-bound).
