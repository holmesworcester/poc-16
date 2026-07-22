# Passive-Store Reconciliation — POC-16 Design

Design of record; no code yet. The staged plan is at the end, and every
number here is an estimate until `bench/` replaces it. [MODEL.md](MODEL.md)
carries the performance model and the loop math behind the numbers.

POC-16 asks one question: **can range-based set reconciliation run against a
counterpart that executes no code?** The counterpart is a dumb object store
(S3, a peer's disk behind six HTTP routes, a static file host) holding a
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

**P2 — efficient engine.** *Drain* takes `(raw piles, admitted set)` to
`(admitted set′)` on request — well-formedness, signature, author known;
no dep I/O — by rewriting the treap's tail range; *promotion* (the cut rule
freezing a full tail into immutable pages) rides the same commit. Litmus:
≥ 300 facts/s validated in a warm 1 GB Lambda against real S3;
thousands/s against a local store.

Everything else is scaffolding around these two.

## The Store

**Facts.** Content-addressed, self-certifying (signature and dep refs in
the payload — the gate checks a fact against nothing but itself and the
snapshot), bodies encrypted.
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

**Pages and fences.** The admitted set serializes as one key-sorted run
of fixed-size leaf records `(ts, fid, author, auth digest)` —
existence and authorship without fetching bodies — cut deterministically
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

**Manifest.** The **only** mutable object besides the piles: generation,
the inlined top fence run (history fences + tail fences), auth snapshot
ref. Changes only by CAS (S3 conditional PUT / SQLite transaction / atomic
rename) — the single commit point for validation and promotion alike.
Everything it references is immutable and content-addressed, so one
conditional GET revalidates a node's whole cached world, readers get
snapshot isolation free, and a ranged GET can never tear across an update.
Unreferenced objects (superseded tails included) are GC'd after a grace
period. Mutable surface of the whole store: `root` ∪ `pile/*`.

**Pile.** `pile/<member>/<hash>` — pure ingress. Puts are
content-addressed, hence idempotent; the member prefix comes from the grant,
so attribution, rate limits, and blame are the same code in every world. A
put is durable — the response is a *delivery* receipt — but *acceptance*
is appearance in the treap, and the walk's exact two-way diff re-offers
anything that fell short. Only the engine reads raw piles: a hostile
writer can litter but never poison, and litter costs readers zero
bandwidth. **Nothing parks**: every drain empties the pile — self-valid
facts into the tail, the rest (malformed, bad signature, unknown author)
deleted on the spot; a fact whose author is unknown *this* drain is
re-offered by its home store's walk after the certifying facts land.

**WAL.** Not a separate tier but **the treap's rightmost range**:
validated-but-unpromoted facts live in a content-addressed *tail page*
(deduped, `(ts, fid)`-sorted, capped at one leaf page, ~128 KB) whose
per-slice fences sit in the manifest's top run beside the history fences,
plus news body bundles `bundle/<hash>`. Every drain rewrites the tail
and CASes the manifest — the root covers the news naturally, and because
the tail's fences are in the top run, no fence pages are rewritten: no
path rebuild. So "did anything change" is one conditional GET for the
whole set, and fetching news is the same fence walk as deep sync. History
ranges = promoted, tail range = admitted news, pile = ingress;
fingerprints cover the whole admitted set, never the pile. The tail is
literally the next leaf page accumulating in public — when it fills,
promotion (the cut rule firing) freezes it into immutable pages in the
same commit. A fact admitted *below* the tail's range boundary (late ts:
offline devices, clock skew) takes an immediate mini-fold of
the page it lands in — same commit, ~2–3 extra PUTs, rare because the
boundary's guard window is the tail's time depth (B_l/λ: hours busy, days
quiet). The boundary itself is content-determined (the highest cut point
with less than a leaf page above it), so the whole layout — tail included
— is a pure function of the set (MODEL.md, Stragglers).

**ObjectStore trait.** Every node stores through one S3-shaped trait:

```text
get(key)  put_if_absent(key, bytes)  list(prefix)
cas(key, etag, bytes)   # manifest only
delete(key)             # GC, pile retirement
```

Layout: `root`, `page/<hash>`, `blob/<hash>`, `bundle/<hash>`,
`pile/<member>/<hash>` — everything but `root` and the piles is immutable
and content-addressed.
Drivers: s3 (also R2/MinIO/Garage), sqlite (peer default), fs, mem (tests).
One named asymmetry: in the cloud the store *is* the server (presigned,
no daemon in the byte path); in a peer the daemon fronts the store.

## The Walk (P1)

```text
manifest <- conditional GET root      # 304 ⇒ NOTHING changed, done; top fences inline
compare(local, remote) per fence:     # tail fences are just the rightmost fences
  equal fingerprint  -> prune
  huge count gap     -> bulk fetch / bulk push (any range = contiguous GETs)
  else               -> ranged GET the covered fence/leaf/tail slices, recurse
then: bodies via bundles (news) or blobs; push what it lacks into its pile
```

The count heuristic is advisory (adds and deletes cancel); depth is capped.

The walk computes the *symmetric* difference, so push is the tail of the
same walk: **one dial converges both sides; the responder runs zero sync
logic.** Eager delivery still exists — put your own new facts into known
piles at write time, then poke — and the walk is the anti-entropy backstop
(the Dynamo split). Ending a write with a walk is a latency nicety, not
a correctness rule: admission never blocks on deps, so a lone PUT cannot
wedge — the walk just delivers the fact's closure promptly for the
consumers' validators, and costs one conditional GET when already in
sync.

Round trips: interactive negentropy descends two levels per round trip, the
one-sided walk one — bought back by fat fanout (256-way pages match 16-way
interactive round-for-round) and parallel subtree fetches. 2–3 sequential
rounds at 10^6 facts.

## The Engine (P2)

One body of code, two loops; only the trigger and store driver differ by
deployment.

```text
validate:                  # on any compute-touched request — peers: every verb; cloud: mint + poke
  auth  <- manifest.auth_snapshot          # O(principals), always current
  facts <- LIST + GET piles
  admit <- well-formed ∧ signed by a snapshot-known author   # no dep I/O
  fold  <- auth facts ⇒ snapshot′          # the one dep-ordered consumer; intra-batch first
  tail' <- tail ∪ admitted (dedup by fid); stragglers mini-fold their page
  if tail' full: promote stable prefix to pages + fences   # the cut rule fires
  put bodies, bundle, tail', promoted pages, snapshot′ if changed
  CAS manifest                             # the single commit point
  delete pile keys                         # admitted and rejected alike
```

**Publish, CAS, delete** — every new object is written first, one manifest
CAS commits them all, covered pile keys are deleted after. A fact is
briefly in both pile and set (dedup by fid makes that harmless), never in
neither; validation and promotion commit through the same CAS, so there is
no multi-object ordering to reason about. The order still guards the
only copy: a pile key deleted before its CAS landed would silently drop
a delivered fact until some walk re-offers it.

Trigger: **on request, in both worlds** — the engine has no timers and no
event plumbing. Every request that reaches compute drains the piles
first: a peer drains before answering any verb; in the cloud that is
mint and poke, since presigned reads cannot compute. The request pauses
(milliseconds) so the requester always gets the latest — in particular
an invitee's first mint sees an invite fact still sitting in a pile.
For the passive cloud data path the request is explicit: `POST
/poke` on the mint Lambda — writers poke after pushing, walkers poke on a
slow backstop cadence, a writer that dies before poking is caught by
cadence (POC-13's rule). Arrival triggers (S3 events) are rejected on
isomorphism grounds: most ObjectStore drivers (sqlite, fs, MinIO, a static
host) cannot signal on put, so the engine's trigger must live in the
protocol, not the backend. A lease keeps the engine single-flight for
cache locality — concurrent pokes coalesce — and the CASes keep it safe
regardless.

Auth state is materialized, never re-derived: the snapshot is a small
object referenced by the manifest, rewritten in the same commit whenever
auth facts are admitted — always current, no union to compute. Structure:
fixed-size records sorted by **device pubkey** (what a mint challenge and
a fact signature prove control of — distinct from the device id,
`H(device_fact)`): pubkey → member, device id, scope/status; plus member
status and KDF epoch heads. **Invite pubkeys are records of the same
shape** — pubkey → invite fact id, provisional scope, expiry — so an
invitee can mint before joining; the join fact consumes the invite.
Expiry is enforced at mint time (expired ⇒ ignored) and expired records
are purged free on the next auth-fact rewrite — no clock-driven
rewrites, every snapshot write is fact-driven. There is no hot half: the
snapshot is the only published projection, O(principals) and never
O(facts) — which is exactly why the mint folds auth facts and nothing
else.

**Admission is self-validation only** — POC-13's rule, and RBSR forces
it: set membership must be monotone and order-independent, or two honest
stores admit different sets and every walk re-diffs the gap forever. The
gate checks well-formedness and a signature by a snapshot-known author —
member device or unexpired invite, dead or alive ("ever certified" is
monotone; refusing a removed author's already-delivered facts would
livelock the walk). No dep check, no chain check, no bodies. The treap
is the **delivered** set: it certifies authorship, integrity, and
delivery — never semantic truth. Validity is each consumer's
deterministic downstream computation: fact handlers run at projection
time and are **dep-pure** — functions of the fact body and its declared
deps' bodies, no ambient state, no reordering footguns — parking
missing-dep facts in their own processing state (a processing status,
not a sync status; the deps arrive by walk). The auth fold is the one
dep-ordered consumer in the store's own compute, and it folds only auth
facts.
**Removal is terminal and monotonic at the connection level**: eviction
kills the mint — no grants, so no reads and no writes — and it is the
*pusher's* liveness transport checks, never the author's. Facts that
made it into any treap before the door shut stay visible everywhere; a
compromised key's leakage window is its grant expiry. No fact-level
death — no seq cutoffs, no fork verdicts (seq left the leaf record with
its last consumer). Deletion, the one feature that genuinely needs
set-level verdicts, follows POC-13's suppress-if relation + death key
when it returns — deliberately out of this proto (Open Questions).

Performance: the gate does no dep I/O, so the drain is transfer- and
verify-bound — GET 10–30 ms, ~100 in flight ⇒ 3–5k GET/s; Ed25519
~50–100 µs ⇒ thousands of facts/s. Memory beats lookups: Lambda RAM bills only while
executing (+1 GB ≈ $0.05/day at a 1-min/2-s cadence ≈ 120k GETs), the hot
set is tens of MB, and immutable pages mean the cache needs no invalidation
— the single-flight engine wrote the current pages itself last run.

## Auth

Two layers, never mixed. **Integrity**: the gate — authorship and
well-formedness, checked only by the engine, gating only the treap, the
same boundary in every deployment; semantic validity is computed
downstream by every consumer, never enforced by the store.
**Transport**: the mint. Prove control of a sigchain-certified device key,
get a grant `{member, scope, expiry}` — presigned URLs in the cloud, a
bearer/signed-URL capability from a peer daemon. To the client a grant is an
opaque request decorator: the only per-backend seam. Renewal is re-mint.
The mint response also carries the current root (bytes + ETag) as a
freebie: auth hands you the top node, every id below it is
content-addressed, and the session's first walk starts a round trip ahead.
Over iroh the mint feels vestigial (the channel proved the key) but stays —
it is load-bearing in the cloud world and keeping it keeps the worlds
isomorphic. Transport identity is never an integrity input.

A **workspace is a store** — root, treap, piles, snapshot, each derived
only from its own facts; the same device pubkey in two workspaces is two
independent certifications. The mint is the one multi-tenant piece:
`/mint` names the workspace, reads that store's root, and the grant
scopes to that store's prefix — but it holds no workspace registry (a
store's existence is the workspace's existence; IAM bounds what a
deployment serves) and mints **one workspace per call**. Only the
client's **keyring** (workspace → device key, store address, grant) knows
which workspaces an endpoint belongs to — the one irreducibly node-local
state, since private keys are never fact-derived — and cross-workspace
identities stay unlinkable by construction. A node syncs its workspaces
(~20 max) round-robin from the keyring; an idle workspace costs one
conditional GET per cadence.

The keyring is written only at the bootstrap edges — **create-workspace
and accept-invite** — since an entry must exist before the node can mint
or sync at all, and replay can never reconstruct private keys (recovery
is re-invite). Both edges are still fact-layer **commands** in code
organization: create-workspace generates the id and keypair, writes the
keyring entry, and authors the genesis facts (workspace, founder, device
cert, first epoch — ordinary facts through the ordinary author; store
provisioning is the one deployment act outside the protocol). Eviction
reaches the keyring only as an app-layer reaction to a synced fact.
Snapshot and keyring are the opposite edges of the fact layer:
downstream projection (serialized at commit, convergent, rebuildable)
vs upstream root of trust (non-derivable, per-node). **Deferred, not rejected —
the personal meta-workspace**: as built, the keyring forgoes the fact
layer's concurrency story (a member's other devices do not learn of a
new workspace through facts). The designed future: a **person is a
workspace** whose members are your devices and whose facts are keyring
events. A join fact carries the credential a sibling device needs to
join by itself, so every store stays sealed — no cross-store reads —
while joins and removals propagate to all devices as ordinary sync.
Device linking becomes person-centered: a device links to your person
once, and the person's DAG links workspaces monotonically. The keyring
then collapses to a projection of the personal workspace plus this
device's private keys, and the bootstrap edge shrinks to exactly one:
link-device. Transport ACLs are never finer than
membership — grants cover whole keys and pages interleave channels — so
sub-workspace confidentiality is the encryption layer (epochs), never
the grant.

## Protocol and Transports

| verb | route | cloud | peer daemon |
|---|---|---|---|
| mint | `POST /mint` → grant + current root | Lambda URL | handshake endpoint |
| poke | `POST /poke` | mint Lambda | implicit (drain-on-read) |
| root | `GET /root` | S3 conditional GET | drain piles, then serve |
| page | `GET /page/{hash}` (+ blob, bundle) | S3 GET | serve blob |
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

Every node = a **responder half** (six verbs over its store, zero sync
logic) + optional **initiator half** (per-workspace walk on cadence,
round-robin from the keyring + eager push). Roles
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
- **Rows in memory, records on the store.** Fact handlers write ordinary
  SQLite rows into the engine's ephemeral db — identical code in both
  worlds, since that db is already connection-string-abstracted. At
  commit the engine emits the snapshot as canonical sorted records
  (`SELECT … ORDER BY pubkey`), and the manifest CAS publishes it; the
  next run loads records back into rows (a warm peer daemon skips the
  reload by generation stamp). Publishing the `.db` itself is rejected:
  SQLite bytes are write-history artifacts — the store holds canonical
  records and SQLite is always the rebuildable working form — and the
  mint path stays SQLite-free, a binary search over the records.
  **Serialization after a fact-processing run is the boundary between
  facts and the auth gate**: the mint — Lambda or peer daemon, same
  code — reads only the objects the last commit published, through the
  same ObjectStore primitive, never the engine's live rows. Facts
  influence auth solely by being processed and serialized; the commit is
  the only channel between the layers.
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
   mem + sqlite drivers; manifest CAS. Property test: same set ⇒
   same layout — pages, fences, and tail.
2. **P1 bench** — divergence sweep, measure rounds/bytes vs O(d · log n).
3. **P2 bench** — messaging-shaped synthetic pile; engine vs sqlite store,
   then vs real S3 from a warm Lambda; pin facts/s and $/M; pick page size.
4. **Protocol** — daemon (six routes) + the one HTTP client with grant
   decorators + s3 driver/presigned flow; conformance suite green against
   daemon and S3+Lambda.
5. **iroh** — h3-over-iroh connector; same conformance suite.
6. **Auth** — real gate + auth fold, snapshot format, eviction test,
   mint over both transports.

## Open Questions

- Deletion: POC-13's suppress-if relation + death key is the direction —
  the one feature that needs set-level verdicts. Tombstones weaken the
  count heuristic; content confidentiality via key destruction (POC-14);
  the reconciliation-visible shape of a delete is undesigned.
- Dead weight: the delivered set accretes facts that never validate
  (certified authors only, blameable); if it ever matters, deterministic
  suppression rides the deletion design.
- Page cut: needs a precise deterministic definition that keeps small diffs
  ⇒ few changed pages (candidate: cut at treap priority thresholds).
- Multi-group on one bucket; blob attachments (`blob/<hash>`, POC-13 branch
  findings, hash-list slices not bao); bulk join wants leaf-aligned body
  bundles (MODEL.md — fresh join is request-bound, not byte-bound).
