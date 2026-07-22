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

**P2 — efficient engine.** *Drain* takes `(raw piles, valid set)` to
`(valid set′)` on request — signature plus dep-pure handler over each
fact's closure, deps resolved from pile ∪ treap (frontier probes only;
the closure arrives with the pile) — by rewriting the treap's tail
range; *promotion*
(the cut rule freezing a full tail into immutable pages) and aug
placement (Closure Walk) ride the same commit. Litmus:
≥ 300 facts/s validated in a warm 1 GB Lambda against real S3;
thousands/s against a local store.

**P3 — closure-complete range sync.** `closure_sync(Q)` returns any
`(ts, fid)` range Q *plus every recursive dependency of every fact in
it*, in the walk's own shape. Litmus: ≤ D + 2 rounds (+1 per
out-of-window frontier hop); ref + fence overhead ≤ 10% of context body
bytes; identical sets ⇒ identical aug bytes; a cold 3-day partial join
at 10^6 ≈ 4 rounds / ~18 MB, projectable on arrival (MODEL.md, Closure).

Everything else is scaffolding around these three.

## The Store

**Facts.** Content-addressed, self-certifying, bodies encrypted; the
signature and dep refs live in the **signed clear envelope** (decided
2026-07-22): the kernel judges a fact against nothing but itself and its
closure, and the engine derives the dep aug from envelopes alone — dep
topology is store-visible, content never is.
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
of fixed-size leaf records `(ts, fid, author, auth digest, body offset)`
— existence and authorship without fetching bodies — cut
deterministically into fat immutable content-addressed **packed pages**
(~256 KB, adopted 2026-07-22): record section first, addressable in 8 KB
slices by ranged GET, then a body heap holding the facts' bodies in
record order (lengths implicit from the next offset). A body over ~8 KB
— and every attachment — spills to its own `blob/<hash>`; the record
keeps the ref. Otherwise there is no per-fact object: a dep probe is one
ranged GET at the record's offset, bulk fetches take whole pages (a
fresh join is ~2.2 k GETs, bandwidth-bound — MODEL.md), and the walk
touches record sections only. Above the record run sit **fence runs**:
one fence per
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
the inlined top fence runs (history + tail fences, fact and aug runs
alike), removal set. Changes only by CAS (S3 conditional PUT / SQLite transaction / atomic
rename) — the single commit point for validation and promotion alike.
Everything it references is immutable and content-addressed, so one
conditional GET revalidates a node's whole cached world, readers get
snapshot isolation free, and a ranged GET can never tear across an update.
Unreferenced objects (superseded tails included) are GC'd after a grace
period. Mutable surface of the whole store: `root` ∪ `pile/*` ∪
`invite/*`.

**Pile.** `pile/<member>/<hash>` — pure ingress. Puts are
content-addressed, hence idempotent; the member prefix comes from the grant,
so attribution, rate limits, and blame are the same code in every world. A
put is durable — the response is a *delivery* receipt — but *acceptance*
is appearance in the treap, and the walk's exact two-way diff re-offers
anything that fell short. Only the engine reads raw piles: a hostile
writer can litter but never poison, and litter costs readers zero
bandwidth. **Piles are closure-complete or rejected**: pile ∪ treap must
be dep-closed — the sender just walked, so it knows the gap exactly and
ships it; the drain verifies with frontier probes (dep ∈ treap,
record-level merge-join). **Nothing parks**: every drain empties the
pile — valid facts into the tail, the rest (malformed, bad signature,
invalid, closure-incomplete) deleted on the spot; anything valid that
sank with a bad batch comes back with its closure on the sender's next
walk.

**WAL.** Not a separate tier but **the treap's rightmost range**:
validated-but-unpromoted facts live in a content-addressed *tail page*
(deduped, `(ts, fid)`-sorted, records + bodies packed, capped at
B_t = 2,048 entries ≈ 1.2 MB) whose per-slice fences sit in the
manifest's top run beside the history fences; news bodies are the tail
heap's suffix — there is no separate bundle object. Every drain rewrites the tail
and CASes the manifest — the root covers the news naturally, and because
the tail's fences are in the top run, no fence pages are rewritten: no
path rebuild. So "did anything change" is one conditional GET for the
whole set, and fetching news is the same fence walk as deep sync. History
ranges = promoted, tail range = admitted news, pile = ingress;
fingerprints cover the whole admitted set, never the pile. The tail is
the next few leaf pages accumulating in public — when it fills,
promotion (the cut rule firing) freezes it into ~⌈B_t/B_l⌉ ≈ 5 immutable
pages in the same commit; the B_t cap is the straggler guard-window
knob, deliberately decoupled from page size. A fact admitted *below* the
tail's range boundary (late ts:
offline devices, clock skew) takes an immediate mini-fold of
the page it lands in — same commit, ~2–3 extra PUTs, rare because the
boundary's guard window is the tail's time depth (B_t/λ: hours busy, days
quiet). The boundary itself is content-determined (the highest cut point
with fewer than B_t entries above it), so the whole layout — tail included
— is a pure function of the set (MODEL.md, Stragglers).

**ObjectStore trait.** Every node stores through one S3-shaped trait:

```text
get(key)  put_if_absent(key, bytes)  list(prefix)
cas(key, etag, bytes)   # manifest only
delete(key)             # GC, pile retirement
```

Layout: `root`, `page/<hash>`, `blob/<hash>` (spilled bodies +
attachments), `pile/<member>/<hash>`, `invite/<id>` (encrypted invite
blobs; the only publicly readable prefix, LIST denied) — everything but
`root`, the piles, and the invites is immutable and content-addressed.
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
then: bodies ride the fetched pages (news = tail heap suffix; spilled via blob/); push what it lacks into its pile
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

## The Closure Walk (P3)

**Any range, closure-complete.** `closure_sync(Q)` returns an arbitrary
`(ts, fid)` window — last 3 days, any mid-history slice — plus every
recursive dependency of every fact in it. That is what makes a partial
replica *projectable* (dep-pure handlers never park), what a residency
pin-set means for a bounded peer, and what turns POC-14's join pathology
(dep-DAG-depth spider rounds) into the same walk shape as P1. Queries
quantize outward to leaf-page cuts (~1 h of facts at canonical λ).

**The aug** is one new run family on the existing skeleton — sorted
fixed-size records (~40 B: target `(ts, fid)`, delta-coded), own fence
runs, top fences inline in the manifest, ordinary `page/` objects,
committed by the same CAS. Fact pages, the gate, and the verbs are
untouched. Above the leaf pages sits a **level ladder** of ranges from
priority-threshold cuts at arity β ≈ 16 — the page-cut rule family,
which must therefore be **split-monotone** (boundaries refine, never
move). For each fact f, k_ℓ(f) counts the level-ℓ ranges whose promoted
facts transitively need f; k_ℓ only falls with ℓ and reaches 1 at the
root, so **home(f) — the lowest level with k_ℓ(f) ≤ h — always exists**
(hoist cap h = 8). The aug stores one ref record per hit range at
home(f), eliding targets that live in their own leaf page. Coverage:
any leaf that needs f has f's ref on its root-to-leaf path, recursion
included ("needs" is transitive) — and cutting expansion at popular
facts is sound because **popularity is monotone along dep edges**: a
dep is at least as needed as any of its dependents. Two sort orders are
published — forward `(level, range, target)` for the walk, inverted
`(target, level, range)` for maintenance and, later, deletion cascades.
The canonical scope is the promoted prefix; for the tail the engine
publishes an **aug tail**: the deduped pre-tail direct targets of tail
facts, derived from clear envelopes alone, equally canonical.

```text
closure_sync(Q):                        # Q snapped to page cuts; aug rides the walk's rounds
  root + fence slices over Q, fact and aug   # rounds 1–2, as P1
  leaf slices of Q (whole packed pages cold — bodies ride along)   # round 3
  aug escape prefixes per cover range        # round 3, same round — refs sort by
                                             #   target, so out-of-Q targets are a prefix
  context bodies, coalesced per page (spill via blob/)             # round 4
  trim (optional): chase envelope refs over the fetched set ⇒ exact closure
```

`R_cl = D + 2` — 4 rounds at 10^6 — whenever the context lies on Q's
cover paths, the common case for suffix queries; a frontier target
outside the cover costs +1 round per escaping hop, so spidering
survives only on out-of-window chains, where POC-14 paid it on every
hop of every join. A cold 3-day partial join is ~18 MB, ~6 s at
25 Mbps, ~$0.002 — vs 3 min and 0.57 GB for the fresh join — and every
fact projects on arrival. Ref bytes stay ≤ ~8% of context bodies:
precision is nearly free, the aug's whole job is rounds, and the
context's own bodies are the floor no protocol beats.

**Write side.** Placement is computed at promotion and is a right-spine
append like the facts themselves (~one aug page per promotion). Counts
maintain by pruned propagation — "A hits y" implies "A hits
closure(y)", so each (target, range) pair is processed once ever;
engine ~2,600 → ~2,100 facts/s vs S3, still ~7× the P2 litmus. Homes
migrate only upward, ≤ L_a times per fact lifetime; the worst case (a
hub promoted after its dependents) is one deterministic cascade bounded
by inverted-run fan-in. Identical sets ⇒ byte-identical aug runs — the
stage-1 property test extends verbatim. **The one workload assumption
is δ′ ≈ 1** (distinct out-of-page targets per fact after elision and
homing): at δ′ ≳ 3 the aug stays correct but its storage stops being
noise — bench on a real corpus before trusting it (MODEL.md, Closure).

## The Engine (P2)

One body of code, two loops; only the trigger and store driver differ by
deployment.

The kernel runs in **two modes, and the verb picks**: `drain` —
evaluate and persist through the commit (put + poke in the cloud; any
verb at a peer) — and `evaluate` — verdict only, structurally
side-effect-free (mint, dial handshake). In evaluate mode there is
nothing a handler could persist, and nothing is lost by it: whatever
the store lacked arrives with the next closure-complete pile anyway.

```text
drain:                     # put + poke (cloud); any verb (peer); under lease
  facts <- LIST + GET piles
  admit <- signature ∧ dep-pure handler over the closure    # deps from pile ∪ treap;
           (frontier probes: dep ∈ treap, merge-join; intra-batch first)
  reject<- invalid or closure-incomplete — deleted with the drain
  fold  <- eviction facts ⇒ removal set′   # the one store-side projection
  tail' <- tail ∪ admitted (dedup by fid); stragglers mini-fold their page
  if tail' full: promote stable prefix to pages + fences   # the cut rule fires
  put tail' (records + bodies), promoted pages, spilled blobs, aug,
      removal set′ if changed
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
event plumbing. Every ingest request drains the piles: a peer drains
before answering any verb; in the cloud that is **poke alone** — the
mint runs in evaluate mode and needs no drain, since its payload proves
itself. The request pauses (milliseconds) so the requester always gets
the latest.
For the passive cloud data path the request is explicit: `POST
/poke` on the mint Lambda — writers poke after pushing, walkers poke on a
slow backstop cadence, a writer that dies before poking is caught by
cadence (POC-13's rule). Arrival triggers (S3 events) are rejected on
isomorphism grounds: most ObjectStore drivers (sqlite, fs, MinIO, a static
host) cannot signal on put, so the engine's trigger must live in the
protocol, not the backend. A lease keeps the engine single-flight for
cache locality — concurrent pokes coalesce — and the CASes keep it safe
regardless.

Store-side auth state is one object: the **removal set** — a monotone
projection of eviction facts, O(removals), riding the manifest,
rewritten in the commit that admits them. It is a gate input only:
**handlers never read the removal set** — the moment a validity handler
consults it, verdicts become time-dependent and order-independence
collapses. Fact validity is forever; removal only closes doors.
Authoring an eviction requires proving admin status and non-removal,
and **mutual removals remove each other** — monotone, no ordering
question to answer. Everything the old auth snapshot held is gone:
certification is proved by each fact's own closure, invites live in the
invite blob (Auth), and epoch heads are content facts like any other.

**Admission is dep-pure validation** — signature plus the family
handler over the fact's closure, nothing else. RBSR still gets what it
forces: the verdict is a function of the fact and its immutable closure
— no ambient state, no clock, no arrival order — so membership is
monotone and order-independent, and the union of two honest stores is
always valid. The treap is the **valid, dep-closed set**: membership
certifies the transitive closure, and the closure walk serves it.
Consumers stay trustless — they re-verify what they pull, closures
always in hand — but nothing parks anywhere: piles arrive
closure-complete by the pile rule, syncs arrive closure-complete by
P3. Anything needing negative or global knowledge (uniqueness,
latest-wins) stays a projection-time verdict, deterministic from the
set — never an admission input.
**Removal is terminal and monotonic at the connection level**: eviction
kills the mint — no grants, so no reads and no writes — and it is the
*pusher's* liveness transport checks, never the author's. Facts that
made it into any treap before the door shut stay visible everywhere; a
compromised key's leakage window is its grant expiry. No fact-level
death — no seq cutoffs, no fork verdicts (seq left the leaf record with
its last consumer). Deletion, the one feature that genuinely needs
set-level verdicts, follows POC-13's suppress-if relation + death key
when it returns — deliberately out of this proto (Open Questions).

Performance: closures arrive with the pile, so dep I/O is frontier
probes only — the drain stays transfer- and verify-bound: GET 10–30 ms,
~100 in flight ⇒ 3–5k GET/s; Ed25519 ~50–100 µs; ~1,600–2,100 facts/s
vs S3 with aug upkeep (MODEL.md), ≥ 5× the litmus. Memory beats lookups: Lambda RAM bills only while
executing (+1 GB ≈ $0.05/day at a 1-min/2-s cadence ≈ 120k GETs), the hot
set is tens of MB, and immutable pages mean the cache needs no invalidation
— the single-flight engine wrote the current pages itself last run.

## Auth

One evaluator, everywhere: **the kernel judges content, auth, and
access alike**. A store executes a request iff the kernel validates its
request fact and the gate finds none of the closure's keys in the
removal set.

**Request facts are an ephemeral family.** The auth payload on any verb
is a fact — authored by the requesting device key, deps on the auth
facts that entitle it, body carrying verb, scope, and a loose expiry —
evaluated in evaluate mode, never admitted. Ephemerality is structural,
for three reasons: the set must not grow with reads; mints must not
churn fingerprints into phantom walk diffs; and read patterns must not
become replicated data. A request family has no admit semantics, so a
stray request fact in a pile is litter and the drain deletes it. For a
request fact, acceptance is the grant.

**The mint is a pure function.** Verify the request fact — deps resolve
against the payload and the treap; the aug makes a closure fetch a few
ranged GETs — apply the removal set, return a grant
`{member, scope, expiry}`: presigned URLs in the cloud, a bearer
capability from a peer daemon; to the client an opaque request
decorator, the only per-backend seam. **The grant is encrypted to the
request fact's author pubkey**, so a captured request replays into
ciphertext — no server nonces, no clock strictness, no per-request
state; renewal is a fresh request fact. No writes, no lease: mints
parallelize freely, and the drain trigger shrinks to poke alone. The
mint response also carries the current root (bytes + ETag) as a
freebie: auth hands you the top node, every id below it is
content-addressed, and the session's first walk starts a round trip ahead.
Over iroh the mint feels vestigial (the channel proved the key) but stays —
it is load-bearing in the cloud world and keeping it keeps the worlds
isomorphic. Transport identity is never an integrity input.

**The invite blob is the bootstrap edge.** An invite is a blob at
`invite/<id>` — the **only publicly readable prefix in the design: GET
without a grant, LIST denied absolutely** (unguessability is the access
control) — encrypted under a link secret, with `id = KDF(seed, "id")`
and `k = KDF(seed, "key")`, so the whole invite link is *store URL +
~32-byte seed*. The blob holds whatever the link must prove — the
invite fact, its full admin closure, an epoch-key box, welcome
metadata — so redemption is self-contained: no race with the inviter's
push, no dependence on treap state. If it can connect, it can join.
The chain inside is frozen at creation but evaluated fresh at mint
(inviting admin since removed ⇒ refused). Unclaimed invites are
revocable by delete and TTL-GC'd; a static mirror can serve them. The
credential a meta-workspace join fact carries for sibling devices is
exactly this link.

A **workspace is a store** — root, treap, piles, removal set, each derived
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
| page | `GET /page/{hash}` (+ blob) | S3 GET | serve blob |
| put | `PUT /pile/{member}/{hash}` | presigned PUT | grant-checked append |
| list | `GET /pile/` | S3 LIST | list pile |
| invite | `GET /invite/{id}` | S3 public GET (LIST denied) | ungated read |

HTTP is the protocol: ETag revalidation on root, h2/h3 streams for parallel
page fetches, and any static HTTPS host is a read-only replica with zero
code. Peers may offer long-poll on `/root` as a liveness hint; cadence
remains the correctness mechanism (POC-13's rule).

Two dialers behind one client, picked by URL scheme: `https://` (WebPKI —
S3, Lambda, mirrors) and `iroh://<node-id>` (h3 over iroh; the node id is
the key, so dialing authenticates; hole-punching and relays included). iroh
is dumb pipes only — no iroh-docs/blobs/gossip, bao stays retired — and
pre-1.0, so the connector module is its containment boundary.

Every node = a **responder half** (seven verbs over its store, zero sync
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

- The removal set is a manifest-riding object, not a local file — the
  Lambda wakes, conditional-GETs the manifest, works, publishes. No EFS,
  no /tmp durability.
- **Rows in memory, records on the store.** Fact handlers write ordinary
  SQLite rows into the engine's ephemeral db — identical code in both
  worlds, since that db is already connection-string-abstracted. At
  commit the engine emits the removal set as canonical sorted records,
  and the manifest CAS publishes it; the next run loads records back
  into rows (a warm peer daemon skips the reload by generation stamp).
  Publishing the `.db` itself is rejected:
  SQLite bytes are write-history artifacts — the store holds canonical
  records and SQLite is always the rebuildable working form.
  **Serialization after a fact-processing run is the boundary between
  facts and the auth gate**: evaluate mode — Lambda or peer daemon, same
  code — reads only the objects the last commit published, through the
  same ObjectStore primitive, never the engine's live rows. Facts
  influence auth solely by being processed and serialized; the commit is
  the only channel between the layers.
- **Option — cloud mode: persist the working db itself.** The `.db`
  rejection above is scoped to *consumed* artifacts — canonical records
  other parties read. A private working state has no readers: under the
  single-flight lease the engine may round-trip its scoped SQLite
  (whitelisted auth families' facts + projections + parked/block-unblock
  relations) through the store as an opaque content-addressed blob —
  load → work → serialize → PUT → CAS, GC'd like superseded tails. One
  kernel implementation in both worlds, with the kernel's existing
  parked/wake machinery intact; cloud mode differs only in where the db
  sleeps between runs. The whitelist (declarable in genesis config
  facts) is bounded by the gate's-closure criterion and doubles as a WA
  budget — a chatty family on the list breaks the mode (MODEL.md,
  Cloud-Mode DB).
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
4. **P3 bench** — aug build at promotion + closure walk; sweep window
   sizes; measure δ′ on a real corpus (the aug's one workload
   assumption).
5. **Protocol** — daemon (seven routes) + the one HTTP client with grant
   decorators + s3 driver/presigned flow; conformance suite green against
   daemon and S3+Lambda.
6. **iroh** — h3-over-iroh connector; same conformance suite.
7. **Auth** — request-fact families + evaluate mode, removal set,
   invite blob, eviction test, mint over both transports.

## Open Questions

- Deletion: POC-13's suppress-if relation + death key is the direction —
  the one feature that needs set-level verdicts. Tombstones weaken the
  count heuristic; content confidentiality via key destruction (POC-14);
  the reconciliation-visible shape of a delete is undesigned.
- (Dead weight: resolved 2026-07-22 — admission is dep-pure validation
  again, so facts that never validate never enter the set.)
- Page cut: needs a precise deterministic definition that keeps small diffs
  ⇒ few changed pages, and it must be **split-monotone** — boundaries
  refine, never move — because the aug's level ladder is built from the
  same rule family (the priority-threshold candidate qualifies).
- Multi-group on one bucket; blob attachments (`blob/<hash>`, POC-13 branch
  findings, hash-list slices not bao). (Bulk-join body bundles: resolved
  2026-07-22 by packed pages — bodies live in the page objects, MODEL.md.)
