# Passive-Store Reconciliation — POC-16 Design

Design of record; no code yet. The staged plan is at the end, and every
number here is an estimate until `bench/` replaces it. [MODEL.md](MODEL.md)
carries the performance model and the loop math behind the numbers.

POC-16 asks one question: **can range-based set reconciliation run against a
counterpart that executes almost no code?** The counterpart is a dumb object
store (S3, a peer's disk behind seven HTTP routes, a static file host)
holding a materialized summary of the validated set. The active side does
the whole reconciliation itself by fetching immutable pages — the only code
left on the passive side is the auth fence checking grants at the door. If
it works, a cloud node stops being a sync participant and becomes an
artifact peers sync against — which dissolves the POC-13 cloud blocker
(sync coverage == residency).

## The System in One Page

A workspace is a dumb object store — S3, a peer's disk, a static
host — holding a materialized, canonical arrangement of a fact set.
Nothing server-side understands the data; readers do all sync
themselves by fetching immutable pages (one-sided RBSR), and one
Lambda-or-daemon runs the only compute: a kernel that judges bytes and
gates access to authorized users.

**The set.** Facts are content-addressed: a type tag, a ts, and a
canonical set of atoms carrying needs, offers, and dep refs in the
clear envelope, values encrypted in the body. Causality lives in refs
alone; ts is an uninterpreted locality key with zero correctness
weight. The valid, dep-closed set serializes as a canonical
`(ts, fid)`-sorted run of packed pages (records + body heap) under
fence runs, topped by one CAS'd manifest — same set, same bytes,
everywhere. Diffing is fence-fingerprint comparison plus ranged GETs:
O(d·log n), ~4 rounds, against a counterpart that executes almost no
code.

**The unit.** *Every fetchable unit is a closed pile*: ingress pile,
tail + annex, range + annex, request payload, invite blob — one codec,
serialized in canonical-topo order (the closure walk's completion
order), carrying its full closure down to genesis.

**The kernel.** One judge for content, auth, and access:
`kernel(stream, anchor, [globals]) → (valid, new globals)`. One
streaming invariant — every need matches an offer already emitted
behind the cursor, or the unit rejects — then per-fact integrity and
the family handler, workspace scope via the anchor (genesis fid;
workspace id = `H(genesis)`). Zero store reads; caller-injected SQLite
working state; parallel invocations. Validity is forever and
globals-blind; only ephemeral request facts read globals (the monotone
removal set — removal is connection-level, mutual removals both land).

**The engine.** Semantics-free: hash-verify, kernel, merge by key into
the tail, promote by the cut rule into write-once pages + annexes,
union globals, one CAS, delete piles. Runs only on request, under a
lease. Access is a handshake: the requester sends a small closed
pile — a request fact plus its auth closure — and the mint, a pure
function, runs the same kernel over it and returns a grant encrypted
to the author's key. Invites are encrypted blobs at
unguessable ids — a link is a URL plus a 32-byte seed.

**Consumers.** Trustless: re-kernel whatever they pull, in any order,
streaming — a fresh join's inbox is usable in seconds. `Valid<Fact>`
flows to projectors with no validity logic, into workspace-tagged read
models; replay is the store's own units through the same kernel. One
body of code across cloud, peer, home server, mirror, and iOS NSE; the
keyring (workspace → anchor, device key, address, grant) is the only
irreducible local state.

**To prove:** P1 walk efficiency, P2 engine throughput, P3
closure-complete range sync.

## What POC-16 Must Prove

**P1 — efficient sync from the treap.** A client with an arbitrary subset
converges in O(d · log n) transfer and O(log_B n) sequential rounds.
Litmus: 10^6 facts, 10^2 recent-clustered diff ⇒ ≤ 4 rounds, ≤ low
hundreds of KB; a fully scattered diff stays ~1 MB via slice fetches
(MODEL.md).

**P2 — efficient engine.** *Drain* takes `(raw piles, valid set)` to
`(valid set′)` on request — hash-verify each pile, run
`kernel(pile) → (valid, new globals)`, a pure predicate over fully
closed piles with **zero store reads**, then k-way-merge the canonical
runs into the treap's tail range; *promotion* (the cut rule freezing a
full tail into immutable pages) and annex placement (Closure Walk)
ride the same commit. Litmus: ≥ 300 facts/s validated in a warm 1 GB
Lambda against real S3; thousands/s per core locally — independent
piles validate in parallel.

**P3 — closure-complete range sync.** `closure_sync(Q)` returns any
`(ts, fid)` range Q *plus every recursive dependency of every fact in
it*, in the walk's own shape. Litmus: ≤ D + 2 rounds (+1 per
out-of-window frontier hop); ref + fence overhead ≤ 10% of context body
bytes; identical sets ⇒ identical aug bytes; a cold 3-day partial join
at 10^6 ≈ 4 rounds / ~18 MB, projectable on arrival (MODEL.md, Closure).

Everything else is scaffolding around these three.

## The Store

**Facts.** A fact is a type tag, a ts, and a canonical set of
**atoms** that adopt both (POC-13's atom model); `fid` hashes that
canonical form. Atoms carry the fact's needs, offers, and dep refs in
the **clear envelope**; encrypted values ride the body — **matching
reads addresses, never values** — so dep topology and the offer
vocabulary are store-visible while content never is, and the engine
derives the annexes from envelopes alone. Signatures are not envelope
fields but their own offering facts (Atoms, below).
Reconciliation key is `(ts, fid)`. **Dependency references must carry the
full `(ts, fid)`** — a bare fid is unresolvable without a secondary index we
refuse to pay for. This is a fact-format constraint. **ts carries no
correctness weight at all**: causality lives in the dep refs alone,
order lives in each unit's serialization, and ts is an uninterpreted
locality key — wall clock by convention, so live diffs land rightmost
and humans see plausible times, but validity never reads it (the only
wall-clock comparisons anywhere are grant/invite expiry, at the gate,
against the checker's own clock). Skew cannot break anything; it can
only price a fact as a straggler, and a windowed reader can never
lose a skewed dep, because the annex delivers context by closure, not
by window.

**Treap.** The canonical structure is a treap keyed `(ts, fid)`, priority
from the fid hash — history-independent, so the same set gives the same
shape, fingerprints, and pages on every node. That is what makes one-sided
comparison possible: aligned ranges, plain Merkle fingerprints, no
boundary negotiation. It is math, not layout — on disk it is realized as
the sorted run + fence hierarchy below. No homomorphic sums — they exist
to compare unaligned ranges (useless here) and invite Wagner's attack.

**Pages and fences.** The valid set serializes as one key-sorted run
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
bandwidth. **A pile is a fully closed set in the canonical mini-run
codec** — sorted records + packed bodies + mini-fences, the same
serialization as tail and pages: an unpromoted leaf range. Closed
means closed absolutely: every dep ref resolves *inside the pile*,
auth chains down to genesis included, embedded and deduped per pile
(~1–3 KB per author) — even deps the receiver already holds, because
dedup at merge by fid is free and it is what keeps validation
stateless. No size cap: splitting duplicates closures, and the merge
streams. **All-or-nothing**: the kernel judges a pile as a unit;
rejects (malformed, bad hash, unresolved ref, invalid) are deleted on
the spot, blame lands on the pusher's own prefix, and anything valid
that sank with a bad batch comes back on the sender's next walk.
Byte-level layout never composes across concurrent piles — the engine
re-cuts, because **recomputation is the verification** — but
record-level merge does, associatively: history-independence makes any
arrival grouping converge to identical bytes. Nothing parks; every
drain empties the pile.

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
ranges = promoted, tail range = valid news, pile = ingress;
fingerprints cover the whole valid set, never the pile. The tail is
the next few leaf pages accumulating in public — when it fills,
promotion (the cut rule firing) freezes it into ~⌈B_t/B_l⌉ ≈ 5 immutable
pages in the same commit; the B_t cap is the straggler guard-window
knob, deliberately decoupled from page size. A valid fact landing *below* the
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
per fence, compare fingerprint + count:   # tail fences are just the rightmost fences
  equal fp      -> prune
  local ≈ empty -> BULK: fetch range + annex units (closed piles),
                   stream-kernel on arrival, newest-first
  else          -> EXACT: ranged GET fence/leaf/tail slices, recurse; diff records
then (exact): bodies via page heaps / tail suffix / blob spills — context local, no annex
then, at walk end — the push tail:
  exact -> push set completes only now (leaf slices carry the responder's
           full in-range entries); one close() over it -> one closed pile,
           PUT into own pile prefix + poke
  bulk  -> PUT copies of own promoted range+annex / tail+tail-annex units —
           already closed piles; no assembly, receiver's merge dedups by fid
```

**Decide with hashes, converge with piles.** Exact mode is the
near-sync path — byte-minimal, ~20 KB per cadence, context already
local so no closure machinery. Bulk mode is onboarding and catchup —
the fetch unit is the closed pile, judgeable the moment it lands.
The mode boundary is per-fence, advisory (adds and deletes cancel),
and mischoosing costs bytes, never correctness. Descent is **read
planning, not negotiation**: the responder is passive, counts ride
every fence, and the inline top run means a cold or far-behind client
decides *in round one* which subtrees to take whole — bootstrap
collapses to root → one fence-run read (enumeration) → parallel unit
fetches, streaming through the kernel as they arrive.

**The push tail is collect-then-close, never per-leaf.** In exact mode
the push set is not even knowable per-leaf — the subtraction needs the
responder's complete entry list inside each differing range, which
arrives with the leaf slices — and one `close()` over the collected
set embeds the shared closure (auth chains, hot deps) once, where
per-leaf piles would re-embed it per leaf: exactly the duplication the
no-size-cap rule exists to avoid. In bulk mode there is no assembly at
all: the pusher's own promoted range + annex and tail + tail-annex
units are already closed piles, so push is copying bytes it already
holds, and over-pushing is harmless because the receiver's merge
dedups by fid. The walker's cross-round state is three entry sets —
descent frontier, pull set, push accumulator — records only, never
bodies; `close()` streams bodies from the local store once, at the
end. Chunking a large push for transport retry is legal, but each
chunk must close independently (splitting duplicates closures), which
is why one pile is the default. Piles are transient ingress, never
canonical: push granularity cannot perturb "same set, same bytes."

The walk computes the *symmetric* difference, so push is the tail of the
same walk: **one dial converges both sides; the responder runs zero sync
logic.** Eager delivery still exists — put your own new facts into known
piles at write time, then poke — and the walk is the anti-entropy backstop
(the Dynamo split). Ending a write with a walk is a latency nicety, not
a correctness rule: validation never blocks on deps, so a lone PUT cannot
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

**Primary mechanism — closed ranges with embed annexes.** Diffing and
closing live at different granularities: fingerprints stay
slice-granular (P1 untouched), while closedness is a property of the
*fetch unit*. Each promoted range gets an **annex** —
`closure(range) ∖ range` plus copies of in-range skew-inversion
targets, deduped, canonical-topo-serialized, its own content-addressed
object beside the page — so range + annex is a fully closed set,
judgeable by the same kernel predicate, same single streaming check,
as any pile. The
annex is a pure set function (identical sets ⇒ identical annex bytes),
and the engine builds it **by aggregation, never by search**: piles
arrive fully closed, so every copy an annex will ever need came in
with some pile; at promotion each ref is classified in one pass
(in-range, else annex) and sufficiency is the same syntactic
resolution check the gate already ran. Fat ranges swallow the common
context; hot hubs (genesis, certs, channels) cost one copy per range —
~20 copies at 10^6 under fat ranges. Storage pays the duplication;
nobody ever chases a graph.

**Write path.** Between promotions the tail keeps its own annex — the
deduped embedded copies covering the tail's out-refs, aggregated from
each valid pile and rewritten with the tail. At promotion the engine
classifies refs with everything in hand (tail facts + tail annex) and
distributes copies into the new ranges' annexes. **Promoted range +
annex pairs are write-once**: deps point backward, so `closure(R)` is
fixed by R's immutable contents the moment it freezes — no reverse
index, no count maintenance, nothing to touch when later facts arrive.
The only reopen is a straggler's mini-fold, which recomputes that one
range's annex from copies the straggler's own pile carried. Annexes
are derived sidecars, content-addressed beside their pages and
**outside the fingerprinted set** — the treap reconciles facts only,
so copies never perturb the walk's diff algebra.

**Every fetchable unit is a closed pile.** Ingress pile, tail +
tail-annex, promoted range + annex, request payload, invite blob —
one codec, one predicate, one streaming invariant: every ref resolves
behind the cursor. Writer-built units satisfy it by canonical-topo
serialization; at-rest ranges stay key-ordered (fingerprints demand
it) and the **annex restores the invariant** — serialized
canonical-topo, holding the out-of-range closure plus copies of any
in-range facts that are dep targets of earlier-keyed in-range facts
(skew inversions: rare, deterministic, deduped by the seen-set). The
annex is a **literal prefix** of its range — annex ∪ range is
concatenation, not a merge — so "context first, then news" holds for
every unit by construction. So sync is a
stream of independently judgeable units: a consumer kernels and
projects each range as it lands, in any order, parallel across cores —
fetch ts-descending and a fresh join's inbox is usable in seconds
while history backfills behind it. Hub copies re-arriving across
ranges cost no re-verification: verdicts are immutable, so a
consumer's fid-keyed verdict cache is append-only and each hub
verifies once per device lifetime.

```text
closure_sync(Q):                        # Q snapped to range cuts
  root + fence slices over Q            # rounds 1–2, as P1
  leaf slices / whole packed pages of Q # round 3 — bodies ride along
  annexes of Q's cover ranges           # round 3, same round
  spilled bodies via blob/              # round 4
```

`R_cl = D + 2` — 4 rounds at 10^6, no escape hops, no workload
assumption: the annex *is* the context. A cold partial join stays
~4 rounds and tens of MB — the context's own bodies are the floor no
protocol beats — and every fact projects on arrival (MODEL.md,
Closure).

**Fallback — the dep aug** (MODEL.md, Closure): the ref-based
augmentation (level ladder, k_ℓ homing, two sort orders, aug tail)
that makes ranges closable *on demand* instead of closed *at rest* —
leaner at rest, but its count propagation is transitive-closure work
in the engine, the one thing the closed-pile design otherwise
eliminates. Retained as the fallback if annex duplication measures
pathological on a real corpus; stage 4 is the bake-off. The
split-monotone constraint it exports to the page-cut rule stays either
way.

## The Engine (P2)

One body of code, two loops; only the trigger and store driver differ by
deployment.

The kernel runs in **two modes, and the verb picks**: `drain` —
`kernel(pile, anchor) → (valid, new globals)`, persisted through the
commit (put + poke in the cloud; any verb at a peer) — and `evaluate` —
`kernel(payload, anchor, globals) → valid`, verdict only, structurally
side-effect-free (mint, dial handshake). The **anchor** is the
workspace's genesis fid — a constant, fixed at creation and identical
across all honest replicas for all time, so verdicts stay
order-independent; time-varying context (globals) remains quarantined
to ephemeral handlers. Persistent-family handlers
never see globals — validity is a function of the pile alone, which is
what keeps validation order-independent; only ephemeral-family handlers
read them, safe because their verdicts never enter the set. In
evaluate mode there is nothing a handler could persist, and nothing is
lost by it: whatever the store lacked arrives with the next closed
pile anyway. Each kernel invocation is **closed in/out with its own
tables**, and two rules make one implementation serve every context.
**Input is a stream**, and the kernel's entire streaming contract is
one check: **every ref resolves among the already-valid facts behind
the cursor, or the unit rejects.** That single check is closedness,
ordering, and dep resolution at once — no reorder buffer, no pending
state, no topo sort in the kernel. Order is the serializer's job,
and it is free: **canonical-topo order is the closure walk's own
completion order** — news in key order, refs in envelope order, emit
each fact when its deps have emitted, dedup by fid. Emit-on-completion
is deps-first by construction (reversed *discovery* order is not —
shared deps break it), deterministic, retry-idempotent; the walk that
gathers the closure *is* the serializer. So a closed pile validates in
a single forward pass, RAM bounded by the working db, judging bytes as
they arrive. **The system orders only at the writing
edge**; readers never sort, never wait.
**The caller injects the db connection**: `:memory:` when unstated, a
tmp on-disk file when the caller knows better (replay, iOS) — never a
flag, because policy belongs to the caller and the kernel stays
context-free; disposal, placement (an NSE uses the app-group
container), and parallelism (one connection per invocation, across
cores) are the caller's too. Replay then costs nothing to build: full and
windowed replay alike are the store's own range + annex units streamed
through the kernel with a disk db — every unit closed, a cumulative
seen-set deduping the hub copies.

```text
drain:                     # put + poke (cloud); any verb (peer); under lease
  piles <- LIST + GET piles; hash-verify mini-run structure  # cheapest checks first
  kernel(pile, anchor) per pile, in parallel ⇒ (valid?, new globals)  # pure predicate; zero store reads
  reject invalid piles whole             # deleted with the drain; blame by prefix
  globals′ <- globals ∪ new globals      # associative union; removal set today
  tail' <- merge valid facts by key (the working db emits sorted), dedup by fid; stragglers mini-fold
  tail-annex' <- tail-annex ∪ embedded copies of tail's out-refs   # aggregation
  if tail' full: promote stable prefix to pages + fences + annexes  # the cut rule fires
  put tail' + tail-annex', promoted pages + annexes, spilled blobs, globals′ if changed
  CAS manifest                           # the single commit point
  delete pile keys                       # valid and rejected alike
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

Store-side auth state is one object family: **globals** — monotone
semilattice projections the kernel itself emits, published as
canonical sorted records riding the manifest, rewritten in the commit
that changes them. Today globals is the **removal set**: the union of
targets of valid eviction facts, extracted per pile by the kernel —
order-free, because per-pile extraction composes as union. Eviction
validity is removal-blind (valid iff the author's chain shows admin),
so **mutual removals remove each other** — monotone, no ordering
question to answer; "non-removal" is enforced at the connection, never
in fact validity. Globals are read **only by ephemeral-family
handlers**: a persistent-family handler that consulted them would make
verdicts time-dependent and collapse order-independence. Fact validity
is forever; removal only closes doors. When deletion returns, its
suppress-if set is the second occupant of the globals slot. Everything
the old auth snapshot held is gone: certification is proved inside
each pile, invites live in the invite blob (Auth), and epoch heads are
content facts like any other.

**There is no admission — semi-untrusted piles go straight to
validation**: integrity plus the family handler over the fact's
in-pile context (POC-13's validator signature,
`valid(fact, context) → bool`, with the waiting removed), nothing
else, and the valid facts merge. RBSR still gets what it forces: the verdict is a function of the
fact and its immutable closure — no ambient state, no clock, no
arrival order — so membership is monotone and order-independent, and
the union of two honest stores is always valid. The treap is the
**valid, dep-closed set**: membership certifies the transitive
closure, and the closure walk serves it. **The kernel enforces
workspace scope on every fact** via the anchor: chains bottom out at a
self-signed genesis, the workspace id is `H(genesis)`, and each
fact's chain must bottom at *the* anchor — so cross-workspace
contamination rejects inside the predicate, even on a shared bucket
with botched prefixes. The kernel *code* stays workspace-agnostic (the
anchor is data, not configuration), and the gate stops checking
anything at all: it is a **parameter supplier**, currying anchor +
globals into the one judge. The anchor's authentic source is the
invite link → keyring on a peer, deployment identity in the cloud
(the bucket is the workspace); the store may repeat it but is never
the authority — a fresh reader trusts its link, not the thing it is
about to verify. What a pile can never do is bind *validity* to its
own delivery: **validity binds to the workspace through the chain;
delivery binds to the pusher through the grant; the two never mix** —
a fact must judge identically however and whenever it arrives. Consumers stay trustless — they re-verify what they
pull, closures always in hand — but nothing parks anywhere: piles are
closed by format, syncs arrive closed by P3. Anything needing negative
or global knowledge (uniqueness, latest-wins) stays a projection-time
verdict, deterministic from the set — never a validation input.

**Atoms — needs and offers.** The relationship grammar in this
prototype is exactly two: an atom either **offers** — publishes a
named, scoped assertion — or **needs** — demands a match. Validation
is matching: a fact's needs must match offers already emitted by
valid facts behind the cursor — the seen-set rule generalized from
"ref resolves" to "need met" — and an unmet need rejects the unit.
**Parking is deleted from the grammar**: POC-13's Require parked on
zero matches; closed units mean the closer either shipped the
providers or authored a broken pile. Pinned dep refs and needs
compose: refs say *where* (exact `(ts, fid)` providers, keeping
closure and annexes deterministic), needs say *what* (the assertion
the provider must offer). Offers are the **version interlingua** —
the reason the model earns its weight: facts of different versions in
one pile never read each other's schemas; each version's handler
decodes only its own bytes and emits normalized offers, consumers
need the offers, and a new version is a new handler, not a migration
(POC-10's adapt layer, dissolved into offer emission).

**Signature is a fact type that offers.** The kernel's built-in
judgment shrinks to integrity — `fid` = hash of canonical bytes,
grammar, the streaming match — and everything semantic, crypto
included, is family handlers: a signature fact verifies its Ed25519
once and offers authorship; certs offer membership; content facts
need both. Heavier — authorization becomes facts beside the content —
but piles make it cheap: signature facts ride the same units, dedup
by fid, and verify once into the offer table. Negative knowledge
(POC-13's SuppressIf) stays out of the grammar by design — it is
globals' job, and it returns with deletion.

**Removal is terminal and monotonic at the connection level**: eviction
kills the mint — no grants, so no reads and no writes — and it is the
*pusher's* liveness transport checks, never the author's. Facts that
made it into any treap before the door shut stay visible everywhere; a
compromised key's leakage window is its grant expiry. No fact-level
death — no seq cutoffs, no fork verdicts (seq left the leaf record with
its last consumer). Deletion, the one feature that genuinely needs
set-level verdicts, follows POC-13's suppress-if relation + death key
when it returns — deliberately out of this proto (Open Questions).

Performance: piles are fully closed, so validation does **zero store
reads** — the drain is transfer- and verify-bound: GET 10–30 ms, ~100
in flight ⇒ 3–5k GET/s; Ed25519 ~50–100 µs, parallel across cores;
~2,400+ facts/s vs S3 (MODEL.md), ≥ 8× the litmus. Memory beats lookups: Lambda RAM bills only while
executing (+1 GB ≈ $0.05/day at a 1-min/2-s cadence ≈ 120k GETs), the hot
set is tens of MB, and immutable pages mean the cache needs no invalidation
— the single-flight engine wrote the current pages itself last run.

## Auth

One evaluator, everywhere: **the kernel judges content, auth, and
access alike**. A store executes a request iff
`kernel(payload, anchor, globals)` says valid — the request fact's
chain proves entitlement at this workspace's anchor, its scope covers
the verb, and it survives the removal set; the gate's only job is
supplying the parameters. **One object serves four roles**: ordinary pile,
notification pile, request payload, and invite blob are all the same
fully closed pile in the canonical codec, sometimes encrypted.

**Request facts are an ephemeral family.** The auth payload on any verb
is a fact — authored by the requesting device key, deps on the auth
facts that entitle it, body carrying verb, scope, and a loose expiry —
evaluated in evaluate mode, never persisted. Ephemerality is structural,
for three reasons: the set must not grow with reads; mints must not
churn fingerprints into phantom walk diffs; and read patterns must not
become replicated data. A request family has no persistence semantics, so a
stray request fact in a pile is litter and the drain deletes it. For a
request fact, acceptance is the grant.

**The mint is a pure function.** The handshake is a small closed
pile — the request fact plus the chain that entitles it, a few KB — so
verification reads nothing: the mint's whole job is one kernel call,
`kernel(payload, anchor, globals)`, and a valid verdict returns a grant
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
metadata — and is itself a closed pile in the canonical codec,
encrypted; redemption is self-contained: no race with the inviter's
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
client's **keyring** (workspace → anchor, device key, store address,
grant) knows
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

- Globals (the removal set today) are manifest-riding objects, not
  local files — the Lambda wakes, conditional-GETs the manifest, works,
  publishes. No EFS, no /tmp durability.
- **Rows in memory, records on the store.** Fact handlers write ordinary
  SQLite rows into the engine's ephemeral db — identical code in both
  worlds, since that db is already connection-string-abstracted. At
  commit the engine emits globals as canonical sorted records,
  and the manifest CAS publishes them; the next run loads records back
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
- Engine and kernel working state is ephemeral SQLite by
  **caller-injected connection**: `:memory:` normally, on-disk temp
  where RAM is tight (iOS) or the input is huge (replay = the
  whole-history pile streamed in key order). Each kernel invocation
  gets its own tables — closed in/out, no shared state — which is what
  lets invocations run in parallel. Discarded after every run.
- A peer's persistent SQLite holds two separate schemas: the sqlite
  ObjectStore driver (canonical layout) and the app read model (API
  queries), rebuilt by replay when its generation trails.
  **Projectors consume kernel-valid facts only** — no validity logic,
  no scope checks; they accept a `Valid<Fact>` type only the kernel
  can construct, so the split is compile-time, not discipline. One
  read model spans all workspaces, rows tagged with the workspace id —
  safe because every fact entered through its own store's anchor'd
  kernel — so cross-workspace queries (a unified inbox) are ordinary
  read-side joins over certified provenance. The safety asymmetry is
  the design: the kernel is small and frozen (its mistakes are
  forever); projectors are big and evolvable (their mistakes replay
  away).

## Deployments

| | store | serving | engine | initiates |
|---|---|---|---|---|
| cloud node | s3 | presigned (store is server) | Lambda on poke | never |
| peer | sqlite | daemon | on request | cadence + news |
| home server | sqlite or s3 | daemon | on request | never |
| static mirror | any HTTPS host | files | no | never |
| iOS NSE | fs pile in app group | no | validate-only; hands off to app | never |

## Staged Plan

Proofs first; no transport work until both numbers exist.

1. **Core** — leaf run + fence runs, deterministic cut, codec; trait with
   mem + sqlite drivers; manifest CAS. Property test: same set ⇒
   same layout — pages, fences, and tail.
2. **P1 bench** — divergence sweep, measure rounds/bytes vs O(d · log n).
3. **P2 bench** — messaging-shaped synthetic pile; engine vs sqlite store,
   then vs real S3 from a warm Lambda; pin facts/s and $/M; pick page size.
4. **P3 bench** — annex build at promotion + closure walk; measure
   annex duplication vs the aug fallback on a real corpus (the
   bake-off); sweep window sizes.
5. **Protocol** — daemon (seven routes) + the one HTTP client with grant
   decorators + s3 driver/presigned flow; conformance suite green against
   daemon and S3+Lambda.
6. **iroh** — h3-over-iroh connector; same conformance suite.
7. **Auth** — request-fact families + evaluate mode, globals,
   invite blob, eviction test, mint over both transports.

## Open Questions

- Deletion: POC-13's suppress-if relation + death key is the direction —
  the one feature that needs set-level verdicts. Tombstones weaken the
  count heuristic; content confidentiality via key destruction (POC-14);
  the reconciliation-visible shape of a delete is undesigned.
- (Dead weight: resolved 2026-07-22 — piles go straight to dep-pure
  validation, so facts that never validate never enter the set.)
- Page cut: needs a precise deterministic definition that keeps small diffs
  ⇒ few changed pages, and it must be **split-monotone** — boundaries
  refine, never move — because the aug fallback's level ladder is built
  from the same rule family (the priority-threshold candidate
  qualifies).
- Multi-group on one bucket; blob attachments (`blob/<hash>`, POC-13 branch
  findings, hash-list slices not bao). (Bulk-join body bundles: resolved
  2026-07-22 by packed pages — bodies live in the page objects, MODEL.md.)
