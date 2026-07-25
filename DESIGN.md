# Passive-Store Reconciliation — POC-16 Design

Design of record. The Engine, Versioning, Auth, Node State, and Concurrency
sections mark landed behavior versus remaining beads; where earlier
System/Store/Walk prose
still describes the pre-S1 flat manifest, those sections are historical
motivation and the later foldback takes precedence. [SIMPLIFY.md](docs/SIMPLIFY.md)
maps the landed core. Unreplaced numbers remain
estimates until `bench/`
supersedes them; [MODEL.md](docs/MODEL.md) carries the performance model and loop
math.

POC-16 asks one question: **can range-based set reconciliation run against a
counterpart that executes almost no code?** The counterpart is a dumb object
store (S3, a peer's disk behind seven HTTP routes, a static file host)
holding a materialized summary of the validated set. The active side does
the whole reconciliation itself by fetching immutable pages — the only code
left on the passive side is the auth fence checking grants at the door
(one exception: invite blobs are public reads — unguessable ids,
encrypted under a secret in the link). If
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
fence runs, topped by one CAS'd manifest — same set, same bytes, everywhere
within a release and a layout configuration (§Versioning). Diffing is
fence-fingerprint comparison plus ranged GETs:
O(d·log n), ~4 rounds, against a counterpart that executes almost no
code.

**The unit.** *Every fetchable unit is a closed pile* — a topo-sorted,
closed set of facts, full stop: ingress pile, leaf pile, tail pile,
request payload, invite blob — one codec, serialized in canonical-topo
order (the closure walk's completion order), carrying its full closure
down to genesis. A leaf is `close` of its in-range leaves; the size
limit counts only those, and the closure the pile drags in rides along,
uncounted. There is no separate "annex" object: because the pile is
topo-sorted, every dependency precedes its dependent, so no dep is ever
copied to fix ordering — the only duplication across piles is the
genuinely shared closure (auth/membership), which is bounded and
amortizes as the leaf grows.

**The kernel.** One judge for content, auth, and access:
`kernel(stream, anchor, [globals]) → (valid, new globals)`. One
streaming invariant — every need matches an offer already emitted
behind the cursor, or the unit rejects — then per-fact integrity and
the family handler, workspace scope via the anchor (genesis fid;
workspace id = `H(genesis)`). Zero store reads; caller-injected SQLite
working state; parallel invocations. Validity is forever and
globals-blind; among validators only ephemeral request facts read globals (the
monotone removal set — removal is connection-level, mutual removals both land).

**The engine.** Semantics-free: hash-verify, kernel, merge by key into
the tail, promote by the cut rule into write-once leaf piles,
union globals, one CAS, delete piles. Runs only on request; the lease is the *optional*
linearizable path — non-serialized by default (§Concurrency & FaaS). Access is a handshake: the requester sends a small closed
pile — a request fact plus its auth closure — and the mint, a pure
function, runs the same kernel over it and returns a grant encrypted
to the author's key. Invites are the one ungated read — **public**
blobs at unguessable ids (LIST denied), encrypted under a secret
carried in the link: a link is a URL plus a 32-byte seed.

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
(docs/MODEL.md).

**P2 — efficient engine.** *Drain* takes `(raw piles, valid set)` to
`(valid set′)` on request — hash-verify each pile, run
`kernel(pile) → (valid, new globals)`, a pure predicate over fully
closed piles with **zero store reads**, then k-way-merge the canonical
runs into the treap's tail range; *promotion* (the cut rule freezing a
full tail into immutable leaf piles, each closed by the Closure Walk)
rides the same commit. Litmus: ≥ 300 facts/s validated in a warm 1 GB
Lambda against real S3; thousands/s per core locally — independent
piles validate in parallel.

**P3 — closure-complete range sync.** `closure_sync(Q)` returns any
`(ts, fid)` range Q *plus every recursive dependency of every fact in
it*, in the walk's own shape. Litmus: ≤ D + 2 rounds (+1 per
out-of-window frontier hop); ref + fence overhead ≤ 10% of context body
bytes; identical sets ⇒ identical leaf-pile bytes; a cold 3-day partial join
at 10^6 ≈ 4 rounds / ~18 MB, projectable on arrival (docs/MODEL.md, Closure).

Everything else is scaffolding around these three.

## The Store

**Facts.** A fact is a type tag, a ts, and a canonical set of
**atoms** that adopt both (POC-13's atom model); `fid` hashes that
canonical form. Atoms carry the fact's needs, offers, and dep refs in
the **clear envelope**; encrypted values ride the body — **matching
reads addresses, never values** — so dep topology and the offer
vocabulary are store-visible while content never is, and the engine
derives each leaf's closure from envelopes plus the owning family's
handler (§Versioning — a need's canonical provider is handler output,
so the closure is not store-visible the way a ref is). Signatures are not envelope
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
lose a skewed dep, because the leaf pile delivers context by closure, not
by window.

**Treap.** The canonical structure is a treap keyed `(ts, fid)`, priority
from the fid hash — history-independent, so the same set gives the same
shape and fingerprints on every node, and the same pages within one release and
layout configuration (§Versioning). That is what makes one-sided
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
fresh join is ~2.2 k GETs, bandwidth-bound — docs/MODEL.md), and the walk
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
sink the design. Run depth is 2–3 (docs/MODEL.md).

**Manifest.** The **only** mutable object besides the piles: generation,
the inlined top fence runs (history + tail fences), removal set. Changes only by CAS (S3 conditional PUT / SQLite transaction / atomic
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
that sank with a bad batch comes back on the sender's next walk. One
exception, and it is versioning's: a pile carrying a version this node
does not implement is *unreadable*, not invalid — retained, unblamed,
retried after upgrade under a bounded cap (§Versioning).
Byte-level layout never composes across concurrent piles — the engine
re-cuts, because **recomputation is the verification** — but
record-level merge does, associatively: history-independence makes any
arrival grouping converge to identical bytes. Nothing parks except across a
version boundary; every other drain empties the pile.

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
— is a pure function of the set given the layout configuration
(docs/MODEL.md, Stragglers).

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
per fence, compare fingerprint over its in-range leaves:
  equal fp -> prune
  else     -> GET the leaf pile (one immutable object, a closed set on arrival)
              PULL it into own ingress if it holds in-range leaves we lack
              PUSH reactively: close() our in-range leaves it lacks into one
                 pile, PUT it — the mirror of the pull; responder drains on receipt
```

**Decide with hashes, converge with piles.** A fence's fingerprint is over its
in-range leaves; an equal fingerprint prunes the range. For a differing range
the fetch unit is the whole leaf pile — one immutable, content-addressed
object, judgeable the moment it lands. Descent is **read planning, not
negotiation**: the responder is passive, counts ride every fence, and the
inline top run means a cold or far-behind client decides *in round one* which
leaves to take — bootstrap collapses to root → one fence-run read → parallel
leaf fetches, streaming through the kernel as they arrive.

**Whole-leaf fetch; intra-leaf slicing deferred.** The unit is the whole leaf,
so a range differing by one fact still pulls the whole leaf. Content addressing
buys immutability, fid-dedup, and CDN/static-mirror serving for free; the cost
is over-fetch on diffs scattered into big cold leaves — the uncommon shape,
since divergence clusters in the recent tail. It is reversible with no
structural change: sub-fingerprints in the fence plus a `Range` GET *within* the
same immutable leaf object reintroduce byte-minimal slicing as a pure
optimization, if a profile ever demands it.

**Push is reactive — the mirror of the pull.** For each differing range where
we hold in-range leaves the responder lacks, we `close()` them into one pile and
PUT it: no collect-at-end, no assembly step to reason about. Each range's pile
re-embeds its shared closure, which the receiver dedups by fid, so the cost is
bounded transferred bytes, never correctness — and in the common case (ahead
only in the recent tail) it is a single pile anyway. Ideally the push copies the
pusher's own already-built leaves verbatim, so over-pushing is just copying
bytes it holds. The responder **drains on receipt** — a pushed pile lands in its
ingress and the same PUT handler turns it into the treap — so a peer push needs
no poke. (The presigned-cloud path, whose write goes straight to S3 with no
handler to hook, keeps the explicit poke; the mint never drains, so it is not an
alternative to it.)

The walk computes the *symmetric* difference, so **one dial converges both
sides; the responder runs zero sync logic.** Eager delivery still exists — put
your own new facts into a known peer's ingress at write time — and the walk is
the anti-entropy backstop (the Dynamo split). Ending a write with a walk is a
latency nicety, not a correctness rule: validation never blocks on deps, so a
lone PUT cannot wedge — it just delivers the fact's closure promptly for the
consumers' validators, and costs one conditional GET when already in sync.

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

**The leaf pile is its own closure.** Diffing and closing live at different
granularities: fingerprints stay over the in-range leaves (P1 untouched), while
closedness is a property of the *fetch unit*. Each leaf is `close` of its
in-range leaves — those leaves plus `closure ∖ in-range`, topo-sorted
(deps-first) into one content-addressed object — so the leaf is a fully closed
set, judgeable by the same kernel predicate as any pile. **Nothing is copied to
fix ordering**: topo-sort places every dependency before its dependent, so the
old "annex" of in-range skew-inversion copies is gone by construction; the only
facts a leaf carries beyond its in-range leaves are the genuinely out-of-range
**shared closure** (auth/membership). That closure is a pure set function within
a release (identical sets ⇒ identical bytes; provider selection is release-scoped
— §Versioning), built **by aggregation, never by search**:
piles arrive fully closed, so every copy a leaf needs came in with some pile; at
promotion each ref *and each handler-resolved need provider* is classified in
one pass (in-range, else shared closure).
Fat leaves swallow the common context; hot hubs (genesis, certs) cost one copy
per leaf, amortized away as leaves grow. Storage pays the duplication; nobody
chases a graph.

**Sizing is by content; the closure rides free.** The size limit counts only
the in-range leaves — the closure a leaf drags in is attached, not counted. So a
leaf's size is a principled *content* choice (bytes, or the cold-tier scheme
below), and the duplication it incurs is whatever the shared closure happens to
be: bounded, because it saturates at the active membership, and amortized as the
leaf grows. Measured on a messaging corpus, catchup duplication falls **3.3× →
~1.4×** as history seals into ~1 MB cold leaves, and toward **~1.0×** once the
topo-sort removes the skew copies and leaves clear the membership closure.

**Write path.** Between promotions the tail carries its own closure, aggregated
from each valid pile. At promotion the engine classifies refs with everything in
hand and each new leaf `close`s its in-range leaves. **Promoted leaves are
write-once**: deps point backward, so a leaf's closure is fixed by its immutable
in-range contents the moment it freezes — no reverse index, no count
maintenance, nothing to touch when later facts arrive. The only reopen is a
straggler's mini-fold, which recomputes that one leaf. The shared-closure copies
sit **outside the fingerprinted set** — the treap reconciles in-range leaves
only, so copies never perturb the walk's diff algebra.

**Every fetchable unit is a closed pile.** Ingress pile, leaf pile, tail pile,
request payload, invite blob — one codec, one predicate, one streaming
invariant: every ref resolves behind the cursor, satisfied by canonical-topo
serialization. So sync is a stream of independently judgeable units: a consumer
kernels and projects each leaf as it lands, in any order, parallel across
cores — fetch ts-descending and a fresh join's inbox is usable in seconds while
history backfills behind it. Shared-closure copies re-arriving across leaves
cost no re-verification: verdicts are immutable, so a consumer's fid-keyed
verdict cache is append-only and each hub verifies once per device lifetime.

```text
closure_sync(Q):                        # Q snapped to leaf cuts
  root + fence slices over Q            # rounds 1–2, as P1
  the leaf piles covering Q             # round 3 — each pile carries its closure
  spilled bodies via blob/              # round 4
```

`R_cl = D + 2` — 4 rounds at 10^6, no escape hops, no workload
assumption: the leaf pile *is* the context. A cold partial join stays
~4 rounds and tens of MB — the context's own bodies are the floor no
protocol beats — and every fact projects on arrival (docs/MODEL.md,
Closure).

## The Engine (P2)

The landed core has **one pure tree engine, one kernel forward pass, and one
workspace mutator**. `shape.py` owns key, cut, priority, and fingerprint
policy. `tree.py` owns `View` plus `build`, `fold`, `diff`, `merge`, and
verification, parameterized by physical `Packing`. Binary treap and flat
manifest packings remain golden compatibility fixtures; production uses
shallow content-defined fat nodes. The engine takes `fetch(oid)` and
`emit(bytes) -> oid` callbacks and knows nothing about files, HTTP, S3, or R2.
Within a packing, a release, a set, and a tree-format configuration determine
byte-identical nodes (§Versioning: the fingerprint is version-free, the oid is
not); `fold(view, delta)` path-copies changed branches and is byte-identical
to a full build of the union. The root is `Root(view, anchor, globals_)`, so
anchor and canonical global rows ride the tree rather than a separate flat
manifest. This absorbs the old `treap.py` / `layout.py` algorithms and the
fat-node and two-root-fold work (`jbg.1` / `jbg.4`) into one implementation.
Two-root merge keeps the pruned path-copy fast path for facts whose dependency
edges cannot change. A delta that offers an address or declares a need can
change the canonical provider graph of either side; without a provider summary
the safe implementation loads the union, recomputes proof ranks, and stages a
full byte-identical rebuild. `jbg.3` owns amortizing that fallback for
append-only root sets without weakening convergence.

Production fat trees also absorb the multi-level pile. Every fact is serialized
once in a content-addressed payload at `settle(f)`, the deepest node covering
its own key and every dependent key. A root-to-node payload union is closed;
a full preorder contains each fact exactly once. Structural node `oid` commits
its payload hash and child summaries, while `fp` covers only in-range keys, so
closure placement never enters the diff algebra. Full sync and rebuild consume
one closed preorder (`ρ → 1`); range sync fetches a deduplicated union of the
selected paths and pays the measured shared-core tax once. Stable span bounds
let `fold` rehome only the new batch's rising dependencies plus nodes whose
physical interval split, preserving path-copy incrementality and exact
full-build identity.

The public kernel verbs — `validate`, `drain`, and `evaluate` — share one
internal judge loop. `validate` returns a boolean; `drain` additionally returns
kernel-minted `Valid` values and monotone global rows; `evaluate` applies
optional ephemeral-family gates and again returns only a boolean. Tree-path
verification uses that same judge through `kernel.Scratchpad`, whose push/pop
context absorbed the copy formerly in `hoist.py`. The **anchor** is the
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
cores) are the caller's too. Replay then costs nothing new to design: a full
replay is the tree's closed preorder and a windowed replay is one closed path
union, both streamed through the same judge. Persistent proof ranks are retained for every offer source and
explicit-ref target, keeping canonical dependency choice stable across
incremental admission and index rebuild.

```text
turn(workspace):                         # the only workspace mutator
  LIST + decode ingress piles
  drain each pile independently, in parallel
  merge durable Valid facts, offers, proofs, globals, and +/− log rows
  PUT immutable blobs and tree.fold/build output
  CAS root                               # the publication point
  pump projection log + cursor atomically
  delete ingress piles
```

**Publish, CAS, pump, retire** is the crash discipline. Immutable objects land
before the root CAS; ingress survives until after it. The idx transaction is
deliberately stamped “ahead of root” while a turn is in flight. A failure
before publication discards and rebuilds that derived state from the old root
and leaves the retained pile retryable. A failure after publication rebuilds or
resumes from the new root and projection cursor. No unpublished fact, proof,
global, or read-model row is observable after the workspace lock is released.

Peer triggers are request-driven: ingress PUT drains on receipt and root GET
drains before serving. Mint runs in evaluate mode and never drains. The
stateless cloud trigger and coordination-free root publication are deployment
policy in §Concurrency & FaaS; the pure tree and kernel do not assume a lease
or a particular driver.

Store-side auth state is one object family: **globals** — monotone
semilattice projections the kernel itself emits, published as
canonical sorted records riding the root, rewritten in the commit
that changes them. Today globals is the **removal set**: the union of
targets of valid eviction facts, extracted per pile by the kernel —
order-free, because per-pile extraction composes as union. Eviction
validity is removal-blind (valid iff the author's chain shows admin),
so **mutual removals remove each other** — monotone, no ordering
question to answer; "non-removal" is enforced at the connection, never
in fact validity. Among validators, globals are read **only by ephemeral-family
handlers**: a persistent-family handler that consulted them would make
verdicts time-dependent and collapse order-independence. (Outside validity
entirely, the authoring floor reads them too — §Versioning.) Fact validity
is forever; removal only closes doors.

Single-target deletion is a separate post-validity layer:

```text
V(D) = kernel-valid facts
S(D) = explicit non-deletion targets of valid deletion facts
E(D) = V(D) ∖ S(D)
```

Live projection folds `+fid` and `−target` in delivery order; a clean rebuild
computes `S` first and folds canonical `E`, firing no retractions. Both yield
the same logical app state for every pile partition, delivery order, and turn
batching. Global 1:N matching, its synced `T_supp`, and suppression closure
remain the `poc-16-yez` work; they extend this seam without making the kernel
or family materializers read `S`.

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
pull, closures always in hand — but nothing parks anywhere except across a
version boundary (§Versioning): piles are
closed by format, syncs arrive closed by P3. Anything needing negative
or global knowledge (uniqueness, latest-wins) stays a projection-time
verdict, deterministic from the set — never a validation input.

**Needs and offers.** The relationship grammar is exactly two. Clear-envelope
offer atoms publish named, scoped assertions; the consuming family declares
normalized needs beside its validator. Validation matches those needs against
offers already emitted by valid facts behind the cursor — the seen-set rule
generalized from "ref resolves" to "need met" — and an unmet need rejects the
unit.
**Parking is deleted from the grammar**: POC-13's Require parked on
zero matches; closed units mean the closer either shipped the
providers or authored a broken pile. Pinned dep refs and needs
compose: refs say *where* (exact `(ts, fid)` providers, keeping
each leaf's closure deterministic), needs say *what* (the assertion
the provider must offer). Offers are the **version interlingua** —
the reason the model earns its weight: facts of different versions in
one pile never read each other's schemas. §Versioning owns the seam
that makes offers handler output rather than envelope atoms, and today
they are still the atoms.

**Signature is a fact type that offers.** The kernel's built-in
judgment shrinks to integrity — `fid` = hash of canonical bytes,
grammar, the streaming match — and everything semantic, crypto
included, is family handlers: a signature fact verifies its Ed25519
once and offers authorship; certs offer membership; content facts
need both. Heavier — authorization becomes facts beside the content —
but piles make it cheap: signature facts ride the same units, dedup
by fid, and verify once into the offer table. Suppression markers are inert
clear-envelope indexes: they never enter the matching grammar or stable
validity and are interpreted only by the post-validity suppression layer.

### Fact-family boundary

The POC-13 core/facts split still applies, but a POC-16 family no longer
returns a mixed projection verdict. Core files stay at package root and route
into `facts/auth/` and `facts/content/`; there is no connection scope because
the transport is not modeled as durable facts. One `somefact.py` owns these
parts, in order:

1. **SHAPE** — exact canonical constructors and the family's atom vocabulary.
2. **NEEDS** — normalized offer addresses, combined by core with envelope refs.
3. **VALIDATE** — `validate(fact, context) → bool`, where context is only the
   already-valid in-pile prefix and the fixed workspace anchor. No waiting,
   node, projection database, clock, mode, or globals enter this function.
4. **MODE** — durable versus ephemeral, immutable object references, drain-only
   monotone global rows, and (only for an ephemeral family) an optional
   `evaluate(fact, globals) → bool` gate. Thus removal validity is timeless;
   its global row is emitted in drain mode and consumed by request facts only
   in evaluate mode.
5. **MATERIALIZE** — insert-only projection of a kernel-minted `Valid<Fact>`
   into source-keyed raw rows, with no repeated validity or suppression policy.
   Every family declares its `TABLES`; aggregate-shaped results are views, and
   the generic pump retracts a source across that inventory.
6. **COMMANDS** — local authoring and ingress. Workspace creation/acceptance
   also records the trusted anchor in the keyring: that local trust choice
   cannot be derived from the store it is about to check.
7. **QUERIES** — observations over materialized rows.

The root command module may remain a stable façade over family commands. The
kernel supplies three explicit views of the same forward pass: validation is
boolean-only, drain additionally returns valid facts plus new global rows, and
evaluate applies ephemeral global gates but is again boolean-only. Every input
is already canonical-topological, so none of these paths sorts.

**Removal is terminal and monotonic at the connection level**: eviction
kills the mint — no grants, so no reads and no writes — and it is the
*pusher's* liveness transport checks, never the author's. Facts that
made it into any treap before the door shut stay visible everywhere; a
compromised key's leakage window is its grant expiry. No fact-level
death — no seq cutoffs, no fork verdicts (seq left the leaf record with
its last consumer). Deletion is the distinct content-suppression path:
single-target retraction is landed, while global 1:N matching and closure are
tracked by `poc-16-yez`.

Performance: piles are fully closed, so validation does **zero store
reads** — the drain is transfer- and verify-bound: GET 10–30 ms, ~100
in flight ⇒ 3–5k GET/s; Ed25519 ~50–100 µs, parallel across cores;
~2,400+ facts/s vs S3 (docs/MODEL.md), ≥ 8× the litmus. Memory beats lookups: Lambda RAM bills only while
executing (+1 GB ≈ $0.05/day at a 1-min/2-s cadence ≈ 120k GETs), the hot
set is tens of MB, and immutable pages mean the cache needs no invalidation
— a warm worker can reuse any content-addressed page it already fetched.

## Versioning

**Three things carry a version, and they live in different places.** The *fact*
version rides the type tag and is frozen into `fid` — the base store is
unversioned in the sense that matters, because atoms are forever: no fact is
rewritten, migrated, or re-signed. There is nowhere to add a version *field*
either, since every family validates by reconstructing the fact from its own
constructor and comparing, so one new byte would have to thread through all
fifteen of them; the tag is the version, and it is already inside `fid`. The
*layout* version is a config string published in the root
(`1:kind:fanout:CUT`) and enforced there — a fold refuses a mismatched config,
a two-root merge refuses a cross-config join. The *derived-state* version
stamps what a node materializes — offers, proof ranks, globals, the projection
log, read models — node-local and rebuildable, except for the globals it
publishes in the root. Underneath all three sits one version-blind discipline:
keys and fingerprints read only `ts` and the fid's own hash, priorities and cuts
only the fid's. **The fingerprint is version-free; the oid is not** — that
single split governs everything below.

**A family tolerates every version of its own type, and no version of anyone
else's.** The tag names family and version; each version keeps its own handler;
a new version is a new handler, never a migration. This is the one place the POC
keeps compatibility on purpose, and the boundary is worth drawing precisely:
everywhere else it keeps none — no read-compat shims, no dual decoders, no state
migrations, because there is no installed base and breaking the format costs
less than the legibility a shim spends. Fact-family versioning is not an
exception grudgingly made; it is the mechanism under test, so the POC should
show it working. `legacy_genesis`, `legacy_signature`, `legacy_invite`, and
`legacy_join` already do — old tags judgeable beside `workspace`, `signature`,
`user_invite`, and `user`, authoring nothing, `legacy_invite` still enforcing its
own admin-only rule while `user_invite` admits any member. That is two versions
of one family disagreeing about semantics and both staying valid, which is
exactly what this section claims is possible. Attachments then did it again
under load: new descriptors author the versioned `file_bao` tag while the old
`file` handler stays read-only, so whole-blob workspaces survive the cutover to
Bao chunking. Three instances now, none of them planned by this section — which
is the argument for naming the pattern. The rule is affordable because the
obligation is local: N versions of my own type, borne by the family that owns them. N versions
× M families is the product no release can ship, and buying it out is what the
interlingua is for. So a release carries one version constant and no matrix of
releases; compatibility with old retained facts lives in the owning family, and
everything that family writes is current-version (POC-10's rule, kept verbatim).

**Offers are that interlingua, so a fact's emitted offers are not the offer
atoms in its body.** The atoms record what the author asserted, in the
vocabulary of the release that authored it — immutable, store-visible in the
clear envelope, and still exactly what the family's own validator reconstructs.
The offer table records what *this* release makes of that assertion, normalized
to the current vocabulary. Today the two are the same thing — the kernel admits
the envelope atoms verbatim and no family has an offer hook — so the interlingua
is asserted rather than built. Versioning is the change that separates them:
offers become the output of a per-version **normalizer**, a pure function from
one supported source shape to one current semantic form, of which today's
behavior is the identity case. **Needs are normalized the same way, or nothing
matches** — both sides of a match must speak one vocabulary, and a version that
relabelled its offers but not its needs would look up an address nothing answers
to. Needs already come from code, a handler function the running release
evaluates; offers come from stored bytes. Closing that gap, so both sides of a
match are normalizer output, is the whole of the change. The payoff is that no
consumer ever decodes a producer's old schema — it needs an address, and the
producer's own old normalizer is what puts a current-vocabulary offer there.

POC-17 works this out in detail and POC-16 should take its shape (its DESIGN.md,
Dotted variables and Provide). Three parts carry the weight. The vocabulary is a
**canonical dotted path** — `content.message.body` — built through one path
object that constructors, normalizers, validators, and queries all share, so a
source version that called the same concept `content.post.text` emits
`content.message.body` from its normalizer and no current code retains the old
name. Emission is **all-or-nothing**: a valid fact's normalized offers are
copied whole, the family never returning a subset, which is what makes the
normalizer the security boundary — it must recognize an exact supported source
shape and reject extra source offers rather than let a sender smuggle one into a
valid owner. And a source offer atom **is not itself a matching offer**; it is
input to that version's normalizer, so only the emitted row matches. That last
line is the seam stated exactly, and it is what licenses renaming a variable,
re-encoding a key or payload, splitting or combining fields, and mapping an old
tag into current semantics without touching one immutable byte.

Globals ride the same seam, being
handler output published in the root; their value space must stay stable
identities, keys and fids, which is what they already carry, because a
schema-shaped global would rewrite root bytes on every release.

**Validity is forever, so a release may not move it.** If a verdict were a
function of the reader's release as well as of the fact and its closure, two
replicas would disagree about membership permanently, fingerprints would differ
over facts both hold, and syncing could never close the gap — the one failure
this design cannot repair. So normalization is a *relabeling*: **meanings are
append-only** — a name, once spent, is never reused for a different assertion —
and an address is just this release's name for a meaning, applied to offers and
needs together, in one release, which is exactly why matching is invariant under
it. A release that genuinely changes a meaning mints a new one and leaves the
old alone. The cost is worth stating plainly: a retained version's validity rule
is frozen forever, but its *vocabulary tail* moves with each release, so a
retained fact's emitted offers are a function of the reader's build. Tier 1 is
therefore a discipline rather than a structural guarantee, and it is enforced by
a test rather than by a type — replay a golden corpus under release N and
release N+1, and the valid set must be identical. It is also not true yet: until
an unimplemented version resolves to *unreadable* below it resolves to
*invalid*, so today a behind-version node already judges facts invalid that an
ahead-version node judges valid, and the reader's release already moves the set.

**The arrangement may move, and the skew is nearly invisible.** Which provider
is canonical for a need decides a leaf's closure, hence its pile bytes, hence
its oid — so a release that changes provider selection republishes rather than
memoizing old fences. Re-selection cannot reach validity: a provider is chosen
only from offers already emitted behind the cursor, so a different canonical
pick is still a behind-cursor pick, the streaming invariant holds under any
release's selection, and readers still never sort. Only the recorded closure
edge moves, and with it the bytes. Fingerprints cover in-range keys only, so the
walk prunes on the same identities and both sides converge on the same set —
which is also the hazard: two peers on different releases holding identical
facts produce identical fingerprints and different roots, the walk reports
convergence, and no *release* version rides the seven verbs, the grant, or the
root to notice by (the root's format marker is written and never read; its
config string pins layout, not release). One place the skew is not inert: the
mint compares a need against the *committed* canonical winner (§Auth), so a
release that re-ranks providers can change a grant decision over an unchanged
set. Grants are ephemeral, so the set is safe — but a deployment must upgrade
before its clients, and a mint and the drain that wrote its root must be the
same release. Byte-identity is a claim *within* a release and a layout
configuration, never across them.

**Activation is an authoring policy; validity never reads it.** POC-10's release
rule survives — do not author a new durable type until every non-deprecated
release can decode, authenticate, validate, and project it — but not its
mechanism: a ceiling computed from a signed release manifest and trusted time is
ambient mutable state, and a validator reading it would make verdicts
time-dependent, the same argument that keeps globals out of persistent handlers.
So a fact authored at version v is valid at version v forever, however and
whenever it arrives. Devices advertise the versions they implement as ordinary
facts, and the authoring floor is the minimum over non-removed members — a
commands-path read, never a validator's. A client that jumps the gun harms
nobody's correctness; it only strands its own facts at peers that cannot yet
read them. The two auth edges need a different floor, having no membership to
take a minimum over: the mint must distinguish *cannot read* from *not entitled*
and say which, since its path retains nothing to retry from; and the invite blob
is authored at the oldest release the deployment still supports, its reader
being a joiner who is not yet a member, its read public and unauthenticated, its
redemption one-shot.

**Meeting a version you do not implement is a verdict about the node, not the
fact.** The two outcomes have to be opposite: an invalid pile is dropped and
charged to its pusher, while an unreadable one is dropped and charged to nobody.
POC-10 said it as "core does not store future-version incoming facts as protocol
truth — incoming is volatile intake", and POC-17 keeps the rule while sharpening
the disposal: bytes become durable only once the current release can decode,
normalize, and project them, so an unreadable version stays *outside* the store
rather than parked inside it. Nothing is retained, which is what keeps an
unknown tag — free to fabricate, needing no key, no chain, no closure — from
becoming pinned storage in a grant-holder's prefix. So this is a third kernel
outcome beside valid and invalid, entering the set never, destroying nothing,
attributing nothing, and costing nothing to hold. Both halves are work,
because today an
unknown tag resolves to no handler and the unit rejects whole — taking down
every fact in it the reader does understand — while ingress is retired
unconditionally after the CAS with nothing counted against anyone either way.
The range then never converges, and the leaf comes back once per root change on
either side and once per process restart: an unbounded refetch rather than a
tight loop, which is why it has gone unnoticed. With the third outcome the same
situation is a clean fail-stop — piles are all-or-nothing, so a behind-version
client stops at the version boundary rather than serving a partial truth, and
nothing is lost, since the peer still holds the range and the fingerprints still
differ. The whole change is therefore bookkeeping rather than storage: stop
charging the pusher, and mark the range stalled so the walk stops rediscovering
it. Deployments whose engine is the vendor's
own — cloud node, home server — upgrade first and never meet any of it.

**An upgrade is one replay.** A stored stamp that does not match the running
release means every derived artifact is suspect; rebuild streams the store's own
leaf piles back through the same kernel, re-emitting offers, proofs, globals,
the projection log, and the read models under the new handlers. No fact is
rewritten — the piles around them are re-emitted at new oids when the
arrangement moves, which is that bump's whole cost. The mechanism is landed, a
semantic index stamp re-running the kernel and republishing while an app schema
stamp replaces the read models, but they are two hand-maintained constants that
have never moved together and are tied neither to each other nor to a release,
and there is no release version in the tree at all. Making one constant drive
both is the versioning work. Two properties come with it, from POC-17: the
rebuild runs in **bounded, resumable transactions** rather than one pass with
the set resident, since the host may be an NSE with a database larger than its
memory budget; and until it reaches quiescence, completeness-sensitive queries
**fail closed** rather than answering from a half-rebuilt view. Cost is the
catchup path, so it is priced by it —
~1.1k facts/s under the shipped monotone cut, against a raw judge ceiling near
9k (bench/RESULTS.md) — and it is the same code as a fresh join. What replay
cannot fix is retiring a version. The suppression-marker cutover is the case in
hand: the marker is a shape requirement of the new content version, so old
markerless facts stay valid at their own version, and the break comes only when
that version stops being judgeable at all. That is a flag day, not a version,
and the only honest support for it is to spend it early.

## Auth

One evaluator, everywhere: **the kernel judges content, auth, and access
alike**. `request.payload` authors one ephemeral request and closes it over its
signature and current membership proof. The resulting bytes use the same
canonical pile codec as ingress, sync leaves, and invites. Conceptually,
`mint = evaluate ∘ close({request})`: the caller closes once; the mint only
decodes and evaluates.

**Request facts are an ephemeral family.** The auth payload on any verb
is a fact — authored by the requesting device key, deps on the auth
facts that entitle it, body carrying public key, verb, and loose expiry —
evaluated in evaluate mode, never persisted. Ephemerality is structural,
for three reasons: the set must not grow with reads; mints must not
churn fingerprints into phantom walk diffs; and read patterns must not
become replicated data. A request family has no persistence semantics, so a
stray request fact in a pile is litter and the drain deletes it. For a
request fact, acceptance is the grant.

**The mint is a pure function.** `mint.mint` decodes the pile, requires exactly
one `DURABLE=False` fact, obtains the candidate `(public key, verb)` through the
family’s `grant` hook, and calls `kernel.evaluate` with the root's anchor and
globals plus the supplied current time. A peer also supplies its root-stamped
canonical offer/proof index: evaluation compares each already-known need with
the committed winner, so a stale closure cannot omit an incompatible authority
conflict and revive a quarantined chain. The request family owns tag, verb,
expiry, removal, and removed-issuer policy; the daemon parses no fact body.
Failure returns no grant. Success returns the family grant for
`Handler.mint` to seal to the requester's public key and pair with the current
root bytes and ETag. Evaluation drains nothing, writes nothing, and never reads
`app.db`; its canonical authority view is a read-only input. A peer may first
rebuild that derived view if its root stamp is stale. Replay only produces
ciphertext for the same requester. The landed peer holds its workspace lock,
synchronizes the index stamp to the current root, then snapshots root plus
canonical idx for evaluation. A stateless deployment
reconstructs that view with `mint.Authority.from_root`, which accepts only
known durable facts and requires root globals to exactly equal the rows derived
by draining them; `mint.stateless` reuses it only while its root ETag matches.

The cloud target returns presigned URLs; the landed peer daemon returns a
bearer token. To the client either is an opaque request decorator, the only
per-backend seam. Auth hands the walk its root at the same time, putting the
session one round trip ahead.
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
  is dumb pipes only — no iroh-docs/blobs/gossip; Bao is confined to attachment
  verification — and pre-1.0, so the connector module is its containment
  boundary.

Every node = a **responder half** (seven verbs over its store, zero sync
logic) + optional **initiator half** (per-workspace walk on cadence,
round-robin from the keyring + eager push). Roles
are per-session, fixed by dial direction. Any peer may dial — news-driven
sends stay fast, and the pair gets the better of the two cadences.
Simultaneous opens: lower node id survives. Always-on public nodes never
initiate.

## Node State and SQLite

The store is the sole source of truth. Every SQLite is a derived projection;
the publication point is the root CAS. A peer keeps two databases with
different jobs, and either can be deleted and rebuilt.

- **`idx.db` is the root-stamped engine projection.** It contains accepted
  fact bytes, offers, persistent proof ranks, monotone globals, metadata, and
  the append-only projection log. A semantic index-version change or a root
  ETag mismatch rebuilds it by streaming the root's one-copy closed preorder
  through `drain`. The index is intentionally marked dirty before publication, so an
  interrupted pre-CAS turn cannot masquerade as current state.
- Engine and kernel working state is ephemeral SQLite by
  **caller-injected connection**: `:memory:` normally, on-disk temp
  where RAM is tight (iOS) or the input is huge (replay = the
  whole-history pile streamed in key order). Each kernel invocation
  gets its own tables — closed in/out, no shared state — which is what
  lets invocations run in parallel. Discarded after every run.
- **`app.db` is a cursored fold of `idx.log`.** The generic `projected`
  ledger records `(workspace, source fid, family, rank)`; family tables retain
  insert-only source-keyed candidates, and views select aggregate winners.
  Applying rows and advancing `(workspace, projector)` share one transaction,
  so a crash is either invisible or resumes at the next sequence. A missing
  cursor or reproject marker clears that workspace and folds canonical `E`
  from scratch; an app schema-version change replaces the database and does
  that for every workspace.
- **Projectors consume kernel-valid facts only.** They repeat no validity,
  scope, or suppression logic. Retraction is generic: find the source's
  family, then delete that source from every table in its declared `TABLES`.
  One app database spans workspaces, with every raw row workspace-tagged, so
  cross-workspace queries remain ordinary read-side joins over certified
  provenance. The kernel is small and frozen; projector mistakes replay away.

Root bytes carry tree view, anchor, and canonical globals, but not the expanded
offer/proof view. On rebuild and stateless mint, all committed facts must be
known durable families and a fresh drain must reproduce those globals exactly;
metadata is authenticated by derivation, not trusted merely because it rides
beside a valid Merkle view. A peer mint reads the offer/proof view from its
root-stamped `idx.db`; `app.db` is never involved. A Worker or Lambda builds the
equivalent root-stamped, read-only `:memory:` projection from the root/tree,
and may cache it by ETag. A cold or stale cache rebuilds before minting, so
warmth cannot change a verdict. The derived view's SQLite byte format is not
part of the protocol; cloud publication remains §Concurrency & FaaS work.

## Deployments

| | store | serving | engine | initiates |
|---|---|---|---|---|
| cloud node | s3 | presigned (store is server) | Lambda on poke | never |
| cloud node (CF) | R2 | Workers (store is server) | Worker on event/poke | never |
| peer | sqlite | daemon | on request | cadence + news |
| home server | sqlite or s3 | daemon | on request | never |
| static mirror | any HTTPS host | files | no | never |
| iOS NSE | fs pile in app group | no | validate-only; hands off to app | never |

## Concurrency & FaaS

**Deployment target:** many stateless workers — Lambda, **Cloudflare Workers**
— run the engine concurrently over one store, coordination-free. The landed
peer runtime's one CAS'd root is the linearized local path; append-only roots
and amortized merge remain `jbg.3`.

**It is a CRDT.** Piles and tree nodes are immutable and content-addressed:
concurrent PUTs are idempotent and commutative, and the arrangement is a
deterministic fold of the pile set. No operation is non-commutative (facts
additive, tombstones remove-wins, fold deterministic), so roots form a
join-semilattice and `merge(A,B) = root(A∪B)`. For roots already validated at
publication, the join is O(diff) when the delta cannot rewire a declared need.
Before any shortcut, untrusted roots must reproduce the byte-identical
canonical settle placement derived from their facts; validating only the full
fact set is insufficient because a malformed partial path may not be closed.
Provider-bearing or provider-consuming deltas currently take the
correctness-first canonical rebuild described in the Engine section.
Convergence is **Strong Eventual Consistency** — same observed set *at one
release and one layout configuration* (§Versioning) ⇒
bit-identical root (one hash compare), no conflict resolution, self-healing.
The only mutable cell is a 32-byte root hash per workspace, itself optional
(state ≡ ⊔ of all published roots). This is the Merkle Search Tree
(Auvolat–Taïani 2019) / prolly-tree (Noms → Dolt) line reconciled by RBSR
(Meyer 2023); full treatment in docs/WORKSPACES.md §9.

**Root without a lease.** Publish roots into an append-only `roots/` set; truth
is `merge(live roots)`, never clobbered. Every fold and every authoritative
read merges what it sees and republishes — anti-entropy amortized into traffic;
concurrent merges are deterministic, so they produce the same hash and dedup (no
storm), so no dedicated sweeper is needed beyond a cold-workspace cron. That
determinism is release-scoped too: merge short-circuits on equal fingerprint and
count by returning its own side, so under release skew `merge(A,B)` and
`merge(B,A)` disagree and rival roots republish forever. A cross-release merge
must refuse the way a cross-config merge already does, rather than silently pick.
CAS on a
single `root` (S3 `If-Match`, R2 `onlyIf`) or blind-LWW+sweep are lease-free
variants. A per-workspace lease/DO returns only as an opt-in for
instant-authoritative reads or to damp folding on a hot workspace.

**Fat nodes, no manifest.** Nodes carry each child's `(hash, fingerprint)` at
B-tree fanout — self-describing and shallow (~2–3 levels), so the flat manifest
is dropped. Full catch-up walks the fat root in ~2–3 parallel round-trip waves,
then bandwidth-bound page transfer; only fat fanout makes this cheap (binary ⇒
~log₂n waves ⇒ keep a manifest). Precomputed fingerprints in the immutable nodes
are what let a **dumb store** answer a reader-driven pruned walk with only GETs
(git "dumb HTTP" over a Merkle DAG). Each node also names its optional settle
payload manifest. The landed v3 representation names canonical fact-body
objects individually. A suppression payload adds a canonical path-local annex
of refs for authority facts without an index key; refs may repeat structurally,
but bodies remain one-copy CAS and unrelated authority never enters a narrow
read (`poc-16-yez.15`). The synced `T_supp` root can reuse the same engine.

**Reads pick a guarantee.** *Fast* — walk any recent root (may lag by fold
latency). *Authoritative* — reconcile: root-vs-`LIST` diff, or peer fingerprint
diff. One primitive; empty-prior = full catch-up. RYW is client-side (fold your
pile after PUT); monotonic reads = merge-not-replace against a watermark; causal
is free from dep-closure.

**GC is generational.** Reclaim only what no root in a grace window reaches
(git-gc + a reflog window); the folder that path-copies stamps superseded nodes
with a grace expiry; reclamation is lazy and never on the correctness path.

**Cloudflare Workers, exclusively.** The tree lives in R2, so every hot op is
O(log n) memory / O(ms) incremental CPU — 128 MB / 30 s (→5 min) never bite in
steady state, and a pile parses in a few MB. R2 gives strong read-after-write +
conditional writes; fold on **R2 event → Queues**; **never put `root` in KV**
(eventually consistent); R2 egress is free. The one O(n) job — a from-scratch
rebuild — is skipped by copying the content-addressed tree or chunked across
invocations via a Durable Object `alarm()`; no heavy tier is required.

## Staged Plan

Proofs first; no transport work until both numbers exist.

1. **Core** — leaf run + fence runs, deterministic cut, codec; trait with
   mem + sqlite drivers; manifest CAS. Property test: same set ⇒
   same layout — pages, fences, and tail — at one release and configuration;
   the cross-release form is §Versioning's golden-corpus replay.
2. **P1 bench** — divergence sweep, measure rounds/bytes vs O(d · log n).
3. **P2 bench** — messaging-shaped synthetic pile; engine vs sqlite store,
   then vs real S3 from a warm Lambda; pin facts/s and $/M; pick page size.
4. **P3 bench** — leaf-pile close at promotion + closure walk; measure
   shared-closure duplication (hub copies) on a real corpus; sweep leaf
   sizes. (Done: `bench/RESULTS.md` — 3.3× at CUT=8 → ~1.0× with 1 MB
   cold leaves and topo-order sig placement.)
5. **Protocol** — daemon (seven routes) + the one HTTP client with grant
   decorators + s3 driver/presigned flow; conformance suite green against
   daemon and S3+Lambda.
6. **iroh** — h3-over-iroh connector; same conformance suite.
7. **Auth** — request-fact families + evaluate mode, globals,
   invite blob, eviction test, mint over both transports.

## Open Questions

- **Global deletion is resolved architecturally, not yet fully landed.**
  Stable validity remains globals-blind and parallel. Clear-envelope death keys
  index a second `T_supp`; its one-sided surfacing walk contributes
  out-of-range victims to closure, and projection masks them after judgment.
  No validator or materializer consults mutable S, so no singleton or
  optimistic validation retry is required. The current engine implements the
  single-target seam; global 1:N construction, sync, surfacing, and closure are
  tracked by `poc-16-yez` (`docs/DELETION_CLOSURE.md`).
- (Dead weight: resolved 2026-07-22 — piles go straight to dep-pure
  validation, so facts that never validate never enter the set.)
- Page cut: needs a precise deterministic definition that keeps small diffs
  ⇒ few changed pages (the priority-threshold candidate qualifies).
  **Tiered cut (prototyped, `layout.COLD_CUT` + benched):** decouple the guard
  window B_t from the cut density — seal history older than a B_t-deep watermark
  into coarse ~1 MB cold pages, keep the recent window fine. Pure in the set
  (split = last coarse boundary ≤ len−B_t), so leaves-are-piles/byte-identity
  hold. Measured 8× catchup throughput and 2.7× less bandwidth (redundancy
  3.3→1.4×) with steady writes unchanged; the cost is stragglers (an old-ts
  write re-ships a whole cold page). Generalization: scale the cold size as
  `∝ √N` on a **dyadic ladder** (2:1 merges, never a re-cut) for O(log N)
  amortized write-amplification — safe because the cut stays a pure function of
  the set; scaling bounds the fence-run length, not the redundancy (which the
  membership-closure size already caps).
- **Versioning is designed, mostly unbuilt, and one live bug.** §Versioning is
  the model: per-version handlers, offers as the interlingua, replay as the
  upgrade. Landed today are the per-version read handlers — `legacy_*` for the
  auth families, and now `file` beside `file_bao` — plus the two derived-state
  stamps. Unbuilt are the offer hook itself (the kernel still admits envelope
  atoms verbatim, so nothing normalizes), the append-only vocabulary registry,
  and any release constant at all. The bug: an unknown tag rejects a whole unit,
  so a behind-version peer never converges that range and refetches it once per
  root change and once per restart, while no release version rides the verbs,
  the grant, or the root to notice by. Open inside it: whether a release marker
  rides the root — making the skew observable in one conditional GET, at the
  price of two releases differing by construction on an unchanged set — or sits
  beside it, in `roots/` metadata or the mint response. Tracked by
  `poc-16-9fc` (`docs/VERSIONING.md`).
- Multi-group on one bucket. (Bulk-join body bundles: resolved 2026-07-22 by
  packed pages — bodies live in the page objects, docs/MODEL.md.)
- **Attachments: Bao, resolved 2026-07-25.** A signed descriptor commits the
  file with one 32-byte BLAKE3 root. Each 256 KiB chunk fact names a separate
  immutable proof object that authenticates its payload against that root.
  This gives two useful properties:

  - progress counts only locally resident chunks whose proof verifies, without
    trusting arrival order, a peer, or projection state; and
  - the descriptor remains O(1), measured at about 660 bytes from 1 MB through
    256 MB, instead of growing with a per-slice hash list.

  The measured price is 6.3–6.5% proof overhead, the pinned `bao 0.13.1` Rust
  dependency, and sequential per-chunk GETs that reached about 93 MB/s for a
  1 GB download. Peak RSS stayed below 100 MB on both daemons, versus 10 GB on
  the replaced whole-blob send path (`bench/RESULTS.md`).

  POC-14's per-slice hashes remain the live alternative: they need only
  `hash(bytes) == id` and avoid native code, but make the descriptor O(chunks).
  The policy boundary is deliberately narrow (`core/bao.py` and
  `facts/content/{file,chunk}.py`) if that trade changes.

  New descriptors use the versioned `file_bao` wire tag; the old `file` handler
  remains read-only so persisted whole-blob workspaces survive upgrades.
  Proofs ride `obj/`; only their signed chunk facts enter the tree. Object
  arrival is therefore a second delivery channel, represented by `*fid` in the
  projection log and folded through the same resumable path as admission.
