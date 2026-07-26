# Download economics — the cost model behind the pile encoding

Status: measured model (2026-07-26), companion to docs/REMOVALS.md. Platform
pinned to Cloudflare Workers + R2. Corpus constants measured by
`bench/measure_piles.py` against this branch's engine (production `tree.build`,
fanout 64, leaf density CUT=8); cloud constants are Cloudflare's published
limits and prices as of this writing — re-verify before contract-level bets.

The question this document answers: **"piles are full closure, with large
blob spillover" is the simplest possible encoding — does anything actually
invalidate it?** Yes: measurement does, and on exactly one axis. Everything
else about it survives and is worth keeping.

## 1. Platform constants (Cloudflare Workers + R2)

Requests and dollars:

- R2: storage $0.015/GB-mo, Class A (writes/list) $4.50/M, Class B
  (reads) $0.36/M, **egress $0**.
- Workers paid: $5/mo incl. 10M requests, then $0.30/M. A client GET proxied
  through a Worker ≈ $0.66/M all-in. One million GETs costs sixty-six cents:
  **request dollars never bind — wall-clock and limits do.**
- Zero egress means byte duplication costs *storage only*: 3× duplication of
  a 37 MB fact corpus is $0.001/mo. The entire hoisting apparatus, priced at
  the scale it was built for, defends fractions of a cent per month.

Hard limits per Worker invocation:

- **128 MB memory.** Streamed pass-through (blob GET/PUT) is exempt; anything
  the Worker *decodes* (ingress pile judgment, index reads) must fit with
  JSON/base64 blow-up (~4-6×) and working set: keep any decoded object
  ≤ ~20 MB, any batch response ≤ ~50 MB (PAGE_BATCH × object size — 256 ×
  2 KB piles is fine; never route blobs through the batch endpoint).
- **1,000 subrequests** (paid; 50 free) and **6 simultaneous open
  connections** per invocation. A Worker cannot fan out a whole clone; the
  scaling axis is *client-side* parallelism — each client GET is its own
  invocation doing one R2 read. Batch endpoints run at 6-way concurrency
  server-side: 256 objects × ~40 ms R2 ≈ 1.7 s/batch — legal, but client
  fan-out over edge-cached objects is faster and cheaper.
- CPU 30 s (configurable): ed25519 verify ≈ 0.1-0.3 ms in WASM, so judging
  a 1,000-fact pile ≈ 300 ms CPU — fine.
- Content-addressed `obj/*` keys are immutable → serve with
  `Cache-Control: immutable` through the edge cache: repeat reads skip R2
  entirely (~10-30 ms at the edge, $0). `root` is the only hot mutable key —
  the etag short-circuit (core/sync.py:37-44) is what keeps idle syncs at
  one conditional GET. Root CAS: R2 conditional put (`onlyIf`) or a Durable
  Object as the single serializer.
- R2 is single-region; pin the Worker with a location hint or every R2
  subrequest from a far edge adds ~50-200 ms.

Latency and energy (mobile is the binding client):

- RTT client→edge ~10-50 ms; edge→R2 ~20-80 ms (cache miss).
- LTE/5G radio: ~1-1.5 W active; ~25 Mbps ⇒ **~0.3-0.5 J/MB**. RRC tail
  after a burst: 1-10 s ⇒ **2-10 J per punctuated exchange**. Battery
  15 Wh = 54 kJ. Consequences: (1) one *sync session* costs 2-10 J in tail
  alone regardless of bytes, so anything under ~1 MB rides free — at fact
  scale, **bytes are not the resource, round trips are**; (2) never trickle:
  N short exchanges cost N tails.
- The real byte constraint is **metered data** (5-20 GB/mo plans): a chat
  app's sync budget is ~≤1 GB/mo. Cold clones above ~150-300 MB are
  user-visible events; blobs are the only thing that can get there.

## 2. The model

For one sync pass:

    T  ≈  d·RTT + (G/C)·RTT_miss + B/BW        wall-clock
    E  ≈  P·T + tail                            client energy
    $  ≈  G·$0.66/M + P_writes·$4.50/M + GB·$0.015/mo
    ρ  =  fact-layer bytes fetched / fact-layer bytes needed

with d = serial round-trip depth (root + tree descent + dependent waves),
G = total GETs, C = client concurrency (~6 HTTP/1.1, ~100 HTTP/2 to one
edge), B = bytes, blobs excluded from ρ by construction (they spill to
their own objects and are fetched on view, never on sync).

Derived bars:

| bar | value | binds because |
|---|---|---|
| serial depth d | ≤ ~6/sync | each wave ≈ 30-100 ms + keeps radio hot |
| warm sync | ≤ 1 s, ≤ ~500 KB | tail-dominated below that — free |
| cold clone (100k facts) | ≤ ~10k GETs, ≤ 30 s, ρ ≤ ~1.5 | wall-clock @ C≈100; metered visibility |
| decoded object (Worker) | ≤ ~20 MB | 128 MB with decode blow-up |
| batch response | ≤ ~50 MB | same |
| blobs | on view only, inline ≤ ~8 KB | the only bytes that can hurt anyone |
| dollars | (never binds) | $0.66/M reads, $0 egress |

## 3. Measured constants (bench/measure_piles.py)

Real corpora through the ordinary ingress (Node + kernel + signatures),
production tree layout. Fact sizes: msg 328 B, **signature 407 B** (the
signature outweighs the message it signs), user 512 B, user_invite 278 B.
≈ 735 B and two facts per message. Leaves: CUT=8 ⇒ ~8 facts ≈ 2-3 KB
member bytes per leaf. Keyless (annex) facts: **zero** — every fact has a
home leaf.

ρ_A = full-closure pile bytes / member-only pile bytes, per configuration
(corpora use random keypairs, so leaf boundaries and ratios vary ~±5% run to
run; trends are stable):

| corpus | members | invite shape | facts | leaves | ρ_A | median leaf (closed) | dep home-leaves/leaf (med/max) |
|---|---|---|---|---|---|---|---|
| 600 msgs | 8 | flat | 1,233 | 154 | **2.21** | 5.3 KB | 3 / 7 |
| 2,400 msgs | 8 | flat | 4,833 | 630 | **2.29** | 5.3 KB | 3 / 6 |
| 2,400 msgs | 32 | flat | 4,929 | 626 | **2.63** | 5.9 KB | 4 / 16 |
| 2,400 msgs | 32 | chain | 4,929 | 604 | **8.48** | 23.9 KB | 9 / 23 |

Also measured: the current main encoding (per-body objects + payload-ref
summaries + hoisting) stores **2.05× corpus in ~1.25 objects/fact** — the
oid-ref overhead is that large because facts are small (66 B of hex hash per
mention of a 368 B fact). Warm-delta tail locality: 40 new messages touch
**9-15 leaves** out of ~620, in every configuration — deltas are tail-local,
so leaf-granular refetch is cheap regardless of leaf size.

Findings:

1. **ρ_A is not a design constant — it is a property of the community's
   invite graph.** Flat shape: 2.2 → 2.65, growing with member count.
   One 32-member invite chain: 8.5, and the mechanism is linear in chain
   depth (each leaf re-inlines the union of its authors' auth chains;
   a mature community re-inlines its entire auth subgraph into every leaf).
   Realistic organic invite trees (depth ~e·ln M) put a 1,000-member
   workspace at roughly ρ 5-15. The design hands its overdownload ratio to
   user behavior it does not control.
2. Even the friendliest measured shape (2.2-2.65) already exceeds the
   1.5-2× bar — at 100k facts, ~85-100 MB fetched for ~40 MB needed; the
   chain shape turns that into 300 MB+.
3. Out-of-leaf dependencies concentrate: median 3-4 distinct home leaves
   per leaf (flat), head-clustered (old auth facts sort low). Resolving
   closure by *fetching home leaves* costs a handful of GETs, once, cached.

## 4. The configurations against the bars (100k facts ≈ 50k messages, 37 MB corpus)

| | (A) full-closure piles | (B) main: per-body + hoist | (E) home-leaf piles + key refs |
|---|---|---|---|
| cold GETs | ~12.7k | ~127k | ~12.7k |
| cold wall @C≈100 | ~4-5 s | ~40-60 s ✗ | ~4-5 s |
| cold bytes | 85-100 MB flat, **313 MB+ chain ✗** | ~75 MB | **~42-46 MB** |
| cold ρ | 2.3-2.65 flat, 8.5+ chain ✗ | ~2.0 | **~1.1** |
| warm sync | ~5-25 KB/leaf × 9-15 leaves — fine | fine, most GETs | ~2-3 KB/leaf × 9-15 — best |
| partial read | 1 GET, self-contained — best | bodies + ancestor payloads (hoisted range tax) | range + 3-9 head-clustered home-leaf GETs, then cached |
| serial depth | ~4 | ~5 | ~5-6 |
| mechanisms | piles only | body CAS + payload summaries + hoist placement + annex | piles + key refs |

(B) fails cold wall-clock on request count and pays ~1× corpus in pure hash
overhead. (A) fails the cold-ρ bar as soon as the invite graph is deep, which
it will be. (E) passes every bar.

## 5. Verdict: the simplest model that survives

"Piles are full closure" survives as the **wire and admission rule** and dies
as the **residence rule**. One amendment kills the ρ pathology and nothing
else changes:

> **A fact's bytes live exactly once, inlined in its home leaf's pile.
> Every cross-leaf need is a ref by key (`<ts:015d>:<fid>`), resolved by
> fetching the dep's home leaf.** Transfer piles (ingress, push, mint) stay
> full closures — admission still judges closed piles. Blobs spill to their
> own objects above ~8 KB and are fetched on view, never during sync. The
> removal index rides beside the tree (docs/REMOVALS.md) and is read whole.

How both halves coexist against a dumb party: "closed" is never a wire
property on the pull side. It is (a) a property of what a *judge* admits —
and judgment always has an active party (the settler holding the root CAS;
pushers construct closed piles because the judge cannot dereference into
their world), and (b) an invariant of the store as a whole:
**closure(store) = store**. Deps-before-facts at admission plus
every-fact-at-its-home-leaf means the store *is* one closed pile, factored
by home leaf, with the spine as its table of contents — no leaf is
self-contained, but every ref out of a leaf is a within-store pointer the
dumb store serves by name-lookup alone (which is exactly why refs are keys,
not bare fids). Active readers complete their own closure with a few more
GETs against the same store; judgment closed-ness on the way in is what
makes reference closed-ness true on the way out. Corollary for any future
residency limiting: eviction must respect reverse-closure, and since deps
point backward (content → auth, nothing → content), that reduces to
**pin the head leaves** — the measured 3-4 head-clustered home leaves that
hold the shared auth core. Content leaves stay freely evictable.

The store then holds five object kinds — root, spine nodes, leaf piles,
the removal index, blobs — and the deletions fall out: per-body CAS objects,
payload-ref summaries (`pay`/`pn`/`spans`), hoist placement and its
migration machinery, and the annex (measured empty). Refs-by-key requires
dep refs to carry the dep's timestamp — an envelope-format break, which
costs nothing here. Self-certification survives: the fid inside the key
checks against the fetched body.

**The minimal spine, derived from the whole-fetch budget.** A whole fetch
affords 1 + N/64 GETs, at which point requests are a constant ~5% of
transfer at any N (ratio ≈ RTT·BW/(C·k·fact_bytes); N cancels). The
simplest structure spending exactly that: ~64-fact leaf piles plus a
**manifest of (boundary-key, oid) pairs, sharded by the same 64-way
boundary rule when it outgrows one object** — depth 0 below ~4k facts
(the root lists leaves directly), one interior level to ~260k, two to
~16M. Because layout is canonical and history-independent
(tests/test_props.py:93) and objects are content-addressed, equal content
⇒ equal oid, so **oid comparison is the entire one-sided diff protocol**:
walk top-down, prune on matching oid, align on separators, fetch the rest.
The fact spine therefore carries no fingerprints, no n-counts, and no
per-node key arrays (full key lists live in the leaf piles; boundary keys
suffice for alignment) — interior entries are ~100 B/leaf, ~64× less
spine than today's keys-in-nodes encoding. The removal index keeps its
fingerprint (I4's reason is specific to it: its pile bytes embed local
closure-edge choices). If two-sided live peering ever returns,
fingerprints return as an addition, not a foundation.

**Closure-resolution round trips, per mode.** Whole fetch: zero — every
dep arrives inlined in its own home leaf inside the same bulk stream.
Warm sync: zero typical (deps point backward in time, so they are already
resident); a never-seen author costs one join-era-leaf wave, once per
device. Cold partial read is the only real walk, and it is batched waves,
not per-fact hops: collect all unresolved dep keys, map them to home
leaves against the locally held manifest (no RTs), fetch the frontier as
one parallel wave, repeat — measured corpora resolve in 2-4 waves
(~100-200 ms, ~24 KB/leaf) because a chain link's invite/sig/user/sig
cluster in one leaf. Worst case: an organically deep chain (depth
~e·ln M ≈ 20 at 1,000 members) discovered strictly sequentially ≈ 20
waves ≈ 1-2 s, once per device, then cached.

The depth fix — **adopted by the cutover plan (docs/CUTOVER.md), because
the deterministic two-wave fetch is less code than the frontier-walk loop,
not because the depth measured as pain**: a
**closure-keys sibling object per leaf** — the keys of the members'
transitive closure **that fall outside the leaf's own key range**:
everything a reader of this range must fetch from elsewhere. Derived
mechanically at settle (for a settled leaf this equals closure minus
members, since a leaf holds every fact in its span — the bench's pricing
measures exactly this set), emitted beside the pile, manifest entry
(sep, leaf-oid, closure-oid). Cold-partial readers fetch leaf + list in
one parallel wave and the whole closure frontier in a second: depth = 2
always. Multi-leaf reads take the union of lists and filter it against
the whole query range, so entries pointing into neighbor leaves already
being fetched drop out locally. Whole fetch and warm sync never fetch it, so the common modes pay
zero — which is the point: *inlining* the list in the pile was measured
at +35-38% (flat) to +202% (chain, unbounded in depth) on every leaf,
the shape disease at one-fifth scale, taxing exactly the modes that never
use it. Semantics are routing-only (removal-span posture): a defective
list degrades to the wave walk, never to wrongness — fetched facts
self-certify against their fids. The remaining unbuilt hatch is a first-contact
auth-warmup wave (the auth subgraph is the universal terminal set,
~1.7 KB/member) — not built before a real corpus shows it mattering
(§8 posture).

Why each rejected simpler/other option loses, in one line each:

- *(A) resident full closure*: ρ is community-shape-dependent and unbounded
  (measured 8.5 at depth 32); everything else about it was fine.
- *(B) per-body CAS (main)*: 10× the GETs (fails cold wall-clock), 2.05×
  storage in hash overhead, and its only justification — cross-index body
  sharing with T_supp — died with T_supp.
- *Hybrid (inline members + oid refs for closure)*: strictly dominated by
  key refs — same bytes, but keeps the body-CAS layer alive for one saved
  descent wave on partial reads.

## 6. Dials and flags

- **Leaf density (shape.py CUT=8) is the request-count dial, and the math
  picks k ≈ 64.** A GET is individually cheap ($0.66/M, ~40 ms, pipelined
  ~2,500/s at C≈100), so the failure mode is being *request-bound*:
  per-fact objects put a 100k-fact clone at ~40 s of request scheduling
  against 12 s of physical transfer, with ~300 B of HTTP headers nearly
  doubling each 368 B payload (batching rescues the count but is POST —
  uncacheable, compute-bound — forfeiting the dumb-store read path).
  Criterion: objects big enough that (N/k)·RTT/C < B/BW ⇒ k ≥ ~16-32;
  past k ≈ 64 the clone is bandwidth-bound (requests ~5% of wall) and
  bigger only grows warm/partial overfetch. Point reads are indifferent:
  fetching a 24 KB leaf vs a 0.4 KB body is the same round trip +8 ms,
  and closure resolution wants neighborhoods anyway (3-4 home leaves
  cover a leaf's whole out-of-leaf closure). Today's CUT=8 is 8× under
  the knee: raise to 64 (one constant + layout stamp; deltas stay
  tail-local — 9-15 touched leaves per 40 messages at any density;
  geometric boundaries put p95 leaves ≈ 3× mean ≈ 70 KB, under every
  bar).
- **`_fetch_blobs` is an eager full mirror** (core/walk.py:115-147): it
  fetches every blob every node has ever referenced. One 10 GB media
  workspace makes every fact-layer number in this document irrelevant.
  Blob-on-view is the single biggest lever in the system and is policy,
  not architecture.
- **Signatures cost more than messages** (407 B vs 328 B, and a second
  fact + hash mention everywhere). Any future envelope compaction
  (binary encoding, sig folded into the signed fact) roughly halves the
  fact layer. Out of scope here; noted because it dominates the constant.
- Per-invocation caps shape the daemon, not the client: keep PAGE_BATCH
  ≤ 256 and batch bytes ≤ 50 MB; prefer client fan-out over edge-cached
  immutable objects.
- Commit batching already matches R2 write pricing (one settle per turn,
  $4.50/M Class A) — do not settle per fact.

## 7. Re-running

`python3 bench/measure_piles.py all` builds the four corpora through the
real ingress and prints the table's raw numbers (deterministic, ~3 min).
Configurations and output schema are at the top of the script.
