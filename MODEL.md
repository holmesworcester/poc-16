# Performance Model — POC-16

Companion to [DESIGN.md](DESIGN.md). This derives the mathematical
relationships behind P1 and P2, writes the send/receive/compaction loops
against them, and checks that the litmus numbers survive the loops as
written. Every number is an estimate until `bench/` (stages 2–3) replaces
it; the point of the model is to expose *which parameter binds where*.

## Parameters

Set and workload:

| sym | meaning | canonical value |
|---|---|---|
| n | validated facts in the treap | 10^6 (stress: 10^9) |
| d | symmetric difference at walk time | 10^2 |
| λ | new-fact arrival rate | 10^4/day/group (~0.12/s) |
| δ | dependency refs per fact | 5–10 |
| ρ | fraction of diff in the recent ts range | ≈1 live; <1 for old edits/late arrivals |
| F | fact object (envelope + ciphertext body) | 0.5 KB (attachments excluded) |

Records and pages (fixed-size records; ts leads the key; **packed pages
adopted 2026-07-22** — bodies live in their page's heap, not in per-fact
blobs):

| sym | meaning | canonical value |
|---|---|---|
| E_l | leaf record `(ts, fid, author, auth digest, body off)` | 72 B |
| E_f | fence record `(separator, fp, count, page ref)` | ~28 B |
| P | page byte target — record section + body heap | 256 KB |
| B_l = P/(E_l+F) | facts per page | ~450 |
| S | slice — the ranged-GET unit, 8 KB of record run | ~113 records |
| B_t | tail promotion threshold (entries) — the guard-window knob | 2,048 |
| — | body spill threshold (bigger ⇒ own `blob/`; attachments always) | 8 KB |

Platform (us-east 2026; R2 in parentheses where it differs):

| item | value |
|---|---|
| GET | $0.40/M ($0.36/M) |
| PUT / COPY / LIST | $5.00/M ($4.50/M) |
| egress to internet | $0.09/GB ($0) |
| storage | $0.023/GB·mo |
| rate limits | 5,500 GET/s, 3,500 PUT/s **per prefix** |
| LIST page | 1,000 keys; batch DELETE 1,000 keys/req |
| conditional PUT | If-None-Match and If-Match native (2024+) |
| ranged GET | native |
| Lambda | $0.20/M invoke + $16.7/M GB·s; 1,769 MB = 1 vCPU (1 GB ⇒ 0.57) |
| RTT R | client→store 30–80 ms WAN; Lambda→S3 5–20 ms; iroh peer 20–150 ms |
| Ed25519 verify t_v | 60–100 µs per core |

## Geometry — Fence Runs

The set serializes as one key-sorted run of fixed-size leaf records, cut
into packed pages — record section first, then a body heap holding the
facts' bodies in record order (offsets in the records, lengths implicit);
above the record run sit **fence runs** — one fence per 8 KB record
slice, sorted, cut, and fingerprinted by the same rule. The
treap never exists as a pointer structure: priorities are only the
deterministic cut function, and the fence hierarchy is its fingerprint
aggregation.

- Fence record `(separator, fp, count, page ref)`: 16 B fp + 2 B count +
  suffix-truncated separator (~8 B) + run-length-shared page ref (~2 B) ≈
  **28 B** encoded.
- Sizes at 10^6: record run 72 MB + ~500 MB of bodies in ~2.2 k packed
  pages / 9 k slices; L1 fence run 9 k · 28 B ≈ 250 KB; top run ~32
  fences ≈ 1 KB — inlined in the manifest. At 10^9: one more level
  (L2 ≈ 0.9 MB), top ≈ 3.5 KB. Run depth **D = 2** at 10^6, **3** at 10^9.
- **Packed pages.** A body over 8 KB — and every attachment — spills to
  its own `blob/<hash>`; the record keeps the ref. Otherwise there is no
  per-fact object: a dep probe is one ranged GET at the record's offset,
  a bulk fetch takes whole pages, and the walk touches record sections
  only — record and body bytes never mix in a fetch. `bundle/` is gone:
  the tail page carries its bodies like any page, and news bodies are
  its heap's suffix.
- **Manifest** (~2 KB): `{generation, top fence run inline — history
  fences + tail-slice fences, auth ref}` — one conditional GET prices the
  whole validated set (news included) *and* locates every top-level
  range. Mutable surface of the store: `root` ∪ `pile/*`; the tail page
  is content-addressed like any page, so a ranged GET can never tear
  across a concurrent update.
- **Retrieval is one operation**: binary-search cached fences, then any
  key range = one contiguous ranged GET per level (fixed-size sorted
  records make offsets arithmetic). Walk descent, dep probes, and bulk
  fetches are all instances of it.
- Fingerprints are 16 B (128-bit second-preimage margin); 8 B would only
  risk hiding a diff until the next cadence (availability, not
  integrity), but 16 B is the default.

## The Walk — receive loop (P1)

Annotated `[round | requests | bytes]`; all fetches within a level are
parallel (≤100 in flight, far under per-prefix limits).

```text
every c seconds, or on news hint:
  m  <- GET /root If-None-Match etag       # 1 | 1 | ~2 KB   history+tail fences inline; 304 ⇒ done
  f1 <- ranged GET L1 fence slices under
        top fences with fp ≠ local        # 2 | F1 | 8 KB each
     count gap huge ⇒ bulk fetch/push (any range = contiguous GETs)
  [one more fence level at 10^9]           # +1 round
  ls <- ranged GET leaf slices under
        differing fences                   # 3 | L(d) | 8 KB each
  diff <- entries(ls) ⊖ local entries      # exact, in BOTH directions
  bodies <- ranged GET body heaps of the
        touched pages, coalesced per page;
        spilled bodies via blob/<hash>     # 4 | ≤ pages touched | d_pull·F
  news bodies: tail heap suffix            # 4 (concurrent) | 1 | Δ·F
  (tail slices arrived via the same fence walk — no separate news path)
  validate pulled facts; apply; then send-loop tail
```

**Rounds.** `R_w = D + 2` sequential (manifest, root slices, leaf slices,
bodies): **4 at 10^6, 5 at 10^9**. Steady state is usually 1 (304). A
fresh session skips round 1: the mint response carries the current root
(bytes + ETag) as a handshake freebie.

**Transfer.**

```text
T(d) ≈ 1.5 KB + (F1 + L(d))·S + d_pull·F
L(d) ≈ ρ·ceil(d / 113) + (1−ρ)·d         leaf slices (birthday-corrected)
F1   ≈ fence slices covering L(d)        (≤ whole L1 run, 250 KB, scattered)
```

Locality is the whole game: ts leads the key, so live diffs land in the
rightmost slices (`ρ→1`) and `L(d) ≈ d/113`. Scattered diffs (old edits,
late arrivals) pay one slice each. Worst-case transfer is
`O((d + D)·S)` — the "log n" of P1's O(d·log n) claim lives in D, and
the constant is the slice size, not the page size.

Three regimes at n = 10^6:

| regime | rounds | bytes | notes |
|---|---|---|---|
| steady repeat, λc = 50, clustered | ≤4 | ~20 KB + bodies | manifest + 1 fence slice + 1 leaf slice |
| cold cache, d = 100 scattered | 4 | ~1 MB | L1 run 220 KB + ~100 leaf slices + bodies |
| fresh join | bw-bound | 0.57 GB, ~2.2 k page GETs | see below |

**Litmus check.** "≤4 rounds, ≤ low hundreds of KB" holds for the
recent-clustered case — which ts-keying makes the live case — and holds
scattered only because of fence-granular slicing: whole-page fetches
would be ~90 packed pages ≈ **23 MB**, a 20× miss. Fences are
load-bearing for P1, not an optimization.

**Fresh join** is bandwidth-bound under packed pages: ~2.2 k page GETs
(+ annexes), 0.57 GB ≈ **3 min at 25 Mbps** (45 s at 100), $0.001 of
requests — and the bulk decision is made in round 1 (count gap at the
root), units stream through the kernel newest-first, so the inbox is
usable in seconds while history backfills. The
pre-packing layout — a blob per fact — was request-bound instead: 10^6
GETs ≈ 5.5 min and $0.40 no matter the bandwidth. That asymmetry is why
packing was adopted; the same collapse rescues every windowed fetch
(Closure below).

**Time.** `t ≈ R_w·R + T/W`. Steady repeat over WAN: 4·50 ms + ~20 KB at
25 Mbps ≈ **0.2 s**. Same shape over iroh; only R changes.

## The Send Loop

```text
on new local fact f:                       # eager path — news latency
  for each counterpart store s with a grant:
    PUT s/pile/<me>/<hash(f)>              # idempotent; 200 = durably delivered
  POST s/poke after the batch              # cloud: wake the engine; peer: implicit
  then walk s                              # latency nicety: the exact diff
                                           # delivers the closure promptly

at walk end:                               # anti-entropy backstop
  push <- local entries in differing ranges ⊖ remote entries(fetched slices)
                                           # exact only now — slices carry the
                                           # responder's complete in-range entries
  close(push) -> one closed pile; PUT pile/<me>/<hash>; poke
                                           # one close(): shared closure embedded once
  bulk ranges: PUT copies of own range+annex / tail+tail-annex units
                                           # already closed piles; merge dedups by fid
```

- The fetched slices contain the responder's *complete* entry list inside
  every differing range, so the push set is **exact** — no speculative
  re-sends, no receipt protocol. Content-addressed PUT makes retries free.
- Cost: one PUT per fact per cloud store ($5e-6); zero per peer. Rate:
  3,500 PUT/s on the member's own prefix ≫ λ.
- The walk after the PUT is latency, not correctness: validation never
  blocks on deps, so a lone fact cannot wedge — the walk just gets the
  closure to consumers' validators sooner; nearly free (one conditional
  GET) when in sync.

## The Engine — compaction loop (P2)

(Modeled here as one pass; the adopted design is validate-with-inline-
promotion — see The WAL below — which changes cadence and write
amplification, not the per-fact costs.)

```text
on request (peer drain-on-read / cloud POST /poke), under lease:
  m     <- GET root (cond)                 # warm: cached
  gl    <- GET globals                     # warm: cached; O(removals)
  keys  <- LIST pile                       # ceil(pile/1000) reqs
  piles <- par GET pile objects            # b reqs | b·F
  hash-verify mini-run structure           # cheapest checks first
  kernel(pile, anchor) per pile, in parallel
        ⇒ (valid?, new globals)            # b·t_v CPU; ZERO store reads (piles fully closed)
  globals′ <- globals ∪ new globals        # associative union
  emit  <- k-way merge into tail; on promotion
           ceil(b/B_l)+D pages + annexes, PUT If-None-Match
           spilled bodies -> blob/; PUT globals′ if changed
  CAS root                                 # the commit point
  batch DELETE pile keys                   # valid and rejected alike; ceil(b/1000) reqs
```

**Throughput.** With w = 100 GETs in flight at in-region R_l:

```text
t(b) ≈ b·R_l/w        pile GETs
     + b·t_v/v        verify (v = vCPU share; parallel across piles)
     + (D + b/B_l + 2)·R_l   emit + CAS   (no per-fact copies — bodies ride the pages)
```

b = 1,000, R_l = 15 ms, 1 GB (0.57 vCPU): 150 + 140 + 95 ms ≈
0.39 s ⇒ **~2,600 facts/s** against real S3 — 8× over the 300/s
litmus, margin absorbed by tail latency and cache misses (packing
deleted the per-fact `COPY pile→blob`; fully closed piles deleted the
frontier-probe term — validation does zero store reads, and annex
assembly at promotion is in-memory ref classification, noise). Against
a local sqlite store the loop is verify-bound: **6–10 k facts/s per
core**, and closed-in/out kernel invocations scale across cores.
Bottleneck order: per-fact pile GETs > verify > emit; uploading
a ~1 MB packed tail adds 10–20 ms, noise. Note vCPU scales
with Lambda memory — 1,769 MB doubles the verify rate.

**Write amplification.**

```text
WA = (ceil(b/B_l) + D) · P / (b·(E_l + F))
```

b = 50 ⇒ ~27×; b = B_t = 2,048 ⇒ ~1.5×. Batching divides WA — and the
pile makes batching free: **facts are visible in the pile the moment
they're PUT, so compaction cadence τ is a pure cost knob, not a
delivery-latency knob.** Choose λτ ≈ B_t/4..B_t where λ allows. Tail
rewrites between promotions churn up to ~1.2 MB per drain, but PUT bytes
are ingress-free — milliseconds of Lambda upload, not dollars. CAS
contention ≈ 0 under the lease; the CAS is only the safety net.

**No parked scan.** Every drain empties the pile — merged or deleted,
nothing waits — so a drain costs O(arrivals), never O(backlog).
Closure-complete piles (auth model C) make parking impossible by
construction, store-side and consumer-side alike: a receiver never
holds a fact it lacks the means to judge.

## Dollars

Per valid fact (S3): 1 client PUT + 1 engine GET + amortized page
PUTs + 1/1000 DELETE ≈ **$6/M facts** written — the per-fact COPY died
with packing. Storage at 10^6 facts ≈ 0.6 GB ≈ $0.014/mo.

Per active reader per day (adopted tail-range design), c = 60 s,
λ = 10^4/day:

```text
(86400/c)·(cond GET root) + news polls·(tail slice + tail-heap ranged GETs)
= 1440·$0.4e-6 + ~700·2·$0.4e-6        ≈ $0.0012
+ egress ~6 MB·$0.09/GB                ≈ $0.0006   (R2: 0)
≈ $0.002/day  (~$0.06/mo)
```

The two-tier baseline was $0.013/day: **LIST was the poll tax** — 12.5× a
GET, paid every poll whether or not there was news — and per-fact pile
GETs did the rest. The WAL exists to delete both; LIST is now engine-only.
Levers: cadence c (linear), a *follower tier* that polls the manifest only
(τ-fresh, ~$0.001/day), long-poll on peers (poll cost → 0), R2 (egress → 0).

Group per day (20 active readers, λ = 10^4, c = 60): writers $0.05 +
engine ~$0.01 (Lambda; page PUTs are noise — copies are gone) + readers
$0.04 ≈ **$0.10/day** — the writers' own pile PUTs now dominate; engine
and reader sides are solved.

Lambda memory: hot set = auth snapshot + right-edge pages + recent window
≈ tens of MB ≪ 1 GB. RAM bills only during execution (~pennies/day at
this cadence) — "memory beats lookups" survives contact with the loop
numbers.

## The WAL — the Treap's Tail Range (adopted)

The model above pins two costs to one decision — that the raw pile is the
only sub-τ tier. Read side: every poll pays LIST + per-fact pile GETs and
readers chew raw litter. Write side: compacting on a fast cadence means
small batches, and WA at b = 50 is ~120×. Splitting the engine into
**validate** (on request) and **promotion** (threshold-triggered) removes
both:

```text
pile/<member>/<hash>    raw, per-member ingress          (unchanged)
tail page               the WAL: validated, deduped,
                        (ts,fid)-sorted, ≤ B_t entries,
                        records + bodies packed —
                        the treap's rightmost range,
                        content-addressed, its fences
                        inlined in the manifest top run  (new)
manifest + pages        the rest of the set              (unchanged)
```

```text
validate (on request: peers drain-on-read, cloud on poke; same lease):
  facts <- LIST + par GET pile; gate (sig + author known; no dep I/O)
  tail' <- tail ∪ valid (dedup by fid); stragglers mini-fold their page
  if tail' full: promote stable prefix to pages + fences   # cut rule fires
  PUT tail', any promoted pages, spilled bodies -> blob/
  CAS manifest                         # the single commit point
  batch DELETE covered pile keys       # pile empties every drain
```

The WAL is the engine's recent window made durable and public — and
since it is (ts,fid)-sorted and capped at B_t = 2,048 entries (~1.2 MB
packed), **it is the next few leaf pages, accumulating in public**;
promotion freezes it into ⌈B_t/B_l⌉ ≈ 5 pages. B_t is deliberately
larger than one page: the cap is the straggler guard-window knob
(B_t/λ), decoupled from page size. Because the tail's per-slice fences
ride in the manifest's top run, updating it touches no fence pages: no
path rebuild.

Reader poll is **one conditional GET of the manifest** — the root
fingerprint covers news too, so "did anything change" has a single
answer, and fetching news is the ordinary fence walk (usually one changed
tail slice + one ranged GET of new tail bodies). No LIST, no per-fact
GETs, no raw litter ever
reaching readers (signature checks stay on ingest as defense in depth,
but litter costs readers zero bandwidth). Between promotions the tail is
mostly-append, so the changed-slice diff is usually the last slice; and
being content-addressed, a ranged tail GET can never tear across a
concurrent CAS — a latent hazard of the mutable-key variant, now gone.

Comparison at λ = 10^4/day, c = 60 s, validate cadence 30 s:

| | two-tier (pile→treap) | three-tier (pile→WAL→treap) |
|---|---|---|
| reader $/day | $0.012 (LIST tax + per-fact GETs) | **~$0.002** (5–9×, burstiness-dependent) |
| treap page PUTs/day | ~7,200 (1,440 compactions) | **~30** (~5 promotions × ~5 pages) |
| page bytes rewritten/day | ~550 MB | **~8 MB** promoted (+ tail churn — bytes free) |
| manifest generations/day | 1,440 (walker caches churn) | ~5 (caches warm for hours) |
| news visibility | ~c (if readers LIST-poll fast) | writer poke→validate (~seconds cloud, ms peer) |
| per-fact validate cost | 1 GET + verify + writes | same — conserved |

The conservation law: each fact must be fetched, verified, and written
once at the store no matter the architecture. The tiers only change who
pays on the read path and how often treap pages churn — and that is where
the money was.

**Is the treap fast enough to fan out from directly?** Updating it is
cheap (~8 PUTs, ~$4e-5 per promotion) — but per-batch promotion was never the
binding cost; making every reader poll raw piles was. Conversely the
treap alone can't serve news cheaper than τ-freshness. So: immutable
pages for history, the tail range for fan-out, promotion on threshold.

**"Requester always gets the latest, pauses on rebuild":** no pause
exists or is needed. Every tier is publish-then-swap (tail and pages
PUT before the index CAS that references them), so a requester always
reads the last committed snapshot, and every valid fact is in ≥1 of
{pile, set} at all times — the tail is part of the set, and validation
and promotion share one CAS, so there is no multi-object ordering. Peers
long-poll `/root`.

**Stragglers — why old facts are treaped, not dumped in the tail.** The
alternative (tail as a *set overlay* holding any-ts validated facts)
would make the layout depend on arrival order: two stores holding the
same set would carry different fences and fingerprints, breaking
history-independence — mirrors would see false diffs, and the stage-1
property test dies. Determinism forces the range semantics; the mini-fold
is its price. The price:

- The promotion boundary is **content-determined**: the highest cut point
  with fewer than B_t entries above it. The whole layout —
  pages, fences, tail — stays a pure function of the set.
- Guard window before a late fact straggles = the tail's time depth,
  B_t/λ — **self-scaling**: ~5 h at λ = 10^4/day, ~2 days at 10^3/day,
  ~30 min at 10^5/day. Busy groups have short windows and present
  members; quiet groups get days.
- A straggler batch (a device reconnecting past the window) clusters by
  ts, so it lands in 1–2 leaf pages: ~2–3 extra PUTs (~$1.5e-5, ~0.5–0.8
  MB rewritten — bodies ride along), committed by the same manifest CAS as the batch's tail
  update. Not a separate round trip, not a separate commit.
- Worst case (every fact a straggler) degenerates to the pre-WAL
  per-batch compaction model (~120× WA at b = 50) — i.e., **the tail is
  pure upside for the ts-sorted common case and is never worse than the
  baseline already costed.**

Adopted (2026-07-22), second revision same day: the WAL dissolved **into
the treap** as its rightmost range — content-addressed tail page, fences
inlined in the manifest, one mutable object, one CAS commit point for
validation and promotion alike, `GET /wal` deleted (tail and bundles ride
the page/blob routes; protocol back to six verbs), auth snapshot always
current (rewritten in the same commit), stragglers below the tail
boundary mini-fold immediately (rare by ts-keying). Validate runs **on
request** — a peer drains piles before serving any read (the request
pauses milliseconds), and cloud clients make the request explicit with
`POST /poke` on the mint Lambda (writers after pushing; walkers on a slow
backstop cadence, ~10–15 min, so no-work pokes stay rare — each costs one
LIST). Arrival triggers (S3 events) were rejected: most ObjectStore
drivers can't signal on put, so the trigger must live in the protocol.
"Requester always gets the latest" is literal p2p, one poke away in the
cloud; a writer that dies before poking is caught by cadence. Third
revision (2026-07-22): **packed pages** — pages and tail carry their
bodies (spill > 8 KB to `blob/`), `bundle/` deleted, promotion threshold
B_t decoupled from page size.

## Closure — Any Range Plus Its Recursive Deps (the closure augmentation — now the FALLBACK; embed annexes adopted as primary 2026-07-22, DESIGN.md)

*Status note:* the closed-pile design made embed annexes
(`closure(range) ∖ range` as a per-range object, built by aggregating
pile-embedded copies) the primary P3 mechanism — no engine closure
work at all. This section's ref-based aug is retained as the fallback
if annex duplication measures pathological on a real corpus; stage 4
is the bake-off. The split-monotone page-cut requirement survives
either outcome.

Target semantics: sync an arbitrary `(ts, fid)` range Q — last 3 days,
last 4 weeks, or any mid-history window — and receive it
**closure-complete**: Q plus every recursive dependency of every fact in
Q. Closure-complete is what makes a partial replica *projectable* —
dep-pure handlers never park — and is what a residency pin-set means for
a bounded peer. Without an index this costs dep-DAG-depth spider rounds
(poc-14's join pathology); the aug makes it the same walk shape as P1.

**Construction.** One new run family on the same skeleton; fact pages
and the gate are untouched.

- Level ladder: the leaf range is the leaf page; above it, ranges come
  from priority-threshold cuts at arity β ≈ 16 — the same rule family as
  the page cut, so the ladder is a pure function of the set.
  REQUIREMENT exported to the page-cut open question: the rule must be
  **split-monotone** (boundaries refine, never move; the
  priority-threshold candidate qualifies). At λ = 10^4/day the ladder is
  a time-scale stratification: page ≈ 1.1 h, L1 ≈ 17 h, L2 ≈ 12 d, L3 =
  the whole set at 10^6. L_a = 3 levels above pages at 10^6, 6 at 10^9.
- k_ℓ(f) = number of level-ℓ ranges whose **promoted** facts
  transitively depend on f. Nesting makes k_ℓ non-increasing in ℓ and
  the root gives k = 1, so **home(f) = lowest level with k_ℓ(f) ≤ h**
  always exists (hoist cap h = 8). Store one ref record per hit range at
  home(f); elide a ref only when the target lives in the same leaf page.
- Coverage: if leaf L needs f, L's ancestor at home(f) is a hit range,
  so f's ref sits on L's root-to-leaf path. Fetching the aug of every
  range on Q's cover paths yields a **closure-complete superset** of
  refs in one descent — recursion included, because "needs" is
  transitive. (Sound to cut at popular facts because popularity is
  monotone along dep edges: a dep is at least as needed as any of its
  dependents.)
- Two published sort orders of the same records — forward
  `(level, range, target ts, fid)` for the walk, inverted
  `(target, level, range)` for maintenance and, later, deletion
  cascades. E_a ≈ 40 B (8 ts + 32 fid; owner implicit in position, ts
  delta-coded). Own fence runs, cut by the same rule, top fences inline
  in the manifest; run depth matches D, so aug fetches ride the walk's
  existing rounds — the ladder depth L_a affects *placement*, never
  round count.
- Tail: the canonical scope is the promoted prefix (its boundary is
  content-determined, so the aug stays a pure function of the set). For
  the tail range the engine publishes an **aug tail**: the deduped
  pre-tail direct targets of tail facts, (ts, fid)-sorted — derived from
  clear envelopes alone, hence equally canonical. This *replaces* the
  writer-declared pile hints from the design thread: the clear-envelope
  decision (2026-07-22) made them redundant — the engine reads dep refs
  straight off valid facts, so no trust, cap, or blame machinery.
- Counts only grow (appends and splits), so homes migrate one way:
  upward, ≤ L_a times per fact ever. Honest need sets are suffix-shaped
  (deps point backward; a hub is needed by everything after it), which
  keeps hit ranges contiguous. When deletion returns, counts stay
  defined over the DELIVERED set to preserve monotonicity.
- Privacy: the aug is derivable from clear envelopes, so it adds no new
  information class to the store (decided 2026-07-22: dep topology
  store-visible, bodies confidential).

Parameters:

| sym | meaning | canonical value |
|---|---|---|
| h | hoist cap — max ranges holding a ref before it homes higher | 8 |
| β | level-ladder arity (priority thresholds) | 16 |
| L_a | ladder levels above leaf pages | 3 at 10^6, 6 at 10^9 |
| E_a | aug record: target (ts, fid), delta-coded | 40 B |
| δ' | distinct out-of-page targets per fact after elision + hub homing | ≈1 (0.5–3) |
| χ(Q) | context size: closure(Q) ∖ Q | workload; ~10^3 for a 3-day suffix |
| H | root-homed hubs (channels, members, epochs) | 10^2–10^3 |

**Storage.** Records ≈ δ'·n plus hoisted copies (≤ h per fact, and only
for the popular minority) ≈ n at canonical δ': 40 MB per sort order,
80 MB for both — ~12% of the 10^6-group store; bodies (~500 MB, packed
in the pages) dominate
as always. Degenerate no-locality bound (every ref random-old, elision
never fires): δ' → δ gives ~560 MB, body-scale — the aug's
affordability rests on temporal locality, and **δ' is the one workload
parameter to bench on real corpora before trusting this section.**

**The closure walk.** Q quantizes outward to leaf-page cuts (elision
scope is the page, so sub-page closure is undefined; the quantum is
~1.1 h at canonical λ). Annotated `[round | requests | bytes]`; aug
fetches ride the walk's rounds:

```text
closure_sync(Q):                             # Q snapped to page cuts
  m   <- GET /root                           # 1 | 1 | ~3 KB   top fences now include aug + aug-tail
  f1  <- fact + aug L1 fence slices over Q   # 2 | few | 8 KB each
  ls  <- leaf slices of Q — whole packed
         pages when cold (bodies ride along) # 3 | ~|Q|/B_l pages | |Q|·(E_l+F) cold
  aug <- per cover range, the escape prefix: # 3 (same round) | r_esc | ≤8 KB each
         records with target < Q.start       #   within a range, refs sort by target ⇒
         (+ aug tail slice if Q meets tail)  #   out-of-Q targets are a computable prefix
  bodies <- context bodies via per-page
         coalesced ranged GETs (spill: blob/) # 4 | ≤ χ probes | χ_pull·F
  trim (optional): chase envelope refs from Q over the fetched set
         ⇒ exact closure locally; slop is boundary ranges only (≤2/level)
```

`R_cl = D + 2` — **4 rounds at 10^6** — whenever the context lies on Q's
cover paths, which suffix queries make the common case (tail refs point
recent, and recent pages are in Q). A frontier target outside the cover
(a tail fact referencing a pre-Q unpopular fact) costs +1 round: fetch
its path aug in parallel with its body. Chains that keep escaping cost
+1 each — spidering survives only on out-of-window chains, where poc-14
paid it on every hop of every join.

**Transfer.**

```text
T_cl(Q) ≈ T_walk(Q) + χ·E_a + r_esc·S + χ_pull·F
r_esc   = cover ranges with ≥1 escaping ref (slice-rounding term)
```

| regime (n = 10^6, λ = 10^4/day) | rounds | requests | bytes |
|---|---|---|---|
| 3-day suffix, cold (partial join) | 4 | ~66 pages + ~25 aug/fence + ~800 context probes | ~18 MB |
| 4-week suffix, cold | 4 | ~620 pages + ~1 k context probes | ~161 MB |
| single page (~1.1 h) | 4 | 1 page + ~5 aug + ~10^2 probes | ~0.4 MB |
| maintained window, steady | 1 (304) – 4 | plain-reader costs | + escapee bodies ~0.1 MB/day |

The 3-day partial join lands in ~6 s at 25 Mbps for ~$0.002 — vs ~3 min
and 0.57 GB for the fresh join — and every fact in it projects
immediately.
Ref bytes run ≤ E_a/F ≈ 8% of context body bytes even at 100% slop:
**precision is nearly free, so the aug's whole job is rounds, and
χ_pull·F is the floor no protocol beats** — the context must be
transferred. If χ(Q) → n the *semantics* demand a join; the aug still
delivers it in 4 rounds, body-request-bound like any join.

**Write side.** Placement is computed at promotion, riding pages being
written anyway:

- The owner range leads the forward key, and new promoted ranges are the
  rightmost, so **aug writes are right-spine appends** — the same
  locality as fact writes. `WA_aug = (⌈b·δ'/B_a⌉ + D)·P/(b·δ'·E_a)`,
  B_a = P/E_a ≈ 6,550 (aug pages carry no body heap): at b = B_t about
  one aug page + fences per promotion (~30 → ~45 PUTs/day; noise).
- Counts maintain by pruned propagation: "A hits y" implies "A hits all
  of closure(y)", so the walk from a new fact's direct refs stops at
  already-hit targets. Each (target, new-hit-range) pair is processed
  once ever — output-sensitive, amortized O(1) per aug record; per batch
  ≈ b·δ ≈ 14 k row probes, ≪ verify. Cold probes hit the inverted run by
  ranged GET (the standard retrieval op); at a 5% cold rate that is
  ~700 GETs ≈ +0.1 s/batch ⇒ engine ~2,600 → ~2,100 facts/s vs S3,
  still ~7× the P2 litmus.
- Migrations (a target crossing h): suffix-shaped hit sets make them one
  contiguous delete + one insert (~2 page touches); scattered need sets
  pay up to ~2h touches; ≤ L_a migrations per fact lifetime. A
  straggler-induced split recounts only the split range's homes,
  amortized against the mini-fold the straggler already pays. The worst
  case is the late-arriving hub — promoted after many dependents — one
  wide deterministic count cascade bounded by reverse-index fan-in,
  which is exactly the scan the inverted order exists for.
- Mirrors diff aug pages by fence fp like everything else; identical
  sets ⇒ byte-identical aug runs, so the stage-1 property test extends
  verbatim. Migration churn is the only extra diff traffic, bounded
  above.

**Litmus (P3, proposed).** Closure sync must cost the range walk plus
the context's own bodies: `R_cl ≤ D + 2` (+1 per out-of-window frontier
hop); ref + fence overhead ≤ 10% of body bytes; identical sets ⇒
identical aug bytes. Open empirical: δ' ≈ 1 — at δ' ≳ 3 the aug stays
correct but its storage stops being noise.

**Rejected alternatives**, for the record: re-keying the treap by
"related to range" (breaks RBSR's disjoint-partition algebra; one new
fact rewrites O(dependent-spread) pages); per-fact inline closure lists
(O(closure) envelope blowup); server-side closure computation (there is
no server). Spidering survives as the fallback rung, not the plan.

**Adopted 2026-07-22 — DESIGN.md now carries:** dep refs in the signed clear envelope
(decided 2026-07-22 — bodies confidential, topology store-visible); the
split-monotone constraint on the page-cut rule; the aug run family and
aug tail riding the manifest (six verbs unchanged — aug is pages and
root like everything else); closure queries quantized to leaf pages; P3
as a third proof obligation. Writer-declared pile closure hints are
dropped before birth — clear envelopes made them redundant.

## Cloud-Mode DB (option)

The engine's scoped working db — whitelisted auth families' facts,
their projections, and the parked/block-unblock relations — round-trips
through the store instead of living on a disk. At 10k users: ~50k auth
facts (invite + join + 2–3 device certs + 10–20% churn) × ~300 B ≈
15 MB of facts, **30–50 MB as SQLite**. Cold load: one GET at
~100 MB/s ≈ 0.3–0.5 s, then `sqlite3_deserialize` ≈ memcpy; warm runs
(the common case under the lease + container reuse) skip it by
generation stamp. Validating a new auth fact: µs-scale in-memory
lookups + one Ed25519 verify ⇒ ~10k auth facts/s CPU-side — a typical
drain carries 0–2, so it is noise. The real cost is write-back:
serialize + PUT 30–50 MB ≈ 300–600 ms, paid only on drains that changed
whitelisted state; content-only drains never open the db. WA is the
number to watch: ~10^5× per auth change is fine at join/evict rates,
which makes the whitelist a WA budget. Growth is O(principals): 100k
users ≈ 300–500 MB — the mode strains (load time + Lambda RAM);
comfortable to ~50k principals.

## Where the Platform Binds

- **`root` is the single hot key**: N readers polling every c seconds
  hit 5,500 GET/s at N ≈ 5,500·c (330 k at c = 60). Past that: CDN in
  front of it, or fan-out copies.
- **LIST pages at 1,000 keys**: pile must stay well under 1,000 live
  entries (λτ) or listing goes multi-request. Batch DELETE
  clears 1,000/req.
- **Conditional PUT is native** on S3 (and R2/MinIO/Garage), so manifest
  CAS and `put_if_absent` port everywhere the trait goes.
- **Egress**: packed pages make bulk fetches egress-bound (a fresh join
  is 0.57 GB but $0.001 of requests) — R2 (zero egress) is the default
  bucket; requests only matter for steady-state polling.
- **p2p**: request-$ and egress vanish; only R, W remain. Same loops,
  smaller c, long-poll instead of LIST polling.

## What the Model Changed in DESIGN.md

1. **Fence runs + slices are load-bearing for P1.** The treap survives
   only as the cut function and fingerprint aggregation; on disk it is a
   key-sorted run indexed by per-slice fence runs, with the top run inlined
   in the manifest. Any key range is one contiguous ranged GET per level —
   walk descent, dep probes, and bulk fetches are the same operation.
   Without 8 KB fence-granular fetches, scattered d = 100 costs ~23 MB
   in whole packed pages and the litmus fails outside the clustered case.
2. **P1 litmus restated** with its locality assumption: clustered (live)
   diffs ⇒ ≤4 rounds, tens-of-KB steady state; scattered ⇒ ~1 MB; worst
   case O((d + D)·S) transfer.
3. **Fresh join was request-bound** (a blob per fact ⇒ 10^6 GETs);
   resolved by packed pages (item 8) — now bandwidth-bound.
4. **τ is a cost knob, not a latency knob** — the pile decouples delivery
   from compaction; batch toward λτ ≈ B_t/4..B_t.
5. **LIST is the reader poll tax**; the follower tier (manifest-only
   freshness) exists in the cost model as the cheap class.
6. **The WAL tier was adopted** (section below): validate piles into a
   validated log served to readers — on request, never on a timer (peers
   drain-on-read; cloud via POST /poke) — promoted into immutable pages
   at ~one leaf page.
7. **The WAL then dissolved into the treap** as its rightmost range:
   content-addressed tail page, fences inlined in the manifest ⇒ one
   mutable object (`root` ∪ `pile/*` is the whole mutable surface), one
   CAS for validation and promotion alike, one "did anything change" GET,
   one fetch function; `GET /wal` deleted; torn tail reads impossible.
8. **Packed pages adopted (2026-07-22).** Page = 256 KB record section +
   body heap; E_l grows to 72 B (body offset); bodies > 8 KB and
   attachments spill to `blob/`; `bundle/` and the engine's per-fact
   COPY are deleted; the tail packs bodies, with the promotion threshold
   B_t = 2,048 entries decoupled from page size (guard window
   unchanged). Bulk fetches collapse from per-fact GETs to whole pages:
   fresh join 10^6 → ~2.2 k requests, per-fact cost $11 → $6/M, engine
   ~1,900 → ~2,600 facts/s.
