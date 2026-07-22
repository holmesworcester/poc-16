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
| ρ | fraction of diff in the recent ts range | ≈1 live; <1 for parked/edited |
| F | fact object (envelope + ciphertext body) | 0.5 KB (attachments excluded) |

Records and pages (fixed-size records; ts leads the key):

| sym | meaning | canonical value |
|---|---|---|
| E_l | leaf record `(ts, fid, author, seq, auth digest)` | 64 B |
| E_i | interior child record `(bound, fp, count, child hash)` | 96 B + 16·k |
| P | page byte target | 128 KB (64–256 elastic) |
| B_l = P/E_l | entries per leaf page | 2,048 |
| k | slices (fences) per page | 16 |
| P/k | slice — the ranged-GET unit | 8 KB / 128 entries |

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
into pages addressable in 8 KB slices; above it sit **fence runs** — one
fence per slice, sorted, cut, and fingerprinted by the same rule. The
treap never exists as a pointer structure: priorities are only the
deterministic cut function, and the fence hierarchy is its fingerprint
aggregation.

- Fence record `(separator, fp, count, page ref)`: 16 B fp + 2 B count +
  suffix-truncated separator (~8 B) + run-length-shared page ref (~2 B) ≈
  **28 B** encoded.
- Sizes at 10^6: leaf run 64 MB, ~500 pages / 7.8 k slices; L1 fence run
  7.8 k · 28 B ≈ 220 KB (2 pages); top run ~28 fences ≈ 1 KB — inlined in
  the manifest. At 10^9: one more level (L2 ≈ 750 KB), top ≈ 3 KB. Run
  depth **D = 2** at 10^6, **3** at 10^9.
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
  bodies <- par GET blob/<fid> I lack      # 4 | d_pull | d_pull·F
  news bodies via bundle/<hash>            # 4 (concurrent) | ~1 | Δ·F
  (tail slices arrived via the same fence walk — no separate news path)
  validate pulled facts; apply; then send-loop tail
```

**Rounds.** `R_w = D + 2` sequential (manifest, root slices, leaf slices,
bodies): **4 at 10^6, 5 at 10^9**. Steady state is usually 1 (304).

**Transfer.**

```text
T(d) ≈ 1.5 KB + (F1 + L(d))·(P/k) + d_pull·F
L(d) ≈ ρ·ceil(d / (B_l/k)) + (1−ρ)·d     leaf slices (birthday-corrected)
F1   ≈ fence slices covering L(d)        (≤ whole L1 run, 220 KB, scattered)
```

Locality is the whole game: ts leads the key, so live diffs land in the
rightmost slices (`ρ→1`) and `L(d) ≈ d/128`. Scattered diffs (old edits,
parked facts arriving late) pay one slice each. Worst-case transfer is
`O((d + D)·P/k)` — the "log n" of P1's O(d·log n) claim lives in D, and
the constant is the slice size, not the page size.

Three regimes at n = 10^6, k = 16:

| regime | rounds | bytes | notes |
|---|---|---|---|
| steady repeat, λc = 50, clustered | ≤4 | ~20 KB + bodies | manifest + 1 fence slice + 1 leaf slice |
| cold cache, d = 100 scattered | 4 | ~1 MB | L1 run 220 KB + ~100 leaf slices + bodies |
| fresh join | bw-bound | n·(E_l+F) ≈ 0.6 GB | see below |

**Litmus check.** "≤4 rounds, ≤ low hundreds of KB" holds for the
recent-clustered case — which ts-keying makes the live case — and holds
scattered only because of fence-granular slicing: page-granularity fetches
would be ~90 pages ≈ **11.6 MB**, a 40× miss. Fences are load-bearing for
P1, not an optimization.

**Fresh join** is body-request-bound, not byte-bound: 10^6 individual
`blob/` GETs ≈ 5.5 min at 3 k GET/s (and $0.40). Metadata is fine (489
pages, one round). If joins matter, the fix is body bundles aligned to
leaf pages — folded into the blob open question, with its own write
amplification cost (rewriting a bundle costs B_l·F ≈ 1 MB).

**Time.** `t ≈ R_w·R + T/W`. Steady repeat over WAN: 4·50 ms + ~20 KB at
25 Mbps ≈ **0.2 s**. Same shape over iroh; only R changes.

## The Send Loop

```text
on new local fact f:                       # eager path — news latency
  for each counterpart store s with a grant:
    PUT s/pile/<me>/<hash(f)>              # idempotent; 200 = durably delivered
  POST s/poke after the batch              # cloud: wake the engine; peer: implicit

at walk end:                               # anti-entropy backstop
  push <- local entries in differing ranges ⊖ remote entries(fetched slices)
  par PUT pile/<me>/<hash> for push        # full fact objects: envelope + body
```

- The fetched slices contain the responder's *complete* entry list inside
  every differing range, so the push set is **exact** — no speculative
  re-sends, no receipt protocol. Content-addressed PUT makes retries free.
- Cost: one PUT per fact per cloud store ($5e-6); zero per peer. Rate:
  3,500 PUT/s on the member's own prefix ≫ λ.

## The Engine — compaction loop (P2)

(Modeled here as one pass; the adopted design is validate-with-inline-
promotion — see The WAL below — which changes cadence and write
amplification, not the per-fact costs.)

```text
on request (peer drain-on-read / cloud POST /poke), under lease:
  m     <- GET root (cond)                 # warm: cached
  snap  <- GET auth snapshot               # warm: cached; O(members)
  keys  <- LIST pile                       # ceil(pile/1000) reqs
  facts <- par GET pile objects            # b reqs | b·F
  verify signatures                        # b·t_v CPU
  deps sorted; resolve intra-batch → recent window (mem) → merge-join leaf pages
  admit / park                             # parked stay in pile
  emit  <- rewrite ceil(b/B_l)+D pages, PUT If-None-Match
           COPY pile→blob ×b; PUT snapshot
  CAS root                                 # the commit point
  batch DELETE admitted pile keys          # ceil(b/1000) reqs
```

**Throughput.** With w = 100 GETs in flight at in-region R_l:

```text
t(b) ≈ b·R_l/w        pile GETs
     + b·t_v/v        verify (v = vCPU share)
     + C_p·R_l/w      cold dep pages (C_p = distinct pages, merge-join)
     + b·R_l/w        pile→blob copies
     + (D + b/B_l + 2)·R_l   emit + CAS
```

b = 1,000, R_l = 15 ms, 1 GB (0.57 vCPU): 150 + 140 + 30 + 180 + 60 ms ≈
0.6 s ⇒ **~1,600 facts/s** against real S3 — 5× over the 300/s litmus,
margin absorbed by tail latency and cache misses. Against a local sqlite
store the loop is verify-bound: **6–10 k facts/s**. Bottleneck order:
per-fact pile GETs ≈ copies > verify > dep pages > emit. Note vCPU scales
with Lambda memory — 1,769 MB doubles the verify rate.

**Write amplification.**

```text
WA = (ceil(b/B_l) + D) · P / (b·E_l)
```

b = 50 ⇒ ~120×; b = 2,048 ⇒ ~3×. Batching divides WA — and the pile makes
batching free: **facts are visible in the pile the moment they're PUT, so
compaction cadence τ is a pure cost knob, not a delivery-latency knob.**
Choose λτ ≈ B_l/4..B_l where λ allows; floor τ at the parked-dep re-check
interval. CAS contention ≈ 0 under the lease; the CAS is only the safety
net.

## Dollars

Per admitted fact (S3): 1 client PUT + 1 engine GET + 1 COPY + amortized
page PUTs + 1/1000 DELETE ≈ **$11/M facts** written. Storage at 10^6
facts ≈ 0.6 GB ≈ $0.014/mo.

Per active reader per day (adopted tail-range design), c = 60 s,
λ = 10^4/day:

```text
(86400/c)·(cond GET root) + news polls·(tail slice + bundle GETs)
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
engine $0.06 (Lambda ~$0.01 + copies $0.05) + readers $0.04 ≈ **$0.15/day**
— per-fact write costs now dominate; the reader side is solved.

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
pile/<member>/<hash>    raw, per-member quarantine       (unchanged)
tail page               the WAL: validated, deduped,
                        (ts,fid)-sorted, ≤ B_l entries —
                        the treap's rightmost range,
                        content-addressed, its fences
                        inlined in the manifest top run  (new)
bundle/<hash>           news body bundles                (new)
manifest + pages        the rest of the set              (unchanged)
```

```text
validate (on request: peers drain-on-read, cloud on poke; same lease):
  facts <- LIST + par GET pile; verify; dep-resolve vs set + batch
  tail' <- tail ∪ admitted (dedup by fid); stragglers mini-fold their page
  if tail' full: promote stable prefix to pages + fences   # cut rule fires
  PUT blob/<hash> each, bundle, tail', any promoted pages
  CAS manifest                         # the single commit point
  batch DELETE covered pile keys       # pile holds only unvalidated + parked
```

The WAL is the engine's recent window made durable and public — and
since it is (ts,fid)-sorted and capped at B_l entries, **it is literally
the next leaf page, accumulating in public**; promotion freezes it. The
B_l cap (128 KB, one GET) and the promotion threshold coincide — "the
size where serving a flat list becomes impractical" is exactly "one leaf
page". Because its per-slice fences ride in the manifest's top run,
updating it touches no fence pages: no path rebuild.

Reader poll is **one conditional GET of the manifest** — the root
fingerprint covers news too, so "did anything change" has a single
answer, and fetching news is the ordinary fence walk (usually one changed
tail slice + one bundle). No LIST, no per-fact GETs, no raw litter ever
reaching readers (signature checks stay on ingest as defense in depth,
but litter costs readers zero bandwidth). Between promotions the tail is
mostly-append, so the changed-slice diff is usually the last slice; and
being content-addressed, a ranged tail GET can never tear across a
concurrent CAS — a latent hazard of the mutable-key variant, now gone.

Comparison at λ = 10^4/day, c = 60 s, validate cadence 30 s:

| | two-tier (pile→treap) | three-tier (pile→WAL→treap) |
|---|---|---|
| reader $/day | $0.012 (LIST tax + per-fact GETs) | **~$0.002** (5–9×, burstiness-dependent) |
| treap page PUTs/day | ~7,200 (1,440 compactions) | **~25** (~5 promotions) |
| page bytes rewritten/day | ~550 MB | **~2.5 MB** |
| manifest generations/day | 1,440 (walker caches churn) | ~5 (caches warm for hours) |
| news visibility | ~c (if readers LIST-poll fast) | writer poke→validate (~seconds cloud, ms peer) |
| per-fact validate cost | 1 GET + verify + writes | same — conserved |

The conservation law: each fact must be fetched, verified, and written
once at the store no matter the architecture. The tiers only change who
pays on the read path and how often treap pages churn — and that is where
the money was.

**Is the treap fast enough to fan out from directly?** Updating it is
cheap (~4 PUTs, ~$2.5e-5 per promotion) — but per-batch promotion was never the
binding cost; making every reader poll raw piles was. Conversely the
treap alone can't serve news cheaper than τ-freshness. So: immutable
pages for history, the tail range for fan-out, promotion on threshold.

**"Requester always gets the latest, pauses on rebuild":** no pause
exists or is needed. Every tier is publish-then-swap (bundle and pages
PUT before the index CAS that references them), so a requester always
reads the last committed snapshot, and every admitted fact is in ≥1 of
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
  with fewer than one leaf page of entries above it. The whole layout —
  pages, fences, tail — stays a pure function of the set.
- Guard window before a late fact straggles = the tail's time depth,
  B_l/λ — **self-scaling**: ~5 h at λ = 10^4/day, ~2 days at 10^3/day,
  ~30 min at 10^5/day. Busy groups have short windows and present
  members; quiet groups get days.
- A straggler batch (a device reconnecting past the window) clusters by
  ts, so it lands in 1–2 leaf pages: ~2–3 extra PUTs (~$1.5e-5, ~400 KB
  rewritten), committed by the same manifest CAS as the batch's tail
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
cloud; a writer that dies before poking is caught by cadence.

## Where the Platform Binds

- **`root` is the single hot key**: N readers polling every c seconds
  hit 5,500 GET/s at N ≈ 5,500·c (330 k at c = 60). Past that: CDN in
  front of it, or fan-out copies.
- **LIST pages at 1,000 keys**: pile must stay well under 1,000 live
  entries (λτ + parked) or listing goes multi-request. Batch DELETE
  clears 1,000/req.
- **Conditional PUT is native** on S3 (and R2/MinIO/Garage), so manifest
  CAS and `put_if_absent` port everywhere the trait goes.
- **Egress**: at F = 0.5 KB request costs dominate egress; attachments
  flip that — R2 (zero egress) is the default bucket.
- **p2p**: request-$ and egress vanish; only R, W remain. Same loops,
  smaller c, long-poll instead of LIST polling.

## What the Model Changed in DESIGN.md

1. **Fence runs + slices are load-bearing for P1.** The treap survives
   only as the cut function and fingerprint aggregation; on disk it is a
   key-sorted run indexed by per-slice fence runs, with the top run inlined
   in the manifest. Any key range is one contiguous ranged GET per level —
   walk descent, dep probes, and bulk fetches are the same operation.
   Without 8 KB fence-granular fetches, scattered d = 100 costs ~11.6 MB
   and the litmus fails outside the clustered case.
2. **P1 litmus restated** with its locality assumption: clustered (live)
   diffs ⇒ ≤4 rounds, tens-of-KB steady state; scattered ⇒ ~1 MB; worst
   case O((d + D)·P/k) transfer.
3. **Fresh join is request-bound** (per-fact body GETs); leaf-aligned body
   bundles are the candidate fix, filed under the blob open question.
4. **τ is a cost knob, not a latency knob** — the pile decouples delivery
   from compaction; batch toward λτ ≈ B_l/4..B_l.
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
