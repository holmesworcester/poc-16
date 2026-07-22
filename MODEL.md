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
- **Manifest** (~1.5 KB): `{generation, top fence run inline, auth ref,
  wal ref}` — one conditional GET prices the whole tree *and* locates
  every top-level range.
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
  m  <- GET /root If-None-Match etag       # 1 | 1 | 1.5 KB   top fences inline; 304 ⇒ wal check only
  f1 <- ranged GET L1 fence slices under
        top fences with fp ≠ local        # 2 | F1 | 8 KB each
     count gap huge ⇒ bulk fetch/push (any range = contiguous GETs)
  [one more fence level at 10^9]           # +1 round
  ls <- ranged GET leaf slices under
        differing fences                   # 3 | L(d) | 8 KB each
  diff <- entries(ls) ⊖ local entries      # exact, in BOTH directions
  bodies <- par GET blob/<fid> I lack      # 4 | d_pull | d_pull·F
  wal <- cond GET index (tail range)
         + unseen bundles                  # 4 (concurrent) | ~2 | ΔKB + Δ·F
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

(Modeled here as one pass; the adopted design splits it into validate +
fold — see The WAL below — which changes cadence and write amplification,
not the per-fact costs.)

```text
on S3→SQS batch / in-process debounce, under lease:
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

Per active reader per day (adopted WAL design), c = 60 s, λ = 10^4/day:

```text
(86400/c)·(cond GET root + cond GET wal) + news polls·(tail + bundle GETs)
= 1440·2·$0.4e-6 + ~700·2·$0.4e-6      ≈ $0.0017
+ egress ~6 MB·$0.09/GB                ≈ $0.0006   (R2: 0)
≈ $0.002/day  (~$0.07/mo)
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

## The WAL — Two-Stage Engine (adopted)

The model above pins two costs to one decision — that the raw pile is the
only sub-τ tier. Read side: every poll pays LIST + per-fact pile GETs and
readers chew raw litter. Write side: compacting on a fast cadence means
small batches, and WA at b = 50 is ~120×. Splitting the engine into
**validate** (fast cadence) and **fold** (threshold-triggered) removes
both:

```text
pile/<member>/<hash>    raw, per-member quarantine        (unchanged)
wal                     CAS'd index: validated, deduped,
                        (ts,fid)-sorted, ≤ B_l entries    (new)
walblob/<gen>           body bundles for wal entries      (new)
manifest + pages        folded history                    (unchanged)
```

```text
validate (every arrival; peers also drain-on-read, same lease):
  facts <- LIST + par GET pile; verify; dep-resolve vs treap+wal+batch
  PUT blob/<hash> each; PUT walblob/<gen> bundle
  CAS wal index (append admitted, dedup by fid)
  batch DELETE promoted pile keys      # pile holds only unvalidated + parked

fold (when |wal| ≥ B_l or age ≥ τ_max):
  emit pages + fences from wal         # ~1 leaf + fence rewrite PUTs
  CAS manifest
  CAS wal index (drop folded)          # briefly in both, never in neither
```

The WAL is the engine's recent window made durable and public — and
since it is (ts,fid)-sorted and capped at B_l entries, **it is literally
the next leaf page, accumulating in public**; the fold freezes it and
rewrites the fences. The B_l cap (128 KB, one GET) and the fold threshold
coincide — "the size where serving a flat list becomes impractical" is
exactly "one leaf page".

Reader poll becomes conditional GET `wal` (+ manifest): no LIST, one
bundle GET per news batch instead of per-fact GETs, no raw litter ever
reaching readers (signature checks stay on ingest as defense in depth,
but litter costs readers zero bandwidth). Between folds the index is
mostly-append, so readers ranged-GET its tail from their last-seen
offset; a header fingerprint detects the rare mid-run insert (late ts)
and forces a full ≤128 KB re-GET.

Comparison at λ = 10^4/day, c = 60 s, validate cadence 30 s:

| | two-tier (pile→treap) | three-tier (pile→WAL→treap) |
|---|---|---|
| reader $/day | $0.012 (LIST tax + per-fact GETs) | **~$0.002** (5–9×, burstiness-dependent) |
| treap page PUTs/day | ~7,200 (1,440 folds) | **~25** (~5 folds) |
| page bytes rewritten/day | ~550 MB | **~2.5 MB** |
| manifest generations/day | 1,440 (walker caches churn) | ~5 (caches warm for hours) |
| news visibility | ~c (if readers LIST-poll fast) | validator cadence (5–30 s cloud, ms peer) |
| per-fact validate cost | 1 GET + verify + writes | same — conserved |

The conservation law: each fact must be fetched, verified, and written
once at the store no matter the architecture. The tiers only change who
pays on the read path and how often treap pages churn — and that is where
the money was.

**Is the treap fast enough to fan out from directly?** Updating it is
cheap (~4 PUTs, ~$2.5e-5 per fold) — but per-batch folding was never the
binding cost; making every reader poll raw piles was. Conversely the
treap alone can't serve news cheaper than τ-freshness. So: treap for
history, WAL for fan-out, fold on threshold.

**"Requester always gets the latest, pauses on rebuild":** no pause
exists or is needed. Every tier is publish-then-swap (bundle and pages
PUT before the index CAS that references them), so a requester always
reads the last committed snapshot, and every admitted fact is in ≥1 of
{pile, wal, treap} at all times. Peers long-poll `/wal` instead of
`/root`.

Adopted (2026-07-22): DESIGN.md names the tier the WAL; validate runs on
every pile arrival, and on peers also before serving `/wal`, making
"requester always gets the latest" literal p2p and
arrival-cadence-approximate on a store that cannot compute on read.

## Where the Platform Binds

- **`root` and `wal` are single keys** (one prefix each): N readers
  polling every c seconds hit 5,500 GET/s at N ≈ 5,500·c (330 k at
  c = 60). Past that: CDN in front of them, or fan-out copies.
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
6. **The WAL tier was adopted** (section below): validate every pile
   arrival into a CAS'd validated log served to readers; fold into the
   treap at ~one leaf page. DESIGN.md's Pile and Engine sections now say
   this.
