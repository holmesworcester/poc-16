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
| k | sub-fingerprints per child record | 16 |
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

## Geometry

- Leaf pages: `n/B_l` — 489 at 10^6, 488 k at 10^9.
- Paged depth `D = 1 + ceil(log_{B_i}(n/B_l))` — **D = 2** at 10^6 (one fat
  root page, 489·352 B ≈ 172 KB), **D = 3** at 10^9.
- **Slices**: pages are cut at fixed entry boundaries (128 entries = 8 KB);
  byte offsets are computable because records are fixed-size, so a slice is
  a ranged GET, never a separate object. The parent's child record carries
  k sub-fingerprints locating which slice of the child differs.
- **Manifest** (~0.5 KB): `{generation, root page hash, root's own k
  sub-fps, auth snapshot ref}`. Carrying the root's sub-fingerprints in the
  manifest lets a repeat walker skip the root page and fetch only changed
  root slices — one conditional GET prices the whole tree.
- Fingerprints are 16 B (128-bit second-preimage margin); sub-fps could
  drop to 8 B (a collision only hides a diff until the next cadence —
  availability, not integrity) but 16 B is the default.

## The Walk — receive loop (P1)

Annotated `[round | requests | bytes]`; all fetches within a level are
parallel (≤100 in flight, far under per-prefix limits).

```text
every c seconds, or on news hint:
  m  <- GET /root If-None-Match etag       # 1 | 1 | 0.5 KB   304 ⇒ pile scan only
  rs <- ranged GET root slices whose
        sub-fp ≠ cached                    # 2 | ≤k | 11 KB each
  for child record with fp ≠ local fp:
     count gap huge ⇒ bulk range fetch/push (contiguous entries ⇒ few big ranged GETs)
     else mark differing child slices via its sub-fps
  [interior levels, same step]             # +1 round each beyond D=2
  ls <- ranged GET differing leaf slices   # 3 | L(d) | 8 KB each
  diff <- entries(ls) ⊖ local entries      # exact, in BOTH directions
  bodies <- par GET blob/<fid> I lack      # 4 | d_pull | d_pull·F
  pile  <- LIST + par GET unseen entries   # 4 (concurrent) | 1+Δ | Δ·F
  validate pulled facts; apply; then send-loop tail
```

**Rounds.** `R_w = D + 2` sequential (manifest, root slices, leaf slices,
bodies): **4 at 10^6, 5 at 10^9**. Steady state is usually 1 (304).

**Transfer.**

```text
T(d) ≈ 0.5 KB + S_root·11 KB + L(d)·(P/k) + d_pull·F
L(d) ≈ ρ·ceil(d / (B_l/k))  +  (1−ρ)·d        (birthday-corrected for large d)
```

Locality is the whole game: ts leads the key, so live diffs land in the
rightmost slices (`ρ→1`) and `L(d) ≈ d/128`. Scattered diffs (old edits,
parked facts arriving late) pay one slice each. Worst-case transfer is
`O((d + D)·P/k)` — the "log n" of P1's O(d·log n) claim lives in D, and
the constant is the slice size, not the page size.

Three regimes at n = 10^6, k = 16:

| regime | rounds | bytes | notes |
|---|---|---|---|
| steady repeat, λc = 50, clustered | ≤4 | ~45 KB + bodies | the common loop |
| cold cache, d = 100 scattered | 4 | ~1 MB | full root 172 KB + ~100 slices + bodies |
| fresh join | bw-bound | n·(E_l+F) ≈ 0.6 GB | see below |

**Litmus check.** "≤4 rounds, ≤ low hundreds of KB" holds for the
recent-clustered case — which ts-keying makes the live case — and holds
scattered only because of slicing: page-granularity fetches would be ~90
pages ≈ **11.6 MB**, a 40× miss. Slicing is load-bearing for P1, not an
optimization.

**Fresh join** is body-request-bound, not byte-bound: 10^6 individual
`blob/` GETs ≈ 5.5 min at 3 k GET/s (and $0.40). Metadata is fine (489
pages, one round). If joins matter, the fix is body bundles aligned to
leaf pages — folded into the blob open question, with its own write
amplification cost (rewriting a bundle costs B_l·F ≈ 1 MB).

**Time.** `t ≈ R_w·R + T/W`. Steady repeat over WAN: 4·50 ms + 45 KB at
25 Mbps ≈ **0.25 s**. Same shape over iroh; only R changes.

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

Per active reader per day, c = 60 s, λ = 10^4/day:

```text
(86400/c)·(GET_manifest + LIST) + λ_day·GET_pile + slice GETs
= 1440·($0.4e-6 + $5e-6) + 10^4·$0.4e-6 + ε  ≈ $0.012
+ egress ~6 MB·$0.09/GB               ≈ $0.0006   (R2: 0)
≈ $0.013/day  (~$0.40/mo)
```

**LIST is the poll tax**: 12.5× a GET, paid every poll whether or not
there is news, and it dominates the reader bill. Levers: cadence c
(linear), a *follower tier* that polls the manifest only (τ-fresh, no
LIST, ~$0.002/day), long-poll on peers (tax → 0), R2 (egress → 0).

Group per day (20 active readers, λ = 10^4, c = 60): writers $0.05 +
engine $0.06 (Lambda ~$0.01 + copies $0.05) + readers $0.26 ≈ **$0.37/day**
— reader polling dominates everything; c and tiers are the levers.

Lambda memory: hot set = auth snapshot + right-edge pages + recent window
≈ tens of MB ≪ 1 GB. RAM bills only during execution (~pennies/day at
this cadence) — "memory beats lookups" survives contact with the loop
numbers.

## The Fresh Log — Two-Stage Engine (proposed)

The model above pins two costs to one decision — that the raw pile is the
only sub-τ tier. Read side: every poll pays LIST + per-fact pile GETs and
readers chew raw litter. Write side: compacting on a fast cadence means
small batches, and WA at b = 50 is ~120×. Splitting the engine into
**validate** (fast cadence) and **fold** (threshold-triggered) removes
both:

```text
pile/<member>/<hash>    raw, per-member quarantine        (unchanged)
fresh                   CAS'd index: validated, deduped,
                        (ts,fid)-sorted, ≤ B_l entries    (new)
freshblob/<gen>         body bundles for fresh entries    (new)
manifest + pages        folded history                    (unchanged)
```

```text
validate (cadence seconds, same lease):
  facts <- LIST + par GET pile; verify; dep-resolve vs treap+fresh+batch
  PUT blob/<hash> each; PUT freshblob/<gen> bundle
  CAS fresh index (append admitted, dedup by fid)
  batch DELETE promoted pile keys      # pile holds only unvalidated + parked

fold (when |fresh| ≥ B_l or age ≥ τ_max):
  emit pages from fresh entries        # ~1 leaf + D spine PUTs
  CAS manifest
  CAS fresh index (drop folded)        # briefly in both, never in neither
```

The fresh log is the engine's recent window made durable and public — and
since it is (ts,fid)-sorted and capped at B_l entries, **it is literally
the next leaf page, accumulating in public**; the fold freezes it and
rewrites the spine. The B_l cap (128 KB, one GET) and the fold threshold
coincide — "the size where serving a flat list becomes impractical" is
exactly "one leaf page".

Reader poll becomes conditional GET `fresh` (+ manifest): no LIST, one
bundle GET per news batch instead of per-fact GETs, no raw litter ever
reaching readers (signature checks stay on ingest as defense in depth,
but litter costs readers zero bandwidth).

Comparison at λ = 10^4/day, c = 60 s, validate cadence 30 s:

| | two-tier (pile→treap) | three-tier (pile→fresh→treap) |
|---|---|---|
| reader $/day | $0.012 (LIST tax + per-fact GETs) | **$0.0013** (~9×) |
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
history, fresh log for fan-out, fold on threshold.

**"Requester always gets the latest, pauses on rebuild":** no pause
exists or is needed. Every tier is publish-then-swap (bundle and pages
PUT before the index CAS that references them), so a requester always
reads the last committed snapshot, and every admitted fact is in ≥1 of
{pile, fresh, treap} at all times. Peers long-poll `fresh` instead of
`root`.

Cost: one more mutable CAS'd object, and DESIGN.md's Pile/Engine sections
change. Recommended, pending that edit.

## Where the Platform Binds

- **Root is one key = one prefix**: N readers polling every c seconds hit
  5,500 GET/s at N ≈ 5,500·c (330 k at c = 60). Past that: CDN in front
  of `/root`, or fan-out root copies.
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

1. **Slices + sub-fingerprints are load-bearing for P1.** Interior records
   carry k sub-fps per child; the manifest carries the root's own sub-fps;
   walkers fetch 8 KB ranged slices, not 128 KB pages. Without this,
   scattered d = 100 costs ~11.6 MB and the litmus fails outside the
   clustered case.
2. **P1 litmus restated** with its locality assumption: clustered (live)
   diffs ⇒ ≤4 rounds, tens-of-KB steady state; scattered ⇒ ~1 MB; worst
   case O((d + D)·P/k) transfer.
3. **Fresh join is request-bound** (per-fact body GETs); leaf-aligned body
   bundles are the candidate fix, filed under the blob open question.
4. **τ is a cost knob, not a latency knob** — the pile decouples delivery
   from compaction; batch toward λτ ≈ B_l/4..B_l.
5. **LIST is the reader poll tax**; the follower tier (manifest-only
   freshness) exists in the cost model as the cheap class.
