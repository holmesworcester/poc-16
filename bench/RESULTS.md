# Sync throughput — measured

Current production rows and the historical baseline below were measured on the
same desktop with 100 members, messages spread uniformly over 3 simulated years,
and 8 kernel workers. Every run asserts that the catching-up / reconciled nodes
reach a **byte-identical root** (`ok = y`), so these are throughput numbers on
provably-correct convergence, not best-effort. Absolute seconds carry a few
percent of machine noise.

## Production settle-node check (2026-07-25)

The current fat-tree format stores each fact once at its settle node; the
leaf-only/tiered results below are retained as the baseline it replaced.
Post-landing real-engine runs measured:

| full catchup | facts | streamed | redundancy | transfer | ingest | facts/s | converged |
|---|--:|--:|--:|--:|--:|--:|:--:|
| 5k | 4,999 | 4,999 | **1.00×** | 3.4 MB | 1.21 s | 4,122 | ✓ |
| 50k | 49,999 | 49,999 | **1.00×** | 32.9 MB | 12.84 s | 3,894 | ✓ |

For bidirectional range sync, “useful” is the missing set on that leg and
“streamed” includes the shared authority path needed to judge it:

| scale | union facts | useful pull / push | streamed pull / push | redundancy per leg | transfer pull / push | reconciliation | useful moved/s | converged |
|---|--:|--:|--:|--:|--:|--:|--:|:--:|
| 5k | 4,997 | 2,300 / 2,300 | 2,697 / 2,697 | **1.17×** | 1.8 / 0.9 MB | 1.78 s | 2,583 | ✓ |
| 50k | 49,997 | 24,800 / 24,800 | 25,197 / 25,197 | **1.02×** | 16.6 / 8.6 MB | 19.77 s | 2,509 | ✓ |

The companion prototype rerun measured flat leaf-only `ρ=2.96–2.98×`
(14.8k fact copies for 4,999 facts), while settle storage and full verification
were exactly 4,999 facts, a 66.5% reduction. The production catchup therefore
hits the predicted `ρ→1` floor. A partial range still pays one flat shared-core
tax per leg, visible as 1.17× at 5k and amortized to 1.02× at 50k.
`bench_order.py 5000 star chain` also retained the ordering result: timestamp
range tax is member-wide, delegation order makes it path-shaped, and deep-chain
leaf-only full sync remains about 24× while settle full sync stays 1×.

Reproduce the current path with `python3 bench/bench_sync.py 5000`. The model
cross-check harnesses (`bench_hoist.py`, `bench_hoist_sync.py`,
`bench_order.py`) were deleted with the tree engine (bead poc-16-oyd.5); their
numbers above stand as the record.

## Historical leaf-only baseline

**Retired default: tiered layout, `COLD_CUT = 4096`** (~1.5 MB cold pages under a
fine `CUT = 8` guard window) — the calibrated one-size-fits-most leaf (see
docs/MODEL.md "Leaf Sizing"). Sections 1–2 measure that default; §3 pins flat
(`COLD_CUT = None`) to show the redundancy-vs-page-size law that motivates it;
§4 is the head-to-head. These tables are archival measurements of the former
leaf-closure layout; the current engine does not expose its CUT/tier sweeps.

## 1. Catchup — a fresh node ingests a whole workspace from empty

Decode every published leaf pile, judge each through the kernel (parallel, own
scratchpads — exactly `turn()`), merge by id, one layout commit.

| target facts | facts | pages | dl MB | streamed | redund | ingest s | **facts/s** | rec/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 5k   | 4,999   | 621   | 5.8  | 14,810  | 3.0× | 4.47  | 1,118     | 3,312 | ✓ |
| 10k  | 9,999   | 1,328 | 12.0 | 30,326  | 3.0× | 8.94  | 1,118     | 3,391 | ✓ |
| 50k  | 49,999  | 200   | 19.1 | 57,494  | 1.1× | 6.32  | **7,909** | 9,094 | ✓ |
| 100k | 99,999  | 974   | 41.6 | 122,876 | 1.2× | 17.16 | **5,826** | 7,159 | ✓ |

**Small workspaces stay fine, big ones tier.** A 4096-fact cold page needs enough
history behind the 256-deep guard to seal; below ~5k facts none seals, so 5k/10k
stay fully fine at the flat 3.0× redundancy — but their absolute catchup is
trivial (≤12 MB, <9 s). At 50k+ the cold pages fire and redundancy collapses to
**1.1–1.2×**, with useful `facts/s` jumping to **5,800–7,900 — at the `rec/s`
ceiling** (the raw judge rate). The engine hasn't changed; tiering just stops
re-shipping the membership annex once per leaf.

**The wobble** (50k faster than 100k; pages 200 vs 974) is the floating fine
zone: its size swings between the guard (256) and ~`COLD_CUT`+guard depending on
where the last cold boundary falls relative to `len − GUARD`. More small fine
piles ⇒ more per-unit overhead ⇒ lower `facts/s`, without touching correctness or
the cold-page economics.

## 2. Bidi — two peers, shared membership, disjoint messages, one walk

Each side authors ~half the messages the other lacks; then one one-sided walk —
A prunes by fingerprint, pulls B's differing ranges as closed piles, pushes the
symmetric difference as one closed pile B ingests. Both converge.

| converged | A before | B before | pull facts | push facts | pull MB | push MB | recon s | facts/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 5k   | 2,697  | 2,697  | 7,083  | 2,300  | 2.7  | 0.9  | 2.70  | 1,851 | ✓ |
| 10k  | 5,197  | 5,197  | 14,924 | 4,800  | 5.7  | 1.7  | 6.01  | 1,665 | ✓ |
| 50k  | 25,197 | 25,197 | 31,724 | 24,800 | 10.8 | 8.1  | 10.40 | 4,810 | ✓ |
| 100k | 50,197 | 50,197 | 63,868 | 49,800 | 21.7 | 16.1 | 23.77 | 4,207 | ✓ |

The tiered seed helps reconciliation too: at 50k+ the shared history rides
amortizing cold pages, so the pull leg carries far less annex (pull_facts 31,724
for 50k disjoint, vs 82,015 under the old flat default) and `facts/s` triples
(4,810 vs the old 1,486). Small scales diff only in the fine tail, so they see the
flat pull tax as before. The push leg is one `close()`d pile whose closure ships
once — cheap per fact either way.

## 3. CUT sweep — the redundancy-vs-page-size law (flat, 50k facts)

Flat (`COLD_CUT = None`), varying the fine cut `CUT = E[facts/page]`. This is the
law the tiered default exploits: bigger pages amortize each range's membership
annex over more facts, so redundancy falls and useful `facts/s` climbs toward
`rec/s`.

| CUT | pages | dl MB | streamed | redund | ingest s | facts/s | rec/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 8   | 6,315 | 60.7 | 154,230 | 3.1× | 44.80 | 1,116 | 3,443 | ✓ |
| 16  | 3,114 | 56.3 | 146,066 | 2.9× | 28.25 | 1,770 | 5,171 | ✓ |
| 32  | 1,550 | 52.3 | 137,700 | 2.8× | 19.55 | 2,558 | 7,044 | ✓ |
| 64  | 746   | 46.6 | 124,441 | 2.5× | 14.77 | 3,386 | 8,427 | ✓ |
| 128 | 398   | 41.3 | 111,759 | 2.2× | 12.08 | 4,138 | 9,249 | ✓ |

Uniformly big pages reach the band but tax every write (a one-fact change
re-ships a big page). The tiered default gets the redundancy win **without** that
write tax — only cold history is big; the hot tail stays fine — §4.

## 4. Tiered (shipped default) vs flat — 50k facts

`COLD_CUT = 4096` (~1.5 MB cold pages, guard 256) vs flat `CUT = 8`:

| layout | pages | dl MB | redund | catchup facts/s | leaves judge alone | steady write | p90 | straggler write |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| flat CUT=8 | 6,353 | 60.7 | 3.1× | 1,108 | 6,354 | 4.2 KB | 9.2 KB | 3.6 KB |
| **tiered 4096** | 266 | **20.4** | **1.2×** | **6,827** | 267 | 3.1 KB | 5.9 KB | **222 KB** |

- Catchup **6.2× faster** (1,108 → 6,827 facts/s, at the `rec/s` ceiling) and
  **3× less bandwidth** (60.7 → 20.4 MB); redundancy 3.1 → 1.2×.
- **Leaves-are-piles holds** — all 267 units, cold pages included, judge alone
  from an empty kernel.
- **Steady writes stay cheap** (~6 KB p90, same class as flat).
- **The cost is stragglers**: an old-ts write lands in a sealed cold page and
  re-ships it — **222 KB vs flat's 3.6 KB (~60×)**. The designed trade: big frozen
  pages make the common case (append + catchup) cheap and the rare case (old-ts
  write into cold) expensive.

**Why 4096.** The annex a leaf carries is its authors' membership closure, which
saturates at the ~Dunbar active-writer core — not at total members — so a single
fixed cold-page size holds redundancy flat (~1.1–1.2×) from 100 to 10,000
members (`B* = a·h̄·W/ε` ≈ 3–5k facts; cross-M measurement in docs/MODEL.md "Leaf
Sizing"). 4096 sits at the upper end of the band to absorb deeper delegation
chains. Past ~100k members you want `COLD_CUT ∝ √N` on a dyadic (2:1-merge)
ladder to keep write-amp O(log N); a fixed 4096 is the sample point for the sizes
here.

## Takeaways

- The **engine is poc-7-class**: the judge does 3,300–9,200 records/s, per-fact
  cost flat across scales. Crypto (Ed25519 verify) is the floor.
- **Tiering is the default**, putting useful catchup `facts/s` at the `rec/s`
  ceiling (5,800–7,900 at 50–100k) with **1.1–1.2× redundancy** and 3× less
  bandwidth — the passive-store "every leaf validates alone" tax, once 3.3×, paid
  down to noise for any workspace big enough to seal a cold page.
- **The knobs are principled**: `CUT = 8` fine hot tail (cheap incremental sync),
  `COLD_CUT = 4096` cold pages (cheap catchup), crossover set by the guard window.
  The one residual cost is old-ts stragglers (~60× a hot write).
- **Rebuild/validate is now O(n log n), not O(n²).** `join` validation matched an
  offer by scanning every same-name offer; a covering index `offers(src,name,…)`
  makes it a seek — the fix that lets a 10k-member workspace rebuild without the
  quadratic blowup this refresh would otherwise have hit.

---
*Reproduce the current engine:* `python3 bench/bench_sync.py` (default catchup +
bidi) or `python3 bench/bench_sync.py 500000` (add 500k). The historical
`cut` and `tier` modes intentionally exit instead of presenting the retired
leaf-layout measurements as current. Working dir defaults to a scratchpad path;
override with `BENCH_DIR`.

---

# Attachments — measured

`python3 bench/bench_files.py` on the same desktop. Files are Bao-rooted: one
32-byte BLAKE3 root commits the whole file, each 256 KiB chunk carries its
authentication path, and only verified chunks count toward progress. Every run
reassembles on the receiver and checks that the saved bytes match the source.

## 1. Self-proving overhead

| MB | chunks | proof % | B/chunk | descriptor B | outboard MB | tree keys |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 4 | 6.28 | 15,704 | 656 | 0.06 | 10 |
| 8 | 31 | 6.35 | 16,392 | 658 | 0.50 | 64 |
| 64 | 245 | 6.42 | 16,780 | 661 | 4.00 | 492 |
| 256 | 977 | 6.47 | 16,959 | 662 | 16.00 | 1,956 |

The proof tax stays near 6.3–6.5% while the descriptor remains about 660 bytes.
A per-slice hash list moves that cost into the descriptor and crosses the 8 KB
body-spill threshold at roughly 20 MB of file.

## 2. Author side, cold local store

| MB | chunks | send s | send MB/s | save s | save MB/s | store MB | peak RSS GB | ok |
|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| 64 | 245 | 0.62 | 103.0 | 0.10 | 628.6 | 68.5 | 0.03 | ✓ |
| 256 | 977 | 1.89 | 135.2 | 0.40 | 641.5 | 274.2 | 0.04 | ✓ |
| 1024 | 3,907 | 7.48 | 136.8 | 1.55 | 661.0 | 1,097.4 | 0.08 | ✓ |

Send builds the Bao tree, extracts and verifies each slice, and spills each
proof before publishing the descriptor and chunk facts. Save re-verifies every
slice while atomically assembling the output.

## 3. Download over two real daemons

| MB | chunks | send MB/s | first chunk s | download s | download MB/s | wall MB/s | RSS tx | RSS rx | ok |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| 8 | 31 | 72.4 | 0.21 | 0.26 | 30.6 | 21.5 | 0.03 | 0.04 | ✓ |
| 64 | 245 | 99.1 | 0.31 | 0.73 | 87.9 | 46.6 | 0.03 | 0.04 | ✓ |
| 256 | 977 | 130.7 | 1.04 | 2.71 | 94.5 | 54.9 | 0.05 | 0.05 | ✓ |
| 1024 | 3,907 | 128.9 | 3.83 | 11.04 | 92.8 | 54.0 | 0.08 | 0.09 | ✓ |

Progress becomes visible at the first verified chunk and advances while objects
land. The sequential fetch loop is the remaining throughput ceiling.

## 4. Against the replaced whole-blob path

Same machine and 1 GB payload:

| | whole blob | Bao chunks | |
|---|---:|---:|---|
| send | 78.3 MB/s | 128.9 MB/s | 1.6× faster |
| download | 129.6 MB/s | 92.8 MB/s | 0.72× |
| peak RSS, sender | 10.03 GB | 0.08 GB | 125× less |
| peak RSS, receiver | 5.03 GB | 0.09 GB | 56× less |
| progress | none | per verified chunk | |
| resumable | no | yes | |

The chunked path keeps one roughly 280 KB proof in memory at a time, making
peak memory a function of chunk width rather than file size.

The integration-line rerun after landing measured 31.4 MB/s at 8 MB and
83.9 MB/s at 1,024 MB, byte-identical, with 0.08 GB peak receiver RSS. That is
within the expected sequential-HTTP variance and preserves the memory result.

---
*Reproduce:* `python3 bench/bench_files.py --mode overhead 1 8 64 256`,
`python3 bench/bench_files.py --mode send 64 256 1024`, and
`python3 bench/bench_files.py 8 64 256 1024`. Override the scratch directory
with `BENCH_DIR`.
