# Sync throughput — measured

`python3 bench/bench_sync.py` against the tinyp2p engine on `main`. 100 members,
messages spread uniformly over 3 simulated years, 8 kernel workers, on this
desktop. Every run asserts the catching-up / reconciled nodes reach a
**byte-identical root** (`ok = y`), so these are throughput numbers on
provably-correct convergence, not best-effort. `rec/s` and the redundancy factor
are steady across repeats; absolute seconds carry a few percent of machine noise.

**Shipped default: tiered layout, `COLD_CUT = 4096`** (~1.5 MB cold pages under a
fine `CUT = 8` guard window) — the calibrated one-size-fits-most leaf (see
MODEL.md "Leaf Sizing"). §1–2 measure that default; §3 pins flat
(`COLD_CUT = None`) to show the redundancy-vs-page-size law that motivates it;
§4 is the head-to-head.

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
members (`B* = a·h̄·W/ε` ≈ 3–5k facts; cross-M measurement in MODEL.md "Leaf
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
*Reproduce:* `python3 bench/bench_sync.py` (default catchup + bidi),
`python3 bench/bench_sync.py 500000` (add 500k), `python3 bench/bench_sync.py cut`
(flat CUT sweep), `python3 bench/bench_sync.py tier` (tiered vs flat).
Working dir defaults to a scratchpad path; override with `BENCH_DIR`.

---

# Attachments — measured

`python3 bench/bench_files.py` on the same desktop. Files are bao-rooted: one
32-byte BLAKE3 root commits the whole file, each 256 KiB chunk carries the
authentication path that proves it against that root, and only chunks that
verify count toward progress. Every run below re-assembles on the receiver and
asserts the saved bytes are identical to the source (`ok = ✓`).

## 1. What self-proving costs

| MB | chunks | proof % | B/chunk | descriptor B | outboard MB | tree keys |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 4 | 6.28 | 15,704 | 652 | 0.06 | 10 |
| 8 | 31 | 6.35 | 16,392 | 654 | 0.50 | 64 |
| 64 | 245 | 6.42 | 16,780 | 657 | 4.00 | 492 |
| 256 | 977 | 6.47 | 16,959 | 658 | 16.00 | 1,956 |

The proof tax is ~6.3–6.5 % of payload, flat. What it buys is the fourth
column: the **descriptor stays ~655 bytes at every size** — the commitment is
O(1), so a 1 GB attachment costs the fact tree no more metadata than a 1 MB one.
A per-slice hash list would put that cost in the descriptor instead, growing it
past the 8 KB body-spill threshold at ~20 MB of file. Both are defensible; this
is the trade, priced.

## 2. Author side (in-process, cold store)

| MB | chunks | send s | send MB/s | save s | save MB/s | store MB | peak RSS GB | ok |
|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| 64 | 245 | 0.62 | 103.0 | 0.10 | 628.6 | 68.5 | 0.03 | ✓ |
| 256 | 977 | 1.89 | 135.2 | 0.40 | 641.5 | 274.2 | 0.04 | ✓ |
| 1024 | 3,907 | 7.48 | 136.8 | 1.55 | 661.0 | 1,097.4 | 0.08 | ✓ |

`send` builds the bao tree, extracts every slice, verifies each one against the
root *before* signing anything, and spills it to `obj/`. `save` re-verifies
every chunk on the way out — export never trusts the projection.

## 3. Download, two real daemons on real sockets

| MB | chunks | send MB/s | first chunk s | download s | download MB/s | wall MB/s | RSS tx | RSS rx | ok |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|:--:|
| 8 | 31 | 72.4 | 0.21 | 0.26 | 30.6 | 21.5 | 0.03 | 0.04 | ✓ |
| 64 | 245 | 99.1 | 0.31 | 0.73 | 87.9 | 46.6 | 0.03 | 0.04 | ✓ |
| 256 | 977 | 130.7 | 1.04 | 2.71 | 94.5 | 54.9 | 0.05 | 0.05 | ✓ |
| 1024 | 3,907 | 128.9 | 3.83 | 11.04 | 92.8 | 54.0 | 0.08 | 0.09 | ✓ |

`first chunk` is time to the receiver's first *verified* chunk — progress is
visible from there on, climbing as objects land, not a step function at the end.

## 4. Against the whole-blob path this replaces

Same box, same 1 GB payload, two daemons. The old path put the entire file in one
object and shipped it base64'd through one JSON document.

| | whole blob | bao chunks | |
|---|---:|---:|---|
| send | 78.3 MB/s | 128.9 MB/s | 1.6× faster |
| download | 129.6 MB/s | 92.8 MB/s | 0.72× — the honest cost |
| peak RSS, sender | 10.03 GB | 0.08 GB | **125× less** |
| peak RSS, receiver | 5.03 GB | 0.09 GB | **56× less** |
| progress | none | per 256 KiB chunk | |
| resumable | no | yes | |

Download throughput is the one number that got worse: 3,907 sequential object
GETs cost more than one 1 GB GET. That is the price of chunking, and it is where
the remaining headroom is — the fetch is strictly sequential today.

The memory column is why the trade is worth taking anyway. The old path needed
**10 GB of RAM to send a 1 GB file** (raw bytes, base64 string, JSON document,
and canonical encoding all resident at once); peak memory scaled with file size,
so 1 GB was near the practical ceiling on a 16 GB machine and 10 GiB was
unreachable. The chunked path holds one 280 KB proof at a time: peak memory is
now a function of chunk width, not file size.

## Takeaways

- **1 GB works and is efficient**: 11 s to download, 93 MB/s, byte-identical,
  under 100 MB of RAM on both ends.
- **Peak memory is decoupled from file size.** This, not throughput, is what
  chunking bought.
- **Verified progress is real progress.** A chunk counts only after its bao proof
  checks against the signed root, so the percentage cannot run ahead of what the
  receiver can actually prove it has.
- **bao is not the bottleneck.** The primitive runs at 516 MB/s encoding and
  761 MB/s verifying at 1 GiB; the engine's JSON/base64 unit codec (~190 MB/s)
  and the sequential fetch loop are what bound the numbers above.

---
*Reproduce:* `python3 bench/bench_files.py --mode overhead 1 8 64 256`,
`python3 bench/bench_files.py --mode send 64 256 1024`,
`python3 bench/bench_files.py 8 64 256 1024`.
Working dir defaults to a scratchpad path; override with `BENCH_DIR`.
