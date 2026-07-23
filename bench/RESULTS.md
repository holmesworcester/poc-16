# Sync throughput — measured

`python3 bench/bench_sync.py` against the tinyp2p engine on `main` (after the
`facts/` family split; 30 tests green). 100 members, messages spread uniformly
over 3 simulated years, 8 kernel workers, on this desktop. Every run asserts
the catching-up / reconciled nodes reach a **byte-identical root** (`ok = y`),
so these are throughput numbers on provably-correct convergence, not
best-effort. Numbers were stable across the family refactor and across repeats;
absolute seconds carry a few percent of machine noise, but `rec/s` and the
redundancy factor are rock-steady.

## 1. Catchup — a fresh node ingests a whole workspace from empty

The "download + ingestion" path: decode every published unit (annex ++ page),
judge each through the kernel (parallel, own scratchpads — exactly `turn()`),
merge by id, one layout commit.

| target facts | facts | msgs | pages | seed build | dl MB | streamed | redund | ingest s | **facts/s** | rec/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 5k   | 4,999   | 2,301   | 633    | 1.6s  | 6.3   | 15,929    | 3.2× | 4.36   | 1,147 | 3,655 | ✓ |
| 10k  | 9,999   | 4,801   | 1,273  | 2.0s  | 12.9  | 32,546    | 3.3× | 8.98   | 1,113 | 3,623 | ✓ |
| 50k  | 49,999  | 24,801  | 6,343  | 6.7s  | 65.3  | 165,407   | 3.3× | 45.56  | 1,097 | 3,631 | ✓ |
| 100k | 99,999  | 49,801  | 12,322 | 12.5s | 130.3 | 330,662   | 3.3× | 90.55  | 1,104 | 3,652 | ✓ |
| 500k | 499,999 | 249,801 | 62,247 | 60.8s | 650.2 | 1,655,201 | 3.3× | 462.92 | 1,080 | 3,576 | ✓ |

**Flat to 500k.** `facts/s` (1,080–1,147) and `rec/s` (3,576–3,655) barely move
across two orders of magnitude — the streaming `kernel → merge → single-commit`
pipeline is O(n), no per-fact drift. A 500k-fact / 250k-message workspace,
spread over 3 years, catches up from empty in ~7.7 min, converging
byte-identical.

**Where the magic band is.** `rec/s` — the raw rate the judge chews records —
sits at **~3,600, inside the 2000-5000 band** poc-7..13 hit. But the *useful*
`facts/s` is ~3.3× lower, pinned at ~1,100. That 3.3× is the **annex
redundancy**, and it is the real finding.

**Why 3.3×.** The invariant we proved — *every treap leaf is a closed pile* —
means each range must carry, in its annex, the membership-closure of its
authors (their `join`/`invite`/`sig`/admin facts) so the range validates from
an empty scratchpad. At CUT=8 a page is ~8 facts but drags ~18 annex facts, and
a full catchup pulls *every* range, re-shipping and re-verifying those closures
once per range. `streamed / facts = 3.3` is exactly that tax. The responder
does zero sync work; the puller pays for it in bytes and repeated Ed25519
verifies.

## 2. Bidi — two peers, shared membership, disjoint messages, one walk

Each side authors ~half the messages the other lacks, then one one-sided walk:
A prunes by fingerprint, pulls B's differing ranges as closed units, and pushes
the symmetric difference as one closed pile B ingests. Both converge.

| converged | A before | B before | pull facts | push facts | pull MB | push MB | recon s | facts/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 5k   | 2,697  | 2,697  | 7,619   | 2,300  | 2.9  | 0.9  | 2.84  | 1,756 | ✓ |
| 10k  | 5,197  | 5,197  | 15,872  | 4,800  | 6.1  | 1.7  | 6.13  | 1,630 | ✓ |
| 50k  | 25,197 | 25,197 | 82,015  | 24,800 | 31.6 | 8.1  | 33.65 | 1,486 | ✓ |
| 100k | 50,197 | 50,197 | 165,255 | 49,800 | 63.8 | 16.1 | 71.29 | 1,403 | ✓ |

A 100k-fact converged state (50k disjoint each side) reconciles in ~71s, both
roots byte-identical. Note the **asymmetry**: the *pull* leg carries the annex
tax (165k records for 50k facts), while the *push* leg is one `close()`d pile
whose closure is shared once (16 MB vs 64 MB for the same fact count). Pushing a
batch is far cheaper per fact than pulling range-by-range.

## 3. CUT sweep — the lever that reaches the band (50k facts, same set)

CUT = E[facts per page]. It is the design's byte-economy knob; it is also the
redundancy knob. Bigger pages amortize each range's membership annex over more
facts, so redundancy falls and useful `facts/s` climbs toward `rec/s`.

| CUT | pages | dl MB | streamed | redund | ingest s | **facts/s** | rec/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 8   | 6,331 | 65.1 | 165,144 | 3.3× | 46.40 | 1,078     | 3,559  | ✓ |
| 16  | 3,070 | 61.2 | 157,685 | 3.2× | 28.99 | 1,725     | 5,439  | ✓ |
| 32  | 1,550 | 57.4 | 149,898 | 3.0× | 20.22 | **2,472** | 7,413  | ✓ |
| 64  | 747   | 51.8 | 136,938 | 2.7× | 15.00 | **3,334** | 9,130  | ✓ |
| 128 | 387   | 46.1 | 123,294 | 2.5× | 12.13 | **4,123** | 10,167 | ✓ |

**CUT=8 is pessimal for catchup.** Useful `facts/s` crosses into the magic band
at **CUT=32 (2,472)** and reaches **4,123 at CUT=128** — a 3.8× speedup on the
identical fact set, with download *bytes falling too* (65→46 MB) because there
are fewer annexes to re-ship. `rec/s` also rises (fewer, larger units means less
per-unit scratchpad/thread overhead). The cost of a bigger CUT is coarser sync
granularity: a one-fact change re-ships a larger page, and the minimum fetch is
bigger — the byte-economy tradeoff DESIGN.md flagged, now quantified.

## Takeaways

- The **engine is poc-7-class**: the judge does 3,600–10,000 records/s, and
  per-fact cost is flat from 5k to 500k. Crypto (Ed25519 verify) is the floor,
  as in every prior POC.
- The passive-store / closed-pile design carries a **catchup redundancy tax**
  (~3.3× at CUT=8) — the price of "every leaf validates alone" and a responder
  with zero sync logic. It is structural, not a bug, and constant with scale.
- **CUT is the dial.** For catchup-heavy or cold-start-heavy deployments, a
  larger CUT (≈32–64) puts useful `facts/s` inside the 2000-5000 band while
  *also* cutting bytes; small CUT favors fine-grained incremental sync. Nothing
  in the semantics changes — every row here converges byte-identical.
- A **catchup fast-path** (share one verified-fact set across the ranges pulled
  in a walk, instead of a fresh scratchpad per range) would close most of the
  gap to `rec/s` without touching CUT — the redundant work is re-verification of
  closures the puller has already accepted this session. Left as future work;
  the honest as-built numbers are above.

---
*Reproduce:* `python3 bench/bench_sync.py` (5k–100k catchup + bidi),
`python3 bench/bench_sync.py 500000` (add 500k), `python3 bench/bench_sync.py cut`
(CUT sweep). Working dir defaults to a scratchpad path; override with `BENCH_DIR`.
