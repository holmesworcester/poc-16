# Sync throughput — measured

`python3 bench/bench_sync.py` against the green engine (commit `267f961`).
100 members, messages spread uniformly over 3 simulated years, 8 kernel
workers, on this desktop. Every run asserts the catching-up / reconciled
nodes reach a **byte-identical root** (`ok = y`), so these are throughput
numbers on provably-correct convergence, not best-effort.

> Measured while an unrelated full-codebase refactor was running on the same
> machine, so absolute seconds carry ±15% noise. `rec/s` (raw judge rate) and
> the redundancy factor are stable across repeats.

## 1. Catchup — a fresh node ingests a whole workspace from empty

The "download + ingestion" path: decode every published unit (annex ++ page),
judge each through the kernel (parallel, own scratchpads — exactly `turn()`),
merge by id, one layout commit.

| target facts | facts | msgs | pages | seed build | dl MB | streamed | redund | ingest s | **facts/s** | rec/s | ok |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|:--:|
| 5k   | 4,999   | 2,301   | 666    | 1.6s  | 6.4   | 16,021    | 3.2× | 6.72   | 744   | 2,384 | ✓ |
| 10k  | 9,999   | 4,801   | 1,282  | 2.7s  | 12.9  | 32,503    | 3.3× | 8.96   | 1,116 | 3,629 | ✓ |
| 50k  | 49,999  | 24,801  | 6,245  | 6.6s  | 65.1  | 164,950   | 3.3× | 43.66  | 1,145 | 3,778 | ✓ |
| 100k | 99,999  | 49,801  | 12,495 | 12.4s | 130.4 | 331,101   | 3.3× | 88.30  | 1,133 | 3,750 | ✓ |
| 500k | 499,999 | 249,801 | 62,228 | 60.5s | 650.6 | 1,656,077 | 3.3× | 458.74 | 1,090 | 3,610 | ✓ |

**Flat to 500k.** `facts/s` and `rec/s` barely move across two orders of
magnitude — the streaming `kernel → merge → single-commit` pipeline is O(n),
no per-fact drift. A 500k-fact / 250k-message workspace, spread over 3 years,
catches up from empty in ~7.6 min, converging byte-identical.

**Where the magic band is.** `rec/s` — the raw rate the judge chews records —
sits at **2,400–3,800, squarely in the 2000-5000 band** poc-7..13 hit. But the
*useful* `facts/s` is ~3.3× lower, pinned at ~1,090–1,145. That 3.3× is the
**annex redundancy**, and it is the real finding.

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
| 5k   | 2,697  | 2,697  | 7,586   | 2,300  | 2.9  | 0.9  | 2.77  | 1,804 | ✓ |
| 10k  | 5,197  | 5,197  | 15,924  | 4,800  | 6.1  | 1.7  | 6.03  | 1,658 | ✓ |
| 50k  | 25,197 | 25,197 | 82,111  | 24,800 | 31.7 | 8.1  | 32.13 | 1,556 | ✓ |
| 100k | 50,197 | 50,197 | 165,217 | 49,800 | 63.8 | 16.1 | 69.05 | 1,448 | ✓ |

A 100k-fact converged state (50k disjoint each side) reconciles in ~69s, both
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
| 8   | 6,224 | 65.1 | 165,102 | 3.3× | 43.84 | 1,140     | 3,766  | ✓ |
| 16  | 3,185 | 61.5 | 158,375 | 3.2× | 28.22 | 1,772     | 5,612  | ✓ |
| 32  | 1,562 | 57.5 | 150,086 | 3.0× | 19.51 | **2,563** | 7,692  | ✓ |
| 64  | 819   | 52.6 | 138,849 | 2.8× | 14.70 | **3,402** | 9,446  | ✓ |
| 128 | 392   | 46.0 | 123,099 | 2.5× | 11.41 | **4,383** | 10,791 | ✓ |

**CUT=8 is pessimal for catchup.** Useful `facts/s` crosses into the magic band
at **CUT=32 (2,563)** and reaches **4,383 at CUT=128** — a 3.8× speedup on the
identical fact set, with download *bytes falling too* (65→46 MB) because there
are fewer annexes to re-ship. `rec/s` also rises (fewer, larger units means less
per-unit scratchpad/thread overhead). The cost of a bigger CUT is coarser sync
granularity: a one-fact change re-ships a larger page, and the minimum fetch is
bigger — the byte-economy tradeoff DESIGN.md flagged, now quantified.

## Takeaways

- The **engine is already poc-7-class**: the judge does 2,400–10,800 records/s,
  and per-fact cost is flat from 5k to 500k. Crypto (Ed25519 verify) is the
  floor, as in every prior POC.
- The passive-store / closed-pile design carries a **catchup redundancy tax**
  (~3.3× at CUT=8) — the price of "every leaf validates alone" and a responder
  with zero sync logic. It is structural, not a bug, and constant with scale.
- **CUT is the dial.** For catchup-heavy or cold-start-heavy deployments, a
  larger CUT (≈32–64) puts useful `facts/s` inside the 2000-5000 band while
  *also* cutting bytes; small CUT favors fine-grained incremental sync. Nothing
  in the semantics changes — every row here converges byte-identical.
- A **catchup fast-path** (dedup annex facts already verified this session,
  instead of a fresh scratchpad per range) would close most of the gap to
  `rec/s` without touching CUT — the redundant work is re-verification of
  closures the puller has already accepted. Left as future work; the honest
  as-built numbers are above.
