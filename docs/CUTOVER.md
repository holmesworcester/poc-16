# One-store cutover — execution plan

Status: plan of record (2026-07-26). Epic: poc-16-oyd (children .1-.7 map to
§4's steps). Branch: removal-index, worktree ~/poc-16-removals. Companions:
docs/REMOVALS.md (removal semantics — unchanged by this plan; epic poc-16-3fo's
sync/node/demolition beads execute inside steps .3-.7 here) and docs/COSTS.md
(the economics and measurements that forced every choice below).

## 1. End state

Six object kinds and nothing else in the store:

    root · manifest shards · leaf piles · closure siblings · removal index · blobs

- A fact's bytes live **once**, inlined in its home leaf's pile. Every
  cross-leaf need is a ref by key `<ts:015d>:<fid>` (dep refs carry the dep's
  ts — envelope break). Self-certification: fid in the key checks the body.
- The **root** is the only mutable fact-layer key:
  `{anchor, globals, manifest: <oid>, removals: {oid, fp}, stamp}`
  (`manifest.encode_root`). The removal index is the only structure keeping
  a fingerprint beside its oid (REMOVALS.md I4); everything else is
  identified by oid alone.
- The spine is a **manifest** of `(sep, leaf_oid, closure_oid)` entries,
  sharded by the same boundary rule as the leaves; depth 0 below ~4k facts,
  1 to ~260k, 2 to ~16M. No fingerprints, no n-counts, no key arrays —
  **oid comparison is the entire one-sided diff**.
- The **closure sibling** per leaf holds the keys of the members' transitive
  closure that fall **outside the leaf's key range** — everything a reader of
  the range must fetch from elsewhere. Whole fetch and warm sync never fetch
  it; cold-partial readers get a deterministic two-wave closure fetch.
- Leaf density CUT = 64 (the knee where clones go bandwidth-bound, COSTS §6).
- The removal index rides beside the tree per REMOVALS.md, fetched before the
  fact leg, consulted head+slice for in-range keys.
- No compat: one layout stamp forces rebuild; old paths are deleted in the
  same step that replaces them, never shimmed.

## 2. The fetch/judgment contract

**Kernel requires a closure; the fetch process assembles it; the kernel
judges it — and never learns where it came from.**

1. Pull diffs the manifest by oid and fetches missing leaf piles.
2. For each fetched range, closure assembly resolves every dep **from our own
   store first** (`resolve_deps` against the index); the remainder comes from
   the closure siblings: union the fetched leaves' sibling keys, drop keys we
   hold, group by home leaf (`fetch_plan` over `locate()`), one batched GET
   wave, then extract exactly the needed facts from each fetched pile by key.
   Sibling keys are **transitive**, so wave 2 is final — assert, don't loop.
3. The assembled closed set is delivered to the **ordinary ingress admission**
   — the same closed-pile judgment push and mint use. One judge. Sync stops
   special-casing "their side" entirely.
4. The **removal consult is for in-range keys only** and gates **E, never V**:
   range evaluation reads the index head plus the `[a,b]` slice and applies
   `applies(r,f)` to in-range facts. Out-of-range deps enter V with no removal
   look — a dead dep is still valid *evidence* (deletion hides content, not
   evidence). A dep's own E-status is resolved wherever it is read as a member
   of its own range.

## 3. DRY inventory — one of each, used everywhere

| mechanism | the one implementation | serves |
|---|---|---|
| pile codec | `close.encode_pile`/`decode_pile` | ingress, push, mint, **resident leaves** |
| chunking rule | `shape.boundary` | leaf cuts **and** manifest shards |
| address form | `shape.key` `<ts>:<fid>` | tree position, dep refs, closure siblings, removal spans |
| closure edges | `kernel.resolve_deps` | judgment, closure assembly, sibling derivation |
| judge | ingress admission path | every arriving fact, regardless of source |
| suppression consult | `removals.overlapping` + `applies` | range evaluation and single-fact stab |
| identity / diff / verify | content addressing (oids) | manifest diff, dedup, integrity (fp survives only in the removal index, I4) |

Anything that duplicates one of these rows is cruft and gets deleted in the
step that touches it.

## 4. Steps (= beads oyd.1-.7; each step deletes what it replaces)

Every bead's full agent brief lives in the bead itself (`bd show
poc-16-oyd.N`); the summaries here are the map, the briefs are the orders.

1. **Skeletons** — this document; skeleton stubs in `core/manifest.py`,
   `core/sync.py` (tail section), `core/node.py` (`apply_removals`),
   `core/removals.py`, `facts/content/delete.py`; skip-marked contracts in
   `tests/test_cutover.py` + `tests/test_removals.py`. Landed with the plan.
2. **Manifest + residency** — fill `core/manifest.py` (all nine functions);
   node `commit`/`rebuild` emit and read leaf piles (encode_pile of members,
   canonical key order), closure siblings, manifest shards, and the new
   root; CUT 8→64; `manifest.LAYOUT` stamp. *Deletes (falls out of the
   commit/rebuild rewrite):* tree.py's build/fold path for FACT, the SUPP
   tree publication (second `layout()`, root indexes) and validation walk,
   `_backfill_supp`. *Tests:* test_cutover §oyd.2 block.
3. **Sync rewrite** — fill `sync.pull_removals` + `sync.assemble`; rewrite
   `sync.sync` as removal leg first (3fo.2) → `manifest.diff` pull →
   assembly per §2 → ordinary admission. Push keeps `walk._push`. *Deletes:*
   the tree.diff/fp loop, SUPP leg + `_empty(SUPP)`, `closure_sync`,
   `close_deletions` call, SUPP-form root validation. *Tests:* test_cutover
   §oyd.3 block + test_removals sync contract.
4. **Read contract + retraction** — the ONE consult path
   (`removals.overlapping` + `applies`) at range evaluation, victim
   admission, and pump's rebuild branch; fill `node.apply_removals`
   (retroactive '-' rows via the supp table); in-range keys only, gating E
   never V (3fo.3). Kernel `refs_seen` (kernel.py:368-370) is **unchanged**
   — a closed store always holds the victim before the removal fact; only
   index *entries* precede victims, via sync. *Deletes:* the
   deletion-admission-only `victims()` hook in `_log_projection`. The supp
   **table** stays (local victims index). *Tests:* test_cutover §oyd.4 block
   + test_removals retraction/prune contracts.
5. **Demolition sweep** — REMOVALS.md §6 residue: shape.py SUPP machinery,
   suppression.py walks (keep the clear-envelope primitives), tree.py
   survivors with no remaining callers, hoist/layout/treap/legacy-flat
   candidates; retarget T_supp test halves (3fo.5). Suite green, grep-proof
   zero dead symbols.
6. **Proofs** — un-skip and fill every remaining contract in
   tests/test_cutover.py and tests/test_removals.py (3fo.6); property
   harness = tests/util.py `replay_random`/`projection_state`.
7. **Measure** — register `facts/content/delete.py`, first production
   deletion end to end; bench rerun on the new encoding into COSTS.md §3-§4;
   index growth + prune-cascade numbers (3fo.7).

Suite discipline: every step ends green, where green includes explicit
skips. The format break happens once, in step 2, behind the layout stamp —
step 2 therefore skip-marks every test that pulls through the old sync or
reads old tree internals with the literal marker
`skip(reason="CUTOVER_SKIP: lands in oyd.N")`, and each later step's
done-criterion includes `grep -rn CUTOVER_SKIP tests/` showing none left for
its number. Unit layers (kernel, pump, families, removals) must never enter
the skip window.

## 5. Explicitly not built

- The frontier wave-walk loop for closure fetch — subsumed by the sibling
  (the deterministic two-wave fetch is *less code* than the loop, which is
  why the sibling is adopted now rather than held as a hatch).
- Grandparent key hints; first-contact auth-warmup (COSTS §5 hatches).
- Segmented/treap removal index (size dial waits for production deletions).
- Two-sided fingerprint reconciliation (returns as an addition if live
  peering ever does).
- GC/compaction (posture unchanged, REMOVALS.md §7).
- Blob fetch policy (`_fetch_blobs` eagerness) — flagged in COSTS §6, its
  own decision, not this epic.

## 6. Standing constraints

Daemon endpoints (root/page/pile/mint) keep their shapes; `Peer.objs`
batching stays for leaf batches (256 × ~24 KB ≈ 6 MB — inside the Worker
memory bar). poc-16-yez.11 is in progress under another agent — untouched.

## 7. Execution protocol (read before starting any bead)

Written so a bead can be executed without re-deriving the design. Trust the
docs and skeletons; when code reality contradicts them, stop and say so in
the bead notes instead of improvising a third design.

**Per bead:**

1. `bd update poc-16-oyd.N --claim`, then `bd show poc-16-oyd.N` and follow
   its brief top to bottom. READ FIRST means read fully, before editing.
2. Skeleton docstrings are the contract — implement exactly the documented
   signature and semantics; delete the `raise NotImplementedError`, keep the
   docstring. Un-skip the bead's listed tests by deleting their `@SKELETON`
   line and writing bodies that test the docstring's claim.
3. Run `python -m pytest -q` from the worktree root (~30 s). Green includes
   skips; red or error is never left behind. For sync-touching work also run
   the slow end-to-end file: `python -m pytest -q tests/test_cutover.py`
   (`tests/test_engine.py` died with the tree engine in oyd.5).
4. Every DELETE in the brief means delete now, in this bead — not comment
   out, not deprecate. After deleting symbol X, `grep -rn "X" core/ facts/
   tests/ bench/` must show nothing (or only the brief-listed survivors).
5. Style: minimal LOC, short clear names, module docstrings carry the
   design; no compat shims, no dual decoders, no state migrations, ever.
   New behavior replaces old in the same change.
6. Finish: `bd update poc-16-oyd.N --append-notes "<what changed, LOC
   delta, measurements>"`, `bd close poc-16-oyd.N`, and land the bead as
   ONE commit on branch `removal-index` (never push; never commit secrets).

**Hard rules (violating any of these is worse than failing the bead):**

- Never touch `~/poc-16-all-night` (another agent's worktree) — read only,
  no writes, no git commands, no test runs there.
- Never run `git clean -fdx`, `git checkout -f`, or any destructive git
  command in any poc-16 worktree: `.beads/embeddeddolt` is a live shared
  Dolt database (gitignored, unrecoverable).
- Never push. Never touch bead poc-16-yez.11 (another agent owns it).
- Don't edit docs/REMOVALS.md semantics or docs/COSTS.md measurements to
  match code; if the code can't satisfy them, stop and note it.
