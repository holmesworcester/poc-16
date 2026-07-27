# TODO — post-cutover work list

Status: plan of record for the next agent (2026-07-27). Branch `removal-index`,
worktree `~/poc-16-removals`. Written from a 13-agent read-only audit of this
branch; every finding below was reproduced at least twice, and the four marked
CRITICAL were re-verified by hand against `b500288`.

**Do not treat this as a design document.** Items 1, 5 and 7 carry real design
decisions that are called out inline as OPEN. Items 8 and 9 will delete this
file: once DESIGN.md is the plan of record, the surviving items move there.

## How to use this

Numbering matches the audit report the design owner responded to; item N here is
finding N there. Each item states the rule (locked by the design owner), the
evidence, what to build, and what "done" means.

**Phase 0, before any item: ship skeletons.** House convention — an
implementation plan lands stub modules plus skip-marked, named tests on a branch
before bodies are written; the signatures are the contract. Items 1, 5, 6 and 7
all need this. Do not start writing bodies against prose.

Ground rules that outlive this file:

- No backwards compatibility. Break the format, delete the old path. No
  read-compat shims, no dual decoders, no state migrations. A rebuild-forcing
  layout stamp is a dev-loop convenience, not compat.
- The author owns the fact type. Family `author`/command functions are the sole
  construction chokepoint; callers pass parameters, never assemble envelopes.
- Workers and daemons stay thin. Algorithm logic belongs in the event modules.
- `~/poc-16-all-night` belongs to another agent: read only. Never run
  `git clean -fdx` or `git checkout -f` in any poc-16 worktree —
  `.beads/embeddeddolt` is a live shared Dolt database, gitignored and
  unrecoverable.
- The interpreter is `python3`. Full suite: `python3 -m pytest -q` (~75 s).

---

## 1. Suppression must be dependency-closed, by construction `CRITICAL`

**THE RULE (locked).** A child fact is responsible for carrying the suppression
ids of its deletable parents. This must *always* be true, and there should be a
static check that enforces it.

### Why — what is broken today

`E = V∖S` subtracts only the directly targeted fact. Dependents stay projected.
Delete an attachment and the front door reports it gone while the bytes remain
trivially recoverable:

```
files(): []              file_bytes(): None
orphan file_chunk_rows still present: 3
their blob objects still in the store: [True, True, True]
raw concat length: 637669   contains marker: True     <- the deleted file
```

`core/pump.py:117-125` computes a topological order with `close(...)` and then
discards it for suppression, testing each fact independently against the index.
The incremental path does the same one-fact consult (`core/node.py:365`
`_log_projection`, `core/node.py:868` `suppressed`).

This is not the disclosed "bytes stay on disk" posture of I5. The chunk *facts*
are never retracted, so `_fetch_blobs` (`core/walk.py:109-121`) still lists them
as live demand and **replicates deleted content to new joiners**.

`facts/content/chunk.py:22` declares a hard `('file', root, pk, ...)` need, so
these are genuinely orphaned dependents, not independent facts.

### What to build

Suppression ids ride the envelope; the read path stays a stab. Concretely:

1. **Every deletable fact carries its own suppression id.** Use the fact's
   one-store key `<ts:015d>:<fid>` (`core/shape.py:key`) as the id — not the bare
   fid — because the removal index is keyed by target key and a child already
   holds its parents' refs *by key* (the cutover's envelope break). The child can
   therefore stab the index at a parent's key with no extra lookup.
2. **Every child carries its deletable parents' full suppression-id sets** — the
   parent's own id *plus* everything the parent declared. By induction the set is
   transitively closed at authoring time, so the consult stays flat (no walk at
   read time) and grandchildren are covered without a second mechanism.
3. **The consult becomes a union of stabs.** For fact `f`:
   `suppressed(f) = stab(key(f)) ∨ ∃ p ∈ suppkeys(f): stab(p)`.
   `core/node.py:868 suppressed` and `core/removals.py:65 overlapping` are the
   only two places this lands — the DRY inventory (CUTOVER §3) must stay one row.
4. **The static check.** Add a declarative per-family constant naming the
   deletable parents a family depends on, and extend `tests/test_fact_contract.py`
   (already an AST contract over `facts/`) to assert that (a) every family whose
   `needs()` names a deletable family declares it, and (b) the family's SHAPE
   emits a TARGET-tag marker for each declared parent. A family that gains a hard
   dep on a deletable family and forgets the marker must fail the suite.
5. Extend `core/suppression.py:30 suppkeys` and the `supp` table
   (`core/node.py` IDX_SCHEMA, currently `PRIMARY KEY(fid, k)` — the shape is
   already many-to-many from oyd.8, so this is population, not schema).

**Why not the obvious alternative.** Making the deletion a *kill* on the victim's
suppression id reaches descendants for free, but every kill lands in the index
HEAD (`span = ("","~")`), which every range evaluation reads. Head width is
currently 1 per kill and measured that way in REMOVALS §8; turning all deletions
into kills makes head width equal the deletion count and destroys the locality
the target-keyed index exists for. Keep deletions targeted; push closure into the
envelope.

**OPEN for the design owner.** Whether the suppression id is the parent's key
(recommended above — free locality) or an opaque per-fact id the family mints. An
opaque id decouples suppression from the ts/key encoding but costs a lookup to
turn it into an index stab.

### Done when

- Deleting a file retracts its chunk facts on both the live and rebuild paths;
  the recovery probe finds no orphan `file_chunk_rows` and cannot reconstruct the
  plaintext.
- The static check exists and fails when a family's parent marker is removed
  (break it, watch red, revert, record it).
- `_fetch_blobs` no longer lists a deleted file's chunks as live demand.

---

## 2. The named theorem is false — covered by 1, but the test gap is not

**Design owner: "covered by 1?"** — Yes for the mechanism; no for the coverage
hole that hid it. Both need closing.

`test_fold_pm_over_d_equals_fold_over_e` (`tests/test_pump.py:452`), headed
`---- THE theorem (poc-16-808.7) ----` and asserting *"identical logical app
state for every suppression world"*, passes only because its fixture has no
attachments. Add one:

```
seed 0: live==source False   rebuilt==source False
seed 1: live==source False   rebuilt==source False
THEOREM HOLDS: False
   diverging table file_chunk_rows: before 3 rows -> after rebuild 0 rows
```

An incrementally-fed node and a rebuilt or cold-joined node hold **different app
state** after any attachment deletion. That is a convergence break, not a
cosmetic gap.

**The coverage hole:** `grep -c send_bytes` returns **0** in all four of
`tests/test_removals.py`, `tests/test_cutover.py`, `tests/test_eset.py`,
`tests/test_pump.py`. The only family with hard dependents was never crossed with
the only feature that retracts facts. The one attachment-plus-deletion test that
exists (`tests/test_attachments.py:234-251`) deletes the *chunk* — the child —
and asserts the parent-free direction, the opposite of what a user does.

### Done when

- `suppression_world` (`tests/util.py:112`) authors at least one attachment, and
  the theorem test passes with it.
- A named test deletes a *parent* with live dependents and asserts live ==
  rebuilt == cold-joined projection state.
- Fixing item 1 without this fixture change would leave the theorem still
  vacuous; land them together.

---

## 3. Investigate the ~8× write-latency regression `CRITICAL`

**Design owner: "we have to figure that out, it seems."** — This item is an
investigation with a decision at the end, not a specified fix.

Measured by hand, one harness, one machine, back to back, **zero removals ever
authored**:

| facts | main@7635cf8 | removal-index |
|---|---|---|
| 801 | 12.3 ms | 23.0 ms |
| 1,601 | 12.9 ms | 61.0 ms |
| 2,401 | 15.1 ms | 92.9 ms |
| 3,201 | 17.7 ms | **137.6 ms** |

Main is flat; this branch is linear in resident fact count with no ceiling.

**Leading suspect.** `core/node.py:829 removal_entries` runs
`SELECT fid FROM facts` with a `node.fact_of` JSON decode per row, and it is
called **twice per commit** — `core/node.py:365` (`_log_projection`) and
`core/node.py:657` (`_removal_slot`). It is unconditional: it does not require
any removal to exist, which is why the curve above has none.

**Note the coupling to item 7.** If removals get their own manifest-sharded tree,
the published-slot floor stops being derived by a full-table scan and this may
disappear as a side effect. Sequence the investigation *after* 7's design is
settled so the fix is not written twice.

Second, smaller offender, and **not** a cutover regression (`_fetch_blobs` is
byte-identical on main): every sync dial does a full `SELECT fid FROM facts` with
a decode per row, under `node.lock` — 46 ms at 4,813 facts, ~600 ms at 50k, per
cadence per peer. An idle converged node burns ~10% of a core. Worth fixing,
worth labelling honestly as pre-existing.

### Done when

- Post latency is flat, or its growth is characterized and accepted with a
  written bound.
- A benchmark in `bench/` pins the curve so the next regression is caught.

---

## 4. Real deletion commands, and black-box tests for them

**Design owner: "add real commands and black box tests for them."**

`grep -n 'remove\|delete' core/cli.py core/daemon.py` exits 1 — zero hits. The
ctl verbs are `status msgs members files file create invite join post send save
evict sync rebuild`. `cmds.remove` exists and is exported from `core/cmds.py:13`,
but its only callers are tests and one bench. The epic's headline feature has no
product surface; the audit had to add a route to a scratch copy to exercise it.

### What to build

- A `remove` ctl route in `core/daemon.py` and a matching CLI verb in
  `core/cli.py`, following the existing thin-worker shape (parse, delegate to
  `cmds`, no logic).
- Black-box coverage in `tests/test_blackbox.py` — today it has **zero** deletion
  coverage, so the production deletion family and the whole removal-index sync
  leg have never run under a real daemon in CI.
- While in `core/cli.py`: it discards the daemon's error message and prints a raw
  traceback (`core/cli.py:10-17`); `ctl_get` has no exception handler, so a
  missing query parameter kills the connection with no response; `ctl/rebuild` on
  an unknown workspace returns success and materializes a phantom workspace.
  Small, adjacent, worth sweeping in the same change.

### Done when

A user can delete a message and an attachment from the CLI, and a black-box test
drives create → post → send → remove → sync → assert-gone across two real
daemons.

---

## 5. Wire the ingress gate `MAJOR`

**Design owner: "this seems straightforward to fix."**

`core/mint.py:145 screen()` is `raise NotImplementedError("poc-16-yez.9 decides;
wire here")` with zero callers. Three consequences, all reproduced over a real
socket:

- **`poc-16-gxz` is live.** An active member relays a closed pile authored by an
  **evicted** key; the receiving node admits, projects and displays it. Confirmed
  for ordinary messages, not just deletions — validity is globals-blind by
  design, and nothing screens the closure at ingress.
- **`delete.needs()` is authorship + membership** (`facts/content/delete.py:41`),
  so any member may irreversibly delete any member's content. I1 means no
  un-delete. No document states a policy.
- **The wire door and the author door disagree.** `remove()` rejects a victim
  that "declares no suppression group (auth facts are outside this content
  family's domain)", but `validate()` — what *peers* enforce — checks only
  `victim.DURABLE and row[0] != TAG`. A hand-crafted deletion targeting an auth
  fact or the workspace anchor passes peer validation.

### What to build

Wire `screen(facts, supp)` at the mint gate and at `PUT /pile`
(`core/daemon.py:135-147`), screening the **whole submitted closure** against S
rather than just the requester, keeping `valid()` globals-blind. Then mirror the
author-side guard into `validate()` so the two doors agree.

**OPEN for the design owner** — the decision `poc-16-yez.9` was parked on, which
must be made before the gate can be written. For a removed member, what happens
to: direct authorship; bearer/device descendants; delegated admins; facts merely
*relayed* by them; facts authored *before* vs *after* removal? And separately:
who may delete whose content — author-only, admin-only, or any member?

### Done when

- `tests/test_mint.py:434` (`test_gate_mask_screens_whole_closure`, the suite's
  one remaining skip) is un-skipped and passes.
- A black-box test proves an evicted member's relayed fact is refused.

---

## 6. Strengthen the suite; prefer black-box tests over a real socket

**Design owner: "strengthen it. prefer black box tests over a real socket."**

The green is shallower than it looks:

- **8 of 8** hostile-input/integrity guards deleted one at a time → suite stayed
  green all 8 times. 17 `raise` lines never execute.
- The **push-before-drain ordering** in `sync()` — an invariant the code comments
  out loud and attributes a concrete failure mode to — is unpinned; reversing it
  leaves the suite green.
- "Manifest oid comparison is the entire diff" is only ever tested at **depth 1**;
  the branch that descends into a child shard (`core/manifest.py:115`) never
  executes.
- **~2% flaky**: `tests/test_mint.py:267` failed 1 run in 14, because a
  wall-clock timestamp feeds a content-derived chunk boundary. Same pattern
  exists in several other tests.
- **95 of 301 collected tests (31.6%)** import nothing from `core/` or `facts/`.
- Net **−63 tests** versus main (363 → 300). The CUTOVER_SKIP markers were
  drained largely by *deleting* tests, not filling them.

### What to build

Black-box first, over real daemons and real sockets: the deletion lifecycle, the
eviction gate, cold join after deletion, partition/heal with removals in flight,
and a poisoned/forged pile refused at the door. Then backfill unit pins for the
guards above. Every new contract should be mutation-proven — break it, watch red,
revert, record which test caught it. Delete `__pycache__` between mutation runs;
a same-size edit reverted within the same second leaves a stale `.pyc` and gives
a false result.

---

## 7. Give removals their own tree, modeled on the manifest spine `MAJOR`

**Design owner: "why don't we have another btree for removals modeled on the main
one? add this."** — Agreed, and it likely subsumes item 3.

Today the removal index is **one unsharded JSON object**
(`core/removals.py:106 encode`). Measured growth: **567 B and 4 refs per
removal**, forever, and I1 guarantees it never shrinks. `core/sync.py:206
pull_removals` refetches it **whole** whenever the fingerprint differs — and the
fingerprint changes on every new removal:

| removals | index bytes | dial ms | dial bytes |
|---|---|---|---|
| 1 | 672 | 85.0 | 14,612 |
| 25 | 14,280 | 95.9 | 45,308 |
| 100 | 56,805 | — | — |
| 200 | 113,505 | 162.2 | 201,675 |
| 300 | 170,205 | 207.5 | 184,699 |

The 201st removal adds 567 B of new information and costs a converged peer
114,072 B to sync — **201× amplification, rising linearly**; O(n²) cumulative.

`REMOVALS.md` §8's "the read-whole posture holds comfortably; the segmented
layout stays unbuilt" extrapolates from n=49 measured in a *single batched
commit*, and it measures index **size** while the posture it endorses is a
**sync** decision whose cost is refetch **volume**. Nothing in the repo has ever
measured that. §8 should be corrected as part of item 8.

### What to build

Reuse the fact spine wholesale — that is the point of the DRY inventory:

- Shard the removal index by the same `core/shape.py:30 boundary` rule that cuts
  leaves and manifest shards, keyed by target key (entries are already
  target-keyed, so the ordering exists).
- A manifest of `(sep, shard_oid)` over those shards; **oid comparison is the
  diff**, exactly as for facts. This retires the removal-index fingerprint (I4),
  the last structure carrying an fp beside its oid — a simplification, not just a
  perf fix.
- `pull_removals` becomes an oid-diff plus a fetch of only the changed shards.
- The published-slot floor stops being a full-table scan (see item 3).

Watch the interaction with **item 1**: the consult becomes a union of stabs, so
the tree must serve multiple point lookups per fact cheaply. Design 1 and 7
together.

### Done when

Syncing one new removal into a converged peer transfers O(one shard), not O(all
removals), with a bench pinning the curve; I4 and the removal fingerprint are
deleted; CUTOVER §3's DRY table still has one row per mechanism.

---

## 8. Docs: make DESIGN.md true, then consolidate everything into it and README

**Design owner: "update DESIGN docs to match code. consolidate all docs to README
and DESIGN."**

`git diff --name-status main..HEAD -- '*.md'` touched 7 files. The cutover
rewrote the storage engine and never updated the documents that describe it.

Stale and load-bearing:

- **DESIGN.md** (1,166 lines, self-declared "Design of record"). 41 lines
  reference `treap`/`hoist`/`layout.py`/`fingerprint`/`tree.py` — all deleted.
  Its 191-line §The Engine is ~100% false and marked CURRENT by the doc's own
  header. It also promises GC that REMOVALS §7 and COSTS §3.1 say does not exist,
  and states the superseded T_supp design plus single-target-only suppression
  semantics that `removals.applies` contradicts.
- **AGENTS.md** — the file an agent reads *first*. Routes to a deleted
  plan-of-record and never mentions CUTOVER.md, REMOVALS.md or COSTS.md. Its
  "current epics" list presents closed beads as the frontier.
- **docs/IMPLEMENTATION.md** — the only doc with a working quickstart; still
  lists deletion as not built, on the branch whose headline feature is deletion.
- **docs/VERSIONING.md** — plan of record for a live epic; 8 citations to
  `core/tree.py`.
- **README.md**, **docs/MODEL.md**, **docs/MULTILEVEL_PILE.md** — same class.

Repo-wide: **41 references to deleted files across 8 of 16 documents.**

**One substantive correction, not just a rewrite.** DESIGN.md:36-38 and :120-124
state as present fact that *"encrypted values ride the body … content never is
[store-visible]"*, and that premise is what licenses "in the cloud the store *is*
the server". **In code there is no body encryption**: `box_encrypt` has exactly
one production caller (the invite blob, `facts/auth/user_invite.py:79`),
`Fact.body` is plain JSON, and message plaintext sits verbatim in store objects.
The only honest statement in the repo is `docs/IMPLEMENTATION.md:191-193`
("**Bodies are plaintext** — epochs/body encryption are out of scope"), in a file
graded stale. DESIGN.md must say what is true today and mark body encryption as
the unstarted work it is.

### What to build

Fold `docs/CUTOVER.md`, `REMOVALS.md`, `COSTS.md`, `MODEL.md`,
`IMPLEMENTATION.md`, `MULTILEVEL_PILE.md`, `SIMPLIFY.md`, `TREAP_PROTOTYPE.md`,
`VERSIONING.md`, `WORKSPACES.md`, `CHAINED_AUTH_PLAN.md`, `KEY_HIERARCHY_ADR.md`
and `PUNCTURABLE_ENCRYPTION_SOURCE.md` into **README.md** (what it is, how to run
it) and **DESIGN.md** (the model, the engine, removals, costs, open work), then
delete `docs/`. Preserve REMOVALS.md's §1 pinned-lineage convention: history that
explains *why* stays, marked as history.

`tests/test_repository_layout.py` already owns a stale-reference regex but points
it at the bead export. Point it at the documentation, where the breakage is.

**OPEN:** whether AGENTS.md survives as the agent entry point (recommended: keep
it, ~20 lines, pointing at DESIGN.md and nothing else).

---

## 9. Reset the beads; fix the removal-index poisoning `CRITICAL`

**Design owner: "reset beads and simplify to a design doc. fix the critical bug
too about removal poisoning."**

### 9a. The poisoning bug — fix this first, independently of the bead reset

A fact with a **negative timestamp**, plus a deletion of it, permanently poisons
the removal index. `core/removals.py:106 encode` and `:127 _keyish` disagree on
key parsing, so the encoded index no longer decodes.

Two things make it unrecoverable rather than merely bad:

- `core/node.py:816 _published` decodes the removal index **outside** its own
  error guard, so the node cannot republish — a general hardening gap, not a
  negative-ts special case.
- `core/node.py:329-341` retires the ingress pile **inside** the try block, after
  `pump`, so any exception during a turn leaves the offending pile in `pile/` and
  it replays on every subsequent turn, across restart *and* rebuild.

The trigger surface is wider than "a deletion of a negative-ts fact": **any**
negative-ts fact anywhere in a removal's closure poisons the index, because
`encode` writes a `shape.key` ref for every closure member. And because the
removal leg runs **first** in `sync()`, a peer serving a malformed index denies
the *entire* sync — and the daemon swallows the error silently, forever.

**Fix:** reject the malformed key at the index door (`core/removals.py:95 admit`);
put `_published`'s decode inside the guard; retire the ingress pile outside the
try or quarantine a pile that has failed N turns; surface sync failures in
`status` instead of swallowing them. Add a hostile-input contract for each.

Related, minor: `removals._keyish` and `shape.fid_of` parse a fact key at
different colons and the door lets the ambiguous form through.

### 9b. The bead reset

The graph has drifted out of contact with the code:

- **`poc-16-92v`** (7 open children) is entirely obsolete — every file it orders
  deleted is already gone. `.2/.3/.4` name `tree.BINARY`, `core/layout.py`,
  `tree.FLAT`, `core/hoist.py`, `tree.verify`.
- **`poc-16-jbg.2`** specifies "precomputed fingerprints", the mechanism the
  cutover eliminated; its closed dependency `jbg.1` was closed on a claim this
  branch reverses.
- **`poc-16-yez`** (7 open children) is orphaned: its plan-of-record document is
  deleted here and its closed foundation bead's code is gone. Two live P1 bugs
  (`up4`, `gxz`) are blocked on **`yez.9`**, a review of a deleted design — so
  landing this branch strands a real removal-correctness bug behind an
  unexecutable bead.
- **`poc-16-x1o`** (27 beads), **`9fc`** (10), **`t9f`** (4) are design-only, with
  no production code. They dominate `bd ready` (35 ready, most unstartable).

Keep as real, live work: **`poc-16-3tg`** — reproduces, and "permanently wedged"
is accurate; nothing recovers the peer. The fix candidate is cheap: swap
`extend_proofs` for `rebuild_proofs` in `core/sync.py:31 _resolver`. It costs
exactly one test — the one at `tests/test_removals.py:777` that pins the wedge as
*current behaviour, not law*. Flipping that assertion is the point.

Also still real: **`gxz`** (item 5), **`up4`**'s acceptance criterion (no test
authors a removal older than its target's membership) even though the bug itself
is fixed, and **`8lq`**, which is a name collision with oyd.8 and was never
touched.

### Done when

Beads are reset, the surviving items live in DESIGN.md, and the poisoning
reproducer is a passing regression test.

---

## Suggested order

```
9a poisoning  ──┐                        (independent, critical, small)
                ├──> 8 docs ──> 9b bead reset ──> delete this file
1 + 2 closure ──┤
7 removal tree ─┴──> 3 latency           (7 likely subsumes 3)
5 gate ─────────┘
4 commands ──> 6 black-box suite         (6 needs 4's routes to test through)
```

1+2 and 7 are the two that change on-disk format; land them before anything
builds on the current shapes. 3 waits on 7's design. 6 waits on 4.

## Reproducers

Probe scripts from the audit are in this session's scratchpad
(`…/scratchpad/audit-comp/probe_*.py`) and will not survive cleanup. The two that
matter are three lines each:

- **Dependency closure** — create a node, `cmds.send_file` a file with ≥3 chunks,
  `cmds.remove(file_fid)`, then count `file_chunk_rows` in the app DB and
  concatenate the referenced blobs. They are still there and still readable.
- **Theorem** — add one `send_bytes` call to `suppression_world`
  (`tests/util.py:112`), delete both a message and the file, then run the test's
  own `replay_random` / `projection_state` helpers. Live, rebuilt and source
  diverge.
- **Latency** — post 1,600 messages in-process, printing mean ms per 400-post
  window, in this tree and in a read-only
  `git archive 7635cf8 | tar -x` extraction of main.
