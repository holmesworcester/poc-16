# Removals — a grow-only, target-keyed index beside the fact tree

Status: plan of record (2026-07-26). Supersedes `docs/DELETION_CLOSURE.md`
(T_supp, epic poc-16-yez), which is deleted on this branch. Epic: poc-16-3fo.
Execution: merged into the one-store cutover — `docs/CUTOVER.md`, epic
poc-16-oyd (3fo's sync/node/demolition/proof/measure beads execute inside
oyd.3-.7). This document remains the removal *semantics*; CUTOVER supplies
the encoding it rides on. Reading rule: §1 is design *rationale* whose code
citations are pinned against `main@7635cf8` (that code is deleted; the
citations are lineage, not references); §2-§5 are LIVING one-store
semantics, kept current by the design owner; §6 is the executed demolition
inventory. Agents editing this repo change §6 only.

The one-sentence design: the fact store stays immutable and content-
addressed over member keys only; deletions live in a single grow-only
removal index — a head of range-kills followed by point entries sorted by
target key — read as head-plus-slice by anyone evaluating a range, synced
whole while small.

## 1. Why removals get their own structure

A removal is a fact, so it already sits in the fact tree at its own
`<ts>:<fid>` position. That placement serves everyone except the partial
reader: a reader who fetches the victim's era does not fetch the removal's
era. Every deletion design is an answer to that one gap. Three answers fail:

**In-leaf payload attachment is invisible to reconciliation.** Fingerprints
cover in-range member keys and nothing else (`_read_leaf` filters to
`lo < key <= hi` and checks `shape.fingerprint(keys)`, core/tree.py:767-771;
"Fingerprints cover ids, not closure edges", core/node.py:736). `diff` prunes
any subtree with matching fp and n. Attach a removal to a leaf's payload and
a peer whose member keys already match never fetches the rewritten leaf.

**Member-key insertion is the duplication staircase.** Making the removal a
member of its victims' leaves needs either an out-of-range key (violates the
leaf contract) or re-keying per victim — and a channel kill has victims in
essentially every leaf of that channel. One fact duplicated across leaves is
the disease hoisting existed to cure; hoisted removals clustered by what they
suppress *is* T_supp. That is the literal commit sequence of 07-25 (3cb0b72
hoist closure payloads → 2444894 closure-only secondary indexes → c9caaf1
sync the secondary tree).

**Fingerprinting attachments re-heats cold ranges.** Folding "matching
removals" into leaf fingerprints makes every affected range's fp churn on
every delete, kills the root-etag short-circuit (core/sync.py:37-44), and
still requires a canonical removal set to validate attachment exactness
against — the global structure exists anyway; in-leaf copies are a second
materialization to keep consistent.

And the fourth answer — T_supp itself — works but is structurally enormous:
keying by suppression group means victims must live in the structure so group
walks can find them, and all four content families emit `supp(channel)`
(facts/content/{message,chunk,file,legacy_file}.py), so |T_supp| ≈ |content
facts|, a second full tree rebuilt via `layout()` on every commit
(core/node.py:627-631).

The resolution: under read-time application the reader already *holds* the
victims — they are the pile being evaluated. Nothing ever needs to enumerate
victims remotely. So the remote structure contains only removals,
O(deletions), and the suppkey→victims direction is served locally by the
`supp` SQLite table (core/node.py:54). Drop the tree, keep the table.

## 2. The index

One entry per removal fact:

    Entry = (lo, hi, fid)

`(lo, hi)` is a closed interval of **fact-tree target keys** — the span the
removal's victims occupy. `fid` is the removal fact. Entries sort by
`"<lo>|<fid>"`.

- A single-target deletion's span is the victim's exact key: `(K, K)` where
  `K = key(victim)`. It sorts to its victim's position.
- A channel kill's victims span all time, so its honest span is `("", "~")`.
  It sorts to the front. Wide-interval entries at the front are the **head**;
  every reader reads the head.

The span is routing, not semantics. It may over-approximate (a too-wide span
costs a wasted read, never a wrong suppression); it must never
under-approximate. The predicate applied per fact decides actual matches.

**A fact belongs to as many suppression groups as it declares.** That is the
mechanism, not an edge case: one message can be reachable by "kill channel
general", "purge author X", and "delete thread T" at once — each one removal
naming one group. A fact's membership is the set of groups its `TARGET`-tag
markers name; a removal's `DELETE`-tag marker names exactly one group (I3's
admission rule). Kind is read off the removal's clear envelope by its
`TARGET` *ref*: present ⇒ point, absent ⇒ kill — and each kind reaches
through a single clause:

    suppkeys(f) = { group(m) : m a TARGET-tag marker of f }        — a SET
    deathkey(r) = the one group r's DELETE-tag marker names

    applies(r, f) = ¬is_deletion(f) ∧ ( target(r) = fid(f)         r a point
                                      ; deathkey(r) ∈ suppkeys(f)  r a kill )

A point's death marker still names a group — that group is **inert for
reach** (it may scope authorization or display); the victim set is exactly
the `TARGET` ref. The spans above are then derived, not asserted: point ⇒
`(K, K)` from the ref; kill ⇒ `("", "~")`. Group markers on a removal are
inert everywhere (I2: removals are never victims), and removals contribute
no victims-index rows.

Two traps, both proven by three independent reviews of the first
implementation (2026-07-26); the predicate above is shaped to avoid them:
the group clause is **membership**, never scalar equality —
`suppression._marker` collapsing 0-or-2+ markers to `None`
(core/suppression.py:22-29) is the one-group-per-fact assumption fossilized
in code, a defect to fix, not a rule to keep; and a point's death marker
must never feed the group clause — channel-mates share the channel group,
so deleting one message would delete the channel while routing to a single
key, exactly the I6 under-approximation the span rule forbids.

Consequences:

- The local victims index is **many-to-many**: `supp(fid, k, PRIMARY
  KEY(fid, k))` with an index on `k` — one row per non-deletion fact per
  group; today's `supp(fid PRIMARY KEY, k …)` hard-codes one group per
  fact. Kill-victim enumeration (§3.3) is `SELECT fid FROM supp WHERE k=?`.
- `tests/util.py::channel_delete` (channel death marker + `TARGET` ref) is
  a valid **point** fixture as it stands; what the suite lacks is a *kill*
  fixture (death marker, no `TARGET` ref) and a multi-group fact.

**Routing invariant (I6):** an entry's span covers every present and future
victim's key. Guards: point spans embed the victim fid in the key, so
`fid_of(lo) == target ref` is a syntactic admission check; and the author
chokepoint derives the span from the actual victim rather than accepting it
as a parameter (the family author owns construction). A deleter who lies
anyway only neuters their own deletion.

## 3. Reading

Three paths, all local once the index is fetched:

1. **Range evaluation** (sync pull, cloud node judging a pile over `[a, b]`):
   read the head plus the slice of point entries with `lo ∈ [a, b]`. Nothing
   else. Sorting is the skipping mechanism — no per-key probing (a slice is
   one contiguous read; probes are one GET per fact for the same entries).
2. **Admission of one fact** `f`: head predicates plus a point stab at
   `key(f)`.
3. **Arrival of a removal** (bucket delta): retroactively retract
   already-projected rows — victims enumerated via the local `supp` table for
   kills, direct fid for points — and mask forward so later-arriving victims
   materialize suppressed. Today suppression fires only at deletion
   admission, forward-only (core/node.py:337-340; the incremental pump branch
   does no S lookup, core/pump.py:136-149), and a deletion cannot precede its
   victim (core/kernel.py:368-370). The index makes removal-before-victim
   normal; both hooks are new, deliberate work.

## 4. Invariants

**I1 — removals are never removed.** The index is grow-only. No un-deletion,
no correcting a mistaken removal, no expiry or GC of the index, ever — write
that into any UX above this. Local caveat that must be hooked: the prune
cascade deletes a removal when its victim is quarantined (`_prune_unresolved`
`DELETE FROM supp`, core/node.py:516; the target is a hard dep,
core/kernel.py:135) and `_restore_quarantine` re-inserts (core/node.py:474-479).
Prune/restore must keep index entries alive or a never-re-checked index keeps
suppressing after its removal is gone locally.

**I2 — the predicate never applies to removals.** `¬is_deletion(f)` is a
correctness requirement, not an optimization: a deletion's deathkey *is* its
suppkey (core/suppression.py:45-47), so a channel kill matches itself and the
index self-annihilates without the guard. `is_deletion` reads only the fact's
own clear envelope — no recursion, no ordering. Corollary: membership is
removal-blind, computed over V, never over E (core/pump.py:110-117).

**I3 — entries are self-validating and individually admitted.** An entry
names its removal **by key**; the removal's closure resolves the way every
other cross-leaf need does — through the manifest, from home leaf piles
(docs/CUTOVER.md §2). The index carries no fact bytes: per-body objects are
what the cutover deleted (docs/COSTS.md §5), and re-adding them here would
store every removal a second time, beside the copy already inlined at its
home leaf. What this invariant is really about is the *granularity of
rejection*: `encode_pile` rejection is pile-atomic (core/kernel.py:381-383,
409-413) and one poisoned entry must not block the whole removal history.
Admission is per entry. (Before 2026-07-26 this paragraph said "closure by
refs, the settle encoding, core/tree.py:583-590" — that encoding no longer
exists; refs-by-key is its one-store replacement.) "Exactly one death
marker" becomes an admission rule (today `_marker` silently collapses 0 or
2+, core/suppression.py:22-29).

**I4 — set identity is a fingerprint, not an oid.** Pile bytes embed local
closure-edge choices (`offer_src` winners; core/node.py:736), so one oid does
not identify the set. The root slot publishes `fingerprint(sorted entry
keys)` beside the pile oid; peers compare fingerprints.

**I5 — victims' leaves never notice a removal.** A removal is an ordinary
fact: admitting it changes its own home leaf pile and the root's removals
slot, nothing else. No victim's leaf pile, key set, or oid changes — cold
ranges stay cold forever, and the root-etag short-circuit keeps meaning
"nothing to do" for them. This is the property every rejected alternative
in §1 gives up. Closure needs no index coverage either: deps are fixed at
creation and closure-completeness is an admission requirement, so the pile
oid already pins everything a valid leaf contains. (Pre-cutover this
invariant read "no fact-leaf byte changes" over a fingerprinted tree; the
one-store manifest states the same law in oids, with the removal's own
home leaf as the one ordinary-admission exception.)

## 5. Sync

The removal index is fetched **before** the fact leg — replacing both the
SUPP index leg (core/sync.py:59-66) and `close_deletions` range augmentation
(core/sync.py:26-29 → core/suppression.py:67-86) with one GET of the pile
(plus the entry table) while the index is small. After that fetch, every
fact range is self-contained: the reader carries the removal set while
reading.

Physical layout is a size dial, not a semantic decision: one pile object
(read whole — the start state), then a header plus segment objects keyed by
span start (read head + relevant segments — the cloud-node case), then, only
if the index ever gets genuinely large, a treap under the existing engine
with span-start keys. Each step is mechanical; none changes §2-§4. With zero
production deletions measured, start at one object and add nothing.

## 6. Demolition inventory (clean house)

Executed across oyd.2-.5 (pinned against `main@7635cf8`; final state below is
the branch after the oyd.5 sweep). Deleted:

- **core/tree.py, core/hoist.py, core/layout.py, core/treap.py** — the whole
  fact-tree engine and its packings (~2,050 lines), including the
  closure-only secondary-index machinery whose sole user was SUPP. The
  manifest spine (core/manifest.py) plus `node.resident`'s single rebuild
  equality replace every reader path.
- **core/shape.py** — `SUPP` shape, `_supp_key`, `SUPP_INDEX`, `supp_shape`,
  and with the tree the legacy flat facade (`COLD_CUT`, `GUARD`,
  `cut_positions`), `priority`, `leaf_cut`, and the `Shape`/`FACT` bundle.
  What survives: `CUT`, `key`, `key_parts`, `fid_of`, `boundary`,
  `stable_cut_positions`, `fingerprint` — the pure key discipline the
  manifest, sync, and removal index share.
- **core/suppression.py** — `key_bounds`, `supp_walk`, `close_deletions`,
  `SuppressionClosure` (and earlier, scalar `suppkey`/`victims`). Kept:
  `atom`, `_markers`, `is_deletion`, `suppkeys`, `deathkey` — clear-envelope
  primitives the index, node, and families consume.
- **core/sync.py** — the SUPP leg, `_empty`, `closure_sync`, the root-index
  validation, and the tree.diff loop, all replaced by the oyd.3 rewrite
  (removal leg + oid-diff + two-wave assembly).
- **core/node.py** — supp-key scalar maintenance, `_backfill_supp`, the
  second `layout()`/root-index publication, the suppression-tree validation
  walk, and `keys()`'s projection parameter. The `supp` **table** stays: it
  is the local victims index the retroactive consult reads.
- **core/kernel.py** — `Scratchpad` (push/pop verified path context): its
  only production caller was `hoist.verify_once`, which died with the tree.
  `_judge` remains the one judge loop, reached from `kernel()`.
- **core/walk.py** — the `walk()` compat shim (its one caller,
  `facts/auth/user.py`, now calls `sync.sync`). `Peer`/`_push`/
  `_fetch_blobs` stay (CUTOVER §6).
- **bench** — `bench_hoist.py`, `bench_hoist_sync.py`, `bench_treap.py`,
  `bench_order.py` (all drove the dead tree); `measure_piles.py` is a stub
  until oyd.7 rewrites it over the manifest spine. `bench_sync.py` and
  `seed_chain.py` were retargeted and live.
- **tests** — `test_suppression_proof.py`, `test_engine.py`,
  `test_bench_order.py` deleted with their machinery. Retargeted with the
  law intact: the E = V∖S fold guard is
  `test_removals.py::test_e_is_the_v_minus_s_fold` (I2's frame); the
  delivery-order theorem and single-judge-loop law live in
  `tests/test_kernel.py`; the sync end-to-end laws moved to
  `tests/test_cutover.py`; the publish-atomicity law is
  `test_eset.py::test_suppression_stays_behind_the_manifest_commit` over the
  removals slot; placement/authority laws retarget to `resident()`'s
  rebuild equality in `test_props.py`/`test_mint.py`;
  `tests/util.py::mismatched_tree_key` died with its subject.
- **docs/DELETION_CLOSURE.md** — superseded by this document.
- **beads** — epic poc-16-yez is superseded (note added on the epic; its
  open review beads .9/.14 retarget to this index; in-progress .11 is its
  owner's call).

New code is `core/removals.py` plus the node/pump hooks of §3.3 and the sync
cutover of §5. Net effect of the epic on `core/`: about 1,550 lines lighter
than main (5,182 → 3,623), with `manifest.py` + `removals.py` (~420 lines)
carrying what the ~2,050-line tree engine and the SUPP machinery used to.

## 7. Explicitly out of scope

(Code citations below are pinned lineage against `main@7635cf8`; that engine
is deleted. The posture is unchanged — see §8 for its first measured price.)

- **Compaction / publishing removals back into leaf ranges** — cut. Bytes
  and keys are one object (core/tree.py:766-772), `fold` is additive-only
  (core/tree.py:1291-1311), an uncompacted peer's `local_only` pushes
  dropped keys straight back (core/sync.py:101-105), and `live_oids` has no
  production caller, so zero bytes are reclaimed today anyway. Space
  reclamation, if ever wanted, is a separate design with its own peer-
  coordination story.
- **Un-deletion** — permanently excluded by I1, by design, not by omission.
- **Transmitted-placement derivation for the primary tree** (receiver
  derives hoist placement from the key set; history-independence,
  tests/test_props.py:93) — a real ~700-line question, decided separately.
- **Authoritative read mode** (yez.12) — orthogonal; the index changes
  where removals live, not when reads are allowed to trust them.

## 8. Measured (2026-07-26, oyd.7)

This section used to say every number here was projection, because no
production deletion family existed. `facts/content/delete.py` now does, and
`bench/measure_piles.py` runs it over four seeded corpora (flat-m8-n600,
flat-m8-n2400, flat-m32-n2400, chain-m32-n2400) at CUT=64. Full tables and
method: docs/COSTS.md §3.1. What the projections got right and wrong:

- **Index growth: 601-737 B per removal** — several times the ~100 B an
  entry costs, because each entry carries its removal's closure keys (~5-6
  refs × ~80 B). 49 removals produce a 29-36 KB whole index. The read-whole
  posture of §5 holds comfortably; the segmented layout stays unbuilt.
- **Head width is 1 per kill, and slice locality is real**: a warm 40-message
  range stabs 1-2 entries. §3.1's "sorting is the skipping mechanism" is
  doing what it claimed.
- **Re-encode cost per admitted removal: 4-5 objects, 31-116 KB median** —
  and it is *not* the index. It is re-emitting the removal's own home leaf
  pile. I5 says victims' leaves never move; the removal's own leaf does, and
  at CUT=64 that leaf is the dominant per-deletion write.
- **The prune cascade is now exercised** (flat-m8-n600): the entry floor
  held through quarantine, suppression held in the window and after restore.
  I1's local caveat is tested rather than argued.
- **Retraction at scale checks out**: 387 retracted / 2,013 surviving in a
  2,400-message corpus, with zero over- or under-retraction asserted.

Two findings that did not come from the projections at all. **Settle garbage
is 1.6-1.9× reachable bytes** at 64-message commit batching and accretes per
commit — the first measured price of the no-GC posture in §7, and the number
to revisit if that posture is ever reconsidered. And a removal quarantined by
its own deleter's shadowed proof **wedges a peer that synced during the
window** (bead poc-16-3tg): not a removal defect — it reproduces with an
ordinary message and no removal anywhere — but the removal-quarantine path is
where it surfaced, and the trailing assertions in
`test_quarantined_removal_holds_locally_but_diverges_peers` pin it as current
behavior, not as law. Fixing it must flip them.
