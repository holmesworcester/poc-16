# Removals — a grow-only, target-keyed index beside the fact tree

Status: plan of record (2026-07-26). Supersedes `docs/DELETION_CLOSURE.md`
(T_supp, epic poc-16-yez), which is deleted on this branch. Pinned against
`main@7635cf8`; line references are to that commit. Epic: poc-16-3fo.

The one-sentence design: the fact tree stays immutable and fingerprinted over
member keys only; deletions live in a single grow-only removal index — a head
of range-kills followed by point entries sorted by target key — read as
head-plus-slice by anyone evaluating a range, synced whole while small.

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
under-approximate. The predicate applied per fact decides actual matches:

    applies(r, f) = ¬is_deletion(f) ∧ (target(r) = fid(f) ∨ suppkey(f) = suppkey(r))

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

**I3 — entries are self-validating and individually admitted.** Each entry
carries its removal's closure by *refs* (the settle encoding,
core/tree.py:583-590), not an inlined pile: `encode_pile` rejection is
pile-atomic (core/kernel.py:381-383, 409-413) and one poisoned entry must not
block the whole removal history. Admission is per entry. "Exactly one death
marker" becomes an admission rule (today `_marker` silently collapses 0 or
2+, core/suppression.py:22-29).

**I4 — set identity is a fingerprint, not an oid.** Pile bytes embed local
closure-edge choices (`offer_src` winners; core/node.py:736), so one oid does
not identify the set. The root slot publishes `fingerprint(sorted entry
keys)` beside the pile oid; peers compare fingerprints.

**I5 — the fact tree never notices a removal.** No fact-leaf byte, key, or
fingerprint changes when a removal is admitted. Cold ranges stay cold
forever; the root-etag short-circuit keeps meaning "nothing to do". This is
the property every rejected alternative in §1 gives up. Closure needs no
fingerprint coverage either: deps are fixed at creation and closure-
completeness is an admission requirement, so fp over member keys already
pins everything a valid pile contains.

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

Everything below is at `main@7635cf8`. Delete:

- **core/shape.py** — `SUPP` shape, `_supp_key`, `SUPP_INDEX` (:127-145) and
  the `is_deletion`/`suppkey` import (:23).
- **core/suppression.py** — `key_bounds`, `supp_walk`, `close_deletions`
  (:50-86). Keep `atom`, `_marker`, `is_deletion`, `suppkey`, `deathkey`,
  `victims` — clear-envelope primitives the index reuses.
- **core/sync.py** — the SUPP index tuple and `_empty(SUPP)` plumbing
  (:55-66), the `close_deletions` import and call (:7, :27-29;
  `closure_sync` returns to dep-closure only), the root-index validation
  (:50-54) in its SUPP form.
- **core/node.py** — supp-key maintenance on admit/restore (:195, :227,
  :378, :480), the second `layout()` and root index publication (:620-634),
  the suppression-tree validation walk (:684-711), `_backfill_supp` (:186),
  and an `INDEX_VERSION` bump (:59) to force rebuild — a dev-loop stamp, not
  compat. The `supp` **table** (:54) stays: it is the local victims index
  that retroactive retraction needs.
- **core/tree.py** — the closure-only secondary-index machinery whose sole
  user was SUPP (added in 2444894 +176 and c9caaf1 +39; `sync.py:50-54`
  proves no other index name was ever legal). Identified symbol-by-symbol in
  the demolition bead.
- **tests** — `test_suppression_proof.py` and the T_supp halves of
  `test_suppression.py`/`test_eset.py`/`test_engine.py`/`test_props.py`/
  `test_pump.py` retarget to the contracts in `tests/test_removals.py`. The
  E = V∖S fold guard (`test_suppression_proof.py:101,104`) survives as I2's
  test.
- **docs/DELETION_CLOSURE.md** — superseded by this document.
- **beads** — epic poc-16-yez is superseded (note added on the epic; its
  open review beads .9/.14 retarget to this index; in-progress .11 is its
  owner's call).

New code is `core/removals.py` (see the skeleton beside this doc) plus the
node/pump hooks of §3.3 and the sync cutover of §5. The earlier estimate for
the analogous flat-bucket surgery was net −70 core lines before the
secondary-index machinery; with it, the branch should come out several
hundred lines lighter than main.

## 7. Explicitly out of scope

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

## 8. Measure before trusting any growth number

There are zero production deletions: every `deletion=True` site is a test
and the only deletion family is monkeypatched into existence
(tests/util.py:37-81). All sizing in this document — |index| at either
granularity, head width, slice locality, re-encode cost per admitted
removal — is projection. The first production deletion family settles them;
its bead includes measuring, and exercising the prune cascade that no test
currently reaches.
