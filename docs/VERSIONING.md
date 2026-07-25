# Versioning — offers as the release interlingua

**Status:** plan (2026-07-25). Tracked by bead epic `poc-16-9fc` — see
`bd dep tree poc-16-9fc`. Companion to `DESIGN.md` §Versioning (the model of
record), `docs/SIMPLIFY.md` §5 (the log/cursor/pump seam a bump replays
through), and `docs/CHAINED_AUTH_PLAN.md` §2 (the family fidelity rubric every
version handler must still satisfy). Handoff for another agent; do not implement
from memory — read this, `DESIGN.md` §Versioning and §The Engine (Needs and
offers, Fact-family boundary), and `core/kernel.py` first. Plan only — each bead
names its section here.

**Skeletons:** branch `versioning-skeleton` (commit `7307280`) holds the stub
surfaces this plan pins — `facts.offers(f)` plus `VERSIONS` /
`handler_for_version` / `current_version`, `core/release.py`,
`core/vocabulary.py`, and `kernel.UNREADABLE` documented beside `Judgment`
(which the bead widens, not the skeleton), plus 30 skip-marked acceptance tests
in `tests/test_versioning.py` — `.1`=4, `.2`=5, `.3`=4, `.4`=2, `.5`=6, `.6`=3,
`.7`=3, `.8`=3. The seam is router-level; no family module is touched. Final
names, signatures and test names, bodies unwritten, suite green.

DESIGN.md already states the answer, in §The Engine:

> Offers are the **version interlingua** — the reason the model earns its
> weight: facts of different versions in one pile never read each other's
> schemas; each version's handler decodes only its own bytes and emits
> normalized offers, consumers need the offers, and a new version is a new
> handler, not a migration (POC-10's adapt layer, dissolved into offer
> emission).

**Nothing emits normalized offers today.** `Fact.offers()` reads the stored
envelope atoms and `core/kernel.py:335` admits them verbatim; no family module
has an offer hook and `tests/test_fact_contract.py:35` does not require one. The
interlingua is asserted, not built. This plan builds it, and pins the two
invariants that keep it from breaking convergence.

---

## 0. The gap

**First, a scope line.** The POC keeps **no** backwards compatibility: it has no
installed base, so the migration story is always to break the format and rebuild
from scratch, and a compatibility shim only costs the legibility the POC exists
to buy. Everything below is therefore a *product* rule being designed here and
tracked here — not a licence to grow compat code in `core/` or `facts/`. Two
consequences worth stating up front. The `legacy_*` modules are residue slated
for deletion, not this epic's foundation: they are cited below as evidence of
the *shape* a version handler takes, never as something to preserve. And a
version stamp that forces a rebuild is a dev-loop convenience, not compatibility
— which is exactly what §8 is about, and why §8 is the part of this plan that
pays off immediately.

What already works:

- **The shape of a per-version handler, as residue.** `facts/auth/legacy_genesis.py`,
  `legacy_signature.py`, `legacy_invite.py`, `legacy_join.py` keep the `genesis`
  / `sig` / `invite` / `join` tags judgeable beside `workspace` / `signature` /
  `user_invite` / `user`, author nothing, and are exercised by
  `tests/test_auth_upgrade.py:58`. `legacy_invite` even keeps its *old*
  authority rule (admin-only) while `user_invite` allows any member — a real
  semantic divergence between two versions of one family, which is precisely
  what a version handler is. These modules should be deleted under the
  no-back-compat rule; what this plan takes from them is the shape, not the
  code.
- **Replay on a semantic bump.** `INDEX_VERSION` (`core/node.py:57`) mismatch ⇒
  `rebuild(ws, republish=True)` (`core/node.py:150-160`, `:579-619`): stream the
  store's own leaves back through `drain`, wipe and re-emit every derived table,
  republish without memoizing old fences. `APP_VERSION` (`core/node.py:58`)
  mismatch ⇒ delete `app.db` and refold. Seven `INDEX_VERSION` bumps on main (eight distinct values since it was
  introduced).

What does not:

- **Offers are envelope atoms, not handler output** (§3). Two versions of a
  family agree today only by both choosing the same atom by hand.
- **Needs are current-version by accident, not by contract** (§4). They are
  handler functions, so they already normalize; nothing says they must, and
  nothing tests that a v1 need still matches.
- **Nothing states what a release may not change** (§5). A handler edit can
  silently move the valid set — the one divergence sync cannot repair.
- **An unknown tag rejects the whole unit, and the leaf keeps coming back**
  (§6). `core/kernel.py:355-371`: no handler ⇒ `deps is None` ⇒ `rank is None`
  ⇒ `Judgment(False, …)` for the entire pile, including every fact in it the
  reader does understand. The facts never land, so the diff still shows them
  missing and `core/sync.py:44-64` refetches the leaf every time the walk gets
  past the conditional-GET short circuit at `core/sync.py:20-23` — once per root
  change on either side, once per restart. Silent, and it never converges.
- **There is no release version** (§8). No `pyproject.toml`, no `__version__`,
  no git tags. `INDEX_VERSION` and `APP_VERSION` are two hand-maintained
  constants with nothing tying them to each other or to a release. `APP_VERSION`
  has been 1 since it was introduced and has never been bumped; the two have
  never moved together.

## 1. Three version axes, and where each one lives

| axis | where it lives | changes fids? | changes fps? | changes root bytes? | recovery |
|---|---|---|---|---|---|
| fact | the type tag, inside `env` ⇒ inside `fid` | n/a (it *is* the fact) | yes (different fact) | yes | none needed — atoms are forever |
| layout | `config` = `1:kind:fanout:CUT` (`core/tree.py:56`), published in the root and refused across on merge; `COLD_CUT`/`GUARD` stamped nowhere | no | the fp *function* is layout-blind, but every fp published in the tree moves (different chunking ⇒ different ranges) | **yes** | full rebuild; roots diverge transiently on a config roll |
| derived state | `INDEX_VERSION`, `APP_VERSION` (`core/node.py:57-58`) | no | no | `INDEX_VERSION` **yes** (globals + leaf oids); `APP_VERSION` no — it is `app.db`-local | replay |

The key discipline is version-blind by construction: `core/shape.py:29-53`
derives key, boundary and priority from `ts` and the fid's own hash, and
`core/shape.py:100-105` fingerprints keys only. Everything version-sensitive is
downstream of a handler.

The split that matters, stated once (`docs/SIMPLIFY.md` §0 says it from the
other end): **`fp` is the diff identity and is version-free; `oid` is the
storage identity and is version-sensitive**, because a leaf's oid hashes
`close(chunk, deps_of, fact_of)` (`core/tree.py:225-229`) and `deps_of` is
`resolve_deps` — refs plus *handler-resolved* need providers
(`core/kernel.py:125-145`).

## 2. Version in the tag, never in a new fact field

Validation is reconstruction equality in essentially every family — `f ==
shaped`, where `shaped` comes from the family's own SHAPE constructor
(`facts/auth/workspace.py:32-35`, `facts/auth/user.py:39-42`,
`facts/content/message.py:31`, and twelve more — every family module in the
tree, six via a `shaped` local and nine calling the SHAPE constructor inline). Any scheme that adds bytes to a
fact must thread them through every constructor or every validator returns
False. So the version stays where the codebase already put it: **in the wire
tag**, with module metadata beside it.

Each family module declares `FAMILY` and `VERSION` next to `TAG`; `TAG` remains
the exact persisted string and is never recomputed. `facts/__init__.py` keeps
`ROUTES` keyed by tag and adds an index by `(FAMILY, VERSION)`. A contract test
asserts both constants exist, `(FAMILY, VERSION)` is unique, and exactly one
version per family is *current* — the one commands author. This bead declares
the dimension on whatever families exist when it lands; it does **not** preserve
the `legacy_*` modules, which are removable under the no-back-compat rule and
may well be gone by then. If they are still present, they are the family at
their old `VERSION` — which is what they already are — and deleting them later
is a deletion, not a versioning decision.

Same pass fixes a family-policy leak the contract test does not cover:
`core/tree.py:694` hard-codes `fact.t in ("workspace", "genesis")` in the merge
path, so a third anchor-family version silently breaks two-root merge.

## 3. Offers become handler output — the one seam

Add `offers(f)` to the family contract, beside `needs(f)`. The kernel admits
`handler.offers(f)`, not `fact.offers()`. Every family's first implementation is
`return f.offers()` — the identity — so the change lands byte-identical, green,
and gives every future version handler the seam it needs.

`Fact.offers()` survives as the envelope accessor: families still shape and
validate their own atoms with it, and the clear-envelope vocabulary stays
store-visible. What changes is only *who fills the offer table*. Call sites to
move (all read atoms today):

```text
core/kernel.py:334-336   _admit -> the offers table            (the seam)
core/kernel.py:246       extend_proofs offer-waiter wakeups
core/kernel.py:278       proof_sources: "does this fact need a persistent rank"
core/node.py:288-290     idx.db offers table
core/node.py:350-358     _shadows conflict / memo invalidation
core/node.py:333,401-417 quarantine offer index
facts/_commands.py:44-46 publish() authorship check
facts/auth/removal.py:38 global_rows
facts/auth/removal.py:50 materialize's removal row
```

The last two are not incidental: **globals are handler output published in the
root** (`core/tree.py:167-172`, the fat-root branch), and today
`removal.global_rows` reads the offer atom *positionally* (`f.offers()[0][1]`),
as does its `materialize`. The value itself — a member public key — already
satisfies the rule that a global's value space stays stable identities, keys and
fids rather than schema-shaped values; so this is plumbing onto the seam, not a
value-space change. Keep the rule anyway: a schema-shaped global would rewrite
root bytes for an unchanged set on every release.

## 4. Needs move with them, or nothing matches

A version's needs must be expressed in the current vocabulary. If a v1 fact
still needed `member@v1` while providers emit `member@v7`, `offer_src`
(`core/kernel.py:78-112`) returns `None`, `resolve_deps` returns `None`, and
`core/kernel.py:370-371` rejects the whole unit. POC-16 gets this half free —
`handler.needs(f)` is evaluated by the running release — but "free" is not
"guaranteed", and the pairing is what §5 turns into a law.

Two shape traps to write down while touching this, both live today:

- The envelope→address map is **not injective**: `["offer","member",PK]` and
  `["offer","member",PK,""]` have different fids and produce the identical
  offers row (`core/fact.py:44`).
- `a1` means three things by position: `""` in a stored offer, `None` =
  wildcard in a need (`core/kernel.py:98-99`), `None`→`""` in a `requires`
  co-offer (`core/kernel.py:110`).

## 5. What a release may not disturb — Tier 1 and Tier 2

**Tier 1 — the valid set. A release may never change it.** Two replicas at
different releases that disagree about membership diverge permanently:
fingerprints differ over facts both hold, and no walk closes the gap. So
normalization is a **relabeling of a stable meaning space**, applied to offers
and needs alike, and matching is invariant under it. Offer addresses are
append-only; a shipped version's needs are frozen in meaning; a genuine change
of meaning mints a *new* address, and each old handler decides for itself
whether it can honestly offer there. Enforcement is §9 plus a checked-in
vocabulary registry (address → the release that introduced it) whose test fails
on removal or redefinition.

**Tier 2 — the arrangement. A release may change it, and republishes.**
Canonical provider choice decides a leaf's closure, hence pile bytes, hence oid.
Fingerprints cover in-range keys only, so the walk prunes correctly and both
sides still converge on the same *set*; the cost is refetching leaves whose
bytes moved for no semantic reason. This is exactly why
`node.rebuild(..., republish=True)` passes `reuse=False` (`core/node.py:611-617`,
comment `:613-615`), and it is already regression-tested
(`tests/test_auth_upgrade.py:164-267`).

**The skew is invisible, and that is a finding, not a footnote.** Two peers on
different releases holding identical fact sets produce identical fingerprints
and different roots. The walk prunes and reports convergence
(`core/sync.py:44-48`). No version rides any of the seven verbs, the grant token
(`core/daemon.py:52-57`), or `decode_root` (the root's `"v": 1` at
`core/tree.py:171` is written and never checked). Making the skew *observable*
is a diagnostic, not a validity input — see §12.

## 6. `unreadable` — the third kernel outcome

An unknown `(family, version)` is not an invalid fact; the node is not current.
The two outcomes must be opposite:

```text
invalid     -> delete the pile, charge the pusher's prefix, never retry
unreadable  -> keep the pile (bounded), charge nobody, do not advance
               that range, retry after upgrade
```

POC-10 said this as *"core does not store future-version incoming facts as
protocol truth. Incoming is volatile intake."* Here it is a third result beside
valid and invalid: it never enters the set, destroys nothing, and attributes
nothing. `Judgment` gains the outcome (widening the NamedTuple means fixing its
tuple-unpacks in `core/node.py`, `core/tree.py`, `core/mint.py` in the same
change); `core/node.py:237-241` is where the outcome must be distinguished from
`False`, and `core/node.py:247-248` — `st.delete(k)  # retire ingress after the
CAS`, today unconditional — is the line that must become conditional;
`core/sync.py` marks the range stalled instead of re-pulling it.

**Both halves are new work: there is no blame mechanism today.** `do_PUT` stores
the pile and returns 204 unconditionally (`core/daemon.py:143-145` — "delivery
receipt; acceptance is the treap"), and `turn()` deletes every pile after the
CAS whatever its verdict. The pusher prefix exists in the key but is never
consulted afterwards. So §6 adds *two* behaviors — charging the invalid side and
exempting the unreadable one — rather than exempting one that exists.

**Retention must be bounded.** An unknown tag is free to fabricate: no key, no
chain, no closure. Keeping such piles unblamed and un-expired converts a solved
DoS (`DESIGN.md` §The Store: "a hostile writer can litter but never poison")
into an open one — unbounded pinned storage in a grant-holder's prefix that
every drain re-reads. Unreadability suspends blame, not accounting: a per-prefix
byte cap and a TTL, after which the pile is dropped and the range simply
re-syncs.

Piles are all-or-nothing, so one unreadable fact stalls its whole unit — which
is the right semantics: a behind-version client stops cleanly at the version
boundary rather than serving a partial truth, with loud upgrade pressure and no
data loss, since the peer still holds the range and the fingerprints still
differ. Measured shape of the bug it replaces: a 66-fact remote workspace with
one fact of an unrouted family loses six facts to the whole-unit rejection, and
the leaf is refetched once per root change on either side plus once per process
restart (`Node.sync_cache` is in-memory) — an unbounded refetch that never
converges, not a per-walk loop. Deployments whose engine is the vendor's own — cloud node, home server —
upgrade first and never meet it.

One consequence to keep: `core/node.py:594` asserts `result.ok, "own store
failed its own kernel"` on rebuild, so deleting or renaming a family module hard
-asserts on any store still holding that tag. That assert is correct and must
stay; `unreadable` is about *foreign* piles, never about one's own store.

## 7. Activation is authoring policy, never validity

POC-10's release rule survives verbatim — *do not author a new durable fact type
until every non-deprecated release can decode, authenticate, validate, and
project that type* — but not its mechanism.

**Release manifest plus trusted time — rejected.** POC-10 computed a network
ceiling from a signed release manifest and a trusted clock, then classified
incoming facts Active / Pending / Dropped. That is ambient mutable state; a
validator reading it makes verdicts time-dependent and collapses
order-independence, the same argument that keeps globals out of persistent
handlers (`DESIGN.md` §The Engine). It also needs parking, which the grammar
deleted.

So: a fact authored at version v is valid at version v forever, however and
whenever it arrives. Devices advertise the versions they implement as ordinary
facts (a `device.capability` family, or an atom on the existing device fact);
the authoring floor is the minimum over non-removed members, read from
`app.db`; commands refuse to author above it. Nothing in `validate`,
`resolve_deps`, `close`, or `layout` may read it. A client that jumps the gun
harms nobody's correctness — it strands its own facts at peers that cannot yet
read them.

## 8. One release constant, one replay

Today `INDEX_VERSION` and `APP_VERSION` mean different things and nothing pairs
them: `INDEX_VERSION` re-runs the **kernel** (validity, needs, `global_rows`);
`APP_VERSION` re-runs only **materialize** — `pump`'s reproject branch rebuilds
`Valid` tuples by hand from the already-admitted `facts` table
(`core/pump.py:76-119`) and never re-judges validity — though it does call the
kernel's `resolve_deps` (`core/pump.py:78`, `:111`), so a `needs()` change
reaches an app-only refold as a `ValueError` out of `pump` rather than as a
verdict. An offers-normalization
change is a kernel change and needs the former.

Introduce one `RELEASE` constant; derive both stamps from it (each may still
carry its own discriminator so an unrelated schema-only change need not force a
kernel replay, but the release always forces both). Two gaps to close in the
same bead:

- `INDEX_VERSION` does not cover `idx.db`'s **own schema**. `IDX_SCHEMA` is
  applied with `CREATE TABLE IF NOT EXISTS` (`core/node.py:146`) and `rebuild()`
  wipes a hardcoded tuple `("facts","offers","proofs","globals","log")`
  (`core/node.py:597`). A new column or a new table is silently not migrated.
- `rebuild()` deletes the durable `meta['reproject']` marker
  (`core/node.py:600`) and relies on the process-local `self._reproject` set;
  safety comes only from `meta['root']` also being deleted. Any new
  version-driven wipe path must preserve that invariant.

Cost is the catchup path, so it is priced by it — ~1.1k facts/s while nothing
has sealed, 5,826–7,909 at 50–100k once the tiered cold pages fire, at the
`rec/s` ceiling (`bench/RESULTS.md` §1) — and it is the same code as a fresh
join. Note the full reproject is currently O(|V| · deps) unbatched SQLite round
trips with the whole set resident (`core/pump.py:97-119`); a release bump makes
that path routine rather than exceptional, so it is worth measuring, not
optimizing blind.

## 9. The proof — cross-release replay of a golden corpus

The centerpiece, and the thing that makes every other bead safe to land.

1. Freeze a corpus: a real workspace built by `cmds` (founder, several members
   through both `legacy_invite`/`legacy_join` and `user_invite`/`user`, an
   eviction, messages spanning several promotions), serialized as its own
   store — `root` plus `obj/**` — checked in under `tests/corpora/`.
2. Build a release harness: a `RELEASE` fixture that swaps `facts.ROUTES` for a
   pinned "previous release" module set (the table is already a plain dict and
   is already monkeypatched by `tests/util.py:63`).
3. Replay the corpus under release N and under release N+1, each into a fresh
   `Node`, and assert:
   - (a) **identical valid set** — the fid sets from `idx.db` `facts` are equal.
     This is Tier 1 and it is unconditional.
   - (b) **identical fingerprints** — the root's `view.fp` matches, so a
     cross-version walk prunes.
   - (c) **root bytes equal unless the release declares an arrangement bump** —
     the declaration is a constant in the release, and the test reads it; an
     undeclared root change fails.
   - (d) **no fact byte moved** — every `obj/` the corpus shipped is still
     reachable and still hash-consistent.
   - (e) **offer identity under the seam** — with identity `offers()` the whole
     existing suite is byte-identical (this is what licenses §3 landing first).
4. Add the mirror case, which is §6's behavior and therefore lands after it: a
   corpus containing a family the pinned release does not have, asserting
   `unreadable` — pile retained, nothing charged, and a clean drain once the
   handler exists. Until V5 lands, this case asserts today's behavior instead
   (whole-unit rejection), so the harness records the bug rather than skipping.

## 9a. The litmus — one real second version

Everything above builds machinery. Only this proves the model, and it is the
last bead for that reason.

Pick one content family — `message` is the natural choice — and ship a genuine
v2: a new tag at `VERSION` 2 with a changed body shape, its own validator, and
its own emitted offers in the current vocabulary. Beside it, the frozen v1
handler keeps its own validity rule untouched while its vocabulary tail moves to
that same current vocabulary, on both the offer and the need side.

Then assert what the model claims: v1 and v2 facts sit in one pile and never
read each other's schemas; a consumer needing an address matches v1 and v2
providers identically; the §9 replay shows an unchanged valid set across the
bump; and the v1 handler is a decoder plus a frozen validator plus a
normalization tail, small enough that N of them per family is affordable.

If the v2 change cannot be expressed as a relabeling — if it genuinely redefines
a meaning — mint a new meaning instead (§5) and record in §12 what that cost.
The v2 commands stay behind §7's authoring floor; this bead does not enable real
authoring above it.

## 10. Coordination with `poc-16-808` and `poc-16-jbg`

- **808 (simplification).** Closed — the one kernel judge loop (`_judge`,
  `core/kernel.py:343-377`) and the cursored pump already landed, so the seam has
  a single place to go and there is no sequencing hazard. What remains live is
  the obligation: a release bump replays through 808's log/cursor pump, so §8's
  constant must invalidate the cursor the way `rebuild()` does.
- **jbg (FaaS).** A stateless mint evaluates a request pile with whatever
  handler set the Worker was deployed with, against a root published by a
  possibly different one. The mint is already `evaluate` over a closed pile, so
  the rule is simply that the deployment upgrades before its clients — but
  `jbg.10`'s canonical-authority-view derivation must be built from the same
  release as the drain that wrote the root, and the two-root merge at
  `core/tree.py:661-663` already refuses a cross-`config` merge; a cross-release
  merge deserves the same refusal once §2 makes the release legible.

## 11. Staging

```text
V1  FAMILY/VERSION module constants + (family, version) index + contract test;
    core/tree.py:694 anchor-tag leak fixed                              (§2)
V2  offers(f) seam, identity implementations everywhere, byte-identical;
    globals moved onto emitted offers                                   (§3)
V3  golden corpus + cross-release replay harness — the proof             (§9)
V4  vocabulary registry + append-only test                              (§5)
V5  unreadable as the third kernel outcome; sync stalls instead of
    re-pulling                                                          (§6)
V6  one RELEASE constant driving both stamps; idx.db schema gap closed  (§8)
V7  device capability facts + authoring floor                           (§7)
V8  ship one real v2 family end to end — the litmus                    (§9a)
V9  docs foldback: DESIGN.md §Versioning to landed behavior; hedge the
    SEC claim; reconcile the deletion flag day                     (§12)
```

V1–V2 are behavior-preserving and unblock everything. V3 is what makes V4–V8
safe to land, so nothing after V2 should merge without it. V5 is independent of
the seam and can go in parallel, but it must precede §9 step 4, whose behavior
it defines. V8 is the only step that proves the model rather than the
machinery, and it needs V7's floor to author against.

## 12. Open sub-questions (log, don't block)

- **Should the root carry a release marker?** It would make §5's invisible skew
  observable in one conditional GET. It is diagnostics only — no validator may
  read it — but a marker in the root is a marker in the CAS'd bytes, so two
  releases would then differ *by construction* on an unchanged set. A marker
  beside the root (`roots/` entry metadata, or a `/mint` response field) buys
  the same observability without touching the published bytes; decide before V6.
- **Retiring a version.** Old handlers accumulate forever, and
  `core/node.py:594` makes deleting one an assert on any store that holds its
  facts. The only honest retirement is a flag day that declares those facts
  invalid — a set change. Log the cost per family (an old handler is a decoder
  plus a frozen validator, small) and defer.
- **The suppression-marker cutover is the one conceded flag day.**
  `docs/DELETION_CLOSURE.md` §"Phase-0 resolution" already records it: accepting
  old markerless `msg`/`file` shapes would let newly signed facts bypass
  deletion, so preserving pre-cutover content needs "a separately versioned
  migration". That is Tier 1 being broken deliberately. Reconcile the two docs
  when V8 lands.
- **`_admit` sits outside the poison guard.** `core/kernel.py:372` is outside
  the `try` at `:354-368` — as is `handler.global_rows` at `:374-375`, so the
  bead covers both, so a fact whose family validates but whose atoms
  carry a non-scalar raises out of `_judge` and out of `kernel()`. Latent today
  because every shipped family rejects such atoms first; a loosened new version
  reaches it. Fix with the seam, not after it.
- **DESIGN.md update:** on green, rewrite §Versioning's "Today there is no such
  outcome" and "Making one constant drive both is the versioning work"
  paragraphs to record what landed, and add the byte-identity hedge —
  *within a release and a layout configuration* — to §Concurrency & FaaS's SEC
  claim, which today has none.
