# TODO — post-cutover work list

Status: bankruptcy ledger and implementation plan of record (2026-07-27).
Replacement epic: `poc-16-kb6`. Landed on `main` from the `removal-index`
recovery branch. Written from a 13-agent read-only audit; every finding below
was reproduced at least twice, and the three marked CRITICAL were re-verified
by hand against `b500288`.

This is the temporary design and execution authority after bead bankruptcy.
Items 1, 5, 7 and 8 are now decided. Items 8 and 9 will delete this file: once
DESIGN.md is true and the replacement graph is complete, the surviving
decisions move there.

## How to use this

Numbering matches the audit report the design owner responded to; item N here is
finding N there. Each item states the rule (locked by the design owner), the
evidence, what to build, and what "done" means. No requirement survives from a
bankrupt bead unless this document restates it and a child of `poc-16-kb6` owns
it.

**Phase 0 is S2: ship the matrix and skeletons.** House convention — the
implementation plan lands callable stub APIs plus skip-marked, named realistic
tests before bodies are written; the signatures are the contract. S2 covers the
selector, named-edge, authorization-guard, removal-admission, capped-tree,
compositional proof-budget, Worker-lookup and screening seams used by S3-S5.
Do not start writing bodies against prose.

The S4/S5 boundary is a deliberate feature gate. S4 builds and cross-checks the
new capped trees in shadow mode while the current removal slot and removal
globals remain authoritative; bounded Worker authorization is not enabled
there. S5 is one rebuild-forcing format/semantic cutover: committed receipt
issuance and screening become live, commit-proof-derived SuppTree slot values
become authoritative, the legacy removal slot and unbounded removal globals
disappear, and only then does the bounded Worker path serve grants. Every
intermediate commit keeps existing deletions effective.

Ground rules that outlive this file:

- No ongoing backwards compatibility. Break the format, delete the old path.
  The one fenced S4-to-S5 grandfather conversion below is an explicit atomic
  cutover, not a lazy read migration; after its seal there are no dual decoders
  or old-format publishers. A rebuild-forcing layout stamp is a dev-loop
  convenience, not compatibility.
- The author owns the fact type. Family `author`/command functions are the sole
  construction chokepoint; callers pass parameters, never assemble envelopes.
- Workers and daemons stay thin. Algorithm logic belongs in the event modules.
- `~/poc-16-all-night` belongs to another agent: read only. Never run
  `git clean -fdx` or `git checkout -f` in any poc-16 worktree —
  `.beads/embeddeddolt` is a live shared Dolt database, gitignored and
  unrecoverable.
- The interpreter is `python3`. Full suite: `python3 -m pytest -q` (~75 s).

---

## 1. Suppression is an explicit, type-owned offer set `CRITICAL`

**THE RULE (locked).** A fact family declares whether facts of that family can
be suppressed and, if so, exactly which suppression selectors they offer.
There is no generic inference from every dependency and no guess based on a
fact's fields.

A suppressible fact can offer several selectors:

```
SELF
PARENT(<declared dependency role>, <parent fid>)
ANCESTOR(<declared dependency path>, <ancestor fid>)
```

The relationship label/path is validation evidence. All three resolve to the
same Worker lookup namespace:

```
resolve(f, SELF)          = "fact:" + fid(f)
resolve(f, PARENT(_, p))  = "fact:" + p
resolve(f, ANCESTOR(_, a))= "fact:" + a
```

`SELF` is a literal on-wire placeholder, not the fact's fid embedded in its own
envelope. The fid hashes the envelope, so embedding it would be circular; the
reader expands `SELF` only after integrity has established the fid.

A family that cannot be suppressed declares `SUPPRESSION = NEVER` and emits no
selector. A deletion/removal may target only a key that its target actually
offers. Removal facts themselves are `NEVER`: the old special-case
`not is_deletion(f)` remains defense in depth, not the source of the law.

Offering a selector means “this selector may suppress me”; it does **not**
automatically grant every removal family permission to name that selector
directly. Each suppressible family also declares an exhaustive
`DIRECT_TARGETS` matrix of `(removal_family, offered_selector_role)` pairs.
Every live exact-target proposal carries the target fact's exact key plus the
selector token it is invoking. Admission reloads that `FactRecord`, requires
the pair in `DIRECT_TARGETS`, recomputes the offered selector and resolved sid,
and rejects any mismatch. A bare inherited sid is never a deletion capability.

In v1, message/file exact removal targets the victim's `SELF` only. Parent and
ancestor selectors still make descendants disappear when that ancestor's own
`SELF` is removed; they do not let “delete this chunk” silently become “delete
its file.” A device fact's `SELF` remains an explicit suppression key inherited
by its requests, but device revocation uses the separately guarded,
family-declared `DevicePrincipal(public_key)` action. That action covers every
device-provider fact for the key, including a duplicate label/timestamp record
and any provider published later. The target capability must itself prove
control of that key: v1 accepts only the key-signed self-bound `device` fact or
the key-signed `DeviceOwnerConsent` for an exact `device_invite`. A bare
`device_invite` remains a provider that a legitimate key-wide action will mask,
but is never a principal-action target; an inviter therefore cannot pre-tombstone
an arbitrary public key. It is nevertheless revocable without cooperation from
the invited key: the invite offers its own exact `SELF` to the separately
declared `device.grant.delete` action. Its retained owner (the inviting user's
principal) may retract that one grant, and an admin may retract any such grant.
This exact action masks only that invite; it does not create a terminal
`DevicePrincipal` tombstone for the key. Terminal user eviction likewise uses
`MemberPrincipal(public_key)`, never an inherited `ExactSids` shortcut. A
principal action is accepted only from an authenticated target FactRecord whose
family derives that exact principal value; a caller-supplied public key alone is
not a capability. A future family may expose another direct selector or
principal action only by adding that exact pair/scope to the exhaustive matrix
and its hostile contract tests.

`NEVER` says only that the fact is **not a suppression target**. It does not say
that the fact may exercise authority without a live principal. Families
separately declare named `AUTHORIZATION_GUARDS`; those dependencies must be
unsuppressed before a new irreversible effect can receive an admission receipt.
This separation lets a removal remain untargetable while still preventing an
evicted admin from authoring a new removal.

An authority-producing family separately declares
`AUTHORITY_LIVENESS_GUARDS`: the exact named proof edges and selector/principal
scopes whose later suppression withdraws an already-published authority
candidate. Authorship proof, one-time admission guards and continuing authority
liveness are three different questions. Merely appearing somewhere in a
candidate's proof closure never makes a fact a continuing liveness guard.
The candidate-producing edge's declaration is the root of this policy. A
`LiveGuard(path, selector_or_principal)` adds that one resolved scope; a
`FollowAuthority(path)` explicitly imports the declaration rooted at that
named nested authority edge. Nothing walks every authority-producing edge in
the proof DAG implicitly. This makes “grantee only,” “grantor only,” “both,” and
“follow the delegated authority chosen at this path” distinct reviewable
contracts rather than consequences of proof shape.

Illustrative authority chain:

```
user U       [SELF]                     -> {fact:U}
device D     [SELF, PARENT(member, U)]   -> {fact:D, fact:U}
request Q    [PARENT(device, D),
              ANCESTOR(device/member,U)] -> {fact:D, fact:U}
removal R    []                          -> NEVER; GUARDS(member, admin);
                                           proposes target fact:U
admission A  []                          -> NEVER; makes R effective
```

Removing `fact:U` closes every device/request that explicitly inherited U.
Removing `fact:D` closes only D's lineage. The remover authors one entry and
never knows or enumerates descendants.

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

### Construction and admission contract

The family owns *which* dependency roles propagate suppression. For example, a
reply may inherit `reply_to` while a quote does not, even though both reference
a message. A chunk inherits its exact file descriptor; a generic author/member
need does not become a cascade edge unless that family's policy says so.

Use a declarative family constant, logically:

```
SUPPRESSION = NEVER
SUPPRESSION = Policy(self=True)
DELETE_OWNER = ActorOwner(("author-principal",))
DIRECT_TARGETS = (Target("content.delete", SELF, modes=(OWNER, ADMIN)),)
SUPPRESSION = Policy(self=True, inherit=(Parent("file"),))
DELETE_OWNER = NEVER
DIRECT_TARGETS = ()
SUPPRESSION = Policy(
    self=True,
    inherit=(Parent("device"), Ancestor(("device", "member"))),
)
DIRECT_TARGETS = ()
PRINCIPAL_TARGETS = (
    Target(
        "device.revoke", DevicePrincipal(field="device_key"),
        target_kinds=(SELF_BOUND_DEVICE, DEVICE_OWNER_CONSENT),
    ),
)
AUTHORIZATION_GUARDS = ()
AUTHORIZATION_GUARDS = (
    Guard(("author-principal", "member")),
    Guard(("author-principal", "admin")),
)
AUTHORITY_LIVENESS_GUARDS = ()
AUTHORITY_LIVENESS_GUARDS = (
    LiveGuard(("grantee", "member"), selector=SELF),
)
AUTHORITY_LIVENESS_GUARDS = (
    LiveGuard(("grantee", "member"), selector=SELF),
    FollowAuthority(("delegation",)),
)
```

The skeleton phase must publish an exhaustive matrix for every registered
family before implementation. That matrix, not generic core code, answers which
parents and grandparents propagate, which offered selectors each removal family
may directly target, which target FactRecord fields derive a terminal
`MemberPrincipal` or `DevicePrincipal` scope, and which named edges authorize an
irreversible effect or keep an authority offer live. A guard is not serialized
as an offered suppression key and does not make a `NEVER` fact targetable.
`DELETE_OWNER = NEVER` emits no delete offer. A directly deletable row instead
names one exact actor edge; admission turns that edge into the proof-carrying
`OwnerBinding` and normalized `DeleteOffer` specified under item 5. Thus
suppression, direct targetability and ownership are all explicit type
declarations, rather than guesses from a field name or from every dependency.
The matrix also contains the durable, device-key-authored
`DeviceOwnerConsent` row from item 5. Only that row exposes a `DEVICE` actor
edge; `device_invite` supplies its exact grant evidence but never by itself
offers ownership of the invited key.

The authoring helper expands the declared paths over the actual closed
dependency set, unions and deduplicates their offered keys, and serializes the
explicit selectors. Parents precede children, so no descendant knowledge is
needed. A diamond dependency contributes one key once.

Admission independently recomputes the exact selector, one-time guard-source
and continuing authority-liveness-guard sets from the named, resolved
dependencies and requires equality. For an exact removal it also recomputes
each target binding from the proposal's authenticated target ref, the target
family's `DIRECT_TARGETS` entry and that target's offered selectors; it never
accepts a caller-supplied sid in isolation. For a principal removal it instead
requires the target family's exact `PRINCIPAL_TARGETS` entry, derives the key
from the authenticated target FactRecord, and expands it through the committed
provider registry. A static source test is necessary but not sufficient: it
catches a family author that forgets the helper, while runtime admission rejects
a hostile peer that strips or invents a selector or liveness guard, promotes an
inherited selector to a direct target, supplies a naked principal key, or
substitutes a non-guard dependency. The current `Valid.deps` tuple loses
dependency names, so the skeleton must add a named resolved-edge representation
rather than trying to recover roles from unordered fids after judgment. A
suppressible offer-resolved parent must either be pinned by an explicit ref or
be revalidated whenever its canonical provider changes; suppression ancestry
may not depend on arrival order.

The effective set is:

```
S(f) = { resolve(f, selector) : selector in declared_selectors(f) }
G(f) = union(S(provider(edge)) for edge in authorization_guards(f))
D    = { sid : SuppTree[SuppSlot(sid)] is authenticated `ACTIVE` }
suppressed(f) = (S(f) ∩ D != ∅)
authorized_now(f) = (G(f) ∩ D == ∅)
```

`core/node.py:suppressed`, rebuild masking, ingress screening and Worker minting
all call this one mechanism. `apply_removals` enumerates resident victims through
the existing many-to-many `supp(fid, k)` table for *every* removal kind; the
direct-target special case disappears. `authorized_now` is consulted when
minting an immutable admission for an irreversible effect; it is not a second
way to suppress ordinary facts.

Full ancestor enumeration trades graph walks for envelope size. The family
matrix must state a maximum selector count/depth and a compositional
worst-case Worker role budget, and admission must enforce both without consulting
the current winner. Attachments are depth one; any future unbounded reply or
authority DAG needs a measured bound or a different persistent-set
representation before it ships.

### Done when

- Deleting a file retracts its chunk facts on both the live and rebuild paths;
  the recovery probe finds no orphan `file_chunk_rows` and cannot reconstruct the
  plaintext.
- The family matrix covers every registered family. `NEVER` rejects every
  selector; every other policy rejects a missing, extra, wrong-role or
  non-ancestor selector.
- The target matrix rejects a bare sid, an inherited parent/ancestor sid
  presented as a content target, a device's exact `SELF` presented in place of
  `DevicePrincipal`, a naked principal key, the wrong target ref, and every
  removal-family/selector or principal-scope pair not explicitly declared.
  A bare `device_invite` cannot be the target of `DevicePrincipal`; only the
  target-key-signed self-bound `device` or `DeviceOwnerConsent` row can create
  that terminal action.
  Removing an ancestor by its own `SELF` still suppresses all descendants that
  offered its id. Two valid device records with the same key but different
  labels/timestamps, plus a later third provider, are all masked by one
  key-wide device tombstone.
- A `NEVER` removal cannot be targeted, but it also cannot produce a suppression
  row without live declared guards and an immutable admission receipt.
- The static check fails when a family author stops using the policy helper, and
  hostile wire tests prove the runtime check independently.
- `SELF` resolves to `fact:<fid>` without a self-reference in the hashed
  envelope.
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

Wire a per-fact
`screen(facts, lookup) -> {fid: (suppressed, guards_live)}` result at the mint
gate and at `PUT /pile` (`core/daemon.py:135-147`). The whole submitted closure
is still validated and is used to recompute every explicit selector and named
guard, but one suppressed support fact does **not** reject every dependent in
the pile. Suppression is applied to each newly admitted durable fact and to the
ephemeral fact being authorized, using that fact's own offered set `S(f)`.
Stable `valid()` remains globals-blind.

This distinction is load-bearing. If a quote depends on a message but its
family intentionally does not inherit `reply_to`, suppressing the message masks
the message and not the quote, regardless of arrival order. A message authored
by an evicted member does inherit that membership key, so screening the message
itself closes the relay gap without turning every hard dependency into an
implicit cascade. Ingress may retain a suppressed fact in `V` for convergence,
but it never projects or authorizes it in `E`.

Targetability and authorization are orthogonal. A family whose fact creates an
irreversible effect declares `AUTHORIZATION_GUARDS`; all named guard providers
must be in `E` when that effect is admitted. In particular, a bare removal fact
is a stable, `NEVER`, inert proposal. Under S5 it remains outside the canonical
frontier and changes no `SuppSlot` until the keyring-pinned,
service-exclusive workspace-global admission authority has checked its
author/member/admin guards against one certified current root and committed
item 7's immutable, frontier-bound admission receipt. An active member relaying
an evicted admin's proposal cannot manufacture its commit proof.

Once committed, the receipt and its effect are permanent: later
canonical-provider changes or eviction of the author do not undo an action that
was already admitted. Revocation prevents **new committed admissions** once the
workspace-global authority has observed it. In a partition, a receipt that wins
the global serialization cell against a certified basis that had not yet
observed the eviction is a concurrent authorized action and remains valid; this
system does not claim an instantaneous global revocation boundary. That is the
explicit availability/authorization rule, not an arrival-order accident.

The mechanism decisions are now locked:

- A membership fact offers `SELF`.
- Device/bearer/request authority inherits the exact membership and device keys
  named by its family policy.
- User eviction declares the family-owned
  `MEMBER_PRINCIPAL(public_key)` target scope. At every certified root that
  scope expands to **all** membership-provider facts for the key, winning,
  losing, published later or restored from the sealed legacy universe, and
  changes each provider's preallocated `SuppSlot("fact:<membership_fid>")` to
  `ACTIVE`. Readers still look up only the exact provider fids in their proof;
  there is no ambient public-key read. A later provider creates its own slot
  already `ACTIVE` in the same ordinary publication. Provider count is
  protocol-capped and capacity for the maximum is escrowed when the principal
  is admitted. In v1 the eviction is terminal for that public key: rejoin uses
  a new key.
- Device-only revocation declares the family-owned
  `DEVICE_PRINCIPAL(public_key)` target scope derived from the authenticated
  target FactRecord. The target must be either that key's signed self-bound
  `device` fact or its signed `DeviceOwnerConsent` naming an exact invite;
  `device_invite` alone is deliberately ineligible. Once admitted, the action
  expands to every device-provider fact for that key, including bare competing
  invites, not just the selected fid. This both closes the current
  stable-validation gap in which different labels or timestamps produce
  several valid device facts for one key and prevents a hostile inviter from
  planting a future tombstone for a caller-chosen key. The same registry rule
  masks a matching provider in the root that first publishes it after
  revocation. Provider count and future-slot escrow are capped exactly as for
  membership, and re-enrollment uses a new device key.
- A bare `device_invite` is still independently retractable by exact `SELF`
  through the family-owned `device.grant.delete` direct-target row. The action
  uses the invite's retained `OwnerBinding`: the inviting user may revoke the
  grant from any consenting device, and an admin may revoke it under the same
  `ADMIN` handler used for other deletable facts. This closes a lost-device
  grant without asking the invited key to mint consent. It never expands to
  other providers for that public key and therefore cannot pre-tombstone an
  unrelated key.
- Facts merely relayed by an active member retain the original author's
  selectors; a relay cannot launder them through its own grant.
- For ordinary facts, before/after authoring is irrelevant. The suppression tree
  is monotone, so an old fact and a later fact carrying the same removed
  ancestor key are screened identically. Irreversible actions instead use the
  explicit admission point above.
- The live author and peer doors both require a target that actually offered the
  named suppression key. A `NEVER` fact cannot be targeted. Item 7's sealed
  `LEGACY_GLOBAL` zero-provider tombstone and exact `LegacyMask` are the only
  migration exceptions; neither can be authored live.
- No bare removal proposal has an effect, even if its stable fact validation and
  signature are otherwise correct.

S4 preserves the current authenticated `globals` and legacy removal-slot
behavior and keeps the new Worker path feature-gated. S5 changes
`auth.removal.global_rows`/the root derivation so a bare proposal emits nothing
and the admission publication alone creates the final SuppTree effect. Before
that rebuild-forcing format bump, item 7's fenced grandfather pass converts
every effective legacy entry into a committed receipt plus
`AdmissionCommitProof` without re-evaluating a now-evicted author. Only the
first completely backfilled S5 root deletes the legacy removal slot and
`request.evaluate`'s whole-global `removed` set and enables bounded Worker
authorization. There is no commit where both old
and new mechanisms are absent.
The submitted closed authority proof already names the membership and device
fids; the final Worker path collects their selectors and performs item 7's
authenticated multi-lookup without rebuilding a fact database.

**SETTLED application policy, to freeze in the exhaustive family matrix before
bodies are written:**

- A delegated-admin provider has **grantee-only continuing liveness**. Its
  immutable admission proof must contain the grantor's authorship, live
  membership and live admin provider and the grantee's live membership. The
  admitted provider then carries `SELF` plus the grantee-membership parent
  selector. Those mandatory provider selectors mask it if the grant itself or
  the grantee is removed. The grantor proof is a one-time
  `AUTHORIZATION_GUARD`, not an `AUTHORITY_LIVENESS_GUARD`, and the production
  row has no `FollowAuthority(grantor-admin)`. Removing the grantor or changing
  that grantor's later canonical admin winner therefore does not retroactively
  revoke an already-admitted grant. This follows the same rule as a committed
  removal receipt: losing authority closes the future, not a valid act already
  committed in the past.
  Migration applies that rule only with authenticated timing. From S4 shadow
  activation onward, first publication of every authority-producing fact
  stores its exact committed actor-authority evidence in the serialized
  publication path. A closure within the native bound uses
  `BOUNDED(AuthorityAdmissionRef)` with its `CommittedAuthorityProof` and
  `AuthorityProofCommitProof`; an over-budget but checkpointable closure uses
  `PAGED_S4(S4PagedAuthorityAdmissionRef)` with a content-addressed paged
  `LegacyAuthorityProofRecord`, its strong commit row and post-commit proof.
  Either form proves whether all one-time authorization guards were live then.
  The same rule applies to an exact proof closure over a provider that already
  existed when the recorder started, and to a newly selected alternate closure
  for an already-recorded provider. Before a deletable target may cite either
  closure, the service admits and post-commit-proves that exact closure at a
  prior frontier. The later target CAS may cite only that durable proof, never a
  prospective row or merely the provider's first recorded closure. This
  two-frontier path is an admission at the current serialized point, not a
  backfill from a later winner. If its one-time guards or the finite shadow
  proof reserve fail, legacy S4 may still publish the target unchanged, but it
  creates no actor record and therefore cannot cut to S5.
  If an authority provider predates that recorder and no post-activation actor
  use committed its exact closure, cutover may admit it only when every
  one-time guard is still live. If any such guard is no longer live in the
  frozen cutover state, S5 cannot distinguish “admitted before removal” from a
  globals-blind first relay after removal, so migration stops on writable S4 or
  explicitly re-anchors. In particular, an old delegated-admin grant with a
  removed grantor is never guessed into or out of existence.
  The grantee address is also preserved literally. An existing
  `admin(target_pk)` whose target is a device member migrates as key-scoped
  `admin(device_key)`, not as an admin grant to that device's owner. The
  migration certifier replays the exact grantee offer and rejects a
  key-to-owner rewrite. Owner-level use is a separate composed proof over
  `admin(owner_principal)` plus the acting device's retained
  `DeviceOwnerConsent`, so it cannot arise from a device-targeted grant.
- A directly deletable target exposes a normalized
  `DeleteOffer("content.delete", SELF, OwnerBinding(...))`.
  `OwnerBinding` contains the signing key, immutable `OwnerPrincipal`, binding
  kind (`DIRECT_MEMBER` or `DEVICE`), exact provider fact key/fid/FactRecord
  oid, the committed authority-proof record/commit-proof identity, and the
  deterministic admission-service-signed `ActorBindingProof` over the target
  fact key/fid and that exact evidence. No mutable root oid, frontier serial,
  retry generation or current winner enters the signed statement. The service
  issues it only after recomputing the complete actor rule at the serialized
  attempt that first claims the immutable target `FactSlot`; inclusion in that
  service-published root is the commit and a signed pre-CAS orphan is inert.
  The target's `FactRecord` roots that complete binding and proof closure.
  Certification verifies the retained signed verdict after provider shadowing,
  historical-root collection and restart; it neither retains/reopens an old
  composite root nor re-resolves current authority to rediscover or change an
  owner, and it never trusts an unproved cached principal. Equal statements
  produce byte-identical proofs under the workspace's fixed deterministic
  Ed25519 admission key, so retries do not make equal logical rows diverge.
  No owner field is accepted from the proposal caller. A target type with no
  suppression selector or no matching
  `DIRECT_TARGETS`/`DeleteOffer` row is not deletable. In particular, `NEVER`
  emits no deletion offer. Admin status does not create one. The
  `device_invite` family is a distinct non-content example: it offers
  `DeleteOffer("device.grant.delete", SELF, OwnerBinding(...))`, so its owner
  or an admin can retract that exact provider without manufacturing a
  key-wide `DevicePrincipal` capability.
- `content.delete` has two explicit proposal modes, `OWNER` and `ADMIN`, so
  each handler returns an ordinary conjunctive needs tuple rather than asking
  the kernel for a generic `AnyOf`. Both modes require proposal authorship, a
  live member actor, the exact target ref, the target's matching
  `content.delete`/`SELF` offer, and live authorization guards. `OWNER`
  additionally requires the authenticated
  `ActorPrincipal(signing_key)` to equal the target's `OwnerPrincipal`.
  `ADMIN` instead carries one explicit `admin_scope`, `KEY` or `OWNER`, and
  derives rather than accepts its subject. `KEY` requires the live
  `admin(signing_key)` offer. `OWNER` is available only to a `DEVICE` actor and
  requires the live `admin(owner_principal)` offer from that actor's retained
  `DeviceOwnerConsent`. A grant to a device key `D` therefore remains exactly
  `admin(D)` and authorizes only `D`; it is never normalized into `admin(U)` and
  never promotes `D`'s siblings. Separately, a grant to user key `U` authorizes
  `U` under `KEY` and each consenting device owned by `U` under `OWNER`. The
  selected scope and exact admin provider/proof are retained in the receipt, so
  no current winner or caller-supplied principal chooses between them.
  Thus an admin may delete every fact whose type declares it deletable, while
  an ordinary user may delete only that user's own deletable facts.
  The bare proposal is therefore constructible and stageable. The immutable
  receipt is the later post-proposal commit gate, not a proposal need or an
  input to its own `proof_digest`: proposal/support proof refs plus the
  service-derived `ActionAuthorization` → `proof_digest` → receipt → receipt
  `EvidenceRef` → `ActionRecord` remains the only construction order.
  These modes are the complete policy for new `LIVE_GUARDS` actions. Fenced
  migration has a third, non-callable receipt variant,
  `GRANDFATHER(LegacyEffectAuthorizationRef)`, solely to preserve an effect
  already present in the authoritative S4 removal slot or removal globals.
  The ref binds the exact pre-seed `LegacyEffectCensus` row, old source
  FactRecord and `LEGACY_SLOT`/`LEGACY_GLOBAL` kind; the migration seal and
  translation attestation prove that row came from the frozen authoritative S4
  state. It deliberately does not claim that the old actor satisfied the new
  owner/admin policy. Thus an old cross-user deletion that S4 validly made
  effective remains grow-only, while no live proposal, caller, later relay or
  bare legacy fact can select `GRANDFATHER`.
- `ActorPrincipal` is also type-owned proof, not a string comparison. A
  `DIRECT_MEMBER` offer normalized only from the matrix's direct-membership
  families (`workspace`/`user`, plus their sealed legacy equivalents) has
  absolute precedence and makes the signing key act as itself, even if a
  `device_invite` also names that key. Classification asks first whether the
  serialized state contains **any admitted, shape-valid direct-member
  claimant**, including a masked one. If it does, the actor class is
  `DIRECT_MEMBER`; a selected direct provider must then pass the live-member
  guard. If all such providers are suppressed the action fails, and it never
  falls through to a device claim. `DEVICE` therefore means no direct-member
  claimant exists at that serializing check, not merely that no direct provider
  is currently live.

  A bare `device_invite` is also never ownership consent. Before a device-only
  signing key may act as a user, that key must author a durable
  `DeviceOwnerConsent(workspace, device_key, owner_principal,
  device_invite_ref)`: it hard-refers to the exact admitted invite/provider,
  needs the device key's own signature and live membership, verifies the
  provider's exact `device(owner_principal, device_key)` co-offer, and exposes
  the matrix's `DEVICE` actor edge. Its own suppression selectors inherit the
  exact provider and member liveness declared by that family. The one-step
  direct-key invite may still admit a known sibling as a member; this consent is
  the separate proof that lets the sibling's key speak for the shared user when
  authoring owned content or actions.

  The same consent boundary applies when the key is the victim rather than the
  actor. A `DevicePrincipal(device_key)` action must target either the
  key-signed self-bound `device` row or this exact key-signed consent row.
  Admission derives the key from that retained target and verifies its
  signature/provider edge. A bare invite is still included among the provider
  fids masked by a legitimate key-wide action, but it offers no
  `device.revoke` target capability of its own.

  Actor resolution selects only a canonical, live
  `DeviceOwnerConsent` proof for the signing key. A competing invite without the
  target-key signature can at worst make an authority edge unavailable; it
  cannot assign the target key's content to the inviter, and the inviter's other
  devices can never gain `OWNER` deletion from it. Multiple consents require the
  existing canonical provider rule, but every candidate was signed by the
  device key whose role it declares. Both actor branches bind and retain the
  exact selected provider/proof and target-bound service verdict as above.
  A direct member's ordinary self-owned `device` provider seeds that user's
  device set and is not a `DEVICE` ownership candidate: the actor remains the
  direct member. A `DEVICE` owner binding comes only from the consent row that
  maps a distinct device key to a user through its exact invite proof. This
  matches the existing direct-member-over-device role rule and prevents an
  unsolicited or conflicting device claim from taking ownership of either a
  member key or a device-only key. Consequently every consenting equal peer in
  one user's device set can delete content owned by that user, and no inviter
  can claim another key as an owner.

  Actor class is serialization-relative, not globally monotonic. A later direct
  rejoin may legitimately rerank a formerly device-only signing key and controls
  new facts/actions from that later serialized state; it does not rewrite an
  older target's signed `OwnerBinding`. Conversely, a later device claim cannot
  steal a key for which any direct-member claimant exists at the check being
  serialized. Two attempts to install different bindings for the same raw target
  race at one `FactSlot`: the first valid service CAS fixes the bytes, and every
  retry or competing attempt must match that binding or reject. Relaying a fact
  never changes either principal.

For a newly admitted target, authoring and admission derive and retain its
`OwnerBinding` from the exact named actor edge. Legacy migration does **not**
rerun direct-member precedence over the frozen S4 set: that would rewrite a
target authored by device `D` for user `U` if `D` joined later as a direct
member. The S4 shadow writer instead begins recording a capped immutable
`LegacyActorAdmissionRecord` for each directly deletable target at the same CAS
that first publishes that target. The record binds its target key/fid, exact
actor class, signing key, owner principal, selected authority proof and exact
legacy binding basis. Normal direct-member and consented-device targets record
the same basis S5 will use. For compatibility while S4 remains authoritative,
a device-only key that has not yet published `DeviceOwnerConsent` may record
the narrow `S4_DEVICE_INVITE_ACCEPTANCE` basis only when the device submits a
separate contextual signature over `(workspace, target key/fid, device key,
owner principal, exact invite key/fid/FactRecord oid)`. The target itself must
also be authored by that device key, and the bound live invite proof must offer
both `member(device_key)` and `device(owner_principal, device_key)`. The ordinary
detached target signature alone is insufficient because it names none of the
workspace, owner or invite fields. The contextual signature is acceptance for
this one target only. It neither creates a standalone `DeviceOwnerConsent`,
authorizes another target or action, nor makes the invite eligible for
`DevicePrincipal`.

The recorder may write that target record only after the exact selected actor
closure has a durable `RecordedActorAuthorityRef`. A within-budget closure uses
`BOUNDED(AuthorityAdmissionRef)` and requires its
`CommittedAuthorityProof`/`AuthorityProofCommitProof`. A closure above
`MAX_AUTHORITY_PROOF_FACTS` uses
`PAGED_S4(S4PagedAuthorityAdmissionRef)`: before the target CAS, the service
canonicalizes the complete closure into the same paged
`LegacyAuthorityProofRecord` shape used by cutover, commits its immutable
manifest/pages and exact provider under `CommittedS4PagedAuthorityProof`, and
waits for `S4PagedAuthorityProofCommitProof`. If the provider predates recorder
activation, or the same provider is now selected through a different proof
closure, the service performs the applicable separate idempotent bounded or
paged admission against the current S4 frontier, validates every one-time
guard, waits for its post-commit proof, and only then attempts the target CAS.
Committing that closure remains useful even if the later target loses its CAS;
it is not an orphan or a target-capacity leak. A closure that cannot pass its
guards or fit the separately provisioned finite shadow authority-proof reserve
is never referenced by `LegacyActorAdmissionRecord`; the legacy target can
still publish without the record and deterministically blocks S5.

The recorder is shadow evidence, not a new S4 validity gate. If an otherwise
valid legacy target lacks the contextual acceptance or another complete actor
basis, S4 still publishes it under the unchanged authoritative rules but
creates no actor-admission record; that explicit absence blocks S5 until
re-anchoring. It never guesses an owner or silently rejects a fact that old S4
peers accept.

For an eligible target, the capped immutable record is first written only after
the service claims one already-provisioned
`S4ActorAdmissionScratchSlot`. That generation-fenced slot charges the maximum
scratch record object/bytes and one write lease before upload. The one
serialized target CAS verifies the sealed scratch hash and live lease, then
atomically publishes the target, debits the disjoint canonical
record/row/slot/proof/lease dimensions from
`S4ActorAdmissionCapacityCell`, writes the
`CommittedLegacyActorAdmission` row, creates the deterministic
`LegacyActorAdmissionProofSlot` in `RESERVED` state, and transitions the
scratch slot to `COMMITTED_COPYING`. Scratch and canonical record allowances
therefore coexist after a winning CAS until the content-addressed canonical copy
has been verified. Insufficient canonical capacity leaves the target valid on
S4 but without a record and therefore blocks S5. A losing or failed CAS changes
no canonical capacity, record or slot; it moves the scratch slot to
`ABORTING`, fences it, definitively drains its write lease, and only then makes
the precharged slot reusable. A successful CAS has already reserved the maximum
proof bytes and lease. The post-CAS signer issues
`LegacyActorAdmissionCommitProof` only after rereading the committed target,
canonical record, row and slot; recovery can deterministically finish the same
copy and proof after a crash. It contains no caller assertion and cannot be
synthesized from a later root.

During the one fenced S4-to-S5 cut, an older deletable target gets an
`OwnerBinding` only from a valid prior immutable owner binding or that exact
admission-time record and proof. The migrated `FactRecord` roots the record,
commit proof and exact legacy authority proof/checkpoint. Its legacy evidence
keeps the record's original `RecordedActorAuthorityRef` as immutable provenance
and separately carries either a byte-equal bounded `DIRECT` S5 transport ref or
an authenticated `CHECKPOINT` transport ref for a `PAGED_S4` source. The
checkpoint form binds the exact new checkpoint provider/commit identity to the
original provider, proof closure, paged legacy proof oid and source candidate
id; certification rederives that translation. It never pretends the future
checkpoint identity
was present in the S4 record. The resulting S5 `ActorBindingProof` signs both
the recorded source and the selected transport while carrying the same actor
fields without retaining or reopening the historical S4 root. A target that
predates the shadow recorder
and has no such evidence is not guessed from current providers—even if the
current state appears unambiguous—and keeps the workspace on writable S4 or
requires explicit re-anchoring. For a target published after the recorder was
enabled, a missing device-key-signed `DeviceOwnerConsent` is not itself a
failure when the committed record proves the exact per-target
`S4_DEVICE_INVITE_ACCEPTANCE` fallback above, including its contextual device
signature. An absent/ambiguous record, a
missing commit row or proof, or evidence beyond both the native proof cap and
signed paged checkpoint/source ceilings has the safe writable-S4 outcome; a
merely deep recorded proof takes the existing `LegacyAuthorityCheckpoint`
path. After S5 activates, the fallback can migrate old target ownership but
cannot authorize the device to publish anything new: the device must first
publish ordinary `DeviceOwnerConsent`.

Admission reloads and authenticates the target and authority `FactRecord`s and
recomputes the proposal mode's complete needs/offer match. A bare target fid,
sid, owner key, inherited selector, unsigned or redirected device consent,
mismatched device co-offer, invalid `admin_scope`, or `OWNER` proposal for
another principal rejects. An ordinary member cannot select `ADMIN` without
the exact live admin provider derived for its declared scope.
The proposal fact remains
`SUPPRESSION = NEVER` and inert until its receipt commits. A receipt committed
before a later admin removal remains effective; after removal that admin cannot
obtain a new receipt. These are family checks over normalized needs and offers,
not a second policy engine and not a reason to rebuild SQLite at request time.

Concretely, the two policy modes instantiate ordinary conjunctive handlers.
`AdminSubject` is a checked family derivation, not a caller-supplied key:

```
OWNER = (Author(proposal, signing_key),
         LiveMember(ActorBinding(signing_key)),
         ExactTargetRef(target),
         Need("content.delete", target.SELF,
              ActorBinding(signing_key).owner_principal))
ADMIN = (Author(proposal, signing_key),
         LiveMember(ActorBinding(signing_key)),
         AdminSubject(
             KEY => signing_key,
             OWNER => ActorBinding(signing_key).owner_principal
                      iff ActorBinding.kind == DEVICE),
         LiveAdmin(AdminSubject),
         ExactTargetRef(target),
         Need("content.delete", target.SELF, ANY))
```

`OWNER`'s exact third field matches the immutable target owner; `ADMIN`'s
canonical `ANY` still has to resolve the exact target's offered row and does not
invent targetability. The `KEY` and `OWNER` `AdminSubject` branches are two
declared resolved-edge variants, each a simple conjunction; there is no generic
kernel disjunction. The named skeleton supplies the proof-carrying
`ActorBinding` and exact admin provider; handlers do not accept a caller-supplied
principal. The receipt is deliberately absent from both tuples.

This freezes the S2/S5 contract; it is not a claim that the legacy
`facts/content/delete.py` handler already enforces it. That handler remains the
documented any-member behavior until the coordinated S5 semantic cut, because
partially changing stable validation before receipts and the new roots are
authoritative would fork peers.

### Done when

- `tests/test_mint.py:434` (`test_gate_mask_screens_whole_closure`, the suite's
  one remaining skip) is un-skipped and passes.
- Black-box tests prove user eviction, device-only revocation, relayed
  authorship, and facts authored on both sides of removal.
- A removed admin cannot obtain or relay a new removal admission. A receipt
  committed before a later eviction survives provider shadow/restore and remains
  effective, while a bare, forged or signature-only receipt never creates a row.
- Production delegated-admin fixtures prove removing the grantee masks the
  admitted admin provider, while removing or re-ranking the grantor does not.
  The generic paired grantee-only/grantor-only fixtures remain to prove the
  engine obeys declarations rather than hard-coding the production choice.
  Migration fixtures distinguish a post-recorder grant committed before its
  grantor's removal (survives), one first relayed after removal (has no admitted
  authority proof), and a pre-recorder grant with a now-removed one-time guard
  (blocks S5/requires re-anchor rather than guessing either history).
  A pre-recorder member closure used by a post-recorder target, and an alternate
  closure for an already-recorded provider, each commit and post-commit-prove
  that exact closure at a prior frontier before the target record can cite it.
  Mutants that reuse only the provider's first closure, cite a prospective
  proof, or consume shadow proof capacity on a losing proof CAS fail.
- Deletion fixtures prove a direct member key and two sibling devices can each
  delete that user's content; an ordinary member cannot delete another user's
  content; a live admin can delete another user's deletable content but cannot
  delete a `NEVER` fact; and hostile owner/mode/device/target-offer
  substitutions reject.
  A direct `admin(D)` grant lets only device key `D` use `ADMIN/KEY` and does
  not promote its owner or siblings. An `admin(U)` grant lets `U` use
  `ADMIN/KEY` and a device with an exact retained `D -> U` consent use
  `ADMIN/OWNER`; wrong-scope and sibling-without-consent attempts reject.
  A direct member key remains self-owned when a conflicting device claim names
  it. A hostile member can publish or grind a competing invite for a device-only
  key, but without that target key's `DeviceOwnerConsent` the claim can neither
  own new content, create a `DevicePrincipal` tombstone, nor let the hostile
  member's siblings delete it. A valid
  device consent, its wrong-owner/provider/target signature mutants, and the
  direct-claim-present-but-masked no-fallback rule all have named fixtures.
  Target ownership remains byte-identical after provider shadowing, root
  collection, restart and restore because the exact owner proof is retained
  without retaining the historical root.
  A direct member can still publish its self-owned primary `device` fact and
  grant the first sibling. A later direct rejoin changes actor resolution for
  new work without changing an older device-authored target's retained owner.
  A closure containing a new actor provider plus a deletable child commits and
  proves the provider first; a forged, missing, wrong-target, root-dependent or
  current-winner-substituted `ActorBindingProof` rejects.
  Grandfather fixtures preserve an authoritative S4 cross-user deletion and a
  later-evicted admin's removal global with
  `GRANDFATHER(LegacyEffectAuthorizationRef)`. Forcing either through
  `OWNER`/`ADMIN`, or allowing a `LIVE_GUARDS` proposal to select
  `GRANDFATHER`, fails.
- A later direct rejoin cannot rewrite a legacy device-authored target:
  migration uses its admission-time `LegacyActorAdmissionRecord`, atomic commit
  row, filled proof slot and commit proof, never current direct-member
  precedence. A fact predating that recorder has no inferred owner and leaves
  S4 writable. A device-authorized S4 target without prior consent records the
  exact device-signed contextual `S4_DEVICE_INVITE_ACCEPTANCE` basis; a mutation
  that substitutes the workspace, target, owner or invite, treats it as reusable
  consent, or accepts only the ordinary target signature fails. A deep
  but checkpointable recorded legacy owner proof migrates through
  `LegacyAuthorityCheckpoint` while retaining its original recorded authority
  ref and a distinct authenticated checkpoint transport. A mutant that
  overwrites the recorded ref with the future checkpoint identity, omits either
  ref, or fails to replay their exact source translation cannot certify. Only
  missing/ambiguous/uncommitted evidence or evidence beyond the signed
  checkpoint/source/cutover ceilings blocks the cut.
- Arrival-order tests prove a suppressed incidental support fact does not veto
  a child whose family deliberately omitted inheritance from that edge.
- Matrix fixtures instantiate grantee-only and grantor-only delegated-admin
  liveness. Suppressing the omitted principal leaves the existing candidate
  live, suppressing the declared principal masks it, and a closure-wide masking
  mutant fails both fixtures.
- A request-time test fails if Worker minting scans all facts, decodes the whole
  suppression tree, or reconstructs SQLite.

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

## 7. Publish an authenticated suppression tree beside the fact tree `MAJOR`

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

### Two removal orders, one removal-specific tree

There are two access paths, but not two new removal indexes:

1. The fact tree stores every ordinary durable fact accepted by ordinary
   publication at
   `K(f) = <ts>:<fid>` as
   `FactTree[FactSlot(K(f))] = ADMITTED(fact_record_oid)`. S5 FactTree is a
   grow-only authenticated admission archive, not the mutable current proof
   DAG: canonical-provider shadowing, suppression and local projection
   quarantine never delete that row or its FactRecord/raw-root closure.
   Eligibility is derived and certified separately from the exact authority
   candidate proofs below. FactTree membership alone can therefore never
   authorize or project a quarantined fact.
   Removal proposals are not ordinary publications: staging one changes no
   canonical root, and a committed action roots its proposal, support and
   receipt records through the filled `ActionSlot`/`ActionRecord` evidence arm
   instead of inserting an unreceipted removal `FactSlot`.
   When a directly suppressible target is first admitted,
   it also creates one fixed-width, initially empty
   `ActionSlot(Sid(sid))`; the first membership or device provider for a
   principal creates `ActionSlot(MemberPrincipal(pk))` or
   `ActionSlot(DevicePrincipal(pk))`, respectively. Filling a slot stores only
   fixed-width `FILLED(action_record_oid)`. The referenced immutable,
   size-capped `ActionRecord` stores the target spec plus a bounded
   `EvidenceRef` for the proposal, receipt and every detached signature/support
   fact needed to certify the action. Each ref names the full ordinary address,
   fid and FactRecord oid; that FactRecord roots the immutable raw-fact chunk
   tree. The immutable evidence bytes retain their original fids, but no Worker
   needs a second lookup tree keyed by removal fid.
2. The suppression tree has one fixed-width row for every admitted suppression
   id, created atomically with the fact that first offers that id:

```
SuppTree[SuppSlot(sid)] = CLEAR
SuppTree[SuppSlot(sid)] = ACTIVE(witness_removal_fid, witness_action_slot)
```

`SuppSlot` uses a reserved, invalid-fid tag in the tree's canonical key
encoding; it is not a fabricated removal id. A Worker already knows `sid`
(`fact:<fid>`) and performs one authenticated **exact** lookup. `CLEAR` proves
unsuppressed and `ACTIVE` proves suppressed under the certified cross-index
invariant. A missing slot is never interpreted as clear: it is a certification
or submitted-proof error, because every selector must resolve to a target whose
slot was admitted first. A later membership or device provider covered by an
existing principal tombstone inserts its new slot directly as `ACTIVE` in the
same prospective publication or does not publish.

This changes the earlier prefix proposal deliberately. Preallocating the
sentinel makes exact lookup sound and, more importantly, turns every future
revocation into fixed-key **value updates**. A removal never inserts a
SuppTree key, deletes an AuthorityTree key, or structurally inserts its
proposal/receipt into FactTree. Authority rows whose last provider disappears
retain the same key with a fixed-width `NO_PROVIDER` value. Therefore an
already-admitted target cannot hit an unlucky future page split.

The action owner is `Sid(min(effect_targets))` for `ExactSids`,
`MemberPrincipal(pk)` for a member tombstone, `DevicePrincipal(pk)` for a
device tombstone, and `Migration(mask_namespace, victim_fid)` for `LegacyMask`.
Each committed action fills its own owner slot even when another action already
suppresses some of the same sids. The slot's fixed pointer reaches an
`ActionRecord` carrying the full target spec and complete immutable evidence
references, so a local reverse SQLite cache may find an action by removal fid
for audit without making removal fid an authoritative tree order. Certification
verifies the pointer oid, digest, size cap and the complete transitive evidence
closure off-request; the Worker never fetches it.

`SuppSlot` is intentionally a single-valued **verdict with one canonical
witness**, not the ownership record for every overlapping action. For a root,
define `effective_actions(root, sid)` as all commit-proven actions whose
recomputed `effect_targets` contain `sid`, and choose:

```
witness(root, sid) =
    min(effective_actions(root, sid),
        key=canon(ActionSlot(owner(action)),
                  fid(proposal(action)), K(admission(action))))
```

The `ACTIVE` value names exactly that witness. Thus an exact removal and a later
member/device-principal tombstone can both remain committed without overwriting
or hiding either action: both ActionSlots remain filled, while the SuppSlot
stores the deterministic minimum. A principal admission still commits its
terminal registry row and future-provider escrow when all current providers are
already active; it changes an existing SuppSlot only if it becomes the
canonical witness. A later provider may implement several typed scopes at once:
for example, `device_invite` offers both membership and a device key. Its
initial effective set is **every** committed `MemberPrincipal` and
`DevicePrincipal` tombstone whose typed scope the new FactRecord provides,
bounded by `MAX_PRINCIPAL_SCOPES_PER_FACT`; its one new SuppSlot points to
`witness(root, sid)` over that complete set, never the first matching registry
row. Certification rejects both an `ACTIVE` value whose witness is not effective
and any effective action target whose slot is not `ACTIVE` with the recomputed
canonical witness.
Grandfathered duplicates remain immutable evidence, but migration admits only
their canonical lowest-removal-fid action; duplicates never create a
request-time range.

Live deduplication is target-spec-specific:

- `ExactSids` contains canonical `TargetBinding` values, not naked strings.
  Admission accepts one only when its proposal ref resolves to the named target
  record and exact content-hash-matching `target_fact_record_oid`, the target
  family permits that exact removal-family/selector pair, recomputing the
  selector produces the redundantly bound sid, and **every**
  named sid still has its exact unspent `RevocationLiability` entry at the
  prospective frontier. One unauthorized, spent, already-suppressed or
  otherwise redundant binding rejects the whole candidate before receipt
  signing; the caller may stage a new proposal containing only the residual
  non-empty set. Admission never silently rewrites the signed target spec.
- `MemberPrincipal(pk)` and `DevicePrincipal(pk)` are rejected only when
  `TargetRegistry` already names an equivalent committed receipt for that exact
  typed principal. Their terminal liabilities are independent of whether all
  current provider fids happen to be masked by earlier `ExactSids` actions. The
  first typed-principal receipt must therefore commit its tombstone and
  future-provider escrow even when every current effect is redundant.
- `LegacyMask` and the zero-provider `LEGACY_GLOBAL` case are admitted only by
  the fenced migration rules below.

A separate authoritative tree keyed only by removal fid would duplicate the
action-slot evidence and serves no Worker query; a local reverse SQLite index
may exist only as rebuildable cache.

Every receipt signs one exact family-owned `target_spec`:

```
TargetBinding(
    target_fact_key, target_fact_record_oid, selector_token, resolved_sid)
ExactSids(non_empty_sorted_bindings)   # content; v1 token is SELF
PrincipalBinding(
    target_fact_key, target_fact_record_oid,
    principal_kind, resolved_public_key)
MemberPrincipal(PrincipalBinding(...)) # terminal user eviction
DevicePrincipal(PrincipalBinding(...)) # terminal device-key revocation
LegacyMask(mask_namespace, victim_fid)  # migration-only; defined below
```

For one certified root, `effect_targets(root, a)` is the exact sid set:
`ExactSids` is the non-empty set of recomputed `resolved_sid` values from its
bindings; `MemberPrincipal` is every `fact:<membership_fid>` in the exact
authenticated provider-binding registry for that key; `DevicePrincipal` is
every `fact:<device_fid>` in the corresponding device-provider registry; and
`LegacyMask` is its one reserved
`legacy-mask:<mask_namespace>:<victim_fid>` migration sid. The namespace is
derived from fenced pre-record state below, never from the final
`cutover_digest`. Either typed-principal set may temporarily be empty. A live
`PrincipalBinding` must resolve its target fact, match the declared
membership/device family, derive the redundantly bound kind and public key from
that FactRecord, and satisfy that family's exact `PRINCIPAL_TARGETS` entry.
For `DevicePrincipal`, the only live target kinds are a key-signed self-bound
`device` row and a key-signed `DeviceOwnerConsent`; a `device_invite` binding
is rejected even though the resulting legitimate tombstone later includes that
invite among its provider effects. The
receipt therefore retains every binding and exact target FactRecord oid. The
ActionRecord makes each named target FactRecord and its raw-root closure
independently reachable for the action's lifetime even if that target later
leaves the current eligible proof DAG for canonical-provider quarantine; its
ordinary admitted row also remains in the grow-only FactTree. These target
records are distinct from the at-most-eight proposal/support/receipt
`EvidenceRef`s and do not consume that evidence cap. A certifier requires each
target key, fid and oid to match, follows its FactRecord/raw root, and replays
the target-ref, family-policy, offered-selector/scope and resolution checks
instead of trusting the cached sid or principal key. The separate provider
bindings below do the same for every provider expanded by a principal action;
they are not smuggled into either the single `PrincipalBinding` capability or
the evidence cap. The
`LEGACY_GLOBAL` binding below is the only target-fact-free migration exception.
A live typed-principal action must resolve at least one provider when admitted. It
requires every existing provider slot to be `ACTIVE` with the recomputed
canonical witness even when another grow-only removal already masks that fid;
the maximum possible witness updates consume the terminal principal reserve,
not the already-released per-fid reserve. A `LEGACY_GLOBAL` receipt is the
deliberate zero-provider exception:
the old global was already a future-provider tombstone, so migration preserves
it even when the sealed legacy universe contains no matching membership fact.
`ExactSids` is capped at
`MAX_EXACT_SIDS_PER_REMOVAL`; member and device expansion are separately capped
at `MAX_MEMBERSHIP_PROVIDERS_PER_PRINCIPAL` and
`MAX_DEVICE_PROVIDERS_PER_PRINCIPAL`; therefore every admission has at most
`MAX_EFFECT_TARGETS_PER_REMOVAL` rows.

The serialized service also maintains
the following canonical value:

```
PrincipalProviderBinding(
    provider_fact_key, provider_fact_record_oid, provider_fid)
PrincipalProviderRegistry[(workspace, typed_principal_scope)] =
    sorted(PrincipalProviderBinding(...), key=provider_fid)
```

Each binding is an authenticated reachability edge to the exact FactRecord and
its raw-root closure, not a bare fid. The certifier derives the typed principal
scope from that record's family-owned offers and rejects a key/fid/oid/scope
mismatch. The value is grow-only, capped by both the corresponding provider
count and `MAX_PRINCIPAL_PROVIDER_REGISTRY_VALUE_BYTES`, and changes in the
same prospective root/frontier transaction that admits a membership/device
provider. A provider leaving the current eligible proof DAG for
canonical-provider quarantine does not delete its FactTree row or registry
binding, free its count, clear its `ACTIVE` SuppSlot, or release its retained
object bytes. Restore must match the exact
retained binding and consumes no new count; a conflicting record rejects.
Consequently a sixty-fifth distinct provider rejects even if any earlier
provider is currently quarantined. `effect_targets` reads the `provider_fid`
fields from this bounded registry rather than scanning FactTree.

If `TargetRegistry` already contains the typed tombstone, that same transaction
queries all at-most
`MAX_PRINCIPAL_SCOPES_PER_FACT` family-declared typed scopes, creates the
provider's SuppSlot as `ACTIVE` with the canonical minimum over every matching
tombstone, and retains the new provider binding, or rejects the provider. S4 may
build the initial registry by an off-request full scan over the published and
registered-quarantine universe. S5 certification rederives that initial value
from `LegacyUniverseMap`; afterward it replays every ordinary provider
publication and requires exact monotone correspondence, including bindings
whose records are no longer live. It is certification/publication support,
never a Worker lookup or a removal-fid index.

The serialized admission service maintains a strongly consistent, service-side
`TargetRegistry[(workspace, typed_principal_scope)] =
(removal_fid, admission_fact_key)` for every committed `MemberPrincipal` or
`DevicePrincipal` receipt. The typed scope makes the row unique and prevents a
second receipt for the same terminal key. The service updates that table in the
same transaction as the receipt/root cells. This is not a fourth request-time
tree and Workers never read it. It lets an ordinary membership/device
publication find its prior principal-wide tombstone without a fact scan, while
`PrincipalProviderRegistry` supplies the complete bounded provider set.
Initial root certification may rebuild the registry only from filled FactTree
`ActionSlot` records that also have the exact committed-admission proof defined
below; a receipt signature by itself is not a registry source. Subsequent
certification maintains it incrementally and checks it against the same
committed set.

The same service also maintains the complete forward candidate set needed to
replace a suppressed authority winner:

```
AuthorityFactBinding(fact_key, fid, fact_record_oid)
AuthorityProofEdge(
    dependent_binding_index, REF | NEED, dependency_ordinal,
    provider_binding_index)
AuthorityProofRecord(
    provider_binding_index,
    sorted_fact_bindings, sorted_proof_edges,
    proof_closure_digest,
    transport_proof_depth, logical_proof_depth,
    canonical_transport_cost)
CommittedAuthorityProof(
    workspace, authority_proof_record_oid, provider_fid,
    admission_basis_root_oid, admission_basis_frontier_serial,
    DirectRoot(committed_root_oid, frontier_serial, frontier_digest)
      | CutoverGeneration(service_generation_id))
authority_proof_commit_id =
    H("authority-proof-commit", workspace, authority_proof_record_oid,
      provider_fid)
AuthorityProofCommitProof[authority_proof_commit_id] =
    sign(admission_sk, canon(["authority-proof-commit-v1",
                             authority_proof_commit_id,
                             CommittedAuthorityProof(...)]))
AuthorityCandidateRef(
    candidate_id, provider_fid, provider_fact_record_oid,
    authority_proof_record_oid, authority_proof_commit_id,
    proof_closure_digest, logical_proof_depth, canonical_candidate_rank,
    NATIVE_RANK | LEGACY_SOURCE_RANK(checkpoint_fid)
      | DERIVED_LEGACY_RANK(sorted_checkpoint_fids),
    canonical_transport_cost,
    COOFFERS_MATCH | COOFFERS_MISMATCH,
    sorted_provider_sids, sorted_action_scopes,
    ADMITTED_PROOF,
    CLEAR | MASKED(witness_action_slot))
AuthorityCandidateRegistry[(workspace, NeedKey)] =
    sorted(AuthorityCandidateRef(...), key=canonical_candidate_order)
BaseNeedKey =
    (offer_name, a0, exact_a1 | ANY, budget_class)
BaseOfferNeedKeyRegistry[(workspace, BaseNeedKey)] =
    sorted_unique(NeedKey...)
AuthorityBaseCandidateRef(
    provider_fid, provider_fact_record_oid,
    authority_proof_record_oid, authority_proof_commit_id,
    proof_closure_digest, logical_proof_depth,
    rank_provenance,
    canonical_transport_cost, sorted_exact_provider_offers,
    sorted_provider_sids, sorted_action_scopes)
AuthorityBaseCandidateRegistry[(workspace, BaseNeedKey)] =
    sorted(AuthorityBaseCandidateRef(...),
           key=(provider_fid, authority_proof_record_oid,
                proof_closure_digest))
```

`BaseNeedKey` removes only the required-co-offer tuple from a full `NeedKey`;
it preserves the base offer query and budget class. An exact offered
`(name, a0, a1)` can affect the corresponding exact and `ANY` base queries in
each compatible finite budget class. The family matrix determines that finite
expansion. `BaseOfferNeedKeyRegistry` is the complete bounded directory from
such a base query to every admitted full NeedKey, including tuples the provider
does not satisfy. `AuthorityBaseCandidateRegistry` is the complete bounded
provider/proof set for that base query. Its exact provider-offer summary is
replayed from the provider FactRecord, capped at
`MAX_PROVIDER_OFFERS_PER_CANDIDATE` and
`MAX_PROVIDER_OFFER_SUMMARY_BYTES`, and is sufficient to derive
`COOFFERS_MATCH` or `COOFFERS_MISMATCH` for any directory entry without a
FactTree scan. Base refs are immutable discovery records. A later full NeedKey
copies only providers whose exact proof has a commit-proven `ADMITTED_PROOF`
record. For **that full NeedKey**, it then derives a fresh `candidate_id`,
canonical rank, co-offer verdict and mask from the retained provider/proof
fields, provider summary and declared scopes. The base order is only a
canonical set encoding; it is never a winner order. This matters because the
candidate-id tie breaker includes the full NeedKey: two proof closures can sort
one way for Alice's required co-offers and the opposite way for Bob's. Reusing
one base rank would select the wrong proof for one of them. A removal therefore
rewrites only affected full values, not this base directory.

The content hash of `AuthorityProofRecord` is
`authority_proof_record_oid`. Its at-most-`MAX_AUTHORITY_PROOF_FACTS` bindings
name the exact FactRecord for every fact in this candidate's closed proof, and
each FactRecord roots its raw fact. Edges use bounded binding/field ordinals:
the certifier reloads the dependent FactRecord's ordered refs/needs, recomputes
the normalized `NeedKey` and family co-offers at that ordinal, and requires the
named provider binding. Thus the record is the authenticated preimage of
`proof_closure_digest`, not another bare digest or an invitation to search
FactTree. Distinct closures for one provider have distinct proof-record oids.
The serialized authority validates the record against the then-current
canonical rows and one-time authorization guards before publication. The same
strong root/frontier transaction stores one `CommittedAuthorityProof` row for
that oid under a deterministic `authority_proof_commit_id`; the post-commit
signer then emits the bounded `AuthorityProofCommitProof`. Base/full refs name
that id, and composite-state GC retains its row and proof sidecar. A pre-CAS
proof record or signature is inert. The row's `CommitBinding` is immutable:
an exact proof closure committed before the fence keeps its historical
`DirectRoot` row and post-commit proof through cutover. The cutover may use the
non-cyclic `CutoverGeneration` binding only when it first commits a closure
that has no row under that deterministic id. It never rewrites or recommits an
existing `DirectRoot` row as `CutoverGeneration`; a byte-different row at the
same id is a certification failure. Registry refs and GC retain whichever one
strong row/proof pair won that closure's first serialized commit. If a crash
left that winning row without its deterministic proof sidecar, the signer
rereads the row and regenerates
`AuthorityProofCommitProof[authority_proof_commit_id]`; row presence is never
misclassified as “uncommitted” merely because the proof write is pending.
Cutover blocks on that recovery instead of attempting a second generation-bound
row.
The full and base candidate-registry values root each proof record, which roots
every support FactRecord/raw closure through shadow, restart and historical-root
GC.

One proof record has at most `MAX_AUTHORITY_PROOF_EDGES`, rejects above
`MAX_AUTHORITY_PROOF_RECORD_BYTES`, and is charged as its own canonical object.
The forward value keeps only its fixed-size oid/digest summary, so 64 bounded
candidate refs do not inline 64 complete proofs. Removal masking still examines
only the preverified scope summaries in at most 4,096 candidate refs; it does
not fetch 4,096 proof records on the action path. Full record replay happens
when a candidate is admitted and during off-request certification.
Because a full NeedKey includes its required co-offers, each ref also contains
the fixed recomputed match state for that exact tuple. Fallback first chooses
the minimum commit-proven `ADMITTED_PROOF`/`CLEAR` **full** candidate by the
rank derived for that full NeedKey; if that ref is
`COOFFERS_MISMATCH`, AuthorityTree stores `NO_PROVIDER` rather than skipping to
a losing candidate. This preserves selection-before-requirement semantics
without fetching proof records on the removal path.

`sorted_provider_sids` is the exact deduplicated suppression-id set offered by
the provider FactRecord itself. It is empty for `NEVER`; for migrated state it
also contains the precomputed migration-only sid added to a `LegacyMask` victim.
A candidate can never remain usable after its own provider record is
suppressed. This mandatory provider-existence check imports no incidental
support fact and grants no removal family new targeting authority.

`sorted_action_scopes` is separately the exact deduplicated expansion of the
candidate-producing edge's declared `AUTHORITY_LIVENESS_GUARDS`. Each
`LiveGuard` names an exact proof path and resolves, through authenticated
FactRecords, to one offered `Sid`, `MemberPrincipal` or `DevicePrincipal`
scope. Only an explicit `FollowAuthority(path)` recursively imports the
declaration rooted at that named nested authority edge; following is
cycle-checked and consumes the same scope budget. A hard dependency, another
authority-producing edge elsewhere in the proof DAG, signature, incidental
support fact or one-time `AUTHORIZATION_GUARD` contributes no scope merely
because it appears in the complete proof closure. Thus a family can deliberately
choose grantee-only, grantor-only, both, neither, or one explicit delegated
chain without generic closure traversal overriding its policy.
`candidate_id` is the domain-separated hash of the **full** NeedKey, provider fid,
`authority_proof_record_oid` and proof-closure digest; distinct valid proof
closures for the same provider are distinct candidates, so an alternate path
cannot hide behind the same fid. It and `canonical_candidate_rank` exist only
in a full `AuthorityCandidateRef`, never in an
`AuthorityBaseCandidateRef`. Materializing a directory entry derives both
after substituting that entry's exact full NeedKey.
The proof record separates bounded Worker transport from logical selection
rank. `transport_proof_depth` and `canonical_transport_cost` replay only the
record's actual ordinal DAG and remain within the 64-fact Worker envelope. In a
topological replay, each native binding's `logical_depth` is zero at a root or
one plus the maximum logical depth of its selected `REF`/`NEED` providers. A
`LegacyAuthorityCheckpoint` binding contributes its certified
`source_proof_depth`, not its deliberately shallow transport depth. The
record's `logical_proof_depth` is the resulting value at
`provider_binding_index` and must not exceed `MAX_LOGICAL_PROOF_DEPTH`.

Only after `authority_proof_record_oid` exists and a full NeedKey is selected
does an ordinary full registry ref derive its `candidate_id` and
`canonical_candidate_rank =
(logical_proof_depth, provider_fid, candidate_id)`. A proof with no checkpoint
ancestor carries `NATIVE_RANK`; a non-checkpoint descendant carries
`DERIVED_LEGACY_RANK(sorted_checkpoint_fids)` naming exactly the checkpoint
bindings that contributed logical depth. A checkpoint candidate itself is the
sole tuple exception: `LEGACY_SOURCE_RANK(checkpoint_fid)` selects by the
checkpoint's certified
`(source_proof_depth, source_fid,
legacy_candidate_id(full_need_key, checkpoint))`, never by the shallow
service-signed proof or new provider fid used to transport that checkpoint to a
Worker. For the checkpoint's original source NeedKey that derived id must equal
its retained `source_candidate_id`; another compatible full NeedKey derives
its own tie breaker from the same certified source proof fields. Thus a child
device/admin of a flattened 519-hop membership has logical depth 520 even when
its transport DAG has depth one. Flattening changes proof transport, not the
canonical ordering that existed at the sealed cut. The certifier rejects
missing/extra checkpoint provenance, a native fact with legacy provenance, a
checkpoint with native/derived provenance, a base ref carrying a candidate id
or winner rank, or any stored logical depth/rank that does not equal this
recurrence.
The candidate-id tie breaker is deliberately outside `AuthorityProofRecord`;
putting it in that hashed record would require a hash fixed point. The
deduplicated union of mandatory
`Sid` scopes from `sorted_provider_sids` and declared
`sorted_action_scopes` has at most
`MAX_AUTHORITY_IMPACT_SCOPES_PER_PUBLICATION` entries. One NeedKey has at most
`MAX_AUTHORITY_CANDIDATES_PER_NEED` candidate refs and one registry value has at
most `MAX_AUTHORITY_CANDIDATE_REGISTRY_VALUE_BYTES`; admitting the next candidate
or an oversized encoding rejects before upload. The same candidate/count/byte
caps apply to one `AuthorityBaseCandidateRegistry` value. In addition, the
deduplicated union of candidate mask scopes across **all** refs in one base
value may not exceed `MAX_AUTHORITY_IMPACT_SCOPES_PER_BASE`. This invariant is
checked when either the first full NeedKey or a later provider arrives. A late
NeedKey therefore updates at most 64 reverse values, rather than as many as
64 candidates times 64 disjoint scopes; the same final provider set is
accepted or rejected in both arrival orders. One base has at most
`MAX_FULL_NEED_KEYS_PER_BASE` directory entries and the canonical directory
value must fit `MAX_BASE_OFFER_NEED_KEY_REGISTRY_VALUE_BYTES`. Candidate
**masking** is
monotonic, but its witness is canonical rather than arrival-order-dependent.
Scope matching follows suppression effects, not only the action proposal's
top-level target tag:

```
guard_actions(root, Sid(sid)) =
    effective_actions(root, sid)
guard_actions(root, MemberPrincipal(pk)) =
    the commit-proven action in
    TargetRegistry[(workspace, MemberPrincipal(pk))], if any
guard_actions(root, DevicePrincipal(pk)) =
    the commit-proven action in
    TargetRegistry[(workspace, DevicePrincipal(pk))], if any
scope_witness(root, scope) =
    min(guard_actions(root, scope), by the canonical action order)
candidate_mask_scopes(candidate) =
    { Sid(sid) for sid in candidate.sorted_provider_sids }
    union set(candidate.sorted_action_scopes)
mask_witness(root, candidate) =
    min(non-empty scope_witness(root, scope)
        for scope in candidate_mask_scopes(candidate))
```

A full ref has one immutable admission marker and one monotonic liveness field.
`ADMITTED_PROOF` means the exact proof was canonical and its one-time guards
were valid at its commit-proven admission basis. That historical authorization
does not re-resolve against later AuthorityTree winners. In particular,
suppressing an incidental grantor can change the grantor's current authority
row without quarantining a grantee-only candidate whose declaration omitted the
grantor. Canonical-provider shadowing still controls new fact admission and
local projection eligibility, but it cannot retroactively revoke an already
admitted authority proof. Continuing withdrawal is expressed only by the
provider's own selectors and the family-declared liveness scopes below.

`mask` is `CLEAR` exactly when the scope-witness set is empty and otherwise is
`MASKED(mask_witness(...))`. In particular, a provider's own sid or a declared
`Sid(provider_fid)` guard is masked by either an exact action or a
`MemberPrincipal`/`DevicePrincipal` action whose recomputed `effect_targets`
contains that provider sid. A migration-only sid masks candidates produced by
its exact `LegacyMask` victim through `sorted_provider_sids`, without pretending
that the mask was a family-selectable `LiveGuard`. These cases are authenticated
by the provider's `ACTIVE` SuppSlot. A provider and its candidate published
after a principal tombstone therefore start `MASKED` exactly like the same
candidate published before the tombstone; no target-tag intersection can make
the two arrival orders disagree. A new ref resolves at most its 64 exact scope
witnesses without enumerating actions: for `Sid`, the authenticated `SuppSlot`
is `CLEAR` or already names `min(effective_actions(root, sid))`; for a typed
principal, the unique `TargetRegistry` row names its terminal action. A later
affecting action changes only the fixed-width state, including replacing an
older witness when the new canonical minimum wins. A masked ref never returns
to `CLEAR`.

The canonical resolver chooses the minimum commit-proven `ADMITTED_PROOF`
candidate whose mask is `CLEAR` from this complete bounded value, or
`NO_PROVIDER` when none remain. A removal first
unions the affected NeedKeys below, reads at most one candidate-registry value
per key, recomputes every ref's `guard_actions`, masks every affected ref and
derives the winner from the remaining refs. It therefore examines at most
`MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION` pre-indexed refs and never scans
FactTree or an unbounded provider population to find a fallback. The prospective
root transaction updates each changed candidate value and its AuthorityTree
row together. No candidate or proof record is deleted by later projection
quarantine, and both still consume the candidate-count and object/byte caps.
S4 may build the initial values off-request; S5 certification verifies every
`AuthorityProofCommitProof`, structurally replays every rooted proof without
consulting later canonical winners, and rederives every ref, scope set, mask,
logical rank and winner from admitted FactRecords and commit-proven actions. The
registry is
publication/certification support, not a fourth Worker tree.

The service pairs that forward registry with a bounded
`AuthorityImpactRegistry[(workspace, action_scope)]`, where `action_scope` is
`Sid(suppression_id)`, `MemberPrincipal(public_key)`, or
`DevicePrincipal(public_key)`. Its value is a sorted, monotonic conservative set
of `NeedKey`s: a key enters when any admitted authority candidate for it
has that scope in its recomputed `candidate_mask_scopes`. This covers the
candidate provider's own explicit suppression ids and losing/fallback providers
as well as the current canonical winner. Beyond the provider itself, it follows
only the transitive named liveness guards selected by each authority-producing
family. Complete proof closure remains authentication evidence, not an ambient
revocation policy.

Reverse lookup uses the same effect semantics:

```
impact_scopes(root, ExactSids(...)) =
    { Sid(sid) for sid in effect_targets(root, action) }
impact_scopes(root, MemberPrincipal(binding)) =
    { MemberPrincipal(binding.public_key) }
    union { Sid(sid) for sid in effect_targets(root, action) }
impact_scopes(root, DevicePrincipal(binding)) =
    { DevicePrincipal(binding.public_key) }
    union { Sid(sid) for sid in effect_targets(root, action) }
impact_scopes(root, LegacyMask(...)) =
    { Sid(sid) for sid in effect_targets(root, action) }
```

`LEGACY_GLOBAL` uses the corresponding typed-principal case, including its
principal scope when the provider set is empty. Thus a principal action queries
the reverse rows for its terminal scope and every at-most-64 provider sid it
actually suppresses. This set is capped at
`MAX_ACTION_IMPACT_SCOPES = MAX_EFFECT_TARGETS_PER_REMOVAL + 1`; the union of
NeedKeys remains capped independently at
`MAX_AUTHORITY_CONSEQUENCES_PER_ACTION`. A future provider is handled by its
ordinary publication: its SuppSlot and candidate state are born `ACTIVE` and
`ADMITTED_PROOF`/`MASKED` in the same prospective root.

Grow-only conservative membership is deliberate. A later winner change or
removal does not require rewriting unrelated scope records, and a stale extra
key only spends capacity; an omitted key could strand revocation and is a
certification error. For an action, `authority_consequences(a)` recomputes the
exact fixed-point candidate-state and AuthorityTree changes within the union of
the registered sets for `impact_scopes(root, a)`. It resolves every fallback
from the paired bounded
`AuthorityCandidateRegistry`; the reverse registry identifies keys but is never
mistaken for the candidate set. Both registries are certification/publication
support, never Worker lookups, and initial S4 construction may derive them by
an off-request full scan.

Variable-width registry values are not inlined in the atomic root transaction.
`PrincipalProviderRegistry`, `BaseOfferNeedKeyRegistry`,
`AuthorityBaseCandidateRegistry`, `AuthorityCandidateRegistry` and
`AuthorityImpactRegistry` use the same authenticated indirection:

```
RegistryValueObject(kind, workspace, logical_key, canonical_value)
registry_value_oid = H(canon(RegistryValueObject(...)))
RegistryValuePointer(registry_value_oid, canonical_value_bytes)
```

The strongly consistent keyed cell stores only the fixed-size
`RegistryValuePointer`; its immutable value object is in the prospective object
manifest and is retained by the canonical composite state. The object binds
kind, workspace and logical key, so a pointer for another registry or key is
not substitutable. Publication builds each complete prospective value, rejects
it above its per-value cap, hashes it, and stages that exact object before the
root commit. The commit flips at most one bounded pointer per changed logical
key. While an attempt is `COMMITTED_COPYING`, the pointer may name only its
sealed, hash-verified scratch copy; the authority blocks every next publication
and serving transition until the same bytes exist at the canonical oid. A
certifier resolves the pointer, verifies the oid, encoded byte count, kind,
workspace and logical key, then rederives the value. Pointer indirection is an
atomic-write bound, not a cache or a weakening of registry completeness.

Full-NeedKey and provider arrival are symmetric and scan-free:

1. When an ordinary fact or a family-declared Worker role first introduces a
   full NeedKey, the service derives its `BaseNeedKey`, appends the full key to
   that base's directory, reads the one bounded base-candidate value, and
   materializes the complete full `AuthorityCandidateRegistry` value. Every
   base candidate is copied, including candidates whose exact provider-offer
   summary yields `COOFFERS_MISMATCH`; candidate ids and ranks are derived
   separately with this exact full NeedKey, and the minimum resulting full
   candidate still wins before the co-offer verdict. It also adds that full key
   to every applicable scope's reverse-impact value. The base value's
   preverified union of scopes is at most
   `MAX_AUTHORITY_IMPACT_SCOPES_PER_BASE`, so this late-key path is bounded by
   that union rather than candidates times scopes.
2. When an ordinary provider candidate arrives, the finite family matrix
   derives its at-most-`MAX_PROVIDER_BASES_PER_PUBLICATION` exact/`ANY` base
   queries. The service appends it to each bounded base-candidate value, reads
   each base's complete directory, and appends the derived match/mismatch ref to
   **every** listed full candidate value. It then recomputes those AuthorityTree
   rows and the candidate's reverse-impact relationships in the same prospective
   operation. A provider that lacks Alice's required co-offer is therefore still
   a mismatch candidate in Alice's row; absence never masquerades as omission
   from the candidate set.

One ordinary fact introduces at most
`MAX_ORDINARY_NEED_KEYS_PER_PUBLICATION` full NeedKeys. Across all bases, one
provider publication may touch at most
`MAX_PROVIDER_AUTHORITY_CANDIDATE_VALUES_PER_PUBLICATION` existing full
candidate values, while the combined operation may touch at most
`MAX_AUTHORITY_CANDIDATE_VALUES_PER_PUBLICATION` full values. The
prospective union may update at most
`MAX_AUTHORITY_IMPACT_VALUES_PER_PUBLICATION` reverse values. Its canonical
proof DAG resolves at most
`MAX_AUTHORITY_IMPACT_SCOPES_PER_PUBLICATION` distinct sid/principal scopes.
Each base candidate value independently has a certified union of at most
`MAX_AUTHORITY_IMPACT_SCOPES_PER_BASE` scopes, and adding a provider that would
make that union larger rejects even when no full NeedKey exists yet. This is
the symmetric admission invariant: 64 candidates with 64 disjoint scopes
cannot be admitted early and surprise a late NeedKey with 4,096 reverse
updates. The prospective union of need-introduction and provider work must
still touch no more than 64 distinct reverse values.

The combined consumer/provider operation is charged by the 162-object
aggregate below. It may change 8 directory values while introducing NeedKeys
and 8 different directory values while publishing offers, and may materialize
8 new full-candidate values in addition to updating 64 existing ones; capacity
therefore uses 16 and 72 respectively rather than assuming favorable overlap.
Sharing does not permit either limit to be exceeded. A
sixty-fifth directory entry for one base, candidate for one base/full NeedKey,
affected full candidate value, reverse value or scope rejects before object
upload. The same prospective transaction handles a fact that both consumes and
produces authority; no arrival order selects which half sees the other.

Thus a new provider never scans AuthorityTree/FactTree or guesses which
required-co-offer tuples already exist, and a new full NeedKey never scans old
providers. S4 may seed both access paths by an off-request full scan; S5
certification rederives the directories, base candidates, full candidates,
match states, reverse relationships and winners from admitted proof records and
rejects an omitted or extra entry. Post-S5 ordinary publication uses only these
bounded values.

The operation also rejects if any NeedKey would exceed
`MAX_AUTHORITY_CANDIDATES_PER_NEED`, any live individual sid or terminal
principal scope would exceed `MAX_AUTHORITY_CONSEQUENCES_PER_ACTION`, or if the
registry/service-capacity budget would be exceeded. Every reverse value rejects above
`MAX_AUTHORITY_IMPACT_REGISTRY_VALUE_BYTES`; the complete NeedKey count and
encoded-byte caps are both required. `ExactSids` additionally computes the exact
fixed-point union under all of its bindings simultaneously and rejects an
over-limit batch; its caller may restage smaller batches because each individual
target retains its own liability. Neither typed-principal action can be split,
so a later membership, device or delegation publication that would make that
principal's terminal impact exceed the bound is the operation rejected. Certification
rederives every required forward candidate and reverse relationship from the
admitted fact/proof graph and rejects an omission, an extra live candidate, or
a state/winner mismatch; conservative historical reverse keys and monotonically
masked candidates are canonical and remain. Consequently the limits are
admission invariants over both losing-candidate width and transitive reverse
fan-out, not assertions that currently visible winners or descendants happen to
be few.

For every effective proposal `r` and admission `a`, the snapshot invariant is:

```
AuthorityAdmissionRef =
    canon(provider_fact_key, provider_fid, provider_fact_record_oid,
          authority_proof_record_oid, authority_proof_commit_id)
S4PagedAuthorityAdmissionRef =
    canon(provider_fact_key, provider_fid, provider_fact_record_oid,
          legacy_authority_proof_record_oid,
          s4_paged_authority_proof_commit_id,
          s4_paged_authority_proof_commit_proof_oid)
s4_paged_authority_proof_commit_id =
    H("s4-paged-authority-proof-commit", workspace, provider_fid,
      legacy_authority_proof_record_oid)
CommittedS4PagedAuthorityProof[s4_paged_authority_proof_commit_id] =
    canon(workspace, provider_fact_key, provider_fid,
          provider_fact_record_oid, legacy_authority_proof_record_oid,
          s4_generation, s4_frontier_serial, committed_s4_root_digest)
S4PagedAuthorityProofSlot[s4_paged_authority_proof_commit_id] =
    RESERVED(MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_PROOF_BYTES)
  | FILLED(s4_paged_authority_proof_commit_proof_oid)
S4PagedAuthorityProofCommitProof[
        s4_paged_authority_proof_commit_proof_oid] =
    sign(admission_sk,
         canon(["s4-paged-authority-proof-commit-v1",
                s4_paged_authority_proof_commit_id,
                CommittedS4PagedAuthorityProof[
                    s4_paged_authority_proof_commit_id]]))
H(S4PagedAuthorityProofCommitProof[
    s4_paged_authority_proof_commit_proof_oid]) =
        s4_paged_authority_proof_commit_proof_oid
RecordedActorAuthorityRef =
    BOUNDED(AuthorityAdmissionRef)
  | PAGED_S4(S4PagedAuthorityAdmissionRef)
S4DeviceInviteAcceptance =
    canon(workspace, target_fact_key, target_fid,
          device_key, owner_principal,
          invite_fact_key, invite_fid, invite_fact_record_oid,
          device_signature)
verify(device_key, H(canon(
    ["s4-device-invite-acceptance-v1", workspace,
     target_fact_key, target_fid, device_key, owner_principal,
     invite_fact_key, invite_fid, invite_fact_record_oid])),
    device_signature) = true
LegacyActorAdmissionBasis =
    NORMAL
  | S4_DEVICE_INVITE_ACCEPTANCE(S4DeviceInviteAcceptance)
LegacyActorAdmissionRecord =
    canon(workspace, target_fact_key, target_fid,
          binding_kind, signing_key, owner_principal,
          RecordedActorAuthorityRef,
          LegacyActorAdmissionBasis)
legacy_actor_admission_record_oid =
    H("legacy-actor-admission-record", LegacyActorAdmissionRecord)
legacy_actor_admission_commit_id =
    H("legacy-actor-admission-commit", workspace, target_fact_key, target_fid,
      legacy_actor_admission_record_oid)
CommittedLegacyActorAdmission[legacy_actor_admission_commit_id] =
    canon(workspace, target_fact_key, target_fid,
          legacy_actor_admission_record_oid,
          s4_generation, s4_frontier_serial, committed_s4_root_digest)
LegacyActorAdmissionProofSlot[legacy_actor_admission_commit_id] =
    RESERVED(MAX_LEGACY_ACTOR_ADMISSION_COMMIT_PROOF_BYTES)
  | FILLED(legacy_actor_admission_commit_proof_oid)
LegacyActorAdmissionCommitProof[legacy_actor_admission_commit_proof_oid] =
    sign(admission_sk,
         canon(["legacy-actor-admission-commit-v1",
                legacy_actor_admission_commit_id,
                CommittedLegacyActorAdmission[
                    legacy_actor_admission_commit_id]]))
H(LegacyActorAdmissionCommitProof[legacy_actor_admission_commit_proof_oid])
    = legacy_actor_admission_commit_proof_oid
ActorAdmissionEvidence =
    NATIVE(AuthorityAdmissionRef)
  | LEGACY(RecordedActorAuthorityRef,
           LegacyActorAuthorityTransport,
           legacy_actor_admission_record_oid,
           legacy_actor_admission_commit_id,
           legacy_actor_admission_commit_proof_oid)
LegacyActorAuthorityTransport =
    DIRECT(AuthorityAdmissionRef)
  | CHECKPOINT(
        checkpoint_fact_key, checkpoint_fid, checkpoint_fact_record_oid,
        checkpoint_authority_ref,
        source_legacy_authority_proof_oid, source_candidate_id)
recorded_actor_authority_ref(NATIVE(ref)) = BOUNDED(ref)
recorded_actor_authority_ref(LEGACY(recorded_ref, ...)) = recorded_ref
transport_actor_authority_ref(NATIVE(ref)) = ref
transport_actor_authority_ref(LEGACY(_, DIRECT(ref), ...)) = ref
transport_actor_authority_ref(
    LEGACY(_, CHECKPOINT(_, _, _, checkpoint_ref, _, _), ...)) =
        checkpoint_ref
ActorBindingStatement =
    canon(workspace, target_fact_key, target_fid,
          binding_kind, signing_key, owner_principal, ActorAdmissionEvidence)
    where binding_kind in {DIRECT_MEMBER, DEVICE}
ActorBindingProof =
    sign(admission_sk,
         canon(["actor-binding-v1", ActorBindingStatement]))
len(ActorBindingProof) <= MAX_ACTOR_BINDING_PROOF_BYTES
OwnerBinding =
    canon(ActorBindingStatement, ActorBindingProof)
AdminSubject(KEY, ActorBinding) = ActorBinding.signing_key
AdminSubject(OWNER, ActorBinding) = ActorBinding.owner_principal
    iff ActorBinding.binding_kind = DEVICE
AdminAuthorityRef =
    canon(admin_scope, AdminSubject, admin_provider_fact_key,
          admin_provider_fid, admin_provider_fact_record_oid,
          admin_authority_proof_record_oid, admin_authority_proof_commit_id)
LegacyEffectAuthorizationRef =
    canon(LEGACY_SLOT | LEGACY_GLOBAL,
          legacy_effect_census_oid, legacy_effect_row_key,
          legacy_effect_row_digest,
          source_fact_key, source_fid, source_fact_record_oid)
ActionActorBinding =
    canon(ActorBindingStatement, ActorBindingProof)
    where ActorBindingStatement.(target_fact_key, target_fid) = (K(r), fid(r))
ActionAuthorization =
    OWNER(ActionActorBinding)
  | ADMIN(ActionActorBinding, AdminAuthorityRef)
  | GRANDFATHER(LegacyEffectAuthorizationRef)
len(canon(ActionAuthorization)) <= MAX_ACTION_AUTHORIZATION_BYTES
DeleteOffer(kind, f) =
    canon(kind, SELF, OwnerBinding)
    where kind in {"content.delete", "device.grant.delete"}
delete_offer_address(kind, f) =
    (kind, resolve(f, SELF),
     OwnerBinding.ActorBindingStatement.owner_principal)
EvidenceRef(role, f) =
    canon(role, K(f), fid(f), fact_record_oid(f))
proof_refs(r) =
    sorted(EvidenceRef("proposal", r),
           EvidenceRef("support", f) for every detached signature/support f)
len(proof_refs(r)) <= MAX_ADMISSION_PROOF_REFS
proof_digest(r) =
    hash(canon(the named proof edges, proof_refs(r), ActionAuthorization))
admission(a) = (workspace, fid(r), target_spec,
                basis_frontier,
                evidence_kind, evidence_fids, ActionAuthorization,
                proof_digest(r))
len(canon(admission(a))) <= MAX_ADMIT_CELL_BYTES
evidence_fids = the fids in proof_refs(r)
# Only after canonical a, fid(a), FactRecord(a), and raw_root_oid(a) exist:
evidence_refs(a) =
    sorted(proof_refs(r), EvidenceRef("receipt", a))
len(evidence_refs(a)) <= MAX_ACTION_EVIDENCE_REFS
FactTree[ActionSlot(owner(a))] =
    FILLED(action_record_oid)
ActionRecord[action_record_oid] =
    canon(target_spec(a), evidence_refs(a))
hash(ActionRecord[action_record_oid]) = action_record_oid
len(ActionRecord[action_record_oid]) <= MAX_ACTION_RECORD_BYTES
FactRecord[b.target_fact_record_oid] has key b.target_fact_key
FactRecord[b.target_fact_record_oid].raw_root_oid roots the complete target fact
    for every live TargetBinding or PrincipalBinding b in target_spec(a)
FactRecord(a).raw_root_oid authenticates admission(a), including the exact
    ActionAuthorization derived by the admission service
ActionRecord's receipt EvidenceRef roots FactRecord(a); certification and GC
    follow ActionAuthorization's bounded actor/admin provider FactRecords,
    AuthorityProofRecords, CommittedAuthorityProof rows and
    AuthorityProofCommitProofs, or its grandfather census/source closure, as
    an additional retained arm
if b selects delete_kind in {"content.delete", "device.grant.delete"}:
    FactRecord[b.target_fact_record_oid].delete_offer =
        DeleteOffer(delete_kind, target)
    transport_actor_authority_ref(
        OwnerBinding.ActorBindingStatement.ActorAdmissionEvidence)
        resolves to the exact provider FactRecord, AuthorityProofRecord,
        CommittedAuthorityProof row and AuthorityProofCommitProof retained for
        the target's author admission
    if ActorAdmissionEvidence is LEGACY:
        H("legacy-actor-admission-record", LegacyActorAdmissionRecord)
            = legacy_actor_admission_record_oid
        LegacyActorAdmissionRecord.(workspace, target_fact_key, target_fid,
            binding_kind, signing_key, owner_principal)
          = ActorBindingStatement's corresponding scalar fields
        LegacyActorAdmissionRecord.RecordedActorAuthorityRef =
            recorded_actor_authority_ref(ActorAdmissionEvidence)
        CommittedLegacyActorAdmission[legacy_actor_admission_commit_id]
            names the same target and legacy_actor_admission_record_oid
        LegacyActorAdmissionProofSlot[legacy_actor_admission_commit_id]
            = FILLED(legacy_actor_admission_commit_proof_oid)
        verify(LegacyActorAdmissionCommitProof[
            legacy_actor_admission_commit_proof_oid]) =
            ("legacy-actor-admission-commit-v1",
             legacy_actor_admission_commit_id,
             CommittedLegacyActorAdmission[
                 legacy_actor_admission_commit_id])
        the proof signer issued it only after rereading the target, record,
            atomic commit row and pre-reserved proof slot
        if RecordedActorAuthorityRef is BOUNDED(recorded_ref):
            recorded_ref resolves to the exact provider FactRecord,
                AuthorityProofRecord, CommittedAuthorityProof row and
                AuthorityProofCommitProof admitted before the target CAS
        if RecordedActorAuthorityRef is PAGED_S4(paged_ref):
            hash and complete replay of paged_ref's
                LegacyAuthorityProofRecord manifest/pages reproduce the exact
                provider, closure digest, NeedKey, actor offer, logical depth,
                cost and liveness scopes selected before the target CAS
            CommittedS4PagedAuthorityProof[
                paged_ref.s4_paged_authority_proof_commit_id] names that exact
                provider, FactRecord and legacy_authority_proof_record_oid
            S4PagedAuthorityProofSlot[
                paged_ref.s4_paged_authority_proof_commit_id] =
                FILLED(
                    paged_ref.s4_paged_authority_proof_commit_proof_oid)
            verify(S4PagedAuthorityProofCommitProof[
                paged_ref.s4_paged_authority_proof_commit_proof_oid]) equals
                that strong commit row
            H(S4PagedAuthorityProofCommitProof[
                paged_ref.s4_paged_authority_proof_commit_proof_oid]) =
                paged_ref.s4_paged_authority_proof_commit_proof_oid
        if LegacyActorAuthorityTransport is DIRECT(ref):
            LegacyActorAdmissionRecord.RecordedActorAuthorityRef =
                BOUNDED(ref)
        if LegacyActorAuthorityTransport is CHECKPOINT(
                checkpoint_fact_key, checkpoint_fid,
                checkpoint_fact_record_oid, checkpoint_authority_ref,
                source_legacy_authority_proof_oid, source_candidate_id):
            LegacyActorAdmissionRecord.RecordedActorAuthorityRef =
                PAGED_S4(paged_ref)
            paged_ref.legacy_authority_proof_record_oid =
                source_legacy_authority_proof_oid
            checkpoint_authority_ref resolves to that exact checkpoint
                FactRecord, AuthorityProofRecord, CommittedAuthorityProof and
                AuthorityProofCommitProof
            the checkpoint's paged source proof replays the exact provider,
                proof closure and commit named by
                paged_ref and its CommittedS4PagedAuthorityProof
            checkpoint.(source_legacy_authority_proof_oid,
                source_candidate_id) equals the transport fields
            the checkpoint source fid, proof digest, NeedKey and actor offer
                equal the recorded source after replay
            ActorBindingProof authenticates this source-to-transport
                translation; the checkpoint ref is not required or permitted
                to equal the earlier recorded ref
        if LegacyActorAdmissionBasis is S4_DEVICE_INVITE_ACCEPTANCE:
            binding_kind = DEVICE
            target is authored by signing_key
            verify(S4DeviceInviteAcceptance.device_signature) = true
            S4DeviceInviteAcceptance.(workspace, target_fact_key, target_fid,
                device_key, owner_principal, invite_fact_key, invite_fid,
                invite_fact_record_oid) = the record's exact corresponding
                workspace, target, signing-key, owner and invite fields
            the exact retained invite FactRecord/proof offers both
                member(signing_key) and
                device(owner_principal, signing_key)
    verify(OwnerBinding.ActorBindingProof) =
        OwnerBinding.ActorBindingStatement
    OwnerBinding.ActorBindingStatement.(target_fact_key, target_fid) =
        (b.target_fact_key, fid(target))
    ActorBindingProof attests that the exact provider proof passed the complete
        direct-claim-present-before-device classification and liveness rule at
        the service CAS that first installed FactSlot(target_fact_key)
        without placing that root/frontier identity in ActorBindingStatement
    if binding_kind = DEVICE and ActorAdmissionEvidence is not the legacy
        S4_DEVICE_INVITE_ACCEPTANCE basis,
        recorded_actor_authority_ref(ActorAdmissionEvidence) names a
        target-key-authored DeviceOwnerConsent whose exact invite/provider ref
        offers device(owner_principal, signing_key)
# The following authorization checks are action-scoped, not nested under any
# TargetBinding or direct-delete branch.
if evidence_kind = LIVE_GUARDS:
    ActionAuthorization.ActionActorBinding is the exact action-time actor
        statement/proof, not any target's OwnerBinding
    ActionActorBinding is service-derived while admitting r; its deterministic
        proof is committed by receipt a rather than by an ordinary FactSlot,
        and a signed pre-CAS orphan is inert
    ActionActorBinding may not use S4_DEVICE_INVITE_ACCEPTANCE to authorize a
        new action after S5
    ActionAuthorization is not GRANDFATHER
    if proposal mode = OWNER:
        ActionAuthorization = OWNER(ActionActorBinding)
        target_spec is ExactSids with at least one matching direct-delete
            TargetBinding
        for every direct-delete TargetBinding b:
            ActionActorBinding.owner_principal =
                FactRecord[b.target_fact_record_oid].
                    OwnerBinding.ActorBindingStatement.owner_principal
    if proposal mode = ADMIN:
        ActionAuthorization =
            ADMIN(ActionActorBinding, AdminAuthorityRef)
        AdminAuthorityRef.admin_scope is KEY or OWNER
        AdminAuthorityRef.AdminSubject = AdminSubject(
            admin_scope, ActionActorBinding.ActorBindingStatement)
        the exact retained admin provider proof offers admin(AdminSubject)
        OWNER requires ActionActorBinding.binding_kind = DEVICE
        no admin(device_key) provider can satisfy admin(owner_principal)
if evidence_kind in {LEGACY_SLOT, LEGACY_GLOBAL}:
    ActionAuthorization =
        GRANDFATHER(LegacyEffectAuthorizationRef)
    LegacyEffectAuthorizationRef.kind = evidence_kind
    LegacyEffectAuthorizationRef names the exact content-hash-matching
        pre-seed LegacyEffectCensus row and old source FactRecord
    LegacyMigrationSeal and LegacyTranslationAttestation authenticate the
        complete census containing that row
    LEGACY_SLOT additionally matches the exact LegacyEntryMap row and
        authoritative old slot entry
    LEGACY_GLOBAL additionally matches the authenticated old removal
        global and its canonical source fact
    no live request path accepts GRANDFATHER and no current owner, member
        or admin guard is rerun during backfill
FactRecord[p.provider_fact_record_oid] has key p.provider_fact_key
FactRecord[p.provider_fact_record_oid].fid = p.provider_fid
FactRecord[p.provider_fact_record_oid].raw_root_oid roots the complete provider
    for every PrincipalProviderBinding p in PrincipalProviderRegistry
hash(AuthorityProofRecord[q.authority_proof_record_oid])
    = q.authority_proof_record_oid
FactRecord[x.fact_record_oid] has key x.fact_key and fid x.fid
FactRecord[x.fact_record_oid].raw_root_oid roots the complete proof fact
    for every AuthorityFactBinding x in that AuthorityProofRecord
replay(record.fact_bindings, record.proof_edges)
    = (record.proof_closure_digest, record.transport_proof_depth,
       record.logical_proof_depth, record.canonical_transport_cost,
       record.sorted_checkpoint_fids)
    for every AuthorityCandidateRef q
CommittedAuthorityProof[q.authority_proof_commit_id]
    has q.provider_fid and a commit binding for the publication that first
    admitted this exact proof record
verify(AuthorityProofCommitProof[q.authority_proof_commit_id])
    = CommittedAuthorityProof[q.authority_proof_commit_id]
q.candidate_id =
    H("authority-candidate", NeedKey, q.provider_fid,
      q.authority_proof_record_oid, q.proof_closure_digest)
q.canonical_candidate_rank if q.rank_provenance = NATIVE_RANK =
    (record.logical_proof_depth, q.provider_fid, q.candidate_id)
q.canonical_candidate_rank
    if q.rank_provenance = LEGACY_SOURCE_RANK(checkpoint_fid) =
    (checkpoint.source_proof_depth, checkpoint.source_fid,
     H("legacy-authority-candidate", NeedKey, checkpoint.source_fid,
       checkpoint.source_legacy_authority_proof_oid,
       checkpoint.source_proof_closure_digest))
q.canonical_candidate_rank
    if q.rank_provenance =
       DERIVED_LEGACY_RANK(record.sorted_checkpoint_fids) =
    (record.logical_proof_depth, q.provider_fid, q.candidate_id)
checkpoint.source_candidate_id =
    H("legacy-authority-candidate", checkpoint.source_need_key,
      checkpoint.source_fid,
      checkpoint.source_legacy_authority_proof_oid,
      checkpoint.source_proof_closure_digest)
AuthorityBaseCandidateRef has no candidate_id or canonical_candidate_rank
derive_full_candidate(NeedKey, base_ref) has q.candidate_id and
    q.canonical_candidate_rank exactly as above
union(candidate_mask_scopes(base_ref)
      for base_ref in AuthorityBaseCandidateRegistry[BaseNeedKey])
    has at most MAX_AUTHORITY_IMPACT_SCOPES_PER_BASE entries
hash(RawFactContentCommit[c.raw_fact_content_commit_id])
    = c.raw_fact_content_commit_id without any upload generation field
walk_manifest_by_ordinal(c.raw_manifest_root_oid)
    = the exact contiguous canonical fact bytes whose hash is c.raw_root_oid
from_json(decode_canonical_fact_bytes(c.raw_root_oid)).fid = c.fid
ContentCommitPin[c.content_commit_pin_id]
    = ROOTED(committed_root_oid, frontier_serial)
    for every CONTENT_COMMIT FactRecord c in that committed root
FactRecord[ref.fact_record_oid].fid = ref.fid
FactRecord[ref.fact_record_oid].raw_root_oid roots the complete raw fact
    for every ref in evidence_refs(a)
SuppTree[SuppSlot(sid)] =
    ACTIVE(fid(proposal(a)), ActionSlot(owner(a)))
    iff a = witness(root, sid)
SuppTree[SuppSlot(sid)] is ACTIVE with witness(root, sid)
    for every commit-proven a and every sid in effect_targets(root, a)
target_spec(r) = target_spec(a)
CommitBinding =
    DirectRoot(committed_root_oid, frontier_serial, frontier_digest)
  | CutoverGeneration(service_generation_id)
CommittedAdmission(workspace, fid(r), hash(a), CommitBinding)
CutoverCommitAnchor(
    workspace, service_generation_id, cutover_service_generation_oid,
    committed_root_oid, frontier_serial, frontier_digest,
    next_certificate_reservation_id)
CutoverContentPinAnchor(
    workspace, service_generation_id, cutover_content_pin_set_oid,
    committed_root_oid, frontier_serial)
AdmissionCommitProof =
    sign(admission_sk, canon(["admission-commit-v2",
                             CommittedAdmission(...),
                             CutoverCommitAnchor(...) or EMPTY]))
```

The construction order is proof refs plus the service-derived
`ActionAuthorization` → proof digest → signed receipt and its FactRecord/raw
root → receipt EvidenceRef → ActionRecord. The receipt never
hashes or names its own EvidenceRef, fid, FactRecord oid or ActionRecord oid, so
there is no content-hash cycle.

The ActionSlot-to-ActionRecord reachability graph has three bounded arms:
every target binding points to its exact target FactRecord/raw root, and every
EvidenceRef points to its proposal/support/receipt FactRecord/raw root. The
receipt's authenticated `ActionAuthorization` additionally follows the exact
action-time `ActionActorBinding` and, for `ADMIN`, the selected
`AdminAuthorityRef`, through their provider FactRecords, proof records,
committed-proof rows and post-commit proofs. It never substitutes the target
author's `OwnerBinding` for the acting principal or reselects a current admin
winner. A migration-only `GRANDFATHER` authorization instead follows its exact
pre-seed `LegacyEffectCensus` row and old source FactRecord through
`LegacyMigrationSeal` and `LegacyTranslationAttestation`; it has no invented
action-time actor arm.
They form the action-specific canonical reachability path after sync, restart and GC.
The forward candidate registry has a third, independent bounded arm:
each `AuthorityCandidateRef` points to one `AuthorityProofRecord`, whose exact
fact bindings point to every FactRecord/raw root in that candidate's proof.
The grow-only FactTree additionally retains every admitted S5 FactRecord
whether or not it is currently projected. Neither a target
needed to re-derive `DIRECT_TARGETS` nor a detached support object relies on an
admission log, a mutable reverse cache, a historical root or incidental object
retention. The
certifier recomputes `proof_refs(r)` from the proposal/support
closure, requires those roles/fids to match the receipt's `evidence_fids`, and
rederives the exact live actor/admin choice or fenced grandfather census
binding, requires byte-equal `ActionAuthorization`, and replays the named proof
edges and authorization preimages committed by `proof_digest(r)`. Separately, it
requires the ActionRecord evidence set to equal those exact proof refs plus the
one self-matching receipt EvidenceRef, and rejects an unreferenced or missing
object. Pre-receipt proof evidence is bounded by `MAX_ADMISSION_PROOF_REFS`;
complete action evidence is bounded by `MAX_ACTION_EVIDENCE_REFS`. The
separately rooted, paged migration map below handles an unbounded number of
legacy duplicates without inflating one ActionRecord.

The commit proof is a portable certification sidecar, not part of canonical
root identity. An ordinary post-cutover admission uses `DirectRoot`; its durable
row may name the already-computed prospective root because that row is not
hashed by the root. The immutable `admit/<workspace>/<fid(r)>` cell and
append-only `CommittedAdmission(..., DirectRoot(...))` row are a durable
**DirectCommitPair**. They are writable only by, and are written together
inside, the same strong transaction that advances the named root and frontier.
The row's `DirectRoot` fields are the durable snapshot of that transaction, not
a reference that requires the mutable current root/frontier cells to retain
their old values. No staging path or standalone API may create either half as a
committed pair.

Grandfather rows in the first cutover generation instead use only
`CutoverGeneration(service_generation_id)`. The generation id exists before
any seeded tree, descriptor or root, so those rows can be hashed by the staged
service manifest without a fixed-point equation. The one
`CutoverCommitAnchor`, mutable `CutoverContentPinGeneration` row and
`CutoverContentPinAnchor` are excluded from that manifest and from canonical
root identity; the bounded activation transaction writes or transitions them
atomically with the root/frontier/generation-pointer flip after
`committed_root_oid` exists.
`frontier_digest` is the already-computed prospective fact/effect frontier; it
does not hash strong-service commit rows or the anchor that binds it.

The authority's post-commit signer is the only component allowed to create an
`AdmissionCommitProof`, and that signer accepts no caller-supplied row. For
`DirectRoot` it strong-reads both halves of the retained `DirectCommitPair`,
checks their workspace/fid/receipt digest correspondence, and signs the stored
row plus `EMPTY`. The atomic pair is sufficient durable commit evidence: proof
regeneration deliberately does not require the historical root object or the
now-advanced current root/frontier cells. For `CutoverGeneration` the signer
instead re-reads the active generation descriptor and exact
`CutoverCommitAnchor`, requires the anchor's
descriptor/root/frontier/reservation fields to equal the activation
transaction, and requires the grandfather row to be one of the descriptor-bound
service rows. Only then does it sign the stored row plus anchor. A certifier may
obtain the proof from the authority or a passive store, but accepts it only
under `admission_pk`; a signature on `a`, either half of an incomplete direct
pair, a staged inactive row, or an anchor without the matching active descriptor
is never a substitute.

For a newly authored S5 proposal, `target_spec(r)` is its exact wire field. For
an allowlisted old-envelope proposal, it means the one migration interpretation
sealed into that proposal's `FactRecord`; no legacy byte is pretended to contain
a field it predates.

A bare `r` is inert and never independently enters the S5 canonical FactTree.
The proposal command writes its immutable bytes and detached author signature
only through a fixed-slot `pending/` gateway governed by the separately pinned
`PendingCapacityEnvelope` (or submits one size-capped bundle directly to
admission). Pending objects are not frontier facts, may be garbage-collected,
and grant no authority. The gateway rejects above
`MAX_PENDING_BUNDLE_BYTES`, can address only its finite overwrite-only slot
pool, and holds a durable write lease until each put settles. The canonical raw
bytes of all at-most-`MAX_ADMISSION_PROOF_REFS` submitted proposal,
author-signature and support records must total at most
`MAX_ADMISSION_PROOF_BYTES`; their canonical bundle framing is independently
capped at `MAX_PENDING_BUNDLE_FRAMING_BYTES`, and the two maxima sum exactly to
`MAX_PENDING_BUNDLE_BYTES`. The service-generated receipt is not transported in
that input bundle. Its service-derived `ActionAuthorization` is separately
capped by `MAX_ACTION_AUTHORIZATION_BYTES`, and the complete canonical receipt
including that field must fit `MAX_ADMIT_CELL_BYTES`; it is not charged to or
accepted from caller-controlled pending framing. Pending slots and
bytes have a physically enforced quota disjoint from both content and canonical
control metadata. Exhausting that optional queue rejects more staging but
cannot consume revocation escrow or prevent the direct admission path; direct
submission enforces the identical aggregate proof/framing limits and moves
immediately into the reserved `PublicationAttempt` without durable pending
storage. Admission publishes the complete `RevocationActionBundle`, fills its
reserved owner `ActionSlot` and
sets every resolved `SuppSlot` to its recomputed canonical-witness verdict in
one transaction after the complete capacity check. One logical workspace-global
admission/publication authority holds a **service-exclusive** signing key,
distinct from both member keys and the deployment-local root-certification key
below. In particular, `workspace.body.pk` is the ordinary
founder/member/admin key and is forbidden as an admission key: domain separation
cannot stop a retained or evicted founder from bypassing the authority's
serialized cells.

New-format workspaces commit `admission_pk` in their anchor. An existing
workspace cannot mutate its content-addressed anchor, so migration has two
different authenticated bindings rather than pretending snapshot-derived values
exist before the snapshot:

1. Before the fence, every registered publisher pins the provider-signed
   `MigrationBootstrapCommitment(workspace, admission_pk,
   s5_policy_template_digest, service_writer_identity,
   capacity_ceiling_oid, pending_capacity_digest,
   content_capacity_digest, legacy_source_ceiling_oid,
   cutover_capacity_digest,
   s4_authority_proof_capacity_cell_id,
   s4_authority_proof_capacity_envelope_oid,
   s4_actor_admission_capacity_cell_id,
   s4_actor_admission_capacity_envelope_oid,
   fallback_generation_id)`. It commits the service
   identity, immutable capacity ceilings, physical quota boundaries, derivation
   policy and fallback generation that must already be provisioned. It
   content-hash-roots the complete canonical `CapacityCeiling` and
   `LegacySourceCeiling` preimages rather than retaining bare comparison
   digests; both objects are provider-authenticated by this signature, capped,
   and retained through the final migration seal.
   It
   deliberately contains **no** `layout_seed`, `cutover_basis_digest`,
   `cutover_digest`, exact `meta-s5/` namespace or seeded-tree root: none of
   those values exists until after the old-writer drain and frozen snapshot.
2. After that snapshot, the service derives those values in the order below and
   signs an
   `S5CutoverBinding(bootstrap_commitment_digest, cutover_basis_digest,
   layout_seed, cutover_digest, exact_metadata_namespace,
   service_generation_id,
   CapacityEnvelope, PendingCapacityEnvelope, ContentCapacityEnvelope,
   CutoverCapacityEnvelope)`. The first S5 root and
   `LegacyMigrationSeal` authenticate this binding. Every exact envelope must
   obey its bootstrap commitment. A certifier fetches the retained,
   content-hash-matching `CapacityCeiling` at `capacity_ceiling_oid`, decodes its
   canonical vector and proves the exact `CapacityEnvelope` componentwise no
   greater than that vector; it never compares a value with a digest. The
   pending, content and physically preallocated cutover envelopes match their
   committed digests byte-for-byte. The namespace must be the
   policy-template-derived exact prefix. A publisher accepts the first S5 root
   only by verifying this post-snapshot binding under the pre-pinned
   `admission_pk`, not by trusting a newly supplied keyring value.

Before the fence, the provider also prepares and attests one inactive, fresh
**S4 fallback credential generation** restricted to the same service-exclusive
writer; no publisher receives it and it cannot write until an S5 attempt aborts.
The bootstrap commitment, physical capacity and fallback activation capacity
must match before the fence can seal. A joining participant receives the final
binding through the same authenticated keyring bootstrap that supplies the
workspace anchor and read/content/pending gateway addresses. No member device
receives the admission private key or a metadata-write credential. If the
deployment cannot complete the bootstrap commitment, fallback preparation and
quota reservation, it does not begin the fence and the workspace remains
writable on S4 or re-anchors as a new-format workspace; there is no unattended
in-place fallback to `workspace.body.pk` or the old publisher credential.

A publisher submits a candidate certified basis plus the integrity-checked
staged `r` to the authority. The authority validates the basis under its own
derivation fence, validates the exact bounded authority proof, resolves the
family-owned target spec, authenticates every declared guard as unsuppressed,
and only then signs candidate receipt `a` over every field above. That signature
proves what was evaluated, but deliberately does **not** prove that the action
won serialization. A receipt becomes effective only with an
`AdmissionCommitProof` for the exact `CommittedAdmission` row. The portable
proof is signed by the same keyring-pinned service key only after the authority
has re-read that row from durable committed state. Peers verify both signatures,
the exact action/target spec and the proof-to-cell/log fields; they do not trust
a passive store or another deployment's local certificate.

The authority also owns one strongly consistent monotonic
`frontier/<workspace>` publication cell. It commits the current canonical root
and the certified join of every accepted fact/effect basis. **Every** S5 root
advance, not only a removal, passes through this cell. It also owns one
conditional `attempt/<workspace>` slot. The slot is a durable
`PublicationAttempt(generation, phase, base_root, candidate_root,
object_manifest_digest, reserved_objects, reserved_bytes)` and only one may
exist. `generation` comes from a monotonic workspace counter and is never
reused; `phase` is `OPEN`, `SEALING`, `ABORTING`, or `COMMITTED_COPYING`. Its
exact manifest
is stored in capped
`attempt-manifest/<workspace>/<generation>/<chunk>` service rows written in the
same transaction. The complete canonical manifest has at most
`MAX_PUBLICATION_ATTEMPT_MANIFEST_ROWS` chunks and
`MAX_PUBLICATION_ATTEMPT_MANIFEST_BYTES`; exceeding either rejects before the
attempt is claimed. It names every prospective canonical **metadata**
key/hash/size and maps it to one fixed, size-capped
`scratch/<workspace>/<slot>` object. The scratch key pool is permanently
provisioned by the `CapacityEnvelope`: clearing a logical attempt never turns
those physical keys or bytes into ordinary/revocation capacity.
Planned or idempotently sealed `RawFactContentCommit` objects are not copied
into this manifest: the attempt names one fixed-size commit/pin reference and
proof, while the separate content protocol below authenticates and charges the
complete raw chunk tree before root CAS.

Publishers receive no raw **metadata-write** object-store credential. Reads use
root-bound grants, and content uploads use the separately quota-isolated content
gateway. Optional proposal staging uses only the fixed-slot pending gateway;
read, content and pending credentials cannot address `meta-s5/`, fixed scratch
or canonical tree keys. The authority-owned metadata upload gateway exposes only
`put_attempt(workspace, generation, manifest_index, bytes)`. It checks the live
`OPEN` generation and exact manifest key/hash/size, caps the request before
accepting the body, and can write only that index's fixed scratch slot. Each
accepted call owns a durable, bounded
`AttemptWriteLease(generation, manifest_index, state)` until the underlying put
has definitely settled and read-back hash validation has completed. An
ambiguous write after a gateway crash does not expire optimistically: it keeps
the attempt charged and publication blocked until the storage adapter can prove
that operation settled. Thus a delayed caller can neither mint a new object key
nor outlive the generation fence. Receipt issuance and publication are one
serialized authority operation:

1. load the frontier and reject a candidate basis that does not contain its
   complete fact and effective-suppression sets;
2. evaluate guards against the prospective advanced frontier, not against the
   submitted branch in isolation;
3. derive the prospective fact, suppression and authority trees. For a removal,
   construct the exact signed receipt bytes in memory and include the complete
   family-declared `RevocationActionBundle`: the staged proposal, its detached
   author-signature/support facts, the receipt, every corresponding FactRecord
   and raw-fact chunk, the bounded immutable `ActionRecord`, its fixed-oid owner
   `ActionSlot` fill, every currently resolved canonical-witness `SuppSlot`
   update, every AuthorityTree consequence, its conditional admission cell and
   admission-log row, plus the `TargetRegistry` row when applicable. Every
   removal tree mutation must name an already-present key; an absent reserved
   slot rejects the action. The
   tree/object bytes and their exact hashes are built here without uploading;
   service records materialize in step 6.
   For an ordinary fact, derive the ordered raw manifest and canonical
   `RawFactContentCommit` id from its complete raw bytes without uploading or
   putting an upload generation into that identity. Include every new grow-only FactTree
   `ADMITTED(fact_record_oid)` row, bounded FactRecord and fixed-size content
   commit reference, never every raw chunk in this metadata attempt. If it produces
   authority, build the content-addressed bounded `AuthorityProofRecord` for
   each distinct candidate closure, derive its
   `AuthorityBaseCandidateRegistry` and full `AuthorityCandidateRegistry`
   commit/match/mask ref, update every newly introduced
   `BaseOfferNeedKeyRegistry` directory, and derive every affected
   `AuthorityImpactRegistry` value through transitive proof closure. Both
   provider-to-full-NeedKey and new-NeedKey-to-existing-provider discovery use
   those bounded access paths; neither scans a tree. Every
   membership/device provider updates its bounded
   `PrincipalProviderRegistry` with the full
   `PrincipalProviderBinding(provider_fact_key, provider_fact_record_oid,
   provider_fid)`, which keeps that FactRecord/raw root reachable across later
   quarantine. A `MemberPrincipal` or `DevicePrincipal`
   receipt also enters `TargetRegistry`, and any later prospective matching
   provider queries that registry and derives its `ACTIVE` slot before
   publication. A later device, membership or delegated provider also updates
   the applicable forward candidate value and sid/principal authority-impact
   scopes before it can become canonical. Every changed variable-width registry
   value is materialized as a content-addressed `RegistryValueObject`; the
   strong-service write set contains only its bounded pointer. For a removal, every affected
   candidate value is read and rewritten with fixed-width mask states in
   this same prospective operation, and its remaining commit-proven
   `ADMITTED_PROOF`/`CLEAR` refs determine the AuthorityTree fallback or
   `NO_PROVIDER`. A shadow/restore transition may change local projection state,
   but it never re-resolves or deletes an admitted authority proof, FactTree row,
   candidate, proof record or raw closure;
4. reject before durable admission if any row, page, depth, root, proof,
   request, service-envelope, aggregate registry-object, attempt-manifest,
   strong-transaction or provisioned-quota budget—or the componentwise
   `occupancy + RevocationLiability` and per-target `AtomicCommitBudget`
   invariants below—would be exceeded. In a
   strong transaction, claim the empty attempt slot with the exact object
   manifest, next generation and its separately provisioned scratch
   object/byte/write-lease reserve, plus the publishing deployment's
   next-certificate object/byte/write-lease reservation. For an ordinary
   `CONTENT_COMMIT` fact, the same transaction creates or matches the exact
   `ContentCommitPin[PENDING(pin_epoch, attempt_id, generation)]`. An absent
   pin starts at epoch one; a retry may advance a fenced/drained
   `ABORTED(e, ...)` pin to epoch `e + 1`. A different live owner, commit id,
   epoch or state rejects. A live or uncleared attempt rejects every next
   publication;
5. for `CONTENT_COMMIT`, first stream the ordered raw chunks/manifest through
   the isolated content gateway, then seal and drain its generation, reassemble
   by ordinal, and store the matching `RawFactContentCommit` row and proof.
   Upload exactly the manifested metadata bytes through `put_attempt`. Then atomically
   move `OPEN -> SEALING`, which makes the gateway reject every new or
   wrong-generation call. Wait for every accepted `AttemptWriteLease` to reach
   a proved-settled state, and only then re-read and hash every scratch slot and
   fully validate prospective cross-index completeness. A stalled or ambiguous
   lease is an availability failure that retains the charge; cleanup may not
   guess that it is dead. Candidate receipt bytes may be among those scratch
   objects, but neither a scratch object nor the attempt row is proof of
   admission;
6. in one strong transaction, require the unchanged attempt/base/frontier,
   advance the canonical root/frontier and, when
   present, memoize the receipt bytes in
   `admit/<workspace>/<removal_fid>`, append the exact
   `CommittedAdmission(..., DirectRoot(candidate_root, ...))` row to the
   workspace admission log as one inseparable `DirectCommitPair`, store the
   at-most-one new `CommittedAuthorityProof` row when an ordinary provider proof
   is first admitted, transition any content pin from the exact
   `PENDING(pin_epoch, attempt_id, generation)` to
   `ROOTED(candidate_root, frontier_serial)`, and update its `TargetRegistry`
   row and every prospective
   bounded principal-provider,
   authority-candidate and authority-impact `RegistryValuePointer`, charge the exact
   newly reachable canonical manifest to committed occupancy **before those
   canonical writes can begin**, and move the attempt to
   `COMMITTED_COPYING`. The encoded row and byte totals of this complete write
   set must fit `MAX_PUBLICATION_SERVICE_TRANSACTION_ROWS` and
   `MAX_PUBLICATION_SERVICE_TRANSACTION_BYTES`; no backend may claim the
   operation in order to discover that limit after signing a receipt. This
   logical commit does not clear the slot and the root is not yet eligible to
   serve; and
7. the authority, never a publisher, copies the sealed scratch bytes to their
   content-addressed canonical keys, verifies every key/hash/size, then clears
   the attempt/manifest/write leases in one transaction. It re-reads the
   admission cell and log row, mints/publishes their `AdmissionCommitProof`, and
   similarly signs any new `CommittedAuthorityProof` as an
   `AuthorityProofCommitProof` and any rooted content pin as a
   `ContentCommitPinProof`. Only then does it make the new root eligible for
   local certification and serving.
   A crash here is an availability delay: the canonical bytes were already
   charged and recovery can idempotently finish the copies and mint the same
   proof from the committed row.

A stale publisher receives the missing frontier/receipts, merges, republishes
and retries. Thus an eviction processed first makes a later pre-eviction branch
ineligible; if the action processes first, its receipt is the explicitly
allowed concurrent action. The per-removal cell alone provides idempotence;
this per-workspace frontier is what provides the post-observation revocation
fence.

The root/frontier transaction above is the S5 root CAS. Before it, candidate
bytes exist only in the fixed scratch pool. Recovery of an `OPEN` attempt first
moves it to an aborting write-fence state, rejects its generation, and proves
every accepted write lease settled; only then may it erase/overwrite those fixed
slots, atomically mark any matching content pin
`ABORTED(pin_epoch, fenced_generation)`, and clear the logical attempt. A
later retry must claim a higher pin epoch before writing. A failed CAS therefore
creates no canonical metadata object and GC
cannot reclaim its content before that fenced abort. After the CAS, every manifest byte is already committed
occupancy and recovery must finish `COMMITTED_COPYING`; it may not abort the
root or release the charge. An R2 root pointer may mirror the completed
publication afterward, but neither a scratch object nor the pointer is an
authorization point.

The gateway's generation check, drain barrier and fixed scratch keyspace are
all required. Merely deleting visible objects and waiting for a token timeout is
not a fence: a previously authorized slow put could recreate them afterward.
A crashed/ambiguous lease may block progress but can never be treated as
settled, and storage adapters unable to provide a definitive put outcome are
ineligible for this path. The single attempt slot and pre-upload reserve
therefore prevent repeated crashes, failed CAS operations and delayed writers
from accumulating uncharged objects or consuming revocation escrow.

Served-root leases themselves are bounded by the `CapacityEnvelope`. A
publisher whose old-root lease would exceed the retained-root budget is fenced;
`authorize_serve` then fails until it reseeds from the current certified root.
Off-request reclamation deletes a superseded root's unshared pages only after no
active served cell or pending inclusion witness leases it. Thus canonical,
retained and in-flight physical object bytes all have disjoint provisioned
budgets; an indefinitely stale publisher cannot make a valid revocation run out
of storage.

In particular, the authority never commits a receipt that no cap-compliant root
can contain. The
conditional
`admit/<workspace>/<removal_fid>` cell memoizes the first signed canonical
receipt bytes and its log correspondence in that same transaction; every
publisher and retry receives those exact bytes. The only commit-proof signing
entry point first reads and matches that durable pair. It refuses an absent
cell, an uncommitted log row, or any receipt/root/frontier mismatch. Therefore a
validly signed candidate receipt orphaned by a crash or failed CAS remains inert
forever; replay after its author is evicted cannot admit it. Conversely, a lost
response after a successful CAS is recoverable because the committed row, not
process memory, authorizes proof issuance. During a partition, competing basis
roots therefore race at one logical serialization point and cannot create
divergent receipts for one removal. Concurrent ordinary roots are serialized
for the same capacity and frontier reason: a signed but unaccepted fact is not
canonical publication state. If the authority is unavailable, new S5
publications and irreversible actions fail closed; publishers never mint a
local substitute.
Registering multiple admission keys, quorum semantics, or a different partition
rule is a future protocol change, not an implicit v1 freedom.

The receipt freezes admission evidence. Canonical-provider shadowing,
quarantine/restore and later eviction of the author do not re-resolve or revoke
an existing row. Both `r` and `a` remain addressable for as long as that row
does. This is the immutable-evidence answer to the current
published-floor/quarantine contradiction: grow-only means receipts and effects
are grow-only, not that every syntactically valid removal proposal has an
effect.

A routed Merkle miss proves absence only from the suppression tree named by a
root; by itself it does **not** prove that the publisher indexed every removal
present in the fact tree. "Authenticated suppression tree" therefore means a
tree bound into the certified composite-root contract below. An R2 miss, an
uncertified composite root, or a row-valid-but-incomplete secondary tree is not
an authorization result.

### One atomic, certified composite root

Use one deterministic capped uniquely represented B-treap codec for the fact,
suppression and authority trees. Full Worker authentication also needs the canonical provider
chosen for each normalized need address:

```
RequiredCoOffer =
    (offer_name, a0, exact_a1)  # exact empty string is encoded, never ANY
NeedKey =
    (offer_name, a0, exact_a1 | ANY,
     sorted_unique(RequiredCoOffer...), budget_class)
AuthorityTree[NeedKey] =
    (canonical_provider_fid, canonical_proof_closure_digest,
     canonical_candidate_rank, canonical_transport_cost)
```

`ANY` is a canonical token distinct from the empty-string offer value and
represents a need whose `a1` is `None`. `budget_class` is one of a finite
protocol table of facts/needs/selectors/bytes ceilings. A provider is eligible
only when its immutable, admission-verified declared class fits the requested
class. Recursive authority edges must request a strictly smaller class/fuel, so
membership/admin/device delegation cannot reset the budget at each hop.
The complete canonical, sorted and deduplicated required-co-offer tuple is part
of the `NeedKey` used by AuthorityTree, both candidate indexes and reverse
impact rows. It contains at most `MAX_REQUIRED_COOFFERS_PER_NEED` entries and
its complete canonical encoding must fit `MAX_NEED_KEY_BYTES`; admission
enforces both before any tree or registry mutation. The AuthorityTree value
fits `MAX_AUTHORITY_TREE_VALUE_BYTES`, and key, value and canonical row framing
together fit `MAX_TREE_ROW_BYTES`. Thus adding required co-offers cannot create
an unbounded tree key or make 64 otherwise legal reverse entries overflow their
declared value cap. The resolver preserves the current selection-before-requirement
rule: it first chooses the canonical base-offer candidate, then requires that
same raw provider to carry every exact co-offer; it never falls through to a
losing source. Consequently the same base address may authenticate a hit for
one required tuple and `NO_PROVIDER` for another without aliasing one tree row.
The `device_invite` contract is the boundary fixture: two `device_key` needs
with different user-specific required `device` co-offers are different
NeedKeys. Required checks count toward the proof cost. This is not another
removal index. It is the bounded
replacement for rebuilding the whole root-derived offer/proof SQLite view at
every mint.

For an authenticated **hit**, a submitted committed dependency source and
closed proof digest must equal the canonical candidate committed here; merely
presenting the same provider through a losing/now-masked alternate proof or a
different valid but losing provider is not enough. An authenticated **miss** is
different: a fresh
ephemeral request necessarily has a fresh `("author", request.fid, pk)` address
whose signature is not in the committed tree. On a miss, the Worker resolves
that address only inside the validated submitted closure, using the same
canonical resolver and bounds. This is an exact family-matrix allowlist, not a
generic bootstrap rule: v1 permits only the signature offer cryptographically
bound to the one ephemeral request fid; membership, device, admin and every
other durable authority provider still require bounded fact-tree membership. A
miss never authorizes omission of a committed winner because the locally
certified completeness invariant proves that no matching committed row exists.

S4 publishes the new roots only in **shadow mode** beside the current
`removals` slot and current globals. The old slot remains the suppression
authority, so an existing file deletion cannot disappear merely because normal
receipt issuance is not live yet; the Worker grant route remains on its current
full-view path.

The shadow writer also timestamps authority admission rather than merely
reconstructing it at cutover. For every authority-producing fact first
published after recorder activation, the serialized transaction creates its
exact `RecordedActorAuthorityRef` only if all named one-time
`AUTHORIZATION_GUARDS` pass at that S4 frontier. A native-sized closure creates
its `AuthorityProofRecord` and `CommittedAuthorityProof` with the exact
historical `DirectRoot` binding, followed by `AuthorityProofCommitProof`. A
larger checkpointable closure instead creates a canonical paged
`LegacyAuthorityProofRecord` and
`CommittedS4PagedAuthorityProof`, followed by
`S4PagedAuthorityProofCommitProof`; that source record is complete S4 evidence,
not a future checkpoint placeholder. Its `S4PagedAuthorityAdmissionRef`
retains both the strong commit id and the content-addressed commit-proof oid,
while `S4PagedAuthorityProofSlot[commit_id]` authenticates that mapping, so
certification and GC reach that proof directly without an object scan. The
proof identity is per exact closure, not per provider fid. Before any later
`LegacyActorAdmissionRecord` can cite a preexisting provider or an alternate
closure, the service uses the same serialized path to commit the applicable
bounded or paged evidence at a separate earlier frontier and waits for its
post-commit proof. An existing commit is reused idempotently, including its
original `DirectRoot` binding; cutover never tries to replace that immutable
row with a `CutoverGeneration` variant. A successful closure commit remains
valid if the subsequent target CAS loses; an uncommitted or prospective closure
is never placed in an actor record. Both first-publication and on-demand closure
commits consume the physically provisioned finite S4 shadow authority-proof
reserve.

The paged strong-commit transaction creates its proof slot as `RESERVED`.
Only after rereading the exact row and reserved slot does the deterministic
post-commit signer write the content-addressed proof and atomically change the
slot to `FILLED(proof_oid)`. A target may retain a `PAGED_S4` ref only after that
fill. A crash at any earlier point leaves an already-budgeted row/slot: restart
recomputes the same proof and oid, or the closure remains ineligible. It never
scans objects, drops the occupied commit id, or takes the cutover
“no commitment” branch.

A fact that legacy S4 accepts through a globals-blind late relay may remain in
S4 storage, but without that committed proof it cannot become an S5 authority
candidate or actor source. Failure of a one-time guard or the shadow proof
reserve leaves legacy S4 validity unchanged and merely prevents the actor
record/S5 cut. For a pre-recorder authority fact never used and committed after
activation, cutover may create a proof only when every one-time guard is still
live; if any such guard has since been removed, the admission time is
unknowable and the workspace remains on S4 or explicitly re-anchors. This rule
covers delegated admin, membership and every other family with a one-time
authority guard; it is not an admin-only exception.

From the moment the S4 shadow writer is enabled, every newly published directly
deletable target with complete actor evidence uses the serialized publication
path to write an immutable `LegacyActorAdmissionRecord`. It builds the record
in a generation-fenced, physically precharged
`S4ActorAdmissionScratchSlot`: the slot's record object/bytes and write lease
are claimed before upload. The target CAS verifies the sealed scratch record,
atomically publishes the target, debits the disjoint canonical dimensions in
`S4ActorAdmissionCapacityCell` for one capped record, one
`CommittedLegacyActorAdmission` row, one proof slot, the maximum commit-proof
object/bytes and its write lease, writes the commit row, creates the proof slot
as `RESERVED`, and leaves the scratch slot charged as `COMMITTED_COPYING`.
Thus the scratch and canonical copies may coexist without borrowing capacity.
If the CAS loses, no canonical debit/row/slot exists; the scratch slot becomes
reusable only after fencing and definitive lease drain. If the CAS wins, the
service verifies the canonical copy before draining scratch, then the post-CAS
signer rereads the target, record, row and slot, emits the deterministic
`LegacyActorAdmissionCommitProof`, and fills the slot. A crash leaves a
repairable, already-budgeted copy or reserved slot, never an unbudgeted or
falsely proved target.

An otherwise valid S4 target that lacks a complete actor basis—including a
device-authorized target missing the contextual
`S4DeviceInviteAcceptance`—or cannot fit the shadow envelope is still published
under the unchanged legacy authority path without a record. That does not
weaken S4, but the missing record is a deterministic S5 eligibility failure
until explicit re-anchoring. Shadow recording never substitutes a bare target
signature, current winner or newly ground invite.

This registry is bounded service-side migration evidence, not a fourth Worker
tree. Each record, row, slot and proof obeys its individual byte cap below; the
S4 envelope has finite object/row/byte/lease dimensions, and the canonical
`CapacityEnvelope`, componentwise `CapacityCeiling` and whole-corpus
`CutoverCapacityEnvelope` separately reserve its retained and staged S5 copy.
It is append-only and never backfilled from a later proof winner. The
`S4_DEVICE_INVITE_ACCEPTANCE` basis preserves current S4 behavior for a
device-authorized target without standalone consent, but is valid only when
that exact device key signed the contextual workspace/target/owner/invite tuple
and separately authored the target under the retained invite proof.
Consequently facts already present when this recorder is deployed may lack
migration evidence; that is an explicit S5 eligibility failure, not a reason to
reconstruct an admission-time actor class from timestamps, the current proof
table or the current root.

S5 starts with a **grandfather/backfill barrier while S4 is still
authoritative**. This is a coordinated per-workspace format cut, not a lazy
reader migration:

1. The workspace-global admission authority acquires the migration fence and
   pauses S4 publication only after the provider has durably prepared the
   inactive service-only S4 fallback generation above. Before changing any
   credential, it also completes the provider-signed whole-cutover capacity
   preflight below. That preflight reserves the complete prospective canonical
   envelope and a simultaneous, physically disjoint
   `CutoverCapacityEnvelope`; it covers the current published corpus, every
   registered retained-quarantine inventory and every object/byte that an
   already-issued old-prefix write lease can still settle. A backend without a
   fixed legacy write ceiling must conservatively charge the entire remaining
   old-prefix provider quota. Before signing the bootstrap commitment, the
   provider activates the corresponding quota guard, so every old-prefix write
   accepted between preflight and credential revocation consumes that signed
   object/byte ceiling and rejects before exceeding it. If the complete bound
   cannot be proven, guarded and provisioned, migration stops here while S4 is
   still writable.

   The preflight runs the protocol-pinned `MigrationSizer` over that ceiling,
   the exhaustive family matrix and every fixed S5 expansion rule. It assumes
   no favorable deduplication: every possible legacy fact is chunked at the
   maximum page cost, every possible old effect receives its grandfather
   evidence/slots, every possible distinct over-budget candidate closure
   receives a proof-bound checkpoint,
   every authority candidate receives its bounded proof record, and both maps,
   registries, generation-staged service rows, activation cells,
   root and sidecars are charged at their maxima. It also rejects before the
   fence unless every staged service batch and the fixed final activation
   transaction fit the protocol operation/byte caps below. Thus the pre-fence
   reserve is an upper bound on every frozen snapshot permitted by the provider
   guard, not an estimate of the current convenient corpus.

   **Before hashing or snapshotting any legacy row**, the authority then
   rotates/revokes every legacy publisher metadata-write credential, makes the
   old metadata namespace read-only (or otherwise impossible to address), waits
   the provider's maximum old-token lifetime, and definitively drains every
   write admitted before the fence. A delayed or ambiguous pre-fence write keeps
   the barrier open; the authority never guesses that it died. It then records
   the provider-signed `LegacyPreCutoverIamAttestation` over the frozen old
   prefix, credential generation, drain watermark and service-exclusive policy
   template. Merely updating keyrings is insufficient, and a backend that
   cannot attest this cut cannot migrate in place.

   Only after that physical writer/drain barrier does the authority reconcile
   every registered authoritative publisher into one fully certified S4
   cutover root. Each publisher contributes its hash-verified retained
   `quarantine/` inventory through the now read-only snapshot interface; the
   frozen legacy universe is the published set plus the union of those
   inventories. It freezes the exact canonical root bytes as
   `reconciled_s4_root`, computes
   `reconciled_s4_root_oid = H(reconciled_s4_root)`, and reserves the root bytes
   as a retained, canonically chunked first-cut payload preimage. Chunking
   changes only physical retention; the semantic oid is always the hash of the
   reassembled original bytes. No old-prefix write can settle between this
   enumeration and the S5 CAS. From the fenced legacy source bytes, before
   constructing any migrated `FactRecord`, it computes
   `old_slot_globals_digest` and:

   ```
   legacy_mask_namespace =
       H("s5-legacy-mask-namespace", anchor, reconciled_s4_root_oid,
         old_slot_globals_digest,
         pre_cutover_iam_fence_attestation_digest)
   legacy_authority_checkpoint_namespace =
       H("s5-legacy-authority-checkpoint-namespace", anchor,
         reconciled_s4_root_oid, old_slot_globals_digest,
         pre_cutover_iam_fence_attestation_digest)
   ```

   Still before constructing any migrated `FactRecord`, the authority enumerates
   both legacy effect sources into one canonical `LegacyEffectCensus`: every
   effective entry in the reconciled root's authoritative `removals` slot and
   every authenticated `("removal", public_key)` legacy global. It resolves each
   old target from the frozen source bytes, canonicalizes equivalent entries,
   applies the static S5 `DIRECT_TARGETS`/principal matrices, and records the
   exact normal selector or `LegacyMask(legacy_mask_namespace, victim_fid)`
   interpretation. For every `LegacyMask` victim it records the migration-only
   sid that must be present in that victim's migrated FactRecord and in
   `sorted_provider_sids` for every candidate the victim produces.

   The result is a retained, canonical length-delimited, **S5-native**
   `LegacyEffectCensus`: each logical row binds its legacy source kind and key,
   old value digest, canonical victim fid, selected interpretation and optional
   migration-only sid. While the fenced S4 converter still exists, it decodes
   the exact `reconciled_s4_root`, proves this is the complete translation of
   both old effect sources, and rejects any source/row mismatch. Its
   deterministic chunk tree is independent of the later B-treap `layout_seed`;
   `legacy_effect_census_oid` names the complete retained object/page closure
   and `legacy_effect_census_digest` is the domain-separated streaming digest
   over its sorted logical rows. The migration preflight charges the complete
   census closure and its bytes.

   Neither `legacy_mask_namespace` nor
   `legacy_authority_checkpoint_namespace` contains a migrated FactRecord oid,
   `legacy_universe_rows_digest`, layout seed, B-treap root or
   `cutover_digest`. Because the census classified the frozen legacy sources
   from their authenticated old bytes, every required migration-only selector
   is fixed before its victim's migrated FactRecord is hashed. The authority
   then materializes that exact **logical row set**, applying all census selector
   additions before computing any `fact_record_oid`:

   ```
   LegacyDisposition =
       ORDINARY
     | EFFECT_SOURCE
     | EFFECT_EVIDENCE
     | INERT_REMOVAL
   LegacyUniverseRows[fid] =
       (PUBLISHED | RETAINED_QUARANTINE(origin_publisher_id),
        LegacyDisposition, fact_record_oid, raw_root_oid)
   LegacyUniverseRows[Publisher(publisher_id)] =
       (inventory_root_oid, inventory_digest, fixed_width_attestation)
   ```

   The eventual seeded `LegacyUniverseMap[fid]` and
   `LegacyUniverseMap[Publisher(publisher_id)]` contain exactly these logical
   rows; there is no second or omitted physical membership set.
   There is exactly one row for every published or registered
   retained-quarantine legacy fact and one fixed-width attestation row for every
   registered publisher. `PUBLISHED` wins when the reconciled root contains the
   fid. Otherwise `origin_publisher_id` is the lexicographically lowest
   registered publisher id whose verified signed inventory contains the exact
   fact bytes. All other matching inventories remain authenticated by their
   publisher rows but are not repeated inline in the bounded fact row. Thus
   opposite publisher-enumeration orders produce identical logical rows and
   `legacy_universe_rows_digest`. The authority reconstructs the canonical fact
   bytes and deterministic S5 FactRecord/raw-root representation before this
   choice; conflicting fact bytes, fid/body integrity, or derived object values
   for one fid abort the migration rather than selecting an origin.
   For each directly deletable ordinary row it also requires either a prior
   immutable owner binding or the exact capped
   `LegacyActorAdmissionRecord`, `CommittedLegacyActorAdmission`, filled proof
   slot and commit proof captured when that target first published under S4
   shadow recording. It checks the target key/fid, actor fields and legacy
   basis against the record and roots that evidence from the new FactRecord.
   It never chooses an owner by replaying current direct-member precedence.
   Missing admission-time evidence aborts the cut while the prepared S4
   fallback remains authoritative.
   The already-frozen `LegacyEffectCensus` and complete old entry/global
   inventory deterministically classify every row before hashing:
   non-removal facts are `ORDINARY`; the canonical lowest-fid proposal selected
   as an old effect's source is `EFFECT_SOURCE`; other removal facts that are
   authenticated evidence for an authoritative old effect are
   `EFFECT_EVIDENCE`; and a valid removal proposal present only in a retained
   inventory, with no authoritative old slot/global effect, is
   `INERT_REMOVAL`. The disposition contains no receipt, action oid or seeded
   tree value and is independently recomputed during certification.
   Each fact row's `fact_record_oid` must name that fid and its `raw_root_oid`;
   each chosen quarantine origin must name a publisher row whose signed
   inventory root contains it. The paged map therefore roots quarantine-only
   FactRecords, raw chunks and the complete registered-publisher attestation set
   across restart and GC instead of relying on a publisher's mutable directory.
   The pre-action
   `legacy_universe_rows_digest` is a domain-separated streaming Merkle digest
   over the sorted canonical row encodings. It is defined over logical rows,
   not pages, leaders, a B-treap root or `layout_seed`.

   The first S5 FactTree receives one
   `ADMITTED(fact_record_oid)` row for every `ORDINARY` fact row in this sealed
   universe, both `PUBLISHED` and `RETAINED_QUARANTINE`. No legacy removal
   proposal receives an ordinary FactSlot. `EFFECT_SOURCE` and
   `EFFECT_EVIDENCE` records remain reachable through their grandfather
   `ActionRecord`, `LegacyEntryMap` and frozen universe rows;
   `INERT_REMOVAL` remains authenticated only by the frozen universe map and is
   forever ineligible for effect or later direct reingestion. Thus a retained
   proposal that never affected S4 cannot become effective merely because it
   crossed the format boundary, and certification can still reject any
   unreceipted removal found in FactTree. The origin flag does not become a
   Worker authority bit: during the fence, certification enumerates every
   bounded sealed ordinary proof closure that was valid or could become
   selectable after an authenticated legacy shadow/restore. If its deterministic
   `authority_proof_commit_id` already names a valid pre-fence `DirectRoot`
   commitment and post-commit proof, the migrator reuses and retains that exact
   immutable pair. Only a closure with no existing commitment may receive a new
   `CommittedAuthorityProof` under the cutover generation, after its applicable
   one-time guards pass at the fenced frontier. A second byte-different row at
   an existing id, including a `CutoverGeneration` replacement for a
   `DirectRoot` row, aborts migration. An existing row whose proof sidecar is
   temporarily absent takes the idempotent proof-recovery path above and blocks
   the cut until it verifies; it is not eligible for the “no commitment” branch.
   An omitted closure is a
   migration-certification failure; later winner changes do not manufacture a
   new proof or revoke one. This makes the S5 FactTree
   the authenticated archive for ordinary facts from the first root onward
   while the frozen map continues to prove all legacy bytes, origin,
   disposition and migration translation.

   Before any layout trial, the authority computes:

   ```
   cutover_basis_digest =
       H("s5-cutover-basis", anchor, reconciled_s4_root_oid,
         legacy_mask_namespace, legacy_authority_checkpoint_namespace,
         legacy_effect_census_digest,
         legacy_universe_rows_digest,
         old_slot_globals_digest,
         pre_cutover_iam_fence_attestation_digest)
   ```

   The IAM basis attestation covers revocation/drain of the old namespace and
   the service-exclusive policy template; it contains no digest-addressed S5
   prefix. The deterministic trial below derives a candidate `layout_seed` only
   from this layout-independent basis, builds
   `LegacyUniverseMap = Btreap(candidate_seed, LegacyUniverseRows)`, and then
   computes:

   ```
   candidate_seed(trial) =
       H("layout-seed", anchor, cutover_basis_digest, trial)
   legacy_universe_map_root =
       root(Btreap(candidate_seed(trial), LegacyUniverseRows))
   cutover_digest =
       H("s5-cutover", cutover_basis_digest,
         candidate_seed(trial), legacy_universe_map_root)
   ```

   Thus fenced source bytes and both root-free migration namespaces exist before
   migrated FactRecords and logical rows, logical rows exist before the seed, the seed
   exists before the map root, and the map root exists before
   `cutover_digest`; none hashes a value that already depends on itself.

   It now materializes and service-signs the post-snapshot `S5CutoverBinding`
   described above, including the derived `layout_seed`, `cutover_digest` and
   exact `meta-s5/<workspace>/<cutover_digest>/` namespace. It verifies every
   exact capacity value against the pre-fence bootstrap ceilings, then creates
   that IAM-isolated namespace with the admission/publication service as its
   only writer. An offline or stale publisher may retain only an already-useless
   credential for the frozen legacy prefix; it cannot address S5
   cutover-scratch/canonical keys, must reseed, and can never inject unregistered
   old-format state. The final provider-signed exact-prefix IAM attestation is
   produced after `cutover_digest` exists. The pre-cut and final evidence become
   the retained `LegacyIamAttestation` object defined below and are bound,
   together with the post-snapshot binding and pre-fence bootstrap commitment,
   by `LegacyMigrationSeal`; that final object is deliberately not an input to
   `cutover_basis_digest`.
2. The authority consumes the already sealed `LegacyEffectCensus`; it never
   discovers or adds a selector after `LegacyUniverseRows` has been hashed.
   Before issuing receipts it verifies the census against the frozen source
   rows and canonicalizes slot entries by their recomputed action owner and
   target spec. The lowest removal fid in each equivalent group supplies the one
   grandfather action and receipt; every other entry is duplicate evidence, not
   another action competing for the same owner slot.

   The immutable, paged
   `LegacyEntryMap[legacy_entry_key] =
   (entry_digest, proposal_fact_record_oid, canonical_removal_fid,
   canonical_action_slot)` contains exactly one row for every entry in the
   sealed legacy removal slot. Its content-addressed root is committed by the
   first S5 composite root. It roots every duplicate proposal FactRecord (and
   therefore its raw chunks) and proves which canonical action accounts for the
   old entry. It is a frozen migration/certification ledger, never a live
   removal-fid index or Worker query path; no S5 publication appends to it.

   For a canonical slot entry, `evidence_kind = LEGACY_SLOT` binds the entry and
   its proposal from the published-or-quarantined legacy universe. The receipt
   carries
   `GRANDFATHER(LegacyEffectAuthorizationRef(LEGACY_SLOT, ...))`, whose census
   row and source FactRecord match that exact authoritative entry. It does not
   force the old proposal through `OWNER` or `ADMIN`: in particular, a
   cross-user content deletion accepted by the legacy any-member handler stays
   effective without being misrepresented as new-policy authorization.
   The receipt
   uses a normal `TargetBinding` only when the allowlisted legacy proposal maps
   to a current removal family, the victim family's `DIRECT_TARGETS` matrix
   permits that exact removal-family/selector-role pair, and recomputation
   resolves to the exact old victim rather than an inherited parent or
   principal. This recomputation may authenticate a quarantine-only victim
   through its exact `LegacyUniverseMap` row; doing so does not publish or
   restore that victim.

   Before filling any normal grandfather action, fenced backfill structurally
   creates the exact `SuppSlot(resolved_sid)` and
   `ActionSlot(Sid(resolved_sid))` if S4 ordinary admission never created them,
   including for a victim present only in retained quarantine. The action owner
   is therefore the same `Sid(min(effect_targets))` used by a live
   `ExactSids`, and certification never relies on the absent-slot fallback.
   Otherwise the receipt uses
   `LegacyMask(legacy_mask_namespace, victim_fid)`. The pre-record census already
   added that reserved sid only to the sealed victim's migrated FactRecord, so
   every authority candidate produced by that victim includes it in
   `sorted_provider_sids` and starts `MASKED`. Because the namespace and census
   were fixed from fenced legacy source bytes before that FactRecord and its
   `LegacyUniverseRows` row were hashed, the row oid can feed `cutover_digest`
   without a fixed-point equation. The mask cannot be authored, selected by
   `LIVE_GUARDS`, or make any new `NEVER` fact targetable; mandatory
   provider-existence masking is not a live targeting capability. The mask
   exists solely to preserve an already-effective S4 entry. This fallback
   covers not only a target that is now `NEVER`, but also a
   membership/chunk/other target that offers a normal selector which the legacy
   removal family has no current authority to invoke. Fenced backfill creates
   that reserved migration `SuppSlot` and
   `ActionSlot(Migration(legacy_mask_namespace, victim_fid))` before filling
   them. Both normal and migration-only structural creations participate in
   layout-seed selection, capacity preflight and the first S5 CAS.

   For a removal global, `evidence_kind = LEGACY_GLOBAL` binds its source
   `auth.removal` fact and
   `MemberPrincipal(LegacyGlobalBinding(cutover_digest, source_fid,
   public_key))`. This migration-only binding derives the key from the
   authenticated old global and is the explicit zero-provider exception to a
   live `PrincipalBinding`. The first S5 root must
   give its receipt the matching
   `GRANDFATHER(LegacyEffectAuthorizationRef(LEGACY_GLOBAL, ...))`; that form
   proves the sealed old global rather than rerunning the source admin's current
   guard. It then must
   structurally create the reserved `ActionSlot(MemberPrincipal(public_key))`
   from that authenticated global even when no membership provider exists, then
   fill it with the grandfather action pointer. It must
   activate slots for every membership provider of that public key in the
   **published or retained-quarantine** legacy universe, and every later
   certified root must materialize a row for any additional matching provider
   before admitting it. If the sealed universe has no matching provider, the
   authority still issues the receipt, records it in `TargetRegistry`, reserves
   its bounded future-provider row budget, and emits zero SuppTree effect
   updates. A later matching provider cannot publish unless its newly inserted
   slot is `ACTIVE` in that same root. These principal, migration-action and
   suppression-key creations are fenced backfill operations included in layout
   seed selection and migration capacity; they are not a live-removal fallback
   from the absent-slot rule.
   If several authenticated old `auth.removal` facts emit the same set-valued
   global row, the lowest source fid is the one canonical evidence source; the
   row receives one receipt/action, not one per equivalent source fact.
3. Before S5 eligibility, the authority processes every Worker-authorizable
   legacy proof closure that is currently valid or can become selected after a
   certified shadow/restore. It gives every within-budget closure its cutover
   `CommittedAuthorityProof`, and flattens every over-budget closure. An
   over-budget closure already named by a post-recorder actor's
   `PAGED_S4(S4PagedAuthorityAdmissionRef)` is not first invented at this fence:
   the migrator verifies its earlier strong commit and post-commit proof, reuses
   the byte-identical content-addressed `LegacyAuthorityProofRecord`
   manifest/pages as the checkpoint source, and includes those already durable
   objects in the frozen source/cutover manifests. Other over-budget candidate
   closures may be paged for the first time only under the fenced rules below.
   The
   one-time authorization decision must itself be unambiguous: a provider first
   published after S4 recorder activation must carry its exact historical
   commit-proven authority proof, while a pre-recorder provider may be admitted
   at the fence only if every one-time guard is still live there. A pre-recorder
   provider whose one-time guard is now removed blocks migration/requires
   re-anchor; current state cannot prove whether it was admitted before that
   removal or first relayed afterward. No cutover-generated proof launders that
   ambiguity into `ADMITTED_PROOF`.
   The
   source closure is not forced into the new 64-fact Worker record. Instead the
   fenced migrator builds, or verifies and reuses an already committed S4 actor
   source with, the canonical paged:

   ```
   LegacyAuthorityProofRecord(
       provider_binding_index,
       fact_binding_pages_root_oid, proof_edge_pages_root_oid,
       fact_count, edge_count, page_count, canonical_bytes,
       proof_closure_digest, proof_depth, canonical_proof_cost)
   ```

   Each fact-binding page contains at most
   `MAX_LEGACY_AUTHORITY_PROOF_PAGE_FACTS`, each edge page at most
   `MAX_LEGACY_AUTHORITY_PROOF_PAGE_EDGES`, and every page and the fixed
   manifest obey `MAX_LEGACY_AUTHORITY_PROOF_PAGE_BYTES`. Total pages/bytes are
   bounded by the signed `LegacySourceCeiling`, migration sizing and disjoint
   cutover envelope, then retained as canonical occupancy. This proof is
   off-request migration/certification evidence; Workers never fetch it. Thus a
   sealed 519-hop source is representable without weakening the 64-fact limit
   on the checkpoint's new bounded Worker proof.

   The migrator then emits a migration-only, service-signed
   `LegacyAuthorityCheckpoint(legacy_authority_checkpoint_namespace,
   source_candidate_id, source_fid, source_legacy_authority_proof_oid,
   source_proof_closure_digest,
   source_proof_depth, source_canonical_proof_cost, source_need_key, subject,
   selectors, sorted_source_provider_sids, sorted_source_action_scopes,
   budget_class)` for every distinct over-budget candidate closure that could
   become canonical after a sealed shadow/restore. It never coalesces two
   closures merely because they share one provider fid.
   `source_candidate_id = H("legacy-authority-candidate", source_need_key,
   source_fid, source_legacy_authority_proof_oid,
   source_proof_closure_digest)` is derived only after the paged proof manifest
   is hashed; neither it nor the checkpoint fid appears inside that manifest.
   The root-free checkpoint namespace was fixed from fenced S4 source bytes
   before any migrated FactRecord. It replaces `cutover_digest` in checkpoint
   identity, so an owner FactRecord may bind the checkpoint oid before
   `LegacyUniverseRows`, its seeded map root and the final digest exist.
   The checkpoint offers exactly the source closure's normalized authority,
   carries its recomputed S5 suppression selectors, has no recursive authority
   need, and is eligible only under the fixed migration budget. Its FactRecord
   and GC traversal root the named `LegacyAuthorityProofRecord` manifest and
   every page; certification replays every binding/ordinal edge, recomputes the
   source candidate id, depth, cost, complete co-offer-bearing source NeedKey and
   selectors, and requires the two stored source scope sets to equal that exact
   candidate ref. It also fixes that ref's rank provenance to
   `LEGACY_SOURCE_RANK(checkpoint_fid)` and its
   `canonical_candidate_rank` to
   `(source_proof_depth, source_fid, source_candidate_id)`. The checkpoint's
   short bounded proof depth, checkpoint fid and service provider fid are
   deliberately ineligible as selection fields. Consequently a 519-hop source
   that lost to a shallow native or legacy provider before the fence still
   loses after flattening, while a formerly winning source keeps the same
   position. If the same checkpoint is discovered through a different
   compatible full NeedKey, materialization derives that full ref's legacy
   candidate-id tie breaker from the new NeedKey and the same certified source
   proof fields; the base registry never reuses the source ref's stored rank.
   A later ordinary proof that selects this checkpoint on a `NEED` edge imports
   `source_proof_depth` into its logical-depth recurrence and records
   `DERIVED_LEGACY_RANK`; it does not import the checkpoint's short transport
   depth. Every further descendant repeats that rule. Thus a child of the
   519-hop checkpoint has logical depth 520 while its bounded transport proof
   may have depth one, and cannot leapfrog a native candidate it previously
   lost to. The `checkpoint-descendant-uses-transport-depth` mutation does
   exactly that and must fail the mixed native/legacy ordering vector. The flattened
   checkpoint candidate then carries the same deduplicated union of source
   provider sids and declared action scopes, so masking one proof path does not
   silently mask or preserve another path with different liveness semantics.
   Live authors cannot mint a checkpoint. A checkpoint that offers membership
   is itself a membership provider, so an existing or later `MemberPrincipal`
   receipt covers it before publication. This flattens proof transport without
   inventing a role or making it survive revocation. If even the checkpoint
   record/selector set or the aggregate reserved root cannot fit, the workspace
   activates the writable S4 fallback generation or explicitly re-anchors; a
   deep but otherwise valid legacy chain is never silently stranded behind an
   S5 root it cannot use.
4. The authority writes the same globally serialized admission cell used for a
   normal action. Backfill deliberately does **not** re-run current guards: an
   effect that took effect before its author was later evicted remains
   grow-only. Its receipt is constructible because `LEGACY_SLOT` and
   `LEGACY_GLOBAL` use only the matching, non-callable
   `GRANDFATHER(LegacyEffectAuthorizationRef)` arm. `LIVE_GUARDS` may never use
   that arm.
5. Certification requires complete correspondence: every legacy slot entry has
   exactly one `LegacyEntryMap` row whose canonical target has a valid receipt,
   every canonical legacy action and every legacy removal global has one valid
   receipt, every duplicate row resolves to that same action owner/target spec,
   and no map row names state outside the sealed universe. Every currently
   resolved receipt target has its canonical-witness `ACTIVE` SuppSlot and the
   receipt's own filled owner ActionSlot; every
   unsuppressed selector has its certified `CLEAR` slot; every zero-provider
   `MemberPrincipal`
   receipt has its registry row and escrow; and every distinct over-budget
   legacy authority candidate closure has exactly one proof-record-bound
   checkpoint. The immutable
   `LegacyIamAttestation` object contains the provider-signed pre-cut
   credential-generation/drain evidence, the monotonic generation watermark,
   proof that the prepared S4 fallback was never activated (or was revoked by a
   later retry), and the provider-signed final service-only exact-prefix policy
   evidence, their verification-key ids and the exact old/new prefixes. Its
   content hash is
   `legacy_iam_attestation_oid`, its canonical bytes must fit
   `MAX_LEGACY_IAM_ATTESTATION_BYTES`, and inability to retain or verify that
   evidence aborts into the writable S4 fallback generation.

   The immutable
   `LegacyMigrationSeal` binds the `cutover_digest`,
   `reconciled_s4_root_oid`, `legacy_mask_namespace`,
   `legacy_authority_checkpoint_namespace`,
   `legacy_effect_census_oid`, `legacy_effect_census_digest`,
   `LegacyUniverseMap` root,
   `LegacyEntryMap` root, old slot/globals digest and registered publisher
   inventory-attestation digest, plus
   `migration_bootstrap_oid`, `capacity_ceiling_oid`,
   `legacy_source_ceiling_oid`, `s5_cutover_binding_oid` and
   `legacy_iam_attestation_oid`. It also carries the pre-pinned admission
   service's `LegacyTranslationAttestation` signature over those canonical
   fields and an exact converter version. The service issues that signature
   only after the still-live S4 converter has verified the frozen root and
   complete census, but before the first-root CAS. Its canonical encoding
   contains only fixed-width version, oid, digest and signature fields and must
   fit `MAX_LEGACY_MIGRATION_SEAL_BYTES`; the census, both maps, the IAM evidence
   object, the bootstrap commitment, its canonical ceiling/source objects, the
   retained canonical `reconciled_s4_root` bytes, the final binding and the seal
   are committed and made GC-reachable by the first S5 root.
   Certification fetches the content-addressed IAM object, verifies both
   provider signatures and exact prefixes, recomputes the pre-cut digest used by
   `cutover_basis_digest`, and rejects a missing, redirected, oversized or
   bare-digest substitute. It also verifies both maps against the seal, fetches
   and reassembles the retained S4 root bytes, and requires their content hash
   to equal `reconciled_s4_root_oid`; this is an audit preimage check, not an
   old-format decode. It then uses only the S5 codec to fetch the complete
   `legacy_effect_census_oid` closure, recomputes its logical-row digest and
   `old_slot_globals_digest`, and verifies the
   `LegacyTranslationAttestation` under the root's pre-pinned `admission_pk`.
   From those S5-native fields and the sealed root oid—not the mutable live root
   cell—it recomputes `legacy_mask_namespace` and `cutover_basis_digest` after
   restart. No post-seal code path imports or retains the S4 decoder. The
   frozen maps and signed census are the retained logical-source proof, so
   superseded S4 child pages need not remain serving authority. It recomputes the
   inventory-attestation digest from the publisher rows, and
   requires every `LegacyEntryMap` row, checkpoint source and grandfather
   EvidenceRef to prove membership in the exact `LegacyUniverseMap` row it
   names.
   Before the first-root CAS, the service constructs the payload sections of a
   complete `CutoverObjectManifest` over every prospective first-S5-root
   **payload** object and a paged `CutoverServiceManifest` over every conditional
   strong-service row except the fixed activation tail:
   migrated tree pages, FactRecords/raw chunks, bounded
   `AuthorityProofRecord`s, paged `LegacyAuthorityProofRecord` manifests/pages,
   both legacy maps, checkpoints, grandfather action
   evidence, ActionRecords, filled slots,
   registries, admission cells/log rows, the exact retained reconciled-S4-root
   bytes, the authenticated legacy-effect census closure, IAM evidence,
   migration seal and next certificate reservation. Every
   grandfather admission-log row uses
   `CommitBinding = CutoverGeneration(service_generation_id)`, never
   `DirectRoot`; the certificate reservation is likewise keyed by the
   pre-root `service_generation_id` and publishing deployment, not by an
   unknown root oid. Newly materialized cutover authority proofs use the same
   generation binding and service manifest, but a proof already committed in
   S4 remains behind its retained `DirectRoot` row/proof pair and is referenced
   from the first-root registries without a duplicate service row.

   A canonical, paged
   `CutoverPayloadManifest(object_manifest_root_oid,
   service_manifest_root_oid, payload_object_count, payload_object_bytes,
   service_row_count, service_row_bytes)` content-hash-roots those two manifests.
   Its oid is the `cutover_payload_manifest_digest` below. The payload
   object inventory deliberately excludes its own manifest pages as well as the
   `CutoverServiceGeneration` descriptor, composite root,
   `CutoverCommitAnchor`, mutable `CutoverContentPinGeneration` row,
   `CutoverContentPinAnchor`, frontier,
   active-generation pointer and
   generation-state write, so no manifest hashes itself. The migration sizer
   nevertheless counts a complete simultaneous copy of the payload-manifest
   pages and every activation-tail object/row in their separate canonical and
   cutover-staging dimensions. It rejects unless the
   final occupancy fits the exact canonical `CapacityEnvelope` and the manifest
   plus a complete simultaneous copy of every prospective object, including
   those fixed tail objects, fits the preallocated
   `CutoverCapacityEnvelope`, including its service-staging row/byte dimensions.
   The service writes object entries only to fixed
   `cutover-scratch/<workspace>/<generation>/<ordinal>` slots, one ordinal per
   preprovisioned object slot, and holds a durable cutover write lease for every
   accepted or ambiguous put.

   Strong-service rows are staged under
   `cutover-service/<workspace>/<service_generation_id>/<logical-table>/<logical-key>`
   in
   idempotent transactions of at most `MAX_CUTOVER_SERVICE_BATCH_ROWS` and
   `MAX_CUTOVER_SERVICE_BATCH_BYTES`. Each row commits its final logical key,
   canonical value hash and bytes from its ordinal in the service manifest, so
   an active request can prepend the generation and perform an exact keyed read
   without an ordinal scan. Those rows
   are inert: every S5 service read is namespaced through the single
   `active_service_generation` cell, which still names S4 until cutover. A
   generation-fenced writer may fill only its manifested ordinals, and any
   mismatch or batch above either cap aborts. After every row and object matches,
   the service seals the independently charged content-pin generation from
   `STAGING` to `SEALED`, then seals an immutable, content-addressed
   `CutoverServiceGeneration(service_generation_id,
   s5_cutover_binding_oid, cutover_payload_manifest_digest,
   service_rows_digest, service_row_count, service_row_bytes)` of at most
   `MAX_CUTOVER_SERVICE_GENERATION_BYTES`. Only then does it construct the
   composite root that names that descriptor, computes its oid, and constructs
   the fixed `CutoverCommitAnchor` binding the generation, descriptor, root,
   frontier and pre-root certificate reservation plus the fixed
   `CutoverContentPinAnchor` binding the `SEALED`
   `CutoverContentPinGeneration` and its pin-set manifest to that root.
   It then appends the descriptor, root, anchors and other fixed activation rows as the manifest's
   activation tail. No hash in the descriptor or payload includes that tail, so
   this order has no
   descriptor/root/manifest content-hash cycle. It then definitively drains all
   object leases.

   The final strong transaction is a bounded **activation**, not a replay of the
   workspace-sized row plan. It requires the unchanged S4 root/frontier and
   migration fence plus the exact sealed generation, writes at most
   `MAX_CUTOVER_ACTIVATION_ROWS` and
   `MAX_CUTOVER_ACTIVATION_BYTES`, and atomically changes the canonical
   root/frontier, `active_service_generation` pointer and generation state while
   inserting the exact `CutoverCommitAnchor` and
   `CutoverContentPinAnchor`; the same transaction changes the content-pin
   generation from `SEALED` to `ROOTED(root, frontier)`. The
   first S5 root repeats the generation descriptor oid. The pointer flip makes
   the complete pre-staged registry/admission state visible at the same instant
   as the root; no batch is ever partially authoritative. A grandfather row
   becomes commit-proven only after the post-commit signer re-reads that active
   row and anchor and emits its proof. The first root is therefore one atomic cut
   without requiring one unbounded provider transaction, and verified
   authority-exclusive object copies occur only after activation under already
   charged canonical occupancy.

   This whole-corpus reserve is distinct from `publication_attempt_*`, which
   bounds one later ordinary publication or revocation. A legacy corpus larger
   than the largest single-action scratch pool is therefore migratable when its
   pre-fence whole-cutover reservation fits; an implementation that reuses only
   the single-operation pool must reject before fencing, not strand the
   workspace after the old writers are revoked. After a failed pre-CAS attempt,
   the abort protocol generation-fences and drains both object and service-row
   staging, marks the generation inert forever, and reclaims its cutover slots.
   After a successful CAS, the active generation's service rows, descriptor,
   payload-manifest pages and `CutoverCommitAnchor` remain canonical and charged;
   they are never deleted as “staging.” The service retains the temporary object
   scratch copies, write leases and duplicate staging charge until every
   canonical copy, commit proof and certificate is verified, then reclaims only
   those temporary resources without changing the root or active generation.

   After the seal, the S5 runtime never restores directly from a mutable pre-S5
   `quarantine/` entry. Every reconciled old fact has an authenticated
   `LegacyUniverseMap` row and matching FactRecord/raw root; every row classified
   `ORDINARY` also has its exact FactTree `ADMITTED` binding. A naked fid,
   mismatched object, old-envelope fact outside the map, or removal proposal
   misclassified as ordinary is rejected as unfenced old state. Migrated
   ordinary facts' later eligibility still requires an authenticated inclusion
   proof for their exact `LegacyUniverseMap` row and matching archived FactTree
   binding. Restoration is a certified proof-DAG transition over those retained
   bytes, not reingestion from a publisher directory. Every ordinary durable
   fact admitted by S5 ordinary publication likewise enters the grow-only
   FactTree once with the exact new family selector shape and remains there
   across shadow/restore. Removal proposals remain outside that path until
   atomic action admission roots them through `ActionRecord`. A local
   `quarantine/` copy is disposable cache only and can never add, replace or
   restore canonical bytes. Only then may the first
   S5 root omit the legacy slot/globals and enable the bounded Worker path. A
   crash before that root CAS leaves S4 authoritative; retrying the global cells
   returns the same receipt bytes and, only for a committed row, its recovered
   commit proof. After the CAS, the authority seals the backfill namespace and
   rejects every S4 basis root.

Any failure after the legacy-writer fence but before the first S5 root CAS uses
one explicit abort protocol. The authority generation-fences and drains every
S5 scratch/IAM writer, discards all uncommitted receipts and candidate objects,
and performs the S4 scratch handoff above before atomically activating the
pre-attested fresh S4 credential generation for the service-exclusive writer.
The handoff changes no workspace-global canonical capacity balance, so all
actor/proof commitments written by every predecessor generation remain charged
and reusable. It never re-enables an old publisher credential or the fenced
generation. The unchanged last S4 root, legacy `removals` slot and removal
globals remain authoritative throughout; once activation is durable,
ordinary S4 publication resumes through the service and registered publishers must
reseed. A later S5 retry is a **new migration attempt**: while that S4
generation is still active and writable, the provider first provisions and
attests another inactive fresh service-only S4 fallback generation, reruns the
whole-cutover sizing/quota guard, emits new retained `CapacityCeiling` and
`LegacySourceCeiling` objects, and has every registered publisher pin a fresh
`MigrationBootstrapCommitment` naming that successor fallback. Only after all
of those steps succeed may it fence the currently active generation. It then
includes that generation's writes, records a fresh provider-signed monotonic
credential-generation watermark proving every earlier writer generation
revoked, and takes a new snapshot. Therefore each of any number of consecutive
pre-CAS aborts has a distinct already-provisioned successor to activate; no
attempt ever fences its only writable generation or reuses a stale bootstrap.
The fallback covers checkpoint, canonical-key, seed-trial, capacity,
object-write, final-IAM-attestation and certification failure; if even its
pre-reserved activation fails, the workspace stays fail-closed/read-only and
requires explicit re-anchor rather than claiming to be writable S4.

Normal S5 receipts use `evidence_kind = LIVE_GUARDS`. All three evidence kinds
have one canonical encoding and one workspace-global cell per removal fid. S5
then bumps the layout and atomically cuts to the final root below:

```
root = canon({
    "anchor": <workspace>,
    "admission": <service-exclusive public key>,
    "cutover_binding": <S5CutoverBinding oid or EMPTY>,
    "service_generation": <CutoverServiceGeneration oid or EMPTY>,
    "layout_seed": <32-byte canonical B-treap seed>,
    "capacity": {
        "control": <immutable workspace CapacityEnvelope>,
        "pending": <immutable workspace PendingCapacityEnvelope>,
        "content": <immutable workspace ContentCapacityEnvelope>,
    },
    "globals": <schema-bounded singleton/config rows>,
    "manifest": <fact manifest oid>,
    "suppressions": <suppression manifest oid>,
    "authorities": <canonical-provider manifest oid>,
    "legacy_universe": <frozen LegacyUniverseMap oid or EMPTY>,
    "legacy_entries": <frozen LegacyEntryMap oid or EMPTY>,
    "legacy_effect_census": <LegacyEffectCensus oid or EMPTY>,
    "legacy_iam": <LegacyIamAttestation oid or EMPTY>,
    "migration_seal": <LegacyMigrationSeal oid or EMPTY>,
    "stamp": <layout>,
})
root_oid = hash(root)
# after the canonical CAS and any AdmissionCommitProof:
local_cert["cert/" + root_oid] = certify(root_oid, <derivation version>)
```

At the S5 cut, the legacy `removals` slot is absent and no family may emit an
unbounded set into `globals`. The current per-member removal rows move wholly to
SuppTree; remaining inline rows, if any, must be schema-bounded
singleton/config values. S4 roots are deliberately not eligible for the bounded
Worker contract. They are accepted only by the fenced backfill procedure above;
ordinary S5 readers reject them.

`certify` is a deployment-held root-certification key/fence available to the
publishing Worker, not a claim that arbitrary passive-store bytes are trusted.
The certificate is local publication metadata outside canonical root identity:
independent peers with different certification keys still produce byte-identical
roots and ETags for the same fact set. Before certification, the publisher
derives the exact suppression slot states only from admissions whose receipt and
`AdmissionCommitProof` both verify under the root's `admission_pk`. It requires
the proof to name the exact receipt digest and a matching committed `admit/`
cell/admission-log row, requires that key to equal the locally trusted
anchor/keyring binding, and for an ordinary admission verifies the
`DirectCommitPair` correspondence plus the proof's `EMPTY` anchor field. It
does not fetch a superseded historical root to re-prove what the retained,
service-signed atomic pair already commits. It derives the exact authority rows
from the canonical
proof resolver, reconstructs/checks the `PrincipalProviderRegistry`,
`TargetRegistry`, `BaseOfferNeedKeyRegistry`,
`AuthorityBaseCandidateRegistry`, forward `AuthorityCandidateRegistry` and
reverse `AuthorityImpactRegistry` correspondences, and verifies every filled
base ref contains no full candidate id/rank, its derived scope union stays
within the per-base cap, and each directory NeedKey independently rederives the
exact full ids, ranks, co-offer states and reverse relationships. It verifies every filled
`ActionSlot` points to a content-hash-matching
`ActionRecord` within `MAX_ACTION_RECORD_BYTES`. It requires one exact
grow-only FactTree `ADMITTED` row for every ordinary fact admitted through S5
publication and every sealed legacy-universe row classified `ORDINARY`,
rejecting a deletion or replacement caused by quarantine. It rejects every
legacy `EFFECT_SOURCE`, `EFFECT_EVIDENCE` or `INERT_REMOVAL` FactSlot and every
new unreceipted removal FactSlot; their only legal reachability paths are the
frozen universe map or a commit-proven ActionRecord as specified above. For
each authority candidate it fetches the
content-hash-matching bounded `AuthorityProofRecord`, follows every exact
fact binding through its FactRecord/raw root, replays every ordinal edge, and
derives the recorded digest, transport depth/cost, logical depth and post-hash
candidate rank without a search. It verifies the exact
`AuthorityProofCommitProof` and never re-resolves that historical admission
against later AuthorityTree winners.
For every directly deletable `FactRecord` it also follows the complete
`OwnerBinding`, verifies its provider FactRecord, proof record, committed-proof
row and post-commit proof, verifies `ActorBindingProof` under `admission_pk`,
requires the signed target key/fid to match this FactRecord, and verifies the
selected evidence and service-attested complete actor verdict. It deliberately
does not fetch or retain the historical composite root: the root-excluded
statement plus its exact provider proof is the bounded certification preimage.
A legacy binding must additionally root a matching
`LegacyActorAdmissionRecord`, `CommittedLegacyActorAdmission`, filled
`LegacyActorAdmissionProofSlot` and valid
`LegacyActorAdmissionCommitProof` from the S4 first-publication transaction.
Certification compares every actor field, recorded provider ref and legacy
basis with the S5 statement; it never recomputes actor class from the cutover
winner set. A `DIRECT` transport must equal that recorded ref. A `CHECKPOINT`
transport may name a different new provider identity only after certification
replays the checkpoint's paged source proof and proves its source
fid/digest/NeedKey/candidate id correspond exactly to the recorded ref. The
signed `ActorBindingProof` authenticates both refs and the transport choice.
Absence of either side of that translation is a cutover failure, not permission
to overwrite the old record with a future checkpoint identity or infer a
convenient current owner.
A `DIRECT_MEMBER` binding must come from a direct-membership family and derive
`owner_principal == signing_key`; the same key's self-owned `device` provider
is auxiliary device-set evidence, not a competing owner kind. A native
`DEVICE` binding must come from a canonical target-key-authored
`DeviceOwnerConsent`, follow its exact invite/provider proof, carry the
matching `device(owner_principal, signing_key)` co-offer, and carry the signed
verdict that no admitted shape-valid direct-member claimant—masked or
live—existed at the serializing check. A legacy `DEVICE` binding may instead
use only its per-target `S4_DEVICE_INVITE_ACCEPTANCE` record, which verifies the
same exact invite/co-offer plus both the contextual acceptance and ordinary
target authorship signatures and grants no reusable post-S5 actor authority.
A later direct rejoin or provider rerank may change actor
resolution for new work but cannot invalidate or rewrite the retained proof.
Certification authenticates that owner; it never substitutes a later provider
winner, an unsigned invite or a caller-supplied principal.
For every `CONTENT_COMMIT` FactRecord it also verifies the generation-free
`RawFactContentCommit` id, exact `ContentCommitPin[ROOTED]` row and post-commit
proof, then walks the positional manifest to the declared bytes/fid. This is
off-request certification; Workers do not spend subrequests on raw display
content.
For a `LegacyAuthorityCheckpoint` it additionally fetches the exact named
paged legacy proof manifest and all binding/edge pages off request, verifies
their declared totals against retained capacity, replays the source closure and
requires the post-manifest source candidate id and both flattened scope sets to
match. It requires `LEGACY_SOURCE_RANK(checkpoint_fid)` and selects the
checkpoint with the recomputed source depth/fid/candidate-id tuple; the new
bounded proof is never substituted into canonical ordering. A bounded Worker
grant follows only the checkpoint's new ordinary `AuthorityProofRecord`.
It follows every bounded target
binding through its exact FactRecord/raw chunk root and replays selector/family
derivation, follows every `PrincipalProviderBinding` through its exact retained
FactRecord/raw chunk root and replays the provider family's typed scope even
when that provider is quarantined, then follows every bounded EvidenceRef through its
FactRecord/raw chunk root and replays the receipt proof,
and verifies the frozen `LegacyUniverseMap`, `LegacyEntryMap`,
`LegacyEffectCensus`, `LegacyIamAttestation` and `LegacyMigrationSeal`,
including that every
entry-map row names an authenticated universe row and the IAM object's
provider-signed evidence matches the pre-cut basis and final exact prefix.
For the first S5 root it also fetches the content-hash-matching
`CutoverServiceGeneration` and retained `CutoverPayloadManifest`, verifies both
manifest roots plus every binding/count/byte commitment, verifies the
`CutoverContentPinSet`, the matching
`CutoverContentPinGeneration[ROOTED]` row and rooted
`CutoverContentPinAnchor`, and requires the
strong service's one
`active_service_generation` cell to name that exact descriptor before any S5
registry or admission row is eligible. Every grandfather
`CutoverGeneration` row must be covered by that payload and have an
`AdmissionCommitProof` over the single matching `CutoverCommitAnchor`; the
anchor must name this root, descriptor, frontier and precharged certificate
reservation. A direct-root row, a root-named row inside the payload, or an
anchor from another generation fails certification.
Only then does it verify all three capped trees plus the componentwise
revocation liability against the same fact set and the authority's actual
admission-cell/log/registry occupancy. It also requires
the strong service's provisioned quotas and IAM boundaries to cover all three
immutable root-bound capacity envelopes. Signature-only receipts, including
service-signed candidates orphaned before the root CAS, are certification
errors.
`workspace.body.pk` is never accepted at this seam. An unreceipted removal
proposal in the S5 FactTree is a certification error, not merely a fact with no
row. Initial certification may require one full rebuild; subsequent
publications maintain and check the derived indexes incrementally. A root
received from a peer is not eligible for bounded authorization until the local
publisher has fully validated it and written its own `cert/<root_oid>` sidecar.
Missing/invalid certification fails closed and schedules that work; request
handling never silently rebuilds SQLite or treats it as a miss.

A certificate proves derivation/completeness for one root, not freshness, and a
pair of root oids does not provide a bounded subset proof. Each publisher
therefore owns one preallocated, strongly consistent
`served/<workspace>/<publisher_id>` cell and one preallocated
`witness/<workspace>/<publisher_id>` row outside canonical root identity. Off
the request path, its certifier performs the potentially unbounded tree
comparison and constructs a signed, fixed-size
`InclusionWitness(served_serial, from_root, to_root, from_frontier_digest,
to_frontier_digest)`. The service registers it by atomically overwriting that
publisher's witness row only after proving that the new root contains the old
root's complete fact/effect frontier. The served cell names the exact witness
generation it may consume, so a partially written or stale row cannot advance
the cell.

The request path makes one bounded `authorize_serve(to_root)` authority RPC. In
one operation the cell reads its current serial, verifies the registered witness
for exactly that current state, advances to `to_root`, and conditionally claims
one preallocated
`WorkerReadLease(publisher_id, lease_slot, lease_generation, root_oid,
certificate_oid, expires_at)` row. The returned freshness token is the signed
capability for that exact lease generation/root/certificate/expiry, not a bare
root observation. Equal-root retries are idempotent only for the same live lease
generation; another concurrent request consumes another fixed slot.

Every FactTree, SuppTree, AuthorityTree and immutable-page fetch for the request
must present that token to the root-bound read gateway. A request releases the
lease in `finally`; if a response hands a root-bound grant to a client, the lease
is retained through that grant's bounded read lifetime and the grant carries the
same root oid/etag. A crashed client cannot retain it forever:
`expires_at <= trusted_now + MAX_WORKER_READ_LEASE_MS`, the gateway rejects an
expired generation before any fetch, and only then may the service clear its
slot. Fencing the publisher invalidates every lease generation immediately and
in-flight reads fail closed. A missing free slot, witness, certificate, a raced
serial, or a valid but older root fails closed before tree reads and schedules
off-request recertification.

Root/certificate reclamation treats every unexpired, unfenced
`WorkerReadLease` as a live reference even after another request advances the
publisher's served cell. Request A may therefore finish reads from R while
request B advances the cell to R2; R cannot be reclaimed until A releases or its
token becomes unusable. The Worker never proves inclusion by walking trees.
This is publisher-local monotonic read-after-observation, not a claim of instant
global revocation: a partitioned publisher that has never observed an eviction
may remain stale, but one that has observed it cannot forget it.

Registration also atomically updates one fixed-size
`PublisherCapacityCell(workspace)` containing the registered count and aggregate
served-row, witness-row, read-lease and certificate reservations. Registration
precreates `MAX_WORKER_READ_LEASES_PER_PUBLISHER` fixed overwrite-only lease
rows, charges each at `MAX_WORKER_READ_LEASE_BYTES`, and reserves worst-case
distinct leased-root/certificate retention for those slots. Creating the
per-publisher rows/reservations and incrementing that cell is one strong
transaction; deregistration first fences the publisher, invalidates every lease
generation and releases every served/read-root lease. The cell is an
authenticated strong-service occupancy fact, not a self-reported root counter.
It permits an O(1) publication check even though the paged publisher registry
has no protocol population cap.

Writers first derive and hash all prospective fact, suppression and authority
objects without uploading. The admission/publication authority performs the
prospective-capacity check and durably claims the exact `PublicationAttempt`
scratch reservation. That attempt also claims one bounded next-root certificate
object, `MAX_CERT_BYTES`, and a certificate write lease for the publishing
deployment before any canonical CAS. In one fixed-size read it verifies the
`PublisherCapacityCell` aggregate still equals the capacity reserved by
registration. It constructs and reserves only the publishing deployment's
direct next-root witness; it never loops over publishers or writes their rows.
A missing aggregate reservation or an undersized publishing slot blocks
publication before the root can change. After those reservations, writers emit
only their manifested bytes through the generation-fenced gateway into fixed
scratch slots. The authority seals and drains every object and witness write
lease before performing the one strong canonical-root/frontier CAS described
above; that CAS charges the complete canonical manifest and preserves the
certificate and serving claims before authority-exclusive copies begin.
**Only after that CAS and copy verification** does the post-commit signer
re-read any `CommittedAdmission` row and emit its proof; the local certifier
then verifies the committed canonical cell, proof and complete cross-index
derivation before settling the claimed certificate at `cert/<root_oid>` and
registering its already-bounded witness overwrite. Every other publisher that
observes the new root fails closed, independently certifies it off-request,
constructs a direct witness from its own served root into its already-reserved
fixed slot, and only then advances its served cell. This work is distributed
across publishers and is never on the canonical CAS or request path. Ordinary
roots with no new admission follow the same ordering and must match a committed
canonical-root/frontier cell before certification.

A crash before the CAS leaves only a charged, bounded fixed-scratch attempt;
abort recovery generation-fences and drains its object, certificate and witness
writers before clearing any reservation. A crash after the CAS leaves a fully
charged committed root and a resumable
canonical copy that remains ineligible for serving until copy, proof and
certificate recovery finish. Any publisher that observes that canonical advance
fails closed rather than falling back to its prior served root; an old-root
reader remains possible only for a partitioned publisher that has not observed
the advance and whose served-root lease remains active, under the stale-publisher
rule above. The R2 `root`
mirror and any new `InclusionWitness` are updated idempotently only after the new
certificate exists, and the mirror is never sufficient by itself. Readers
therefore serve the old tuple, fail closed during recovery, or serve the fully
certified new tuple—never a half-indexed removal or stale authority winner. An
ordinary fact commit appends its immutable `ADMITTED` row permanently and can
reuse an unchanged suppression root. Staging a bare removal proposal changes no
canonical root. Admission fills its reserved FactTree `ActionSlot` and sets
every resolved SuppTree slot to the recomputed canonical `ACTIVE` witness in the
same CAS; an overlap may retain an existing winning value while both action
slots remain filled. Any provider-changing commit also changes AuthorityTree,
and a new membership/device provider covered by its typed-principal tombstone
changes SuppTree too. During shadow S4,
the authoritative legacy slot/globals remain in this same CAS. S5 removes them
only in the format bump that makes committed receipt issuance and the new lookup
path live. Canonical-provider quarantine changes derived eligibility and local
projection, never FactTree reachability. Admitted proposal/receipt pairs have
the additional ActionRecord evidence path and remain addressable for as long as
their `ACTIVE` suppression slot values do.

All three request-time trees use one **uniquely represented B-treap** codec, not
a conventional insertion-history-dependent B+tree. The construction is the
ordered external-memory B-treap described by
[Golovin, *B-Treaps: A Uniquely Represented Alternative to
B-Trees*](https://doi.org/10.1007/978-3-642-02927-1_41), with protocol-pinned
iterated weight-leader page partitioning. A row's priority is
`H(layout_seed, tree_domain, logical_key)` with ties broken by the full logical
key. Keys, fixed-width padded values, leader ranks, child order and page bytes
have one canonical encoding. Thus the logical key/value set plus the workspace
`layout_seed` determines exactly one page graph and root oid; insertion order,
batching, caches and publisher identity do not.

The algorithm's probabilistic performance theorem is not treated as a hard
deployment bound. A new-format anchor commits `layout_seed`; an existing
workspace's first S5 root commits the selected seed explicitly and every later
root must repeat it byte-for-byte. The fenced legacy migration first derives
`legacy_mask_namespace` from the fenced source and
constructs every migrated FactRecord and logical universe row without knowing a
layout seed or final cutover digest. It then tries candidate seeds derived from
`H("layout-seed", anchor, cutover_basis_digest, trial)` in increasing `trial`
order. For each candidate it builds `LegacyUniverseMap` from the already
committed logical-row digest, computes the resulting `cutover_digest`, derives
the remaining exact fixed-width migration values and then builds the complete
sealed FactTree, SuppTree, AuthorityTree and LegacyEntryMap. It pins the first
candidate whose complete sealed set plus every required empty
action/suppression slot satisfies all page/depth/update caps.
`legacy_mask_namespace` and `cutover_basis_digest` contain no B-treap root or
seed, while the final `cutover_digest` is computed only after that trial's
universe-map root, so this search is constructible rather than a fixed-point
equation. If no seed within
`MAX_LAYOUT_SEED_TRIALS` fits, the authority activates the writable S4 fallback
generation or re-anchors. Once S5 seals, the seed never changes: an ordinary
structural insertion whose actual
prospective B-treap mutation exceeds a cap rejects before publication rather
than triggering a global repack or seed rotation.

That rejection rule cannot be used for revocation. Admission of a suppressible
ordinary target therefore structurally inserts its `SuppSlot` and `ActionSlot`
while the target is still rejectable. AuthorityTree likewise retains every
admitted `NeedKey`, using `NO_PROVIDER` instead of structural deletion. A later
removal changes only fixed-width values at already present keys. Such an update
rewrites at most one existing page per level and never splits, rotates or
repartitions. This is the structural part of `RevocationLiability`: capacity is
not enough unless the future action's exact keys are already present.

S2 must vendor or implement this exact codec behind executable golden vectors:
the same set constructed in forward, reverse, randomized, one-by-one and bulk
orders has byte-identical pages/root; changing the priority, leader or padding
rule makes a named vector fail. Full-leaf/internal/root fixtures separately pin
the bounded ordinary-insert path. The old fact manifest's probabilistic
`shape.boundary` and arbitrarily large closure-packed leaf are not a Worker
membership bound, so S4 replaces a fact leaf with fixed-size ordinary and
reserved-slot rows.

`FactRecord(f)` is a bounded, certified derivation containing the fid/key, family
tag, normalized need/offer addresses, resolved suppression selectors and the
`raw_root_oid` of the immutable raw fact representation. It contains only
proof-relevant fields, never arbitrary display text or content bytes. The
unchanged canonical fact bytes are encoded behind that content-addressed root as
a deterministic fixed-size chunk tree when they do not fit one object;
reachability traversal from the FactRecord visits every chunk. Rebuilding this
physical layout changes neither the fact nor its fid. Existing unbounded message
text is therefore representable and does not block S4 publication. Blob bodies
remain separate.

For a directly deletable fact, that bounded record additionally contains its
one canonical `DeleteOffer` and complete immutable `OwnerBinding`. Composite
reachability follows the binding to the exact provider FactRecord/raw root,
`AuthorityProofRecord`, `CommittedAuthorityProof` row and
`AuthorityProofCommitProof`, plus the deterministic target-bound
`ActorBindingProof`. It does not point to or retain the prior composite root;
GC may collect that root and may not replace the retained proof arm with a
current authority lookup.
Those bytes and objects count against
`MAX_FACT_RECORD_BYTES`, content/control occupancy and the fact's
`AtomicCommitBudget`. For a newly authored target the referenced actor proof is
already committed and does not contain the target; the service signs the
statement over the already-known raw target fid before hashing the target
FactRecord, so this adds no self-hash cycle. The statement omits mutable
root/frontier/generation values; identical statements therefore produce
identical FactRecords across retries. If one submitted closure introduces both
an actor provider and a directly deletable child, the authority advances and
commit-proves the provider first, then evaluates the child against that next
certified frontier; it never writes a child binding to a merely prospective
provider proof.

At the S5 fence a legacy actor proof above the native bound is represented by
its sealed `LegacyAuthorityCheckpoint`; the migrated target and checkpoint are
built in the cutover generation's already-acyclic order. The target retains the
original `PAGED_S4(S4PagedAuthorityAdmissionRef)` from
`LegacyActorAdmissionRecord` as recorded provenance and separately binds the
checkpoint's deterministic committed-provider identity as its `CHECKPOINT`
transport. The checkpoint FactRecord roots the exact paged legacy source proof
that was already strongly committed before the target CAS; certification
replays both that S4 commit and the source-to-checkpoint translation, and the
post-activation checkpoint proof sidecar is required before certification.
The recorded paged ref and checkpoint transport ref are deliberately not
byte-equal and neither is substituted for the other. A within-native-bound
legacy actor instead retains `BOUNDED(AuthorityAdmissionRef)` and uses only the
byte-equal `DIRECT` transport. A legacy `DEVICE` binding
additionally requires either the device key's signed `DeviceOwnerConsent`, an
already immutable equivalent owner binding, or its non-reusable per-target
`S4_DEVICE_INVITE_ACCEPTANCE` record proving that the same key signed the
complete contextual tuple and separately authored the target. An invite or
ordinary target signature alone, without that contextual acceptance, is
insufficient. Every legacy binding also requires its admission-time
`LegacyActorAdmissionRecord`, committed row, filled proof slot and commit
proof; the cutover never reapplies direct-member precedence to the current set.
Missing, ambiguous or uncommitted ownership/consent evidence, or evidence
exceeding the signed legacy checkpoint/source and cutover ceilings, keeps the
workspace writable on S4.

Raw ordinary fact bytes do not have to fit the fixed metadata
`PublicationAttempt`. Before ordinary metadata publication, the same authority
uses the quota-isolated content gateway to execute:

```
RawFactChunkRef(ordinal, byte_start, byte_len, chunk_oid)
RawFactManifestChild(
    first_ordinal, last_ordinal, subtree_raw_bytes, child_oid)
RawFactManifestPage(
    LEAF(sorted RawFactChunkRef by ordinal)
      | INTERNAL(sorted RawFactManifestChild by first_ordinal))
RawFactContentCommit(
    workspace, fid, raw_root_oid, raw_manifest_root_oid,
    raw_bytes, raw_objects)
raw_fact_content_commit_id =
    H("raw-fact-content-commit", workspace, fid, raw_root_oid,
      raw_manifest_root_oid, raw_bytes, raw_objects)
RawFactContentCommitProof =
    sign(admission_sk, canon(["raw-fact-content-commit-v1",
                             raw_fact_content_commit_id,
                             RawFactContentCommit(...)]))
content_commit_pin_id =
    H("content-commit-pin", workspace, fid, raw_fact_content_commit_id)
ContentCommitPin =
    PENDING(pin_epoch, publication_attempt_id, attempt_generation)
  | ROOTED(committed_root_oid, frontier_serial)
  | ABORTED(pin_epoch, fenced_attempt_generation)
ContentCommitPinProof =
    sign(admission_sk, canon(["content-commit-pin-v1",
                             content_commit_pin_id,
                             ContentCommitPin(...)]))
```

The gateway streams canonical fact bytes into at-most-`MAX_FACT_CHUNK_BYTES`
objects and a deterministic paged Merkle manifest. Every manifest page has at
most `MAX_RAW_FACT_MANIFEST_PAGE_ENTRIES` entries and fits
`MAX_RAW_FACT_MANIFEST_PAGE_BYTES`; the tree may have as many charged pages as
that concrete fact and the workspace content quota require. Leaf entries carry
contiguous zero-based ordinals and byte ranges; internal entries carry
non-overlapping contiguous ordinal ranges. Certification rejects a gap,
overlap, reordered range, wrong byte count or child whose covered range differs.
Chunk oids are integrity fields, never sort keys: repeated chunks remain
separate positional entries, and walking ordinal order must reproduce the exact
canonical fact bytes. Their hash must equal `raw_root_oid`; the certifier then
decodes those bytes with the running fact codec, recomputes the body hash and
envelope fid, and requires that fid to equal the separately stored `fid`.
Hashing the complete raw JSON directly as the fid is invalid: the running
`Fact` identity is the hash of its canonical envelope, whose `bh` is the hash
of the canonical body.

Each upload/batch uses generation-fenced fixed content scratch, a durable write
lease and bounded requests. `attempt_generation` belongs only to this mutable
upload/pin state. It is not a field of `RawFactContentCommit` and does not enter
`raw_fact_content_commit_id`; retrying identical fact bytes in a later
generation therefore produces the same canonical commit, FactRecord and
composite root. Only after sealing the upload generation, definitively draining
every lease, hash-verifying every chunk/page, replaying positional order,
recomputing the raw byte count and `raw_root_oid`, decoding the canonical fact,
and recomputing its body hash and envelope fid does the strong content service
store the bounded commit row and sign its proof.

Before upload, one strong transaction claims the durable
`PublicationAttempt` and creates or idempotently matches its fixed
`ContentCommitPin[PENDING]` reservation for that exact attempt, generation and
precomputed canonical commit id. `pin_epoch` is a monotonic per-pin counter.
An absent pin starts at epoch one; an identical live retry may idempotently
match only the exact pending tuple. After an abort has generation-fenced and
definitively drained every writer from epoch `e`, a later retry may atomically
change `ABORTED(e, ...)` to `PENDING(e + 1, new_attempt, new_generation)`.
The new pending reservation is durable before any re-upload, and every gateway
write lease binds both epoch and generation, so a delayed old writer cannot
recreate content or win an ABA race. A rooted pin is terminal. Every
subsequently accepted content write is therefore already protected from
collection. After sealing, the authority
requires the commit row and proof to match that pin. The metadata manifest
carries the deterministic pin id and commit proof. The
root/frontier transaction refuses any other pin state and atomically changes
that pin to `ROOTED(committed_root_oid, frontier_serial)` with the FactTree/root
CAS. Its post-commit signer emits `ContentCommitPinProof`; off-request
certification verifies the rooted pin and complete ordered manifest before the
new root can be served.

GC may collect only an `ABORTED` pin. It may never collect a commit or any
chunk/page behind `PENDING` or `ROOTED`, merely because upload write leases are
drained. Recovery either finishes the exact pending publication or first fences
and drains its metadata/upload generations, proves that no root committed it,
atomically changes the pin to `ABORTED`, and only then releases the content
charge. A subsequent higher-epoch retry establishes `PENDING` before restoring
any collected object. Thus collection cannot race between content validation
and metadata publication, an aborted deterministic pin does not permanently
block retry, and a post-root/pre-proof crash remains recoverable.

The later metadata `FactRecord` contains the fixed commit id, raw root, manifest
root, byte/object counts, deterministic pin id and storage class
`CONTENT_COMMIT`. Its `PublicationAttempt` manifests that bounded record and
claim/commit proof reference, not the raw chunks or manifest pages. Off-request
certification follows the rooted pin, commit proof and complete paged content
manifest; a Worker uses the already-certified proof-relevant FactRecord fields
and never fetches arbitrary display content.
Bounded proposal/signature/support/receipt facts instead use
`CONTROL_EVIDENCE`: their raw bytes remain in the revocation-reserved metadata
bundle so content-quota exhaustion cannot strand a removal.

S4 preflight reserves isolated content/cutover capacity through the signed
source ceiling and may prepare reusable commits for the current corpus; it does
not claim that corpus is final. After the definitive old-writer drain freezes
the snapshot, the service reconciles that exact universe and seals one matching
content commit for every ordinary raw fact, including any write admitted before
the fence. A missing/changed object or short content/cutover dimension activates
the writable S4 fallback before an S5 root. The first S5 metadata manifest
also seals a paged `CutoverContentPinSet` under the inactive service generation.
Its sorted `CutoverContentPinEntry(fid, raw_fact_content_commit_id)` values name
every sealed content commit exactly once. One strong
`CutoverContentPinGeneration(workspace, service_generation_id,
cutover_content_pin_set_oid, state)` row is `STAGING`, `SEALED`,
`ROOTED(committed_root_oid, frontier_serial)`, or
`ABORTED(fenced_service_generation)`. GC protects every entry while the
generation is `STAGING`, `SEALED`, or `ROOTED`; only a fenced, definitively
drained `ABORTED` generation releases the set. The bounded final activation
atomically changes `SEALED` to `ROOTED` and writes one
`CutoverContentPinAnchor` with the first S5 root, so it does not rewrite one
strong row per legacy fact. Aborting first fences and drains the generation and
only then writes `ABORTED`; no extra cutover pin state is implicit and there is
no anchor to fence before activation.
The first S5 metadata manifest carries only the fixed commit references. Thus a large legacy or post-S5
ordinary fact is limited by explicit content capacity, not by the eight-row
metadata manifest, and cannot consume revocation escrow.
The `inline-raw-fact-chunks-overflow-publication-attempt` mutation puts every
chunk back into the metadata scratch manifest and fails once a legal paged fact
exceeds that fixed pool. The `sort-raw-manifest-by-chunk-oid`,
`content-generation-in-canonical-commit`, `hash-raw-bytes-as-fid`,
`aborted-content-pin-blocks-retry`,
`collect-sealed-content-before-metadata-cas` and
`collect-sealed-cutover-generation` mutations respectively lose byte order,
fork identical logical roots across retries, confuse raw identity with fact
identity, make a deterministic aborted pin terminal, leave a committed
FactRecord pointing at collected content, or collect a sealed cutover set, and
must all fail.

`FactTree[FactSlot(K(f))] = ADMITTED(fact_record_oid)` is monotonic for ordinary
durable facts in S5.
Suppression, canonical-provider shadowing and projection eligibility never
remove or rewrite that binding. Local projection may quarantine and later
restore a fact as the current finite proof DAG changes, but an authority proof
that received a `CommittedAuthorityProof` at admission remains immutable.
Later canonical winners do not become an undeclared revocation mechanism; only
its provider selectors and declared liveness scopes can mask it. Restore never
trusts a node-local copy or a collected historical root. Every ordinary admitted fact
continues to consume FactTree, FactRecord and raw-chunk occupancy. Committed
removal evidence remains separately charged and rooted by its ActionRecord;
sealed inert legacy removals remain charged and rooted only by
LegacyUniverseMap. This is the bounded
authenticated post-S5 quarantine path: each row/value and record is
individually capped, while the total archive is bounded by the workspace's
provisioned `CapacityEnvelope`.

The Worker reads only certified `FactRecord` objects. An `ADMITTED` FactTree hit
proves immutable admission and reachability, not authority by itself. The
Worker must also match the submitted bounded closure to the selected
commit-proven AuthorityTree candidate and require every policy-selected
suppression selector `CLEAR`; projection quarantine alone neither grants nor
withdraws that historical authority proof. S2 identifies every family
whose proof-relevant values can appear in a grant. S3 enforces record and
compositional proof caps for newly authored state; its migration preflight
surfaces legacy over-budget proof paths for S5 checkpointing instead of
discarding them before S4 can shadow-build. An old oversized *raw* fact is
chunked, not rejected. An oversized derived record is a format-contract failure
with its fid surfaced during the S3 preflight; the exhaustive family matrix must
make every currently valid family derive a bounded record before S4 can start.
Protocol constants are:

```
MAX_TREE_ROW_BYTES    = 1024
MAX_TREE_PAGE_ROWS    = 64
MAX_TREE_PAGE_BYTES   = 4 * 1024
MAX_TREE_DEPTH        = 8
FACT_TS_MIN           = 0
FACT_TS_MAX           = 999999999999999  # exactly 15 decimal digits at max
MAX_FACT_KEY_BYTES    = 80  # 15-digit ts + ":" + 64 lowercase hex fid
MAX_FACT_RECORD_BYTES = 32 * 1024
MAX_ACTOR_BINDING_PROOF_BYTES = 4 * 1024
MAX_ACTION_AUTHORIZATION_BYTES = 6 * 1024
MAX_LEGACY_ACTOR_ADMISSION_RECORD_BYTES = 8 * 1024
MAX_LEGACY_ACTOR_ADMISSION_COMMIT_ROW_BYTES = 8 * 1024
MAX_LEGACY_ACTOR_ADMISSION_PROOF_SLOT_BYTES = 512
MAX_LEGACY_ACTOR_ADMISSION_COMMIT_PROOF_BYTES = 4 * 1024
MAX_S4_AUTHORITY_PROOF_CAPACITY_ENVELOPE_BYTES = 4 * 1024
MAX_S4_ACTOR_ADMISSION_CAPACITY_ENVELOPE_BYTES = 4 * 1024
MAX_S4_AUTHORITY_PROOF_CAPACITY_CELL_BYTES = 4 * 1024
MAX_S4_ACTOR_ADMISSION_CAPACITY_CELL_BYTES = 4 * 1024
MAX_S4_AUTHORITY_PROOF_SCRATCH_SLOT_BYTES = 4 * 1024
MAX_S4_ACTOR_ADMISSION_SCRATCH_SLOT_BYTES = 4 * 1024
MAX_FACT_CHUNK_BYTES  = 32 * 1024
MAX_RAW_FACT_MANIFEST_PAGE_ENTRIES = 64
MAX_RAW_FACT_MANIFEST_PAGE_BYTES = 64 * 1024
MAX_RAW_FACT_CONTENT_COMMIT_BYTES = 4 * 1024
MAX_RAW_FACT_CONTENT_COMMIT_PROOF_BYTES = 4 * 1024
MAX_CONTENT_COMMIT_PIN_BYTES = 8 * 1024
MAX_CONTENT_COMMIT_PIN_PROOF_BYTES = 8 * 1024
MAX_RAW_FACT_CONTENT_BATCH_OBJECTS = 64
MAX_RAW_FACT_CONTENT_BATCH_BYTES = 2 * 1024 * 1024
MAX_AUTHORITY_PROOF_FACTS = 64
MAX_AUTHORITY_PROOF_EDGES = 128
MAX_AUTHORITY_PROOF_RECORD_BYTES = 64 * 1024
MAX_LOGICAL_PROOF_DEPTH = 2**63 - 1
MAX_AUTHORITY_PROOF_COMMIT_ROW_BYTES = 4 * 1024
MAX_AUTHORITY_PROOF_COMMIT_PROOF_BYTES = 4 * 1024
MAX_LEGACY_AUTHORITY_PROOF_PAGE_FACTS = 64
MAX_LEGACY_AUTHORITY_PROOF_PAGE_EDGES = 128
MAX_LEGACY_AUTHORITY_PROOF_PAGE_BYTES = 64 * 1024
MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_ROW_BYTES = 4 * 1024
MAX_S4_PAGED_AUTHORITY_PROOF_SLOT_BYTES = 512
MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_PROOF_BYTES = 4 * 1024
MAX_ACTION_RECORD_BYTES = 16 * 1024
MAX_ADMISSION_PROOF_BYTES = 56 * 1024
MAX_PENDING_BUNDLE_FRAMING_BYTES = 8 * 1024
MAX_PENDING_BUNDLE_BYTES = 64 * 1024
MAX_REVOCATION_RECORD_RAW_BYTES = 32 * 1024
MAX_ADMIT_CELL_BYTES = 32 * 1024
MAX_ADMISSION_LOG_ROW_BYTES = 8 * 1024
MAX_PUBLICATION_ATTEMPT_CELL_BYTES = 8 * 1024
MAX_TARGET_REGISTRY_ROW_BYTES = 512
MAX_REGISTRY_VALUE_POINTER_BYTES = 256
MAX_PRINCIPAL_PROVIDER_REGISTRY_VALUE_BYTES = 32 * 1024
MAX_BASE_OFFER_NEED_KEY_REGISTRY_VALUE_BYTES = 32 * 1024
MAX_AUTHORITY_CANDIDATE_REGISTRY_VALUE_BYTES = 512 * 1024
MAX_AUTHORITY_IMPACT_REGISTRY_VALUE_BYTES = 32 * 1024
MAX_REQUIRED_COOFFERS_PER_NEED = 4
MAX_NEED_KEY_BYTES = 320
MAX_AUTHORITY_TREE_VALUE_BYTES = 320
MAX_TREE_ROW_FRAMING_BYTES = 64
MAX_PROVIDER_OFFERS_PER_CANDIDATE = 16
MAX_PROVIDER_OFFER_SUMMARY_BYTES = 4 * 1024
MAX_FULL_NEED_KEYS_PER_BASE = 64
MAX_PROVIDER_BASES_PER_PUBLICATION = 8
MAX_ORDINARY_NEED_KEYS_PER_PUBLICATION = 8
MAX_BASE_OFFER_NEED_KEY_VALUES_PER_PUBLICATION = 16
MAX_AUTHORITY_BASE_CANDIDATE_VALUES_PER_PUBLICATION = 8
MAX_PROVIDER_AUTHORITY_CANDIDATE_VALUES_PER_PUBLICATION = 64
MAX_AUTHORITY_CANDIDATE_VALUES_PER_PUBLICATION = 72
MAX_AUTHORITY_IMPACT_VALUES_PER_PUBLICATION = 64
MAX_PRINCIPAL_PROVIDER_VALUES_PER_PUBLICATION = 2
MAX_PUBLICATION_REGISTRY_VALUE_OBJECTS = 162
MAX_PUBLICATION_REGISTRY_VALUE_BYTES = 44_630_016
MAX_PUBLICATION_FIXED_SERVICE_ROWS = 31
MAX_PUBLICATION_FIXED_SERVICE_BYTES = 168 * 1024
MAX_PUBLICATION_SERVICE_TRANSACTION_ROWS = 193
MAX_PUBLICATION_SERVICE_TRANSACTION_BYTES = 512 * 1024
MAX_PUBLICATION_ATTEMPT_MANIFEST_ROWS = 8
MAX_PUBLICATION_ATTEMPT_MANIFEST_BYTES = 256 * 1024
MAX_LEGACY_MIGRATION_SEAL_BYTES = 4 * 1024
MAX_LEGACY_IAM_ATTESTATION_BYTES = 32 * 1024
MAX_MIGRATION_BOOTSTRAP_BYTES = 8 * 1024
MAX_S5_CUTOVER_BINDING_BYTES = 8 * 1024
MAX_CAPACITY_CEILING_BYTES = 8 * 1024
MAX_LEGACY_SOURCE_CEILING_BYTES = 4 * 1024
MAX_CUTOVER_SERVICE_GENERATION_BYTES = 8 * 1024
MAX_CUTOVER_COMMIT_ANCHOR_BYTES = 8 * 1024
MAX_CUTOVER_CONTENT_PIN_GENERATION_BYTES = 8 * 1024
MAX_CUTOVER_CONTENT_PIN_ANCHOR_BYTES = 8 * 1024
MAX_CUTOVER_SERVICE_BATCH_ROWS = 128
MAX_CUTOVER_SERVICE_BATCH_BYTES = 1 * 1024 * 1024
MAX_CUTOVER_ACTIVATION_ROWS = 8
MAX_CUTOVER_ACTIVATION_BYTES = 128 * 1024
MAX_ROOT_BYTES        = 64 * 1024
MAX_FRONTIER_CELL_BYTES = 8 * 1024
MAX_ACTIVE_SERVICE_GENERATION_CELL_BYTES = 8 * 1024
MAX_WORKER_FACTS      = 64
MAX_WORKER_NEEDS      = 64
MAX_WORKER_SELECTORS  = 32
MAX_SUPPRESSION_LOOKUPS = 32  # subset of MAX_POINT_LOOKUPS
MAX_EXACT_SIDS_PER_REMOVAL = 32
MAX_MEMBERSHIP_PROVIDERS_PER_PRINCIPAL = 64
MAX_DEVICE_PROVIDERS_PER_PRINCIPAL = 64
MAX_PRINCIPAL_SCOPES_PER_FACT = 2
MAX_EFFECT_TARGETS_PER_REMOVAL = 64
MAX_ACTION_IMPACT_SCOPES = 65  # terminal principal scope + 64 provider Sids
MAX_ADMISSION_PROOF_REFS = 7
MAX_ACTION_EVIDENCE_REFS = 8
MAX_REVOCATION_BASE_RECORDS = 13
MAX_REVOCATION_BASE_TREE_PATHS = 1
MAX_AUTHORITY_CONSEQUENCES_PER_ACTION = 64
MAX_AUTHORITY_CANDIDATES_PER_NEED = 64
MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION = 4096  # 64 consequences * 64 candidates
MAX_AUTHORITY_IMPACT_SCOPES_PER_PUBLICATION = 64
MAX_AUTHORITY_IMPACT_SCOPES_PER_BASE = 64
MAX_LAYOUT_SEED_TRIALS = 1024
MAX_ORDINARY_TREE_INSERTS = 13
MAX_TREE_PAGES_PER_INSERT = 17  # 2 * MAX_TREE_DEPTH + 1
MAX_ORDINARY_CHANGED_PAGE_OBJECTS = 221  # 13 inserts * 17 pages
MAX_TREE_PAGES_PER_VALUE_UPDATE = 8  # MAX_TREE_DEPTH; no split
MAX_CHANGED_TREE_PATHS = 129
MAX_CHANGED_PAGE_OBJECTS = 1032  # 129 fixed-key updates * 8 pages
MAX_POINT_LOOKUPS     = 100  # exact routed paths
MAX_R2_SUBREQUESTS    = 900
MAX_CERT_BYTES        = 4 * 1024
MAX_SERVED_CELL_BYTES = 4 * 1024
MAX_INCLUSION_WITNESS_BYTES = 4 * 1024
MAX_PUBLISHER_CAPACITY_CELL_BYTES = 4 * 1024
MAX_SERVED_RPC_BYTES  = 4 * 1024
MAX_SERVED_SUBREQUESTS = 1
MAX_WORKER_READ_LEASES_PER_PUBLISHER = 64
MAX_WORKER_READ_LEASE_BYTES = 4 * 1024
MAX_WORKER_READ_LEASE_MS = 60 * 1000
MAX_LOOKUP_FETCH      = 8 * 1024 * 1024
```

The aggregate registry maxima are derived rather than aspirational:

```
MAX_PUBLICATION_REGISTRY_VALUE_OBJECTS
  = 16 NeedKey directories + 8 base-candidate values
    + 72 full-candidate values + 64 impact values
    + 2 principal-provider values
  = 162
MAX_PUBLICATION_REGISTRY_VALUE_BYTES
  = (8 + 72) * 512 KiB + (16 + 64 + 2) * 32 KiB
  = 44,630,016
MAX_PUBLICATION_FIXED_SERVICE_ROWS
  + MAX_PUBLICATION_REGISTRY_VALUE_OBJECTS
  = MAX_PUBLICATION_SERVICE_TRANSACTION_ROWS
MAX_PUBLICATION_FIXED_SERVICE_BYTES
  + MAX_PUBLICATION_REGISTRY_VALUE_OBJECTS
      * MAX_REGISTRY_VALUE_POINTER_BYTES
  = 213,504 < MAX_PUBLICATION_SERVICE_TRANSACTION_BYTES
MAX_NEED_KEY_BYTES + MAX_AUTHORITY_TREE_VALUE_BYTES
  + MAX_TREE_ROW_FRAMING_BYTES
  = 704 <= MAX_TREE_ROW_BYTES
64 * (MAX_NEED_KEY_BYTES + 1) + 2
  = 20,546 <= MAX_AUTHORITY_IMPACT_REGISTRY_VALUE_BYTES
```

The fixed service allowance covers the root, frontier, attempt state, occupancy
charge, admission cell/log row, optional target row, one content-pin transition
and transaction framing at their declared maxima; certification measures the
actual canonical encoding as well as checking this conservative allowance.
Registry **objects** consume the separate
162-object/44,630,016-byte scratch and canonical capacity, but the atomic
transaction writes only their 256-byte pointers. The attempt claim also
rejects unless its complete paged manifest fits both
`MAX_PUBLICATION_ATTEMPT_MANIFEST_ROWS` and
`MAX_PUBLICATION_ATTEMPT_MANIFEST_BYTES`. A backend must attest support for the
publication row/byte caps at bootstrap; otherwise the workspace cannot enter
S5.

Every admitted fact address is exactly
`f"{ts:015d}:{fid}"`: `ts` is an integer but not a boolean and lies in the
closed interval `FACT_TS_MIN..FACT_TS_MAX`, while `fid` is exactly 64 lowercase
hex characters. The wire/index door requires the canonical
`[0-9]{15}:[0-9a-f]{64}` round trip, so every fact key and every
`EvidenceRef.fact_key`/`TargetBinding.target_fact_key` is exactly
`MAX_FACT_KEY_BYTES = 80` bytes. Negative, 16-digit positive, signed,
whitespace-padded and ambiguous-colon forms reject before fact/index admission.
The maximum-`ExactSids` ActionRecord calculation and fixture use this longest
legal key; the generic `MAX_TREE_ROW_BYTES` cap is not substituted for it.
Migration preflight reports every sealed legacy fact whose timestamp/key cannot
round-trip through this exact S5 grammar. It never drops or rekeys that fact:
any such row aborts the S5 attempt into the writable service-only S4 fallback,
or the operator explicitly re-anchors. Existing 16-digit-positive facts are the
named regression even though S1 prevents creating another one.

`MAX_ROOT_BYTES` is an S5 eligibility rule. A shadow S4 root may still exceed
it because the retained legacy removal metadata is unbounded; that is precisely
why S4 cannot serve the bounded Worker path.

Every leaf **and internal route page** follows the canonical weight-leader
partition and refuses either page maximum. An individually oversized tree row
or Worker-visible record rejects at admission; an oversized raw fact uses its
chunk tree. Publication refuses a tree deeper than the protocol limit, an
ordinary insertion touching more than `MAX_TREE_PAGES_PER_INSERT`, or an
ordinary fact requiring more than `MAX_ORDINARY_TREE_INSERTS`. These checks run
on prospective bytes inside the serialized publication operation. Revocation
tests additionally assert that every action mutation is a fixed-key value
update; encountering an absent reserved key is a certification failure, never
permission to fall back to structural insertion.

Capacity includes a security escrow, not merely current occupancy. Every
new-format workspace pins one immutable, canonical `CapacityEnvelope` at
bootstrap. An existing workspace's pre-fence `MigrationBootstrapCommitment`
pins a componentwise ceiling; only the post-snapshot `S5CutoverBinding` pins the
exact envelope, which may not exceed that ceiling:

```
S4AuthorityProofCapacityEnvelope(
    s4_authority_proof_scratch_slots,
    s4_authority_proof_scratch_slot_bytes,
    s4_authority_proof_scratch_objects,
    s4_authority_proof_scratch_bytes,
    s4_authority_proof_scratch_write_leases,
    authority_proof_record_objects, authority_proof_record_bytes,
    authority_proof_commit_rows, authority_proof_commit_bytes,
    authority_proof_commit_proof_objects,
    authority_proof_commit_proof_bytes,
    authority_proof_commit_proof_write_leases,
    s4_paged_authority_proof_manifest_objects,
    s4_paged_authority_proof_manifest_bytes,
    s4_paged_authority_proof_page_objects,
    s4_paged_authority_proof_page_bytes,
    s4_paged_authority_proof_commit_rows,
    s4_paged_authority_proof_commit_bytes,
    s4_paged_authority_proof_slot_rows,
    s4_paged_authority_proof_slot_bytes,
    s4_paged_authority_proof_commit_proof_objects,
    s4_paged_authority_proof_commit_proof_bytes,
    s4_paged_authority_proof_commit_proof_write_leases,
)
s4_authority_proof_capacity_envelope_oid =
    H("s4-authority-proof-capacity-envelope",
      canon(S4AuthorityProofCapacityEnvelope(...)))
s4_authority_proof_capacity_cell_id =
    H("s4-authority-proof-capacity-cell", workspace)
S4AuthorityProofCapacityCell[s4_authority_proof_capacity_cell_id] =
    canon(workspace, s4_authority_proof_capacity_envelope_oid,
          remaining_canonical_authority_proof_capacity)
S4AuthorityProofScratchSlot(
    workspace, s4_generation, scratch_slot,
    FREE
      | OPEN(attempt_id, reserved_objects, reserved_bytes, write_lease)
      | SEALED(attempt_id, manifest_oid, object_count, canonical_bytes,
               write_lease)
      | COMMITTED_COPYING(attempt_id, authority_commit_id, write_lease)
      | ABORTING(attempt_id, write_lease))
S4ActorAdmissionCapacityEnvelope(
    legacy_actor_admission_scratch_slots,
    legacy_actor_admission_scratch_slot_bytes,
    legacy_actor_admission_scratch_record_objects,
    legacy_actor_admission_scratch_record_bytes,
    legacy_actor_admission_scratch_write_leases,
    legacy_actor_admission_record_objects,
    legacy_actor_admission_record_bytes,
    legacy_actor_admission_commit_rows,
    legacy_actor_admission_commit_bytes,
    legacy_actor_admission_proof_slot_rows,
    legacy_actor_admission_proof_slot_bytes,
    legacy_actor_admission_commit_proof_objects,
    legacy_actor_admission_commit_proof_bytes,
    legacy_actor_admission_commit_proof_write_leases,
)
s4_actor_admission_capacity_envelope_oid =
    H("s4-actor-admission-capacity-envelope",
      canon(S4ActorAdmissionCapacityEnvelope(...)))
s4_actor_admission_capacity_cell_id =
    H("s4-actor-admission-capacity-cell", workspace)
S4ActorAdmissionCapacityCell[s4_actor_admission_capacity_cell_id] =
    canon(workspace, s4_actor_admission_capacity_envelope_oid,
          remaining_canonical_actor_admission_capacity)
S4ActorAdmissionScratchSlot(
    workspace, s4_generation, scratch_slot,
    FREE
      | OPEN(attempt_id, reserved_record_bytes, write_lease)
      | SEALED(attempt_id, legacy_actor_admission_record_oid,
               canonical_bytes, write_lease)
      | COMMITTED_COPYING(attempt_id, legacy_actor_admission_commit_id,
                          write_lease)
      | ABORTING(attempt_id, write_lease))
CapacityEnvelope(
    fact_tree_rows, fact_tree_bytes,
    supp_tree_rows, supp_tree_bytes,
    authority_tree_rows, authority_tree_bytes,
    s4_authority_proof_capacity_envelope_objects,
    s4_authority_proof_capacity_envelope_bytes,
    s4_authority_proof_capacity_cell_rows,
    s4_authority_proof_capacity_cell_bytes,
    s4_actor_admission_capacity_envelope_objects,
    s4_actor_admission_capacity_envelope_bytes,
    s4_actor_admission_capacity_cell_rows,
    s4_actor_admission_capacity_cell_bytes,
    fact_record_objects, fact_record_bytes,
    raw_fact_chunk_objects, raw_fact_chunk_bytes,
    authority_proof_record_objects, authority_proof_record_bytes,
    authority_proof_commit_rows, authority_proof_commit_bytes,
    authority_proof_commit_proof_objects,
    authority_proof_commit_proof_bytes,
    legacy_authority_proof_objects, legacy_authority_proof_bytes,
    s4_paged_authority_proof_commit_rows,
    s4_paged_authority_proof_commit_bytes,
    s4_paged_authority_proof_slot_rows,
    s4_paged_authority_proof_slot_bytes,
    s4_paged_authority_proof_commit_proof_objects,
    s4_paged_authority_proof_commit_proof_bytes,
    legacy_actor_admission_record_objects,
    legacy_actor_admission_record_bytes,
    legacy_actor_admission_commit_rows,
    legacy_actor_admission_commit_bytes,
    legacy_actor_admission_proof_slot_rows,
    legacy_actor_admission_proof_slot_bytes,
    legacy_actor_admission_commit_proof_objects,
    legacy_actor_admission_commit_proof_bytes,
    action_record_objects, action_record_bytes,
    legacy_universe_map_objects, legacy_universe_map_bytes,
    legacy_entry_map_objects, legacy_entry_map_bytes,
    legacy_effect_census_objects, legacy_effect_census_bytes,
    legacy_iam_attestation_objects, legacy_iam_attestation_bytes,
    legacy_migration_seal_objects, legacy_migration_seal_bytes,
    migration_bootstrap_objects, migration_bootstrap_bytes,
    s5_cutover_binding_objects, s5_cutover_binding_bytes,
    capacity_ceiling_objects, capacity_ceiling_bytes,
    legacy_source_ceiling_objects, legacy_source_ceiling_bytes,
    reconciled_s4_root_objects, reconciled_s4_root_bytes,
    cutover_service_generation_objects, cutover_service_generation_bytes,
    cutover_payload_manifest_objects, cutover_payload_manifest_bytes,
    cutover_commit_anchor_cells, cutover_commit_anchor_bytes,
    cutover_content_pin_set_objects, cutover_content_pin_set_bytes,
    cutover_content_pin_generation_rows,
    cutover_content_pin_generation_bytes,
    cutover_content_pin_anchor_cells, cutover_content_pin_anchor_bytes,
    canonical_root_cells, canonical_root_bytes,
    frontier_cells, frontier_bytes,
    active_service_generation_cells, active_service_generation_bytes,
    admit_cells, admit_cell_bytes,
    admission_log_rows, admission_log_bytes,
    target_registry_rows, target_registry_bytes,
    principal_provider_registry_rows, principal_provider_registry_bytes,
    principal_provider_registry_value_objects,
    principal_provider_registry_value_bytes,
    base_offer_need_key_registry_rows, base_offer_need_key_registry_bytes,
    base_offer_need_key_registry_value_objects,
    base_offer_need_key_registry_value_bytes,
    authority_base_candidate_registry_rows,
    authority_base_candidate_registry_bytes,
    authority_base_candidate_registry_value_objects,
    authority_base_candidate_registry_value_bytes,
    authority_candidate_registry_rows, authority_candidate_registry_bytes,
    authority_candidate_registry_value_objects,
    authority_candidate_registry_value_bytes,
    authority_impact_registry_rows, authority_impact_registry_bytes,
    authority_impact_registry_value_objects,
    authority_impact_registry_value_bytes,
    retained_root_slots, retained_object_bytes,
    publisher_capacity_cells, publisher_capacity_bytes,
    served_cell_rows, served_cell_bytes,
    inclusion_witness_rows, inclusion_witness_bytes,
    worker_read_lease_rows, worker_read_lease_bytes,
    certificate_objects, certificate_bytes, certificate_write_leases,
    publication_attempt_manifest_rows, publication_attempt_manifest_bytes,
    publication_attempt_objects, publication_attempt_bytes,
    publication_attempt_write_leases,
)
```

The first existing-workspace cut additionally uses:

```
CapacityCeiling(
    # Exactly the same ordered dimensions and integer domains as
    # CapacityEnvelope, interpreted as componentwise maxima.
    ...
)
LegacySourceCeiling(
    published_objects, published_bytes,
    registered_quarantine_objects, registered_quarantine_bytes,
    unsettled_old_write_objects, unsettled_old_write_bytes,
)
CutoverCapacityEnvelope(
    cutover_manifest_rows, cutover_manifest_bytes,
    cutover_staging_objects, cutover_staging_bytes,
    cutover_staging_write_leases,
    cutover_legacy_actor_admission_objects,
    cutover_legacy_actor_admission_bytes,
    cutover_legacy_actor_admission_service_rows,
    cutover_legacy_actor_admission_service_bytes,
    cutover_content_manifest_objects, cutover_content_manifest_bytes,
    cutover_content_staging_objects, cutover_content_staging_bytes,
    cutover_content_staging_write_leases,
    cutover_content_pin_set_objects, cutover_content_pin_set_bytes,
    cutover_content_pin_generation_rows,
    cutover_content_pin_generation_bytes,
    cutover_content_pin_anchor_rows, cutover_content_pin_anchor_bytes,
    cutover_service_staging_rows, cutover_service_staging_bytes,
)
```

These are workspace-specific finite bounds, not request-size constants.
The two `S4*CapacityCell` rows are workspace-global, durable and monotonic;
`s4_generation` is deliberately absent from their keys. Each is initialized
exactly once from the content-addressed envelope named in the cell before its
shadow recorder is enabled. Its remaining vector contains only canonical
dimensions. Canonical records, commit rows, proof slots and proof objects from
every S4 generation debit that one vector and are never refunded merely because
a migration attempt aborts or a new fallback generation becomes writable.
Existing canonical objects from predecessor generations therefore remain both
reachable and charged. The exact envelope preimages are retained beside the
cells, hash-checked by their oids, and capped respectively by
`MAX_S4_AUTHORITY_PROOF_CAPACITY_ENVELOPE_BYTES` and
`MAX_S4_ACTOR_ADMISSION_CAPACITY_ENVELOPE_BYTES`. The first S5 root and cutover
object manifest carry them forward, and the matching eight `CapacityEnvelope`
dimensions charge those two retained objects/bytes plus the two strong
capacity-cell rows/bytes. The cells reject above
`MAX_S4_AUTHORITY_PROOF_CAPACITY_CELL_BYTES` and
`MAX_S4_ACTOR_ADMISSION_CAPACITY_CELL_BYTES`; a bare oid, collected preimage or
unbudgeted cell cannot certify a balance.

Scratch slots remain generation-fenced but reuse one separately precharged
physical pool. A post-fence abort first rejects new predecessor writes, settles
every ambiguous CAS, finishes or aborts each `COMMITTED_COPYING` operation, and
definitively drains every scratch write lease. One strong fallback-activation
transaction then makes the predecessor scratch rows inert, rebinds the same
physical slots as `FREE` rows for the already attested successor generation,
and proves the workspace-global canonical capacity-cell ids and balances are
byte-identical before and after activation. The per-attempt
`MigrationBootstrapCommitment` binds those stable cell identities and immutable
envelope oids; it cannot provision a fresh canonical vector. A retry may reset
only the drained scratch state. Failure to drain, rebind, or preserve either
canonical balance leaves the workspace fail-closed/read-only or requires
explicit re-anchor; it never activates a refill.

`S4AuthorityProofCapacityEnvelope` is physically provisioned before either
first-publication or on-demand authority recording is enabled. Before accepting
any proof bytes, the service atomically claims one fixed
`S4AuthorityProofScratchSlot` whose precharged object/byte maximum can hold the
complete permitted bounded record or one permitted paged manifest and all its
pages; each strong slot row also fits
`MAX_S4_AUTHORITY_PROOF_SCRATCH_SLOT_BYTES`, and every scratch upload holds the
slot's write lease. After seal, the strong
proof commit validates the exact manifest/hash/counts and atomically debits the
applicable disjoint canonical bounded or paged dimensions in
`S4AuthorityProofCapacityCell`, creates its commit row and, for paged evidence,
its `RESERVED` proof slot, and moves the scratch slot to `COMMITTED_COPYING`.
Scratch and canonical allowances coexist
until every content-addressed copy verifies and the lease definitively drains.
An idempotent canonical match consumes nothing new. A losing proof CAS debits no
canonical dimension but moves its scratch slot through `ABORTING`; the slot is
not reusable until fencing and definitive lease drain. The post-commit signer
consumes the already reserved proof object/byte/lease allowance. A bounded
`AuthorityProofRecord` receives the ordinary commit/proof pair. An over-budget
but checkpointable actor closure receives a `LegacyAuthorityProofRecord`,
`CommittedS4PagedAuthorityProof` and
`S4PagedAuthorityProofCommitProof` before any target may cite it. A proof
committed solely to support a later actor record remains canonical if that
target loses its CAS, because it is itself a valid admission of that exact
provider closure rather than target scratch. Canonical
`authority_proof_*` or `legacy_authority_proof_*` plus
`s4_paged_authority_proof_commit_*` dimensions retain it after S5, while the
whole-cutover object/service staging totals fund its disjoint copy. Every
`CommittedS4PagedAuthorityProof` row fits
`MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_ROW_BYTES`; its strong proof slot fits
`MAX_S4_PAGED_AUTHORITY_PROOF_SLOT_BYTES`. The retained proof is addressed by
the proof oid carried in `S4PagedAuthorityAdmissionRef`, matched by that slot,
and fits
`MAX_S4_PAGED_AUTHORITY_PROOF_COMMIT_PROOF_BYTES`.

`S4ActorAdmissionCapacityEnvelope` is physically provisioned before the shadow
recorder is enabled. Its fixed scratch-slot object/byte/lease dimensions are
physically precharged separately from the canonical remaining vector held in
the strong `S4ActorAdmissionCapacityCell`. Before record upload the service
claims one `S4ActorAdmissionScratchSlot`, whose write gateway accepts only the
matching live generation/attempt and at most
`MAX_LEGACY_ACTOR_ADMISSION_RECORD_BYTES`; the slot row itself fits
`MAX_S4_ACTOR_ADMISSION_SCRATCH_SLOT_BYTES`. Each successful eligible-target CAS
verifies that sealed scratch record and atomically charges one canonical record
no larger than
`MAX_LEGACY_ACTOR_ADMISSION_RECORD_BYTES`, one commit row no larger than
`MAX_LEGACY_ACTOR_ADMISSION_COMMIT_ROW_BYTES`, one fixed proof slot no larger
than `MAX_LEGACY_ACTOR_ADMISSION_PROOF_SLOT_BYTES`, and one proof object plus
write lease for at most
`MAX_LEGACY_ACTOR_ADMISSION_COMMIT_PROOF_BYTES`. The proof allocation and lease
are reserved in the same transaction before the new target becomes visible,
even though its deterministic signature is written afterward. The winning CAS
also changes the scratch slot to `COMMITTED_COPYING`; because its capacity was
already charged separately, scratch and the canonical record can coexist until
the canonical hash/size is verified. A failed CAS leaves the canonical capacity
cell unchanged and moves only its scratch slot to `ABORTING`; a
generation-fenced scratch record is reclaimed only after every write lease
drains. Exhausting a scratch or canonical dimension omits the shadow record and
makes S5 ineligible without rejecting the still-valid legacy target or changing
the old authority path.

The canonical legacy-actor dimensions retain the complete record/commit/slot/
proof closure after S5. The explicitly named cutover dimensions fund a
simultaneous inactive-generation copy; they are also included in the aggregate
staging totals rather than borrowed from content or ordinary publication
capacity. Thus the migration sizer charges the worst case once per potentially
deletable target admitted after recorder activation and never assumes that
proof objects will deduplicate.

`CapacityCeiling` has exactly the canonical field order, names and nonnegative
integer domains of `CapacityEnvelope`; its retained encoding rejects above
`MAX_CAPACITY_CEILING_BYTES`. A componentwise proof therefore decodes two
vectors of the same schema. `LegacySourceCeiling` is a retained canonical object
of at most `MAX_LEGACY_SOURCE_CEILING_BYTES`, provider-authenticated through the
bootstrap commitment before the old-writer fence, and covers the complete set
that can still enter the frozen snapshot; every outstanding legacy write
consumes one fixed object/byte lease within it. Where the old backend cannot
prove per-writer bounds, the ceiling is the entire remaining provider quota for
the frozen prefix. `CutoverCapacityEnvelope` is physically provisioned at the
same time and must hold the complete
`CutoverObjectManifest`, every prospective first-root object at once, and all
their write leases plus the complete generation-scoped service-row staging set
while the separate final canonical occupancy is also reserved.
The content dimensions separately cover every pre-fence `RawFactContentCommit`
chunk/page upload, pending pin and lease in the isolated content namespace;
control staging cannot borrow them and the first-root metadata manifest
contains only their fixed commit references. The inactive generation stages a
paged `CutoverContentPinSet` and one strong
`CutoverContentPinGeneration`; the bounded activation changes that generation
from `SEALED` to `ROOTED` and roots its one `CutoverContentPinAnchor`, not every
member pin. The canonical envelope retains the set objects, generation row and
anchor cell independently, while the cutover envelope funds their simultaneous
staged copy and activation. Every staging
transaction obeys `MAX_CUTOVER_SERVICE_BATCH_ROWS` and
`MAX_CUTOVER_SERVICE_BATCH_BYTES`; the final pointer/root/frontier transaction
also writes exactly one `CutoverCommitAnchor` and obeys
`MAX_CUTOVER_ACTIVATION_ROWS` and
`MAX_CUTOVER_ACTIVATION_BYTES`. Failure to reserve either envelope or prove
either per-operation bound leaves S4 writable and prevents the credential
fence.

The existing-workspace envelope charges exactly one logical retained
`reconciled_s4_root` preimage, its canonical storage chunks and its actual
bytes. Those finite dimensions are fixed by the pre-fence
`CapacityCeiling`/`LegacySourceCeiling`; `MAX_ROOT_BYTES` is an S5 request-path
root limit and is not incorrectly applied to the possibly larger S4 preimage.
The payload manifest and `LegacyMigrationSeal` keep the reassemblable preimage
reachable for restart certification; it is not charged as a generic retained
served root and cannot be reclaimed with superseded S4 pages. The
`legacy_effect_census_*` dimensions separately retain every canonical census
page needed to verify the signed S5-native translation of that preimage's
effect set.

This is the **canonical control-metadata** envelope. `fact_record_*` charges
every out-of-line certified FactRecord, including proposal, detached-signature,
support and receipt records. `raw_fact_chunk_*` charges every immutable bounded
`CONTROL_EVIDENCE` byte/chunk behind action records; ordinary `CONTENT_COMMIT`
raw chunks/manifests are charged by the isolated `ContentCapacityEnvelope`.
Neither class is hidden in a tree-row count. S5 quarantine never lowers these
dimensions: every ordinary admitted FactTree row, its exact FactRecord and its
referenced content commit remain current occupancy even when absent from local
projection. Action evidence
and sealed legacy removal rows remain charged through their distinct rooted
paths even though they never gain ordinary FactSlots.
`authority_proof_record_*` separately charges every immutable bounded
`AuthorityProofRecord`. Each forward candidate ref roots exactly one such
object, and that object roots every proof FactRecord/raw closure named by its
bindings; neither a proof digest nor a provider FactRecord substitutes for this
preimage. `authority_proof_commit_*` charges the retained strong row and
post-commit proof for every distinct admitted proof record. An ordinary
publication creates at most one new row/proof pair, whose exact encodings fit
`MAX_AUTHORITY_PROOF_COMMIT_ROW_BYTES` and
`MAX_AUTHORITY_PROOF_COMMIT_PROOF_BYTES`; the fixed 31-row allowance already
includes that row. A missing, orphaned or mismatched commit proof prevents
certification even when the proof-record bytes themselves are valid.
`legacy_authority_proof_*` separately charges each checkpoint source
manifest and all of its capped binding/edge pages. Its workspace-specific total
comes from the signed legacy source ceiling and cutover manifest, never from a
Worker request budget or favorable cross-closure deduplication. Every generated
post-recorder paged actor source additionally retains its exact
`CommittedS4PagedAuthorityProof` row and
`S4PagedAuthorityProofCommitProof`; the
`s4_paged_authority_proof_commit_*` dimensions charge those rows and objects
independently of the manifest/pages and cutover checkpoint proof. Every generated
revocation base fact must fit one
`MAX_REVOCATION_RECORD_RAW_BYTES` raw chunk, and there are at most
`MAX_ACTION_EVIDENCE_REFS` such facts. The submitted pre-receipt subset also
obeys
`sum(canonical_raw_bytes(proof_refs)) <= MAX_ADMISSION_PROOF_BYTES`, and its
framing obeys `MAX_PENDING_BUNDLE_FRAMING_BYTES`; therefore both pending and
direct transport fit `MAX_PENDING_BUNDLE_BYTES` even at their legal boundary.
The separately generated receipt may consume one additional
`MAX_REVOCATION_RECORD_RAW_BYTES` chunk. Admission rejects the whole action
before receipt signing if any newly canonical proposal, signature or support
record exceeds its individual or aggregate input cap, or if any receipt exceeds
its individual cap or the aggregate base count. Revocation liability charges
the proof aggregate plus the maximum receipt, not seven independently maximal
proof records that transport can never carry.
The conditional admission cell retains the complete canonical signed receipt
for byte-identical retries, so `admit_cell_bytes` charges its exact encoding and
admission also rejects any cell above `MAX_ADMIT_CELL_BYTES`.
Every terminal-principal receipt likewise reserves one exact
`TargetRegistry` encoding against both `target_registry_rows` and
`target_registry_bytes`; the canonical row rejects above
`MAX_TARGET_REGISTRY_ROW_BYTES`. Row availability without byte availability is
therefore not sufficient to sign or commit the action.
Every admitted authority candidate charges the exact prospective base and full
forward value objects against their respective
`authority_base_candidate_registry_value_*` and
`authority_candidate_registry_value_*` dimensions, and their fixed pointers
against the corresponding `*_rows`/`*_bytes`; either candidate value rejects
above `MAX_AUTHORITY_CANDIDATE_REGISTRY_VALUE_BYTES`. Its immutable
`ADMITTED_PROOF` marker and fixed-width mask field are reserved at insertion;
removal rewrites only `CLEAR`/`MASKED(witness_action_slot)`, without growing the
value. Projection quarantine does not delete the ref, its proof object or its
candidate-count charge. The attempt/work limit
still reserves enough scratch and transaction work to examine at most
`MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION` refs and rewrite at most one forward
value per authority consequence.
Base-offer NeedKey directories, principal-provider and reverse-impact values use their corresponding
`*_value_objects`/`*_value_bytes` dimensions and reject above
`MAX_BASE_OFFER_NEED_KEY_REGISTRY_VALUE_BYTES`,
`MAX_PRINCIPAL_PROVIDER_REGISTRY_VALUE_BYTES` or
`MAX_AUTHORITY_IMPACT_REGISTRY_VALUE_BYTES`; their `*_rows`/`*_bytes`
dimensions charge only the bounded keyed pointer cells. Replacement path-copies
the immutable value object and atomically overwrites the same pointer row; it
does not leak the old value after no certified current/retained root reaches it.
Arbitrarily large ordinary content is still representable as a separately
sealed paged `RawFactContentCommit`, but it may consume only the isolated
content remainder after its exact prospective object/byte/page count is known.
Its fixed metadata attempt carries one commit/pin reference and the strong root
transaction performs one bounded pin transition; it never attempts to fit
every raw object into `publication_attempt_*` or leaves a validated commit
collectible before metadata CAS.
`legacy_universe_map_*`, `legacy_entry_map_*`, `legacy_effect_census_*`,
`legacy_iam_attestation_*`, `legacy_migration_seal_*`,
`migration_bootstrap_*`, `s5_cutover_binding_*`, `capacity_ceiling_*` and
`legacy_source_ceiling_*` plus `cutover_service_generation_*`,
`cutover_payload_manifest_*`, `cutover_commit_anchor_*`,
`cutover_content_pin_set_*`, `cutover_content_pin_generation_*` and
`cutover_content_pin_anchor_*` are fenced migration
allocations fixed at the S5 cut: they root the exact authenticated legacy
universe, duplicate-accounting ledger, provider-signed IAM evidence, both
temporal bindings, fixed-width seal, retained payload manifests, active
service-generation descriptor and its non-cyclic root-binding anchor, and can
never become ordinary or live-revocation capacity.
The IAM allocation includes one content-addressed object of at most
`MAX_LEGACY_IAM_ATTESTATION_BYTES`; the seal allocation includes one object of
at most `MAX_LEGACY_MIGRATION_SEAL_BYTES`. The bootstrap and final binding each
occupy one retained content-addressed object capped respectively by
`MAX_MIGRATION_BOOTSTRAP_BYTES` and `MAX_S5_CUTOVER_BINDING_BYTES`. The
ceiling/source preimages each occupy one retained object capped by
`MAX_CAPACITY_CEILING_BYTES` and `MAX_LEGACY_SOURCE_CEILING_BYTES`.
The active service-generation descriptor occupies one retained object capped by
`MAX_CUTOVER_SERVICE_GENERATION_BYTES`; its paged payload manifest is retained
under the exact object/byte allocation. The one strong-service
`CutoverCommitAnchor` occupies a retained cell capped by
`MAX_CUTOVER_COMMIT_ANCHOR_BYTES`; the co-committed
`CutoverContentPinGeneration` occupies a retained strong row capped by
`MAX_CUTOVER_CONTENT_PIN_GENERATION_BYTES`, its paged set has an exact retained
object/byte allocation, and its
`CutoverContentPinAnchor` occupies one cell capped by
`MAX_CUTOVER_CONTENT_PIN_ANCHOR_BYTES`. The commit anchor, content-pin
generation transition and content-pin anchor all fit inside the eight-row
bounded activation. The fixed canonical root, frontier and active-generation cells are
charged by both row and byte dimensions; their values reject above
`MAX_ROOT_BYTES`, `MAX_FRONTIER_CELL_BYTES` and
`MAX_ACTIVE_SERVICE_GENERATION_CELL_BYTES` respectively.
The
unbounded publisher count lives
as individually capped rows in the paged universe map, never inline in either
object.

Optional uncommitted proposal staging uses a separately quota- and IAM-isolated
`PendingCapacityEnvelope(staging_slots, staging_bytes, staging_write_leases)`;
every slot is a fixed overwrite-only key and every accepted write remains
charged until definitive settlement. Bao payloads, invite blobs and other user
content use a third isolated
`ContentCapacityEnvelope(content_objects, content_bytes, content_attempts,
raw_fact_commit_rows, raw_fact_commit_bytes,
raw_fact_commit_proof_objects, raw_fact_commit_proof_bytes,
raw_fact_commit_pin_rows, raw_fact_commit_pin_bytes,
raw_fact_commit_pin_proof_objects, raw_fact_commit_pin_proof_bytes,
raw_fact_manifest_objects, raw_fact_manifest_bytes,
raw_fact_scratch_objects, raw_fact_scratch_bytes,
raw_fact_write_leases)`.
Raw-fact commit rows/proofs obey `MAX_RAW_FACT_CONTENT_COMMIT_BYTES` and
`MAX_RAW_FACT_CONTENT_COMMIT_PROOF_BYTES`; pin rows/proofs obey
`MAX_CONTENT_COMMIT_PIN_BYTES` and `MAX_CONTENT_COMMIT_PIN_PROOF_BYTES`.
Pending and rooted pins retain the full charged closure, while only a fenced
`ABORTED` pin releases it. Each streamed write batch obeys
`MAX_RAW_FACT_CONTENT_BATCH_OBJECTS` and
`MAX_RAW_FACT_CONTENT_BATCH_BYTES`. Manifest pages obey their own entry/byte
caps, while the envelope's concrete object/byte dimensions bound the total
paged fact.
In production each envelope has a distinct bucket/binding or an enforceable
provider quota boundary, not logical counters over one exhaustible allocation.
Filling or leaking pending or content storage may reject another staging/upload
request, but can never consume canonical-tree, action-record, scratch or
revocation bytes. Direct admission bypasses a full optional pending pool under
the same aggregate proof, framing and `MAX_PENDING_BUNDLE_BYTES` request caps.
Existing `obj/` stores are
repacked into these three S5 namespaces at the fence; `FactRecord`s,
`ActionRecord`s, tree pages and bounded `CONTROL_EVIDENCE` raw chunks are
charged control metadata, `pending/` bundles are staging, and ordinary
`CONTENT_COMMIT` raw-fact chunks/manifests, `blob_refs` payloads and invite blobs
are content.

The strong service and workspace-scoped immutable metadata store must provision
at least the control envelope plus fixed overwrite-in-place
root/frontier/attempt slots before S5 can certify, and must attest the pending
and content quota boundaries separately; deployment quota smaller than any
committed envelope is a hard failure. `retained_*` is the hard union budget for
old roots leased by registered served cells or pending inclusion witnesses.
`publication_attempt_*` is a disjoint **post-cutover, single-operation** scratch
reserve large enough for the largest permitted prospective action, including
the fixed-key page-copy bound below and the separately bounded ordinary-insert
path. It is never used to stage the first S5 root. Its object/byte component is
a fixed overwrite-only scratch key pool and
its write-lease component bounds the drain barrier; neither becomes ordinary or
revocation capacity when an attempt clears. The
`admission_log_*` fields cover only grow-only `CommittedAdmission` rows—ordinary
root advances update the fixed frontier cell and do not consume this log.
For `DirectRoot`, the corresponding full-size `admit/` cell and log row form the
retained `DirectCommitPair`; for `CutoverGeneration`, the row is paired with the
one retained generation anchor. `AdmissionCommitProof` is a deterministic
bounded signature over that retained evidence and can be regenerated after the
live root advances, old root objects are collected and a passive proof cache is
lost. Neither historical canonical-root/frontier cells nor the proof cache are
mandatory state.

`served_cell_*`, `inclusion_witness_*` and `worker_read_lease_*` are mandatory
serving capacity, not best-effort caches. Registering a publisher precreates one fixed
`served/<workspace>/<publisher_id>` row and one fixed overwrite-only
`witness/<workspace>/<publisher_id>` row, reserves
`MAX_SERVED_CELL_BYTES` and `MAX_INCLUSION_WITNESS_BYTES` respectively, and
also precreates the fixed read-lease slots and bytes specified above. It fails
before registration if any row/byte or worst-case retained-root dimension is
unavailable. There
is at most one pending direct witness from that publisher's current served root
to the newest candidate root; replacing an unconsumed intermediate witness
requires proving the direct inclusion and atomically overwrites the same slot.
The same registration transaction charges those dimensions and the local
certificate reserve into the one
`PublisherCapacityCell` charged against `publisher_capacity_cells` and
`publisher_capacity_bytes`; its canonical encoding rejects above
`MAX_PUBLISHER_CAPACITY_CELL_BYTES`. Canonical publication checks that one
fixed-size aggregate and prepares only its publishing deployment.
Nonpublishing deployments populate their own fixed witness slots off-request
after observation. Exhausting unrelated strong-service metadata can therefore
neither strand `authorize_serve` nor consume revocation escrow, while root
publication remains independent of registered-publisher count.

`certificate_*` is not an optional cache budget. For every registered publisher
it provisions the certificate for its current served root, every certificate
still referenced by a retained served-root lease, live `WorkerReadLease` or
unconsumed `InclusionWitness`, and one `MAX_CERT_BYTES` next-root reservation
plus write lease. The publishing deployment must prove that reserve before the
workspace-global root may advance; the service never commits a root whose
publishing deployment cannot materialize `cert/<root_oid>`. Another publisher
whose precharged local reserve is later unavailable fails closed on observation
and is fenced/reseeded independently; it does not force an O(publishers)
pre-CAS walk. Certificate capacity cannot borrow from revocation escrow, fixed
scratch, pending storage or content storage.

`RevocationLiability(root)` is the deterministic worst-case capacity vector
across FactTree, SuppTree, AuthorityTree, their page splits, out-of-line
FactRecords and raw-fact chunks, immutable AuthorityProofRecords and
ActionRecords, the frozen legacy
universe/entry maps and authenticated effect census, retained reconciled-S4-root
preimage, `LegacyIamAttestation` and migration seal,
`admit/` cells and their bytes, admission-log rows/bytes, TargetRegistry
rows/bytes, forward AuthorityCandidateRegistry values and reverse
AuthorityImpactRegistry values, the base-offer NeedKey directory and base
candidate values, plus PrincipalProviderRegistry rows/bytes and
the next-root certificate reservation required to exercise every distinct
live, unspent suppression target already admitted by that root. The
componentwise invariant also pins each registered publisher's fixed served-cell
row/bytes, inclusion-witness row/bytes, bounded read-lease row/bytes and
worst-case leased-root retention, plus one bounded next-witness overwrite;
these are mandatory control occupancy/pre-CAS reserves, not caches and not
multiplied once per suppression target. Empty `SuppSlot`/`ActionSlot` rows are
current occupancy, not promises: the remaining liability covers their maximum
filled values, path-copy objects, immutable action/evidence records and service
rows. A normal per-sid target whose carriers are already monotonically masked
has no remaining ordinary liability; the terminal-principal exception is
defined below.
For each distinct directly targetable ordinary sid, the calculation reserves
the family matrix's complete maximum-size action. Define
`BaseRevocationRecords` as at most `MAX_ACTION_EVIDENCE_REFS = 8` proposal,
detached-signature/support and receipt FactRecords, plus the immutable
`ActionRecord`, owner `ActionSlot` fill, conditional `admit/` cell,
admission-log row and optional `TargetRegistry` row: at most
`MAX_REVOCATION_BASE_RECORDS = 13` logical records in total. Its byte liability
charges the full `MAX_ACTION_RECORD_BYTES` even though the tree's `ActionSlot`
contains only one fixed-width oid, plus one full `MAX_FACT_RECORD_BYTES` for
each of the at-most-eight evidence FactRecords. Raw evidence is charged once at
`MAX_ADMISSION_PROOF_BYTES + MAX_REVOCATION_RECORD_RAW_BYTES`: the aggregate
seven-ref input bound plus the separately generated maximum receipt, never
eight independently maximal raw chunks. It also charges one full
`MAX_ADMIT_CELL_BYTES` reservation for the durable retry cell. A terminal
base additionally charges one full `MAX_TARGET_REGISTRY_ROW_BYTES` row against
the TargetRegistry byte envelope. Only the
preallocated owner `ActionSlot` is a base tree path, so
`MAX_REVOCATION_BASE_TREE_PATHS = 1`; the other base records are immutable
objects or strong-service rows. It explicitly excludes SuppTree effect updates
and AuthorityTree consequences; those are variable, separately capped sets.
The at-most-32 target FactRecords/raw roots are already committed occupancy,
not newly generated `BaseRevocationRecords`; the prospective action verifies
they are present, and its target bindings add canonical reachability edges that
prevent their object/byte occupancy from being released while the action
survives. A capacity calculation that assumes quarantine or historical-root GC
will free those target bytes is invalid.
Likewise, the at-most-64 FactRecords/raw roots named by a terminal principal's
`PrincipalProviderBinding` values are already committed occupancy and remain
rooted by the grow-only registry whether live or quarantined. The terminal
action does not count them as new base records. A later provider publication
charges its ordinary FactRecord/raw bytes before publication and consumes the
pre-reserved registry-binding/effect metadata; neither quarantine nor restore
returns that count or capacity.
`RevocationActionBundle` is the union of the base records, all effect updates
and all authority consequences, with every fixed-key value-update path charged
exactly once. It is not merely a proposal/receipt row count.

Storage escrow alone is insufficient: every live target also carries a
recomputed, non-consumable execution witness:

```
AtomicCommitBudget(action_bundle) =
    (registry_value_objects, registry_value_bytes,
     attempt_manifest_rows, attempt_manifest_bytes,
     strong_commit_rows, strong_commit_bytes)
```

`RevocationLiability(root)` requires the padded worst-case witness for each live
unspent target to fit the publication registry-object, manifest and strong
transaction maxima above. These dimensions are compared per possible action,
not added across unrelated targets, because one serialized revocation consumes
one transaction at a time. They are nevertheless admission invariants:
publishing a new authority candidate or reverse relationship recomputes every
affected target/principal witness and rejects before object upload if any one
would no longer fit. A multi-target action additionally checks its exact union.
The witness counts the full prospective variable-width values as staged
objects, but only fixed `RegistryValuePointer`s in `strong_commit_*`; inlining
the values is forbidden. This proves that a legal 64-consequence action remains
executable even when all 64 candidate values are at their byte cap, rather than
discovering a 32 MiB transaction after the target has already been admitted.

For each live sid, liability includes its complete conservative transitive
`AuthorityImpactRegistry` set padded to
`MAX_AUTHORITY_CONSEQUENCES_PER_ACTION`, including every possible
AuthorityTree `NO_PROVIDER` or winner replacement, its paired bounded
`AuthorityCandidateRegistry` value read/fixed-width state rewrite, and its
page-copy cost. At most `MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION` refs are
examined across that padded set. Their full AuthorityProofRecords are already
rooted occupancy and are not fetched on the action path. The terminal principal reserve does the same
for each aggregate
`MemberPrincipal(pk)` or `DevicePrincipal(pk)` scope, not once per currently
visible provider row. An
ordinary authority-providing publication must update those impact sets and
forward candidate values and fund the enlarged liabilities before it can
consume non-escrow capacity. This is what makes an eighth, ninth or sixty-fourth
reverse descendant or losing candidate safe; a sixty-fifth consequence or
sixty-fifth candidate for one NeedKey rejects the new provider rather than
making an already-admitted target unevictable or its fallback unbounded.

`ExactSids` admission consumes only liabilities present for every recomputed
`TargetBinding`; partial redundancy rejects before anything is signed.
Reserving each binding as if removed separately is deliberately conservative;
one batched receipt may return the unused base/service-record reserve, but the
simultaneous union of authority consequences must still fit the action cap.

For each member or device principal the calculation also reserves the family
matrix's terminal revocation action. A typed terminal-principal liability is
released only by its committed `MemberPrincipal` or `DevicePrincipal` receipt,
never merely because the currently known provider fids were masked through
other selectors. A principal-wide reserve includes up to the corresponding
`MAX_MEMBERSHIP_PROVIDERS_PER_PRINCIPAL` or
`MAX_DEVICE_PROVIDERS_PER_PRINCIPAL` effect slot values, including slots that
may be needed after a zero-provider or currently smaller typed-principal
receipt, the maximum encoded `PrincipalProviderBinding` growth, plus its
`TargetRegistry` row.
The terminal reserve charges that row at
`MAX_TARGET_REGISTRY_ROW_BYTES`, not only as a logical row count.
The certificate deduplicates shared parent/ancestor sids and recomputes the
liability from FactRecords and commit-proven receipts; it never trusts a mutable
counter.

Every canonical root must keep `occupancy + RevocationLiability` componentwise
within its `CapacityEnvelope` under worst-case key placement. This check includes
the strong service's current durable occupancy, not a self-reported counter in
the root, and every still-live target's `AtomicCommitBudget` must independently
fit the protocol transaction/manifest/object maxima. Ordinary publication may
use only the non-escrow remainder. A
successful removal converts only the at-most-64 **directly named** scope
liabilities to the actual complete bundle. It does not enumerate descendants
and does not release their individual escrow, even though their inherited
selectors now mask them. This conservative v1 rule intentionally trades
capacity reclamation for bounded publication: a one-row ancestor removal does
O(action) work regardless of descendant count. An optional future off-request
reclaimer may cursor through descendants and publish separately capped,
authenticated `LiabilityReleaseCheckpoint` batches, but neither revocation
success nor ordinary capacity may assume that work occurred. A checkpoint can
release only a slot already proved permanently masked under a committed action;
it never changes suppression state.

The direct release still does not release an unspent terminal-principal
liability. Unused provider-row escrow stays attached to the corresponding
terminal `MemberPrincipal` or `DevicePrincipal` tombstone and is consumed if a
later matching provider is admitted. A provider above the per-principal cap
rejects before canonical publication. If migration cannot fund this invariant
it activates the writable S4 fallback or re-anchors; if a running root ever
violates it, certification and Worker grants fail closed rather than serving an
unevictable principal.

The fixed scratch and retained-root components are checked separately and may
never be borrowed as ordinary capacity. On a successful root advance, the exact
new canonical manifest is charged before authority-exclusive copies leave the
sealed fixed scratch pool; pages needed only by an actively served or
read-leased old root move to the retained budget. The attempt slot cannot clear
until every canonical copy verifies, while abort cannot clear until its
generation is fenced and all scratch write leases are definitively drained. If
retained storage is full, the service may fence/reseed stale publishers but may
not reclaim an unfenced, unexpired concurrent read lease; it waits or rejects
the advance rather than charging a revocation liability or leaking an object.
Certification checks the physical object-store accounting against the exact
current/served/read-leased root reachability sets, fixed scratch pool and
live/committed attempt, not only the logical tree row counts.

Certificate reclamation follows the same served-root leases. A
`cert/<root_oid>` object remains charged while that root is current, served, or
named by a live served/read lease or unconsumed `InclusionWitness`. Once the
served cell has advanced and the last such lease/witness is released, expired
after its gateway capability became unusable, or is fenced, the service
generation-fences any certificate writer, deletes the sidecar and reclaims its
object/byte slot. If the certificate partition is full, stale publishers and
leases are fenced/reseeded before another advance; neither an ordinary action
nor a revocation may consume the always-reserved next-certificate slot.

Thus an ordinary action at the non-escrow capacity boundary fails cleanly and
leaves no receipt cell or frontier change, while a valid first revocation of an
admitted target must still fit its escrow. The conservative no-cache envelope is
itself below the byte cap:

```
100 routed lookups * 8 pages * 4 KiB
  + 64 fact records * 32 KiB
  + one 64 KiB canonical root
  + one 4 KiB certificate
  + one 4 KiB served-authority response
  = 5,447,680 bytes
```

The byte arithmetic leaves `2,940,928` bytes for codec/HTTP working overhead.
The independent cold-cache subrequest bound does not assume page sharing:

```
100 routed lookup paths * 8 page reads
  + 64 FactRecord reads
  + root + certificate
  + one served-authority RPC
  = 867 subrequests < MAX_R2_SUBREQUESTS < Cloudflare's 1,000 hard limit
```

The implementation must assert both inequalities; these constants may not drift
independently. The individual fact/need/selector maxima are also constrained by
the aggregate `MAX_POINT_LOOKUPS`; a request cannot spend all three maxima at
once. Every suppression consult is one authenticated exact `SuppSlot` path and
counts against both `MAX_SUPPRESSION_LOOKUPS` and `MAX_POINT_LOOKUPS`;
FactTree and AuthorityTree exact lookups count once against
`MAX_POINT_LOOKUPS`. `MAX_WORKER_NEEDS` counts wildcard/exact authority queries
and required co-offer checks. Page batching and deduplication are optimizations,
never the proof of the bound. Authority-proof commit sidecars and raw-content
manifests are verified by off-request certification and covered by the root
certificate; neither adds a request-time fetch. A Worker fails closed before granting if any
count, byte or subrequest budget is exceeded.

Request failure is not the first enforcement point. Each Worker-authorizable
role in the S2 family matrix has a **compositional worst-case `ProofBudget`** for
facts, needs, selectors and encoded bytes. A family reserves the sum of its own
fixed cost and the declared maxima of every named authority role it can select;
it never relies on the currently winning provider being cheap. Authoring and
admission recompute and reject a fact whose immutable declared budget class does
not cover that composition. Each need carries the maximum provider class it
reserved, and recursive needs consume a strictly smaller class. Every provider
eligible for one `NeedKey` therefore fits the same reserved ceiling, so swapping
the canonical winner after a set union remains within the already reserved
request/action budget.

An actual `ProofCost` may ride AuthorityTree for measurement and fetch planning,
but it is not an admission decision based on current downstream facts, and
publication never refuses an otherwise valid union to protect a prior
credential. Opposite-order peers therefore accept the same facts, choose the
same winner, remain serviceable and publish the same root. Ephemeral request
construction checks the same compositional template before sending. Fail-closed
protects against hostile requests and uncertified roots; it does not strand a
normally admitted member.

The proof-budget rule is prospective for S5-authored state. It does not discard
pre-cut recursive authority. The fenced migration emits the
`LegacyAuthorityCheckpoint` records above and makes those bounded providers the
canonical Worker path; the original facts remain immutable evidence in
FactTree. After the seal, new checkpoints are impossible and new over-budget
proofs reject at authoring/admission.

Canonical B-treap page identity makes oid comparison the diff, retiring I4's
separate fingerprint;
`pull_removals` becomes a manifest oid-diff.

### Cloudflare Worker read contract

A request-time Worker never rebuilds SQLite or reads the whole fact or
suppression set:

1. Strong-read one current canonical composite root, reject it above
   `MAX_ROOT_BYTES`, verify the local sidecar and keyring-pinned `admission_pk`,
   then make the one bounded `authorize_serve(root_oid)` call. The served cell
   accepts only an equal root or a pre-registered inclusion witness from its
   exact current serial, advances atomically and claims one fixed
   `WorkerReadLease`. The response is the signed freshness/read token naming
   that exact lease generation, root oid, certificate oid and expiry. Every
   tree, FactRecord and immutable-page read in steps 2–5 must present that token
   to the root-bound gateway. An uncertified, unwitnessed or replayed root, an
   unavailable lease slot or a token/root mismatch fails closed before any such
   read; none is interpreted as no removals.
2. Validate the submitted closed authority/request proof and verify bounded
   `ADMITTED` FactTree membership for every claimed committed support fact.
   Proof membership authenticates bytes; it does **not** make every support
   fact's suppression selectors part of the request. Resolve only the ephemeral
   request fact's own family-declared selectors plus, for each selected
   authority candidate, its mandatory provider selectors and exact
   `AUTHORITY_LIVENESS_GUARDS`/`FollowAuthority` scopes. An incidental support,
   one-time authorization guard, or unselected authority edge contributes no
   suppression lookup merely because it is in the closed proof. The FactTree hit
   proves bytes, not an authority admission: step 3 must also match the
   commit-proven canonical candidate and its immutable
   `AuthorityProofCommitProof`. Fresh ephemeral request and
   signature facts are integrity-checked from the submitted closure rather than
   falsely required to be committed. Before deriving any grant, invoke the
   request family's ephemeral evaluation gate with exactly one
   service-supplied trusted `("now", now_ms)` value. The S5
   `facts.auth.request.evaluate` equivalent must still require the canonical
   request tag/shape, `verb in request.VERBS`, and `exp >= trusted_now`; neither
   the request body nor a submitted global may choose the clock. Its legacy
   removal-global checks move to the authenticated whole-closure suppression
   decisions in steps 4–5, but the family gate itself is not bypassed. An
   expired or unsupported-verb request fails closed before `grant_of` can
   produce a capability.
3. For every normalized need, authenticate the routed authority-tree result.
   On a hit, require both the submitted provider fid and closed-proof digest to
   equal the committed canonical candidate whose rooted proof is
   `ADMITTED_PROOF` and `CLEAR`. The local cross-index certificate has already
   verified its commit proof; the Worker authenticates the certificate-covered
   commit id and logical-rank provenance without an extra object fetch, and
   never re-resolves incidental support against later winners. On a certified
   miss, resolve only
   among submitted fresh providers. This accepts the request's fresh signature
   while still detecting omission of a better or incompatible committed
   provider/proof path.
4. Deduplicate exactly that policy-selected suppression set and execute the
   authenticated exact `SuppSlot(sid)` operation for each resolved Sid.
   Typed-principal liveness scopes are already reflected in the selected
   candidate's certified `CLEAR`/`MASKED` state and its provider SuppSlots; the
   Worker never expands them by scanning proof facts or a service registry. The
   authenticated fixed-width value is either `CLEAR` or `ACTIVE`; a missing row
   fails closed because certification requires a slot for every resolved
   selector. Batch-fetching shared pages is only an optimization.
5. An `ACTIVE` value under the local cross-index certificate is already an
   authoritative suppression verdict: certification validated its owner
   `ActionSlot` pointer, bounded `ActionRecord`, complete rooted EvidenceRef
   closure, exact binding, service-exclusive admission signature and post-commit
   proof before serving this root.
   Mask/deny immediately; do not fetch the evidence on the request path. A
   `CLEAR` value grants only with that same certificate. An optional audit
   endpoint may return full removal evidence under a separate response budget,
   but granting and ingress screening never depend on it.
6. Bind a grant to the certified root oid/etag and the same
   `WorkerReadLease` generation used for every lookup; the grant expiry cannot
   exceed the lease expiry. Release the slot only after the last response read,
   or retain it until a handed-out root-bound grant becomes unusable. A bare
   etag or served-cell observation is not a read lease. An
   irreversible proposal first stages outside the canonical frontier. The
   admission service requires its certified basis to dominate the monotonic
   workspace frontier, checks guards there, then constructs and validates the
   cap-compliant prospective composite root containing the complete
   `RevocationActionBundle` and all suppression slot updates. Proposal, detached
   signature/support records, receipt, slot updates, conditional `admit/` cell,
   admission-log entry, applicable `TargetRegistry` row, frontier and canonical
   root commit together; a capacity failure leaves the logical tuple unchanged
   and pre-CAS recovery generation-fences/drains the fixed scratch attempt before
   retry. The CAS charges every canonical object before authority-exclusive
   copies begin. The root remains unservable until those copies verify, the
   post-commit signer re-reads that cell and log entry, emits its
   `AdmissionCommitProof`, and the local certifier verifies the committed root.

Work is logarithmic rather than linear in workspace size, and the explicit
depth/count/byte ceilings above are the hard per-request bound. Hot pages may be
cached by certified root hash, but cache is never authority.

The old head-plus-one-contiguous-slice claim is deliberately retired. Once a
fact can name several ancestor keys, those keys may occupy scattered shards.
The chosen answer is a deduplicated exact lookup of each preallocated
`SuppSlot`; it neither globally head-reads removals nor duplicates a removal
into descendant ranges.

Publication/sync cost is bounded by the fixed-key values an action changes, not by
the total removal population. For admission `a`, let:

```
q = len(proof_refs(r))                     <= MAX_ADMISSION_PROOF_REFS = 7
e = len(evidence_refs(a))                  <= MAX_ACTION_EVIDENCE_REFS = 8
b = len(BaseRevocationRecords(a))          <= MAX_REVOCATION_BASE_RECORDS = 13
p = len(BaseRevocationTreePaths(a))        <= MAX_REVOCATION_BASE_TREE_PATHS = 1
m = len(effect_targets(root, a))           <= MAX_EFFECT_TARGETS_PER_REMOVAL
s = len(impact_scopes(root, a))            <= MAX_ACTION_IMPACT_SCOPES = 65
c = len(authority_consequences(a))         <= MAX_AUTHORITY_CONSEQUENCES_PER_ACTION
k = sum(len(AuthorityCandidateRegistry[key]) for key in consequences(a))
                                             <= MAX_AUTHORITY_CANDIDATE_REFS_PER_ACTION
rv = changed_registry_values(a)              <= MAX_PUBLICATION_REGISTRY_VALUE_OBJECTS
rb = encoded_registry_value_bytes(a)         <= MAX_PUBLICATION_REGISTRY_VALUE_BYTES
RevocationActionBundle(a) = base(a) union effects(a) union consequences(a)
changed_tree_paths(a) <= p + m + c          <= MAX_CHANGED_TREE_PATHS = 129
pages_per_value_update <= MAX_TREE_DEPTH
                       = MAX_TREE_PAGES_PER_VALUE_UPDATE = 8
changed_page_objects(a)
    <= changed_tree_paths(a) * MAX_TREE_PAGES_PER_VALUE_UPDATE
    <= MAX_CHANGED_PAGE_OBJECTS = 1,032
strong_commit_rows(a)
    <= MAX_PUBLICATION_FIXED_SERVICE_ROWS + rv
    <= MAX_PUBLICATION_SERVICE_TRANSACTION_ROWS
strong_commit_bytes(a)
    <= MAX_PUBLICATION_FIXED_SERVICE_BYTES
       + rv * MAX_REGISTRY_VALUE_POINTER_BYTES
    <= MAX_PUBLICATION_SERVICE_TRANSACTION_BYTES
```

`b` separately proves the logical object/service-record bound; it is not used as
a tree-path count. `p` is exactly the preallocated owner ActionSlot update.
Both deliberately exclude the `m` suppression updates and `c` authority
consequences, so neither variable set is double-counted.
`s` bounds strong-service reverse-registry reads, not tree mutations: the
terminal principal scope plus its at-most-64 provider Sids may overlap in their
NeedKey values before the exact union is capped at `c`.
`c` is the exact fixed-point change set independently recomputed within the
bounded conservative `AuthorityImpactRegistry` union; direct children alone are
not a valid count. `k` is bounded independently of workspace/provider
population by the complete forward `AuthorityCandidateRegistry`: at most 64
affected NeedKeys times 64 refs per key equals 4,096 candidate refs. Each
consequence may rewrite one already charged candidate-registry value plus its
one AuthorityTree fixed-key value, but only the latter is a B-treap path. `rv`
and `rb` count complete immutable registry-value objects in the sealed attempt;
the strong transaction counts one pointer per object and must also fit its
actual canonical row/byte encoding. A
multi-target `ExactSids` action and a principal-wide action both use these same
per-action union and candidate-width caps.

A value update cannot change B-treap priority, leaders, page membership or
depth; it emits at most the existing leaf plus one ancestor page at each level.
Several base records are strong-service rows rather than tree paths, so the
formula is conservative. A one-target content deletion changes one SuppTree
slot plus its owner ActionSlot and any authority consequences. Syncing an
admission transfers at most this fixed-key path bound plus bounded raw action
records, independent of total facts, removals or descendants.

Ordinary structural insertion has a separate bound. One insert may touch at
most `MAX_TREE_PAGES_PER_INSERT = 2 * MAX_TREE_DEPTH + 1 = 17` prospective
B-treap pages, and one ordinary fact may insert at most
`MAX_ORDINARY_TREE_INSERTS = 13` tree keys: one FactSlot, one new SELF
SuppSlot, one directly targetable SELF ActionSlot, at most two typed-principal
ActionSlots, and at most eight new AuthorityTree NeedKeys. Inherited
parent/ancestor SuppSlots already belong to their earlier facts. The resulting
worst case is `MAX_ORDINARY_CHANGED_PAGE_OBJECTS = 13 * 17 = 221`. These are
measured from exact prospective bytes and reject before admission. They are
never substituted for a missing revocation slot.

### Done when

- Syncing a one-sid, maximum-`ExactSids`, maximum-provider `MemberPrincipal`,
  and maximum-provider `DevicePrincipal` admission into a converged peer stays
  within the fixed-key `changed_tree_paths <= 129` and
  `changed_page_objects <= 1,032` formula above, not O(all removals), with
  benchmarks pinning all three curves. A mutant that structurally inserts an
  absent removal slot or charges the ordinary-insert bound to revocation fails.
  Separate ordinary-publication fixtures exercise the full
  `13 * 17 = 221` structural-insert budget and reject the next insert before
  publication.
- A fault-injection test crashes before object writes, between each tree build,
  after every fixed-scratch put, while one old-generation put is deliberately
  delayed, after `OPEN -> SEALING`, after the root CAS but between every
  authority-exclusive canonical copy, before commit-proof publication, around
  sidecar certification and around the root pointer mirror. The delayed writer
  is rejected after the generation fence and an accepted-but-unsettled lease
  prevents attempt clearing; it cannot create an arbitrary/canonical key or
  corrupt the next generation. A pre-CAS orphan can never certify or replay and
  creates no canonical object; repeated failed attempts cannot reduce either
  ordinary or revocation capacity. A post-CAS copy crash remains fully charged
  and resumes idempotently. A committed row missing only its proof recovers that
  proof idempotently; no local certificate can be issued before copy and proof.
  The ordinary-admission recovery fixture then advances the live root, removes
  the passive proof cache, collects the superseded root objects, restarts the
  signer, and regenerates the byte-identical `DirectRoot` proof solely from the
  retained `DirectCommitPair`; a
  `live-root-only-direct-proof-regeneration` mutant fails closed instead of
  stranding certification of the later root. A publisher that observes the
  uncertified committed root fails closed instead
  of serving its old root; and peers with distinct certification keys still
  converge to byte-identical canonical roots. A separate capacity fault fills
  every certificate sidecar slot, proves that a missing next-certificate
  reservation prevents the canonical CAS, then fences/releases a stale
  served-root lease, deletes and reclaims its certificate, and publishes a
  removal without borrowing revocation escrow. A fixture registers many
  publishers, proves canonical publication reads one fixed
  `PublisherCapacityCell` and prepares only the publishing deployment, then
  lets every other publisher independently build its direct witness
  off-request. Removing or exhausting a served-cell, witness,
  read-lease slot, publisher-capacity-cell or certificate reservation makes
  registration, `authorize_serve`, the publishing deployment's CAS, or the
  affected observer fail at its exact boundary; it never creates an
  O(publishers) CAS loop or an unsafe grant. With request A holding a lease on
  R, request B advances the same served cell to R2: A continues to read only R
  through its token, and R's pages and certificate remain charged until A
  releases or expires. `served-cell-only-read-lease`, `unbound-read-token` and
  unreserved-lease-slot mutants either lose R under A or read a mixed root and
  fail.
- An S4 upgrade with existing message/file deletions keeps them suppressed
  through the authoritative legacy slot; the bounded Worker route remains
  disabled. The fenced backfill test includes a content deletion whose author
  was later evicted and a pre-cut member eviction held only in globals, maps
  both legacy sources to grandfather receipts, includes one target membership
  available only from a registered publisher's retained quarantine inventory,
  one removal global with no provider anywhere in the sealed universe, and a
  legacy content deletion of a fact whose S5 family is `NEVER`, plus one aimed
  at a membership/chunk fact that offers a normal selector but whose
  removal-family/selector pair is absent from `DIRECT_TARGETS`. It derives
  `LegacyMask` for both illegal direct targets without cascading to their
  parent/principal; derives their shared `legacy_mask_namespace` from the
  fenced pre-record source, constructs and authenticates the complete
  `LegacyEffectCensus`, applies every migration-only provider sid before
  hashing any victim FactRecord, proves the masked victim FactRecords and
  logical rows can be constructed before `cutover_digest`, and rejects both a
  `late-legacy-mask-selector` mutant and a mutant that derives either mask from
  that final digest; preserves the zero-provider
  global as a zero-effect-update registry receipt with a filled, precreated
  principal `ActionSlot` whose later provider is immediately masked;
  seals the inventory against later direct restoration; authenticates a
  quarantine-only fact through `LegacyUniverseMap` after restart; after
  first-root publication, deletes the superseded S4 child pages and mutable
  root cell **and the S4 decoder**, then re-certifies by hash-checking the
  retained `reconciled_s4_root` bytes and verifying the S5-native census plus
  `LegacyTranslationAttestation`; a `drop-reconciled-s4-root`,
  `post-seal-s4-decoder-dependency` or census-translation mutation fails closed.
  It rejects a
  missing row, naked fid and row whose FactRecord/raw root was redirected;
  retains the same unpublished fid in two registered publisher inventories and
  proves opposite enumeration orders select the same lowest publisher id,
  logical-row digest, seed and root, while conflicting bytes abort; gives one
  registered inventory a valid removal proposal that appears in no
  authoritative legacy slot/global effect, classifies its universe row
  `INERT_REMOVAL`, gives it no FactSlot, receipt, ActionSlot fill or SuppTree
  effect, and proves it remains inert after restart and attempted direct
  reingestion—an `admit-inert-legacy-removal` mutant puts it in FactTree and
  fails certification; and gives one legal legacy removal a quarantine-only
  victim, proving fenced backfill
  creates its normal `ActionSlot(Sid(resolved_sid))` and `SuppSlot` before the
  grandfather action fills them rather than incorrectly using `LegacyMask`;
  crashes at every phase; injects checkpoint, seed, capacity, object-write,
  final-IAM and certification failure after the irreversible fence and proves
  the fresh service-only S4 generation resumes publication with all legacy
  effects intact while every old credential still rejects; retries from that
  newer S4 generation; and proves the S5 format bump removes the slot/removal
  globals only when the receipt-and-commit-proof-derived path is complete.
- Dropping one suppression slot/value, canonical-provider row,
  `PrincipalProviderRegistry` binding or forward `AuthorityCandidateRegistry` ref
  makes certification fail. An uncertified root
  and a valid losing committed provider both fail
  closed, while a normal fresh request signature succeeds through an
  authenticated authority miss. The same Worker fixture supplies trusted time
  to the request-family gate: `exp == trusted_now` with `sync` succeeds, while
  `exp < trusted_now`, a verb outside `request.VERBS`, a client-supplied second
  `now`, and a `skip-ephemeral-family-gate` mutant all fail before a grant.
  A user with two membership providers is denied
  through both. The non-target provider is then shadowed into quarantine, the
  historical root is collected, and certification still derives its principal
  scope through the retained `PrincipalProviderBinding`, keeps its SuppSlot
  `ACTIVE`, and counts it against the provider cap. Restoring it must match that
  exact binding. A `principal-provider-bare-fid-after-quarantine` mutant loses
  the proof or frees the count and fails. Adding or restoring a third provider
  after eviction
  deterministically inserts its `ACTIVE` SuppSlot before that root can publish,
  so AuthorityTree fallback never revives the principal. Two valid device facts
  for one key with distinct labels/timestamps are likewise denied together, and
  a third device-provider fact published after revocation is born `ACTIVE`. A
  `device_invite` fact covered simultaneously by committed `MemberPrincipal`
  and `DevicePrincipal` tombstones queries both typed rows and selects the
  canonical minimum witness in either action-arrival order; a first-match mutant
  fails certification.
- Authority-impact tests construct more than eight devices/delegated providers
  whose distinct `NeedKey`s depend transitively on one membership sid, then
  suppress it and verify every affected AuthorityTree row changes within the
  recomputed union and reserved page budget. They fill a terminal principal to
  exactly `MAX_AUTHORITY_CONSEQUENCES_PER_ACTION`; the next ordinary provider
  rejects before publication without consuming escrow. A second fixture puts
  exactly `MAX_AUTHORITY_CANDIDATES_PER_NEED` distinct losing providers behind
  one NeedKey, suppresses successive winners and proves every fallback is
  selected only from the complete bounded forward value; candidate 65 rejects
  before publication. Two distinct proof closures for the same provider create
  distinct content-addressed `AuthorityProofRecord`s. The fixture shadows the
  current winner and collects its historical root, then certifies and selects
  the losing fallback by replaying the retained fact bindings and ordinal edges
  without a FactTree search. Dropping one support FactRecord/raw root, retaining
  only `proof_closure_digest`, redirecting a binding, or exceeding the
  fact/edge/byte caps fails the
  `bare-authority-proof-digest` and
  `drop-authority-proof-support-after-quarantine` mutations.
  A construction-order vector first encodes a record containing only
  proof-closure digest/depth/cost, hashes it, then derives candidate id and
  `(depth, provider_fid, candidate_id)` rank; an
  `authority-proof-candidate-id-cycle` mutant that puts either post-hash value
  back into the record is rejected as unconstructible. A separate
  `device_invite` vector creates two needs with the same base `device_key`
  address and budget class but different user-specific required `device`
  co-offers. Their canonical required-co-offer tuples produce distinct
  NeedKeys and AuthorityTree/candidate rows; one may be a hit while the other
  is `NO_PROVIDER`. A `needkey-drops-required-cooffers` mutant aliases them and
  fails. The longest current tuple fits the explicit NeedKey and 1 KiB tree-row
  bounds; a fifth co-offer, one encoded byte beyond the key cap, and an
  `unbounded-required-cooffers` mutant all reject before registry mutation.
  A base-offer directory fixture first admits Alice and Bob full NeedKeys with
  different required tuples, then admits a lower-ranked provider carrying only
  Alice's co-offer. The bounded `BaseOfferNeedKeyRegistry` enumerates both rows,
  and the provider is appended as `COOFFERS_MATCH` for Alice and
  `COOFFERS_MISMATCH` for Bob before either AuthorityTree winner is recomputed.
  Introducing Charlie's tuple afterward reads the bounded
  `AuthorityBaseCandidateRegistry` and likewise includes every older provider.
  Two same-depth proof closures whose full candidate-id hashes reverse order
  between Alice's and Bob's NeedKeys prove that the base value stores no
  candidate id or winner rank: materializing each full value derives its ids
  and selects its own canonical winner. A
  `reuse-base-rank-for-full-needkey` mutant incorrectly selects one common
  winner and fails.
  A `provider-scans-or-omits-full-needkeys` mutant drops Bob or searches
  AuthorityTree/FactTree and fails completeness/budget certification; directory
  entry 65 and an aggregate affected-value 65 both reject prospectively.
  A paired arrival-order vector next gives 64 legal base candidates 64 disjoint
  liveness scopes. Provider-first admission rejects as soon as the base scope
  union reaches 65, before any full NeedKey exists; NeedKey-first admission
  rejects at the same provider. A legal companion shares one 64-scope set
  across all candidates and a late NeedKey changes exactly 64 reverse values.
  A `late-needkey-multiplies-candidate-scopes` mutant accepts the provider-first
  state and later attempts 4,096 reverse-value updates.
  Across 64 affected NeedKeys the action examines exactly
  the 4,096-ref maximum without a FactTree/provider scan. Removing one
  transitive reverse entry or losing forward candidate, flipping a masked
  candidate back to clear, re-resolving a commit-proven proof against a later
  incidental winner, or choosing a nonminimal admitted/clear fallback makes
  certification fail. Paired delegated-admin fixtures use the same authenticated
  proof shape but declare grantee-only and grantor-only
  `AUTHORITY_LIVENESS_GUARDS`; suppressing the omitted principal leaves the
  candidate live, while suppressing the named principal masks it. A
  closure-wide-candidate-masking mutant fails both, and a mutant that follows
  every nested authority edge without an explicit `FollowAuthority` fails a
  nested fixture. The same grantee-only fixture changes the omitted grantor's
  AuthorityTree winner after admission and still retains the exact
  `ADMITTED_PROOF` candidate; a
  `reresolve-admitted-proof-against-current-winner` mutant quarantines it and
  fails. A migrated `LegacyMask` victim that itself produces the
  winning authority candidate is masked through its mandatory
  `sorted_provider_sids`, and the next live fallback wins even though
  `LegacyMask` is not a family-selectable `LiveGuard`; a
  `legacy-mask-authority-provider-stays-live` mutant fails. A separate
  paired-order fixture gives a candidate only
  `LiveGuard(provider, SELF)`: publishing it before a `MemberPrincipal` or
  `DevicePrincipal` action masks it through `effective_actions(root, sid)`,
  while publishing the identical provider/candidate afterward creates both its
  SuppSlot and candidate ref already `ACTIVE`/`MASKED`. The two roots have the
  same winner and candidate state. A
  `principal-scope-does-not-mask-sid-guard` mutant leaves the first candidate
  live or makes the second order disagree and fails. An `ExactSids` batch whose
  individually legal scopes have an over-limit simultaneous union rejects and
  succeeds when restaged as smaller actions.
- A valid `MemberPrincipal` removal whose fact timestamp sorts before its target
  membership fact remains effective. Two peers receive the committed removal
  and membership in opposite orders; live projection, restart/rebuild and cold
  join all deny the member. This pins the rule to the committed target spec and
  registry, never to timestamp or arrival order.
- SuppTree tests place slots at the first and last position of adjacent leaf
  pages, authenticate both `CLEAR` and `ACTIVE` values by exact key, and prove
  that an absent reserved slot fails closed rather than meaning clear. A
  grandfather fixture with more duplicate legacy removals than fit one page
  produces one `LegacyEntryMap` row per old entry but only one receipt/action and
  one `ACTIVE` slot for the canonical lowest removal fid. Removing a duplicate
  row, pointing it at another target, or requiring its own receipt makes
  migration certification fail. A separate overlap fixture first exact-removes one
  membership provider and then commits `MemberPrincipal`: both owner
  ActionSlots remain filled, the SuppSlot names the deterministic witness, and
  a later provider points to the principal action. A dual-scope fixture commits
  member and device tombstones before a later `device_invite` provider and
  requires `witness(root, sid)` over both actions. Mutants that overwrite/drop
  either action, take the first typed tombstone, interpret a miss as `CLEAR`,
  scan a sid prefix, or require a second removal-fid lookup all fail named
  Worker tests.
- A staged bare proposal changes no root, and a forged receipt, a signature-only
  receipt, and a validly service-signed candidate orphaned by a failed CAS all
  have no effect; replaying the orphan after its author is removed still fails.
  A removed admin cannot obtain a new receipt. A receipt committed before later
  eviction/provider shadowing remains verifiable and its proposal never falls
  into quarantine while its row survives. Two partitioned publishers racing
  different certified basis roots hit one workspace-global cell and receive one
  byte-identical receipt plus commit proof for the removal fid; once the
  authority processes an eviction, a later stale basis cannot obtain a
  different action's unused receipt cell.
- The founder/member key cannot verify an admission receipt. Existing-workspace
  migration fails unless all registered publishers pin the same pre-fence
  `MigrationBootstrapCommitment` and separately generated service key; that
  commitment contains no snapshot-derived seed, cutover digest or exact S5
  prefix. Only after the definitive old-writer drain and frozen logical rows
  does the service derive and sign `S5CutoverBinding`, and the first S5 root
  authenticates both bindings. A pre-fence-final-binding mutant is therefore
  unconstructible. A stale or evicted founder cannot bypass
  `frontier/<workspace>` or `admit/<workspace>/<removal_fid>`. The migration
  test admits one old-prefix write before the fence, delays its settlement
  across credential revocation, and proves neither the logical-universe digest
  nor any migration seal is computed until that write is definitively drained
  and included. A post-fence old-prefix write is rejected. The test also
  retains an old publisher token through its maximum lifetime and proves that
  it cannot address the IAM-isolated `meta-s5/` namespace before the fence
  seals; a backend without definitive revocation/drain attestation stays on S4.
  The retry fixture injects at least two consecutive post-fence/pre-CAS
  failures. Each failed attempt activates only its already-prepared fresh
  service writer, publishes one new S4 fact successfully, then provisions and
  pins a distinct successor fallback plus a fresh
  `MigrationBootstrapCommitment` before fencing that now-current generation.
  A third attempt carries both intervening S4 facts into a successful S5 cut.
  All bootstrap/fallback generation ids are distinct and monotonic, every
  fenced credential remains rejected throughout, and a mutant that reuses the
  active generation as its own fallback fails before the next fence.
  The content-addressed `LegacyIamAttestation` survives restart and reachability
  GC; a missing, redirected, oversized, wrong-prefix or provider-signature
  mutant fails certification. Read and content-upload credentials likewise
  cannot write metadata.
- A whole-cutover fixture migrates a legacy corpus whose first S5 object
  manifest is larger than `publication_attempt_objects` and
  `publication_attempt_bytes` and whose strong-service rows exceed one
  `MAX_CUTOVER_SERVICE_BATCH_ROWS` transaction. Before the old-writer fence, the
  provider proves and retains canonical `CapacityCeiling` and
  `LegacySourceCeiling` objects, provisions canonical occupancy and a disjoint
  `CutoverCapacityEnvelope`, and rejects the migration while S4 is still
  writable if either is one object, byte, manifest row, service-staging row/byte
  or write lease short, or if the bounded final activation cannot fit. After
  restart and reachability GC, a
  new certifier fetches both retained preimages, verifies their content hashes
  against `MigrationBootstrapCommitment`, decodes the capacity vector and
  performs the componentwise comparison. A digest-only ceiling, a collected
  ceiling preimage, a redirected object, a schema mismatch, and an oversized
  ceiling/source object each fail before the fence or first-root CAS.
  After the fence, the exact snapshot remains within that ceiling; every
  prospective first-root object is written to a fixed cutover ordinal and every
  service row is written through several capped generation-scoped batches.
  Crashing between any two batches leaves S4 authoritative and the partial
  generation invisible. Every lease drains before CAS, and a final transaction
  within `MAX_CUTOVER_ACTIVATION_ROWS` and
  `MAX_CUTOVER_ACTIVATION_BYTES` flips the generation pointer with the complete
  root and one `CutoverCommitAnchor`. A grandfather admission row contains only
  `CutoverGeneration(service_generation_id)` until that bounded activation;
  its post-commit proof then binds the row to the anchor and computed root. The
  retained payload manifests, active service rows and anchor survive restart
  and reachability GC. Mutants that size only for one action, borrow canonical
  or revocation capacity, omit a grandfather/checkpoint/map object, put
  `committed_root_oid` in a descriptor-bound grandfather row, key the pre-root
  certificate reservation by that unknown oid, apply the
  workspace-sized-service-row-plan in the final CAS, expose a staged generation
  early, make the generation descriptor hash a manifest/root tail that already
  contains its oid, delete active generation rows as staging, or reclaim
  temporary cutover scratch before verified copy/certificate fail at their
  named boundary. The `root-bound-grandfather-row`,
  `root-keyed-cutover-certificate-reservation` and
  `cyclic-cutover-generation-manifest` mutants are rejected as unconstructible.
- Adversarial fact and index keys whose fids never hit `shape.boundary` still
  produce pages within every hard cap; an existing oversized message rebuilds
  through raw-fact chunks without changing its fid, while oversized
  Worker-visible records and excessive tree depth reject before publication.
  Forward, reverse, randomized, one-by-one and bulk construction of the same
  logical set under one `layout_seed` yields byte-identical B-treap pages and
  root oid; priority, weight-leader, padding and insertion-history-dependent
  B+tree mutants fail golden vectors. The migration selects the first fitting
  seed from layout-independent `cutover_basis_digest` or activates the writable
  S4 fallback after exactly `MAX_LAYOUT_SEED_TRIALS`; the test asserts
  logical-row digest, basis, candidate seed, universe-map root and final
  `cutover_digest` in that order, and requires the selected `layout_seed` as an
  explicit authenticated first-root field.
  Deriving the seed from a digest containing the seeded map root is a rejected
  dependency-cycle mutant. Deriving `LegacyMask` or its migration owner from
  `cutover_digest` is a second rejected dependency-cycle mutant: the test pins
  old source digest, `legacy_mask_namespace`, masked FactRecord/logical-row
  digest, basis, seed, map root and final digest in that order. A sealed
  workspace never repacks or rotates its seed.
  A maximum 32-binding `ExactSids` fixture with all eight EvidenceRefs uses
  `FACT_TS_MAX` in every exact 80-byte target/evidence fact key, includes one
  exact 32-byte `target_fact_record_oid` per binding, and proves the full
  `ActionRecord` fits `MAX_ACTION_RECORD_BYTES` while its FactTree
  `ActionSlot` remains within `MAX_TREE_ROW_BYTES`; negative, boolean,
  16-digit-positive, signed, whitespace-padded and ambiguous-colon keys reject,
  and an inline-target-spec or unbounded-inline-evidence mutant fails. The
  fixture constructs at most seven proposal/support `proof_refs`, hashes and
  signs the receipt, then appends exactly its one receipt EvidenceRef before
  hashing the ActionRecord. A seven-record input whose canonical bytes total
  `MAX_ADMISSION_PROOF_BYTES` plus maximum framing fits the 64 KiB pending and
  direct bundle; one more input byte rejects before receipt signing, and two
  individually legal records cannot evade the aggregate cap. Revocation
  capacity charges eight full `MAX_FACT_RECORD_BYTES` envelopes but only
  `MAX_ADMISSION_PROOF_BYTES + MAX_REVOCATION_RECORD_RAW_BYTES` raw bytes. A
  `per-record-max-raw-proof-liability` mutant that multiplies the raw maximum by
  all eight EvidenceRefs fails the exact boundary fixture. A sealed legacy
  16-digit-positive fact is never dropped or rekeyed: it aborts to writable S4
  or explicitly re-anchors. A mutant that includes the receipt ref in its own
  `proof_digest` is rejected as a content-hash cycle. After sync and restart,
  reachability GC starting only from the composite root and its atomically
  paired service state retains every proposal, detached signature/support fact,
  receipt, exact target FactRecord, principal-provider FactRecord and raw chunk
  needed to re-certify the action. The fixture shadows every direct target and
  one non-target provider out of the live FactTree, advances and collects the
  historical `DirectRoot`, and still replays each `DIRECT_TARGETS`/selector
  derivation through the ActionRecord's `target_fact_record_oid` and the
  principal scope through the registry's `provider_fact_record_oid`; a
  `drop-target-record-after-quarantine`,
  `principal-provider-bare-fid-after-quarantine`, dropping any evidence
  ref/object, or relying on a reverse cache fails.
  A separate post-cutover fixture admits an ordinary message that is neither
  action evidence nor a principal provider, shadows its authority chain so the
  message leaves the eligible proof DAG, advances and collects the historical
  root, restarts, and later restores the provider. The current FactTree still
  authenticates the same `ADMITTED(fact_record_oid)` and raw closure throughout;
  the message is ineligible while shadowed and reappears after restore without
  node-local `quarantine/` bytes. A `drop-post-s5-quarantined-fact-from-facttree`
  mutant, treating `ADMITTED` membership alone as eligibility, or restoring
  from the mutable local directory fails.
  A post-S5 ordinary fact whose deterministic raw representation spans more
  chunk/manifest objects than the fixed metadata scratch pool streams through
  bounded content batches, seals one paged `RawFactContentCommit`, and publishes
  one fixed commit/pin reference in the metadata attempt.
  Restart/certification follows every positional page and reconstructs the
  exact canonical bytes and raw-root hash, decodes them with the running codec,
  and recomputes the original body hash and envelope fid. The fixture proves
  that the raw-root hash is not generally the fid. It deliberately chooses
  chunk hashes whose lexicographic
  order differs from byte order and includes a repeated chunk; ordinals and byte
  ranges preserve both. Retrying the identical bytes in two upload generations
  yields one commit id, FactRecord and root. A collector racing after content
  seal sees `PENDING`, the root CAS atomically changes it to `ROOTED`, and a
  crash before that CAS must fence the attempt and record `ABORTED` before
  collection. Retrying those identical bytes after collection advances the
  same deterministic pin to a higher `PENDING` epoch before re-upload and then
  roots it; an old-epoch delayed writer rejects. Cutover separately proves a
  sealed pin generation remains live through activation and that only a
  fenced/drained `ABORTED` generation is collectible. The
  `inline-raw-fact-chunks-overflow-publication-attempt` mutation places those
  objects back in the eight-row metadata attempt and fails while the separated
  content-root path succeeds. `sort-raw-manifest-by-chunk-oid`,
  `content-generation-in-canonical-commit`, `hash-raw-bytes-as-fid`,
  `aborted-content-pin-blocks-retry`,
  `collect-sealed-content-before-metadata-cas` and
  `collect-sealed-cutover-generation` fail the order, convergence, identity,
  retry and lifetime variants respectively.
  At the non-escrow capacity boundary an ordinary fact fails before publication,
  a smaller subsequent fact still publishes, and a valid removal of every
  already-admitted target succeeds from reserved capacity, including its
  detached author signature and every other action-bundle record. The fixture
  fills the non-escrow FactRecord/raw-chunk, frozen
  legacy-universe/entry-map/effect-census, retained reconciled-S4-root,
  IAM-attestation and migration-seal object and byte dimensions independently;
  an implementation that charges only tree rows or
  `ActionRecord` bytes fails before the reserved action commits. It also fills
  served-cell and inclusion-witness rows and bytes independently and proves a
  missing mandatory slot blocks registration/publication before the root CAS.
  A partially
  redundant `ExactSids(A, B)` proposal rejects without spending B's liability;
  restaging B alone succeeds. When every current membership provider was already
  masked by prior exact removals, the first `MemberPrincipal` action still
  commits its terminal tombstone and future-provider escrow; only an equivalent
  committed principal receipt deduplicates it. The same boundary test fills the
  non-escrow `admit/` cell count and bytes, admission-log, TargetRegistry row
  and byte dimensions, and AuthorityCandidateRegistry row and byte dimensions:
  a new suppressible ordinary target rejects, while removal of every
  already-admitted target still commits its maximum-size signed receipt,
  maximum-size target row, bounded fallback-state rewrites and reserved service
  records. A 64-consequence boundary fills all forward values to 512 KiB:
  staging charges the full 32 MiB-plus immutable value set, while the strong
  commit writes only 64 fixed pointers and stays below the aggregate row/byte
  cap. The same fixture drives an ordinary authority publication through the
  162-object NeedKey-directory/base-candidate/full-candidate/impact/
  principal-provider maximum and proves the exact manifest, scratch and
  193-row pointer-write arithmetic, including the content-pin transition. An
  `inline-registry-values-overflow-atomic-commit` mutant attempts to write the
  full values in step 6 and exceeds the transaction cap; an
  `unbounded-authority-impact-value` mutant exceeds the reverse encoded-byte cap.
  Mutating away the bundle, cell-byte, target-row-byte, candidate-set,
  `AtomicCommitBudget`, terminal, migration-seal or service-record reserve makes the tests
  demonstrate the unevictable-member or unbounded-fallback failure.
- A target with more descendants than any request/action cap is removed with
  the same fixed-key action bound as a target with none. V1 retains every
  descendant's individual revocation liability; an eager-release mutant exceeds
  the bound. Optional `LiabilityReleaseCheckpoint` tests reclaim only capped
  off-request batches and prove that neither revocation success nor a later
  ordinary publication relies on reclamation. Filling
  `ContentCapacityEnvelope` with Bao and invite payloads still leaves a
  fully escrowed control-metadata removal publishable, while content upload
  remains rejected. Filling every optional `PendingCapacityEnvelope` slot with
  inert proposals likewise rejects further staging while a direct, bounded
  removal still publishes from control escrow. Shared-physical-quota and
  unbounded-pending-key mutants fail.
- A sealed valid 519-hop membership chain migrates through exact
  `LegacyAuthorityCheckpoint` records and obtains an S5 Worker grant within the
  64-fact/100-lookup budget; shadow/restore and later principal eviction still
  behave identically. A paired legacy provider has two over-budget closures
  with the same source fid but different paged legacy-proof oids and flattened
  liveness scopes; migration emits two distinct proof-bound checkpoints,
  spans the 519-hop closure across capped pages, retains both source proof
  preimages after historical-root GC, and suppressing one path masks only its
  checkpoint candidate. A
  `checkpoint-coalesces-proof-closures` mutant collapses them and fails.
  A mixed-order fixture places a deep formerly losing legacy source beside a
  shallow native provider. The checkpoint's new service-signed proof is
  deliberately shallower than both, yet selection still uses the certified
  source depth/fid/candidate-id tuple and preserves the native winner; a
  `checkpoint-reranks-legacy-candidate` mutant that uses checkpoint proof depth
  changes the winner and fails certification. A child device/admin then selects
  that checkpoint: its transport depth remains one, its logical depth becomes
  source depth plus one, and the native winner still wins. A
  `checkpoint-descendant-uses-transport-depth` mutant promotes the child and
  fails certification.
  New deep authority chains reject at authoring/admission
  before they create an unserviceable credential; swapping a canonical provider
  after opposite-order peer admission stays within the compositional role budget
  and converges. More than
  `MAX_MEMBERSHIP_PROVIDERS_PER_PRINCIPAL` providers reject before publication,
  including when earlier providers are quarantined rather than live.
  The root-inclusive no-cache byte-envelope assertion and cold-cache
  867-subrequest assertion pass; hostile byte, lookup and subrequest exhaustion
  tests fail closed before grant.
- Worker tests authenticate both present and absent suppression keys with
  exactly the request's own selectors plus selected providers and their declared
  liveness paths, no incidental proof-support selectors, no per-hit
  removal-evidence paths, and no full scan or SQLite reconstruction. A paired
  grantee-only fixture includes a suppressed grantor membership fact as
  authenticated proof support and still grants; the
  `worker-suppresses-all-proof-evidence` mutant incorrectly unions that fact's
  selectors and fails. Advancing the served cell
  uses exactly one bounded authority RPC backed by an off-request inclusion
  witness and returns a root/certificate-bound `WorkerReadLease`; every later
  object read and the grant use that same generation. A missing or raced
  witness, exhausted lease pool, expired token or token from another root fails
  without an on-request tree diff.
- I4 and the removal fingerprint are deleted; CUTOVER §3's DRY table still has
  one row per mechanism.

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

**SETTLED:** `AGENTS.md` survives as the short agent entry point beside
`README.md` and `DESIGN.md`, and points at `DESIGN.md` rather than preserving a
fourth plan. `tests/test_repository_layout.py::test_only_entrypoint_docs_live_at_root`
already ratchets that exact three-file root set.

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

### 9b. Bead bankruptcy — declared 2026-07-27

The pre-bankruptcy graph had **76 active beads** (75 open, one in progress) and
35 nominally ready. It mixed requirements for deleted T_supp/tree code,
unimplemented design-model epics, already-landed work, real bugs blocked behind
obsolete decisions, and one active agent implementing the design this branch
removed. Its dependency state no longer represented executable work.

The declaration snapshot was the live Dolt database, not the stale tracked
export at the branch's prior HEAD. At that instant `poc-16-yez.4` had already
closed independently and `poc-16-3tg` had opened; the 76 uniform bankruptcy
closures therefore include `3tg` and exclude `yez.4`. The export and executable
test below preserve that provenance.

Bankruptcy means:

- Preserve all closed history. Do not delete or compact the database.
- Close every bead that was active at the declaration, including the
  in-progress `poc-16-yez.11`, with one explicit reason: superseded by this
  document and `poc-16-kb6`.
- Do not copy dependencies from the old graph. A requirement survives only when
  this document states it and a replacement child owns it.
- The reproducible `3tg`, `gxz` and `up4` acceptance gap survive by being
  restated in S7, S5 and S9, not by reopening their old beads.
- `8lq` (multiple workspaces sharing one bucket, including naming, isolation
  and GC) is deliberately out of this recovery scope. It has no replacement
  owner and may be proposed afresh after S10; suppression selectors do not
  accidentally inherit it.
- Export the rebuilt graph to this worktree's tracked
  `.beads/issues.jsonl`, commit it with this document, and push the Dolt change.
- Claim `poc-16-kb6` during S0 and keep it in progress through S10. The epic is
  coordination state, not an independently claimable implementation task;
  `bd ready --exclude-type=epic` is the executable frontier. Only S10 may close
  it.

Replacement epic: **`poc-16-kb6` — Post-cutover recovery: explicit suppression
keys and indexed Worker reads.**

The complete replacement frontier is deliberately small:

| Track | Bead | Priority | Replacement work |
|---|---|---:|---|
| S0 | `poc-16-kb6.1` | P0 | Declare bankruptcy, publish this ledger and replacement graph |
| S1 | `poc-16-kb6.3` | P0 | Harden the removal-index door and recover from poisoned ingress |
| S2 | `poc-16-kb6.4` | P0 | Freeze suppression, authorization, receipt and bounded-proof contracts; land skeleton APIs/tests |
| S3 | `poc-16-kb6.2` | P0 | Implement explicit SELF/parent/ancestor selectors and dependency-closed masking |
| S4 | `poc-16-kb6.5` | P0 | Build shadow capped fact/suppression/authority trees and the bounded Worker lookup library |
| S5 | `poc-16-kb6.6` | P1 | Atomically cut to ingress/auth screening, immutable removal admission and bounded Worker grants |
| S6 | `poc-16-kb6.7` | P1 | Ship proposal/admission CLI/daemon commands and black-box lifecycle coverage |
| S7 | `poc-16-kb6.8` | P1 | Repair the shadow/restore sync wedge and hostile-input gaps |
| S8 | `poc-16-kb6.9` | P1 | Characterize and repair post/idle-sync latency |
| S9 | `poc-16-kb6.10` | P1 | Complete adversarial, confluence and mutation-proven coverage |
| S10 | `poc-16-kb6.11` | P2 | Consolidate README/DESIGN, delete stale docs/TODO and close the recovery epic |

No new feature line for versioning, encryption, infrastructure orchestration or
legacy compatibility exists after bankruptcy. A future design owner may propose
one from the truthful README/DESIGN baseline; the old bead is not a mandate.

### Done when

After S0 closes, the active graph contains only the claimed/in-progress
`poc-16-kb6` and unfinished S1-S10; `bd ready --exclude-type=epic` shows the
actual executable frontier; dependencies are acyclic; the tracked export
matches the database; the poisoning reproducer passes under S1; and S10
eventually moves the surviving design into DESIGN.md, deletes this file and
closes the epic. An open/ready recovery epic before S10 is the
`unclaimed-recovery-epic` mutation and fails the repository-layout ratchet.

---

## Suggested order

```
S0 bankruptcy ledger (this commit; then closes)

S1 poison recovery ---------------------------------------------------\
S2 contracts -> S3 selectors -> S4 shadow trees -> S5 cut -> S6 CLI ---+-> S9
                                      \-------------> S8 perf --------/     |
S7 sync wedge + hostile doors ---------------------------------------/      v
                                                                       S10 docs
```

S2 is the format-contract gate: no bodies before the exhaustive family matrix,
named resolved-edge/guard/receipt shapes, compositional `ProofBudget` and
failing test skeletons exist. S3 and S4 are the format break and land in that
order. S5/S6/S8 build on the new read path. S1 and S7 are independent critical
repairs. S9 is the integration/proof gate; S10 is the only child allowed to
delete this file and close `poc-16-kb6`.

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
