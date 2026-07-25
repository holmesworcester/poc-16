# Chained auth port — plan of work

**Goal.** Bring poc-13's authentication model into poc-16 so the workspace can grow
a genuine multi-hop **delegation tree** (A invites B, B invites C, …), then use that
to test hoisting on **chained seeds** — closing the "depth-1 star" caveat in
`MULTILEVEL_PILE.md` §A.5.

**The one model difference (lambda-centric).** One workspace per fact tree; do **not**
mingle workspaces yet. A **keychain sits above workspaces** — node-level identities
(keys) that are decoupled from any single tree. So we port poc-13's *authority* facts
and *keychain* layer, and we deliberately **drop** poc-13's workspace-mingling machinery
(`active_workspace`, the multi-workspace `workspace` index).

**Match poc-13's structure and simplicity as much as possible** — see the rubric in §2.
This is the primary style constraint on the whole port.

**Consistency with the settled model.** `WORKSPACES.md` is the model-of-record for how poc-16
does multi-workspace / identity / infra; this port must stay consistent with it. Four points it
fixes that touch this plan:
1. **member-can-invite is the foundational primitive**, not just a depth knob — cross-device
   mirroring and infra admission ride on the *same* rule (a member vouching for a key). §1's
   one-line change is load-bearing well beyond the hoisting test.
2. **Two invite forms.** *Bearer* (ephemeral key, two-step invite + self-authored join — today's
   poc-16 `invite`+`join`, for a stranger) and *direct-key / device-targeted single-use* (names
   a key you already know and declares it a member, one-step, no separate join — for your own
   devices). **Phase 1 needs only the bearer form**; the direct-key form is Phase 3 (§6).
3. **Content-key access is a fact-layer concern** (`WORKSPACES.md` §4), *not* in the mint. The
   hoisting seed uses cleartext facts, so key-wrapping / "mint scope" is **out of scope** here —
   do not add it.
4. **Identity is a flat device set** (all device keys equal, no ruler; recovery by readmission).
   For the measurement a "user" is that *set* of keys, reconstructed from the device roster — not
   a single durable key.

---

## 1. Why poc-16 is stuck at a star, and the single change that unblocks it

poc-16 today builds a **depth-1 star** by construction, for two reasons:

1. `tinyp2p/facts/auth/invite.py` — `needs()` requires the signer be **`admin`**:
   ```python
   def needs(f):
       pk = f.body.get("pk", "")
       return (("author", f.fid, pk), ("admin", pk, None))   # admin-only
   ```
   Only the genesis founder is admin (there is no admin-delegation fact), so **every**
   invite is founder-signed → every member is one hop from the root.

2. `tests/util.py::add_member` hardcodes `n.pk` (the founder) as the inviter.

poc-13 encodes the different rule that produces depth. `facts/auth/user_invite.py`:

> *"Simplest honest rule (stated): any member, or the founder, may invite a user."*

Its `project` blesses an invite whose signer is `root` **or any member `key`**. Because
`user`/join publishes the joiner's key as a member key, **once B joins, B can invite C.**
That is the whole mechanism for depth.

**The unlock is one line:** change poc-16 `invite.needs` from `("admin", pk, None)` to
`("member", pk, None)`. `join` already provides a `member` offer for every joiner, and
genesis provides one for the founder, so any enrolled member's key then resolves as a
valid invite signer. Keep `admin` for `evict` (removal) authority; per poc-13, an
admin-only or single-use invite is *"a later value-compare, not new machinery."*

Everything else in this plan is (a) building seeds that actually exercise the depth this
unlocks, (b) the keychain/device layering the user asked for, and (c) the measurement.

---

## 2. poc-13 fidelity rubric (apply to every file you touch or add)

poc-16's auth family already mirrors poc-13's discipline; keep it exact.

- **One file per family** under `tinyp2p/facts/auth/`. `__init__.py` stays a pure
  router / table-of-contents (poc-13's `Router`, poc-16's `MODULES` list). No policy in it.
- **Rigid section skeleton, in order, with the banner comments** the existing files use:
  `SHAPE` → `NEEDS` → `VALIDATE` → `MODE` (`DURABLE`/`global_rows`/`blob_refs`) →
  `MATERIALIZE` → `COMMANDS` → `QUERIES`. (poc-13 calls them SHAPE/EXTRACT/PROJECT/
  COMMANDS/QUERIES/CLI — same spirit.)
- **SHAPE is the only place atoms are chosen.** Constructors build the canonical fact;
  `validate` re-derives the SHAPE and compares (`f == shaped`) so every cross-field
  constraint comes for free. Do not hand-check atoms in `validate`.
- **VALIDATE/PROJECT is the only place meaning lives.** Pure, immutable, exactly `bool`;
  no projection, no mutable globals (those belong to the optional `evaluate` hook).
- **COMMANDS: build a fact, admit it, stop.** Terse. Keep the "publish one signed fact
  with its authority edge" helper pattern (`_commands.publish` / `closer`).
- **Docstring states the honest authority rule** in one or two sentences, poc-13-style
  (e.g. *"any member, or the founder, may invite"*), and names the poc-10/poc-13 lineage.
- **CLI/queries are a thin string boundary**; observations over validated state only.

**Vocabulary map (poc-13 → poc-16), so you can read poc-13 and port intent, not code:**

| poc-13 (projection/gather kernel) | poc-16 (offers/needs kernel) |
|---|---|
| `Atom(PROVIDE, name, scope, key, val)` | an `offer` atom → `f.offers()` |
| `Atom(REQUIRE, name, …)` / `by(ctx, name)` | `needs()` address resolved by `offer_src` |
| a `ref` to another fact id | a `ref` atom → `f.refs()` |
| `project(f, ctx) -> Out(provides=…)` | `validate(f, ctx) -> bool` + `materialize` |
| `signature.blessed(ctx)` value-compare | `offer_src(db, "member"/"admin", pk)` |
| `local_signer_secret` (node identity fact) | **keychain** (see §5); node `sk/pk` today |
| `workspace` (root, embeds root pk) | `workspace` (was `genesis`; root, founder = member+admin) |
| `user` / `user_invite` | `user` / `user_invite` (was `join`/`invite`; bearer form, two-step) |
| `device` / `device_invite` | `device` / `device_invite` **new** (§6); direct-key grant — names a known key, one-step |
| `active_workspace`, ws index | **dropped** (one tree per workspace) |

**Naming: use poc-13 names (decided).** Rename the families to poc-13's vocabulary as the
**first, mechanical step** — before any semantic change — so everything downstream reads in
poc-13 terms:

| poc-16 today | → poc-13 name | TAG | file |
|---|---|---|---|
| `genesis` | `workspace` | `genesis`→`workspace` | `genesis.py`→`workspace.py` |
| `invite` | `user_invite` | `invite`→`user_invite` | `invite.py`→`user_invite.py` |
| `join` | `user` | `join`→`user` | `join.py`→`user.py` |
| `signature` | `signature` | `sig`→`signature` | (file unchanged) |
| `removal` | `removal` | `evict` (keep) | (file unchanged) |
| — new — | `device`, `device_invite` | new | `device.py`, `device_invite.py` (§6) |
| — new, optional — | `admin` | new | `admin.py` (§7) |

Bare tags (no poc-13 `auth.` prefix — keep poc-16's flat tag convention; add the prefix only if
you want that too). The rename touches every import + test/bench (`tests/util.py`,
`bench_sync.py`, `bench_order.py`, `cli.py`, `cmds.py`, `content/message.py`, …) — do it as **one
mechanical commit, kept green**, before touching semantics.

**One semantic note on `genesis`→`workspace`.** poc-16's root fact makes the founder
member+admin in a single fact; poc-13's `workspace` is *only* the root, and the founder joins via
the first invite + a bootstrap `admin`. Keep poc-16's simpler baked-in bootstrap under the new
name (recommended, minimal). Adopting poc-13's separate founder-`user` + bootstrap-`admin` flow
is a larger change, **not** needed for the hoisting test — flag as an optional fidelity follow-up.

**Note on the rest of this plan:** §§1, 4, 7 name today's files (`invite.py`/`join.py`) for
accuracy about current code; substitute per the table above once renamed.

---

## 3. Deliverables at a glance

| # | File | Change |
|---|---|---|
| 3.0 | *(rename, first)* | poc-13 names: `genesis→workspace`, `invite→user_invite`, `join→user`, tag `sig→signature`; one mechanical commit, kept green (§2). |
| 3.1 | `tinyp2p/facts/auth/user_invite.py` (was `invite.py`) | `needs`: `admin`→`member`; docstring states "any member or founder may invite". |
| 3.2 | `tests/util.py` | `add_member(n, ws, name, inviter=…, ts)` takes an explicit inviter identity; add `grow_tree(...)`. |
| 3.3 | `bench/seed_chain.py` *(new)* | build a delegation **forest** (tunable shape) + content; bulk-insert like `bench_sync`. |
| 3.4 | `bench/bench_order.py` | run on the chained seed; confirm `deleg` (DFS) no longer collapses to a star. |
| 3.5 | `tinyp2p/keychain.py` *(new)* | node-level plural identities above workspaces (mirror `local_signer_secret`). |
| 3.6 | `tinyp2p/facts/auth/device.py`, `device_invite.py` *(new, optional)* | the user↔device split + the direct-key grant form (§6); enables user-grouping vs device-grouping in the measurement. |
| 3.7 | `tinyp2p/facts/auth/admin.py` *(new, optional)* | admin-grant fact (member-gated by founder root) if evict authority should delegate. |
| 3.8 | `MULTILEVEL_PILE.md` §A.5 | replace the star caveat with the deep-chain result. |

Stage in the order below. **Phase 1 alone satisfies "test hoisting with chained seeds"**;
2–4 add the poc-13-faithful keychain/device model and richer measurement. The user may
scale down after Phase 1.

---

## 4. Phase 1 — deep chains + the core measurement (the must-have)

### 4.1 `user_invite.py` (was `invite.py`) — member-can-invite (3.1)
Change the one `needs` line (admin→member). Update the docstring to state the rule.
Nothing else in the family moves: `join` already provides `member` per joiner.

**Confirm the resolver path.** `resolve_deps` for an invite calls
`offer_src(db, "member", inviter_pk)` → the inviter's `join` fid (or `genesis` fid for the
founder). So an invite by member B closes over B's join, which closes over B's invite, …
up to genesis. The **closure spine of a join *is* the delegation path.** Add/keep a unit
test that a member-signed invite validates and a non-member-signed one does not.

### 4.2 `add_member(inviter=…)` (3.2)
Today `add_member` uses `n.pk` (founder) and resolves the inviter's `admin` source.
Generalize:
```python
def add_member(n, ws, name, inviter=None, ts=None):
    # inviter = (sk, pk) of an existing member; default = founder (n.sk, n.pk)
    isk, ipk = inviter or (n.sk, n.pk)
    inv = invite(ipk, ephemeral_pk, ts)          # invite authored BY the inviter member
    si  = signature(isk, ipk, inv, ts)           # ... and signed by them
    ...
    msrc = offer_src(n.idx(ws), "member", ipk)   # was "admin"; the inviter's member source
    deps = {inv.fid: [si.fid, msrc], si.fid: [],
            j.fid: [inv.fid, sj.fid], sj.fid: []}
    n.ingest_new(ws, [si, inv, sj, j], deps)
    return bsk, bpk, j
```
**Invariant to preserve:** the inviter must already have joined (its `member` offer must
exist) and `ts(inviter.join) < ts(invite) < ts(join)`. Keep timestamps **monotone along a
chain** so the closure DAG stays acyclic; content-message ts stays random over the window.

### 4.3 `seed_chain.py` — grow a real forest (3.3)
Build on `bench_sync`'s bulk-insert style (facts straight into the index, one layout at the
end — O(n log n), never replay turns). Grow the membership as a **tree**, not a star:

- **Realistic shape (default):** each new member picks a random *existing* member as
  inviter (preferential-attachment optional). This yields ~`log(N)`-depth trees — the
  honest "who really invited whom" shape.
- **Adversarial-deep shape (flag):** force a long spine (each member invites exactly one
  child) to stress depth, plus a shallow-wide shape (founder invites everyone = today's
  star) as the low bar. Parameterize `shape ∈ {star, wide, random, chain}` and record the
  realized **depth distribution** (min/median/max hops to root) in the seed stats.

Then author messages exactly as today (`bulk_author`: msg+sig per member, random ts).
Return `(node, ws, stats)` with the depth histogram so the measurement can bucket by it.

> **Realism note to carry into the writeup:** a real Quiet-style graph is shallow-and-wide
> (a few admins invite most people). Measure *all* shapes so the conclusion distinguishes
> "hoisting's delegation order helps in the realistic shallow case" from "…in the
> adversarial deep case." Do not report only the deep number.

### 4.4 Re-run `bench_order.py` on the chained seed (3.4)
`bench_order.py`'s `deleg` reconstruction is **already the corrected one** (parent built
via *joins*, not the invite's ephemeral invitee field — see the trap in §7). It builds
`parent[member] = inviter` from `join → invite ref → invite's signer`, then DFS-preorders.
That logic generalizes from depth-1 to depth-*d* unchanged; **verify** it now recovers the
multi-hop tree (in the star it degenerated to "everyone's parent = founder").

**What to measure and the hypotheses to confirm/refute:**

- `ts` (shipped): tax stays flat ≈ `4 × members` regardless of depth (scatter). *Baseline.*
- `author` (group by signer pk): content co-locates per key; invites/sigs stay high.
- `deleg` (DFS preorder of the real tree): **an ancestor's own facts sit on the root-path
  prefix of its whole subtree.** Predicted: the range-sync **tax to pull the subtree under
  member X ≈ 4 × depth(X)** (its ancestors' membership facts), i.e. **path-length-bounded,
  not `N`-bounded.** This is the claim the star could not test — with depth 1 "path length"
  and "distance to founder" are the same constant, so beneficiary-grouping and DFS looked
  identical. With real depth, **DFS should beat flat beneficiary-grouping** because only DFS
  makes an ancestor contiguous with (a prefix of) its descendants' range.

Report, per shape: leaf-only ρ, ML full-sync (order-invariant `|V|`), over-inclusion %, and
the tax + crossover at 1 / small / large / full subtree — same table `bench_order` prints
today, now with a **depth** column.

**Acceptance for Phase 1:** on the deep shape, `deleg` tax at a subtree scales with that
subtree's depth (not with `N`), and `deleg` strictly beats `author`/`ts`; on the star shape
the numbers reproduce today's §A.5 figures (regression guard). Tests stay green.

---

## 5. Phase 2 — the keychain above workspaces (3.5)

poc-16's `keyring.json` is *already* structurally "a keychain above workspaces": it holds
one `sk` plus a `workspaces` map. Generalize it to **plural identities**, mirroring poc-13's
`local_signer_secret` (single durable node identity) but as a small node-level holder:

- `keyring = {"keys": {kid: sk_hex, …}, "workspaces": {ws: {..., "identity": kid}}}`.
- `tinyp2p/keychain.py`: `add_identity()`, `identity(kid) -> (sk, pk)`, `default()`,
  `bind(ws, kid)`. Keep it as terse as `local_signer_secret.py` (a keygen + a `current`).
- The keychain is **not a fact inside any tree** and never syncs — exactly poc-13's
  `b"local"`-scoped signer secret, just plural. Each workspace membership uses one identity.
- **Do not port `active_workspace`** or a multi-workspace `workspace` index. One tree = one
  workspace; the keychain is the only thing that spans them.

For the seed, the keychain is simply the set of member keypairs; today the bench already
holds them in a `members` list — Phase 2 just gives that list a first-class home above the
workspace so the model matches the user's description. This phase is **structure, not new
measurement**; keep it minimal.

Per `WORKSPACES.md`: identity is a **flat device set** — every device key an equal peer, no
ruler, recovery by readmission — so the keychain is exactly that set of equal keys (enclave-backed
in a real deployment, plain hex in the seed). The device-group *workspace* is their replicated
roster; the keychain is the local secret-holder beneath it.

---

## 6. Phase 3 — user ↔ device split (3.6, optional, poc-13-faithful)

poc-13 separates a **user** (durable membership identity, the invited/joined key) from a
**device** (a node's operating/endpoint key, self-attested, *"valid only if the signer is an
enrolled member"*). A user can drive several devices; `device_invite` is *"literally the same
shape as user_invite."* Port both as new families rhyming with `invite`/`join`:

- `device_invite.py` ≈ `invite.py`: a member blesses a fresh device key (member-gated).
- `device.py` ≈ `join.py`: binds a device/operating key to a user; provides an
  `operator`/`device` offer under that user. Drop poc-13's endpoint/transport atoms
  (`endpoint_shared`, X25519) — not needed for the hoisting question; keep only the
  authority binding.

**Reconcile with `WORKSPACES.md`.** There, the device-targeted invite is the **one-step
direct-key grant**: because the inviter already holds the sibling's durable key (from the device
roster), it names that key and declares it a member directly — no ephemeral key, no separate
`device` join. So `device_invite` + `device` can collapse to a *single* direct-key grant for the
known-key (mirroring) case; keep the two-family split only if you also want to admit a device
whose key you do *not* yet know. And since identity is a flat device set, the measurement's
"user" = that set of keys (from the roster): **user-grouping** = group a device set's keys
together, then DFS over device sets.

**Why it matters for the measurement (not just fidelity):** content is authored by *device*
keys, but the delegation tree is over *users*. So a **user-grouping** order (all of a user's
devices' facts together, then DFS over users) vs a **device-grouping** order (`author` today)
diverge exactly when users have >1 device. Add a `user` order to `bench_order.py` and show
user-grouping ≥ device-grouping when the seed gives members multiple devices. This is the
one place the device layer changes a number rather than only the shape.

Keep Phase 3 gated behind a seed flag (`devices_per_user`); default 1 (= Phase 1 behavior).

`admin.py` (3.7) is independent and only needed if `evict` authority should delegate beyond
the founder; port poc-13's `admin` (member-gated by the founder root) if desired, else skip.

---

## 7. Correctness traps — read before writing the seed or the measurement

1. **The ephemeral-invite-key trap (this bit us twice).** An `invite` names an *ephemeral*
   `invitee` pk that the joiner never signs with — the member joins with a *different*
   operating key, linked to the invite only by the join's **ref**. So you **cannot**
   reconstruct "who invited whom" from the invite's `invitee` field (`invitees ∩ member_pks
   = ∅`). Reconstruct via: `member = join.member_pk`; `parent = author of the signature over
   the invite that this join refs`. `bench_order.py` already does this correctly — do not
   "simplify" it back to the invitee field.

2. **Timestamp monotonicity.** Along any invite chain, `ts(parent.join) < ts(invite) <
   ts(join)`. Otherwise the closure DAG can cycle and `_spans` will assert. Content ts stays
   random over the window (that scatter is what makes the `ts` baseline honest).

3. **Every published leaf still closes alone** (leaves-are-piles). After the chained seed,
   `bench_sync.check_leaves` must still pass — a leaf's pile must carry its full delegation
   closure. This is exactly what hoisting/path-closure guarantees; use it as an oracle.

4. **Order is a relabeling only.** In `bench_order`, changing the sort prefix must not change
   fids, deps, closures, or the by-hash tree shape — only *which leaf* a fact lands in.
   Keep that invariant explicit (the module docstring already asserts it).

5. **Report what you drop.** If the seed caps depth, samples, or fixes a shape, `log`/print
   it. A silent star masquerading as a chain is the failure mode this whole plan exists to
   fix.

---

## 8. Acceptance criteria

- [x] `invite` accepts a member-signed invite and rejects a non-member-signed one (unit test).
- [x] `seed_chain.py` produces a forest with **measured** median depth > 1 on the `random`
      shape and a long spine on the `chain` shape; depth histogram printed.
- [x] `bench_order.py` on the deep shape shows `deleg` tax scaling with subtree **depth**,
      strictly below `author` and `ts`; on the `star` shape reproduces current §A.5 numbers.
- [x] `bench_sync` catchup/bidi and `check_leaves` still green on the chained seed.
- [x] (If Phase 3) a `user` order ≥ `author` order when `devices_per_user > 1`.
- [x] `MULTILEVEL_PILE.md` §A.5 updated: the star caveat replaced by the deep-chain result,
      stating honestly which shapes it helps and by how much (path-length vs `N`).
- [x] Every touched/added file passes the §2 rubric (section skeleton, docstring rule,
      "build a fact, admit it, stop", one-file-per-family, router `__init__`).

## 9. What to hand back

The updated §A.5 numbers for all four shapes (`star`/`wide`/`random`/`chain`), the depth
histograms, and a one-paragraph verdict: **does aligning key order to the real delegation
tree turn the range-sync tax from `O(members)` into `O(depth)`, and does it matter for the
realistic (shallow-wide) shape or only the adversarial (deep) one?** That verdict is the
actual point of the exercise.

**Verdict.** Yes: delegation-DFS order turns semantic-subtree range tax from
member-scale timestamp scatter into the ancestor path plus a small leaf-boundary
residual — `O(depth)`, measured directly as 401/361/197 facts for chain depths
99/90/50 instead of 49,424/45,154/25,112. The largest practical gain is not the
adversarial chain, where `depth = Θ(N)`, but the realistic shallow-wide shape:
mean tax falls 399→48 (8.3×, and 3.8× below author grouping); the chain mainly
shows the bound and still benefits from avoiding scatter, while hoisting's
ship-once/verify-once property remains order-independent.
