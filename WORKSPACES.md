# Workspaces, device groups, and infrastructure — architecture

Settling this **before** the chained-auth port (`CHAINED_AUTH_PLAN.md`), because the
port bakes in the workspace shape.

## 0. The reframe, and its collapse to something simpler

You asked for "a clever way to use facts and monotonicity" so one workspace can
"idempotently/atomically/monotonically issue commands to many devices above the level of
workspace." The first move is to **stop issuing commands** — replace them with facts a peer
reacts to. The second move, which you arrived at, collapses most of the machinery:

> **Workspaces are structurally independent. No control layer reaches into another
> workspace's tree.** The only cross-workspace primitive is *invite delivery + notification*.
> A "device group" or "provider org" is just an ordinary workspace used as a private channel
> that routes offers/keys/revocations to your devices/nodes and surfaces them; it has **zero
> authority** over any other workspace. Every join and every eviction is a normal,
> self-contained fact authored under the *target* workspace's own rules (member-can-invite,
> admin-evict). **"Meta" is a UX layer over ordinary invites, not a protocol layer.**

So there is **one invite mechanism** — member-can-invite — in **two forms**: a *bearer* invite
for a stranger whose key you don't know (two-step, self-authored join), and a *device-targeted
single-use* grant for your own device whose key you already hold (one-step, directly declares it
a member — the basis of cross-device mirroring, §3). The mint is a uniform **auth gate**: it
authorizes a key and **carries no content keys.** Otherwise what people call "different kinds of
invite" varies only along axes that are *not* structural and *not* part of the mint's payload:

- **Delivery route** (UX) — out-of-band link/QR (a new person) · in-band device-group channel
  (your own other devices) · in-band infra API (a provider's nodes).
- **Content-key access** (fact layer, separate and downstream) — whether content-key *facts*
  are ever wrapped to this participant. Full members: yes. Infra/sync nodes: no — they
  validate and serve ciphertext they cannot read. Decided by who gets the key-facts, **not**
  by the mint (§4).

The invite/join *fact structure* is identical in every case. Everything below is this one
idea; the **device group** and **provider org** are ordinary workspaces used as delivery
channels + rosters. Adding a workspace **binds** it onto all your devices in one multi-scope
command — the mirroring magic — and removing is one monotone tombstone that wipes it everywhere
(§3); yet every fact this authors is still a normal fact in the target tree under that tree's
own rules, never a cross-tree reach.

---

## 1. Layers

| Layer | Unit | Scope | Purpose |
|---|---|---|---|
| **Keychain** | device keys (enclave) | node-level, above all workspaces | identity; signs; unwraps |
| **Treap / fact tree** | one per workspace | per-workspace | replication (RBSR + hoisting) |
| **Materialized store** | one SQLite, `ws`-scoped rows | multi-workspace | the app's single source of truth for reads |
| **Command** | authors a fact | workspace-scoped (FE names the ws) | writes |
| **Control workspace** | a treap of desired-state facts | spans object workspaces | coordinates devices/nodes |
| **Reconciler** | a local loop | per node | turns desired-state into local join/leave facts |

- **Treaps are per workspace** (your point) — the reconciliation/sync unit. The mint is the
  gate to each.
- **SQLite is multi-workspace and scoped** (your point) — every row carries `ws`; the app
  queries one store and always knows the source of truth. Object workspaces *and* control
  workspaces project into it.
- **Commands are workspace-scoped** (your point) — the FE says "create fact X in ws W"; the
  command authors into W's treap and W's projection. The only commands that are *not*
  ws-scoped are keychain ops (link a device) and control-workspace ops (enroll/leave/grant),
  which are themselves just commands against a control workspace.

---

## 2. Two kinds of workspace

**Object workspace** — a normal content workspace (a community, a channel set). Full members
hold its content keys; it carries messages, files, membership, admin, removal.

**Control workspace** — an ordinary workspace used as a private **delivery + notification
channel**, carrying invite-offers, wrapped keys, and revocations to a set of targets. Same
treap, same sync, same auth chain, and — the key point — **no structural authority over any
other workspace**: it delivers, it does not enforce. Two instances:

- **Device group** (one per user/identity). Targets = the user's devices, held **flat: every
  device is an equal peer, no primary/ruler**. It holds two rosters — which device keys, which
  workspaces — plus wrapped keys and remove tombstones. Adding a workspace **binds (mirrors)**
  it onto every device at once (§3): a member device mints a device-targeted grant for each
  known device key. Linking a device is symmetric — it is admitted into every group workspace.
  Recovery is just this run in reverse from a survivor (§4).
- **Provider org** (one per infra provider). Targets = the provider's always-on nodes. It
  carries "we were granted infra on W (auth-only)"; each node, per the operator's standing
  policy, joins W **auth-only** (no content keys).

The device group is the concrete form of "a keychain sits above workspaces": the keychain is
the enclave keys; the device-group workspace is the *replicated roster* of which device keys
and which workspaces belong to the group — and adding a workspace binds (mirrors) it onto
every device via device-targeted grants (§3).

---

## 3. The mechanism: bind on the add side (magical mirroring)

You opt in **once, at the group level** — "add this workspace," "link this device" — and every
device mirrors it. Two facts make this work without the meta workspace ever gaining authority
over another tree.

**One invite mechanism (member-can-invite), two forms** — which one depends on whether you
already know the target's key:

- **Bearer invite** — a stranger whose key you don't know: an ephemeral invite key, two-step
  (*invite + self-authored join*; the joiner signs their own membership with their own enclave
  key, countersigned by the ephemeral key). A *person* joining.
- **Device-targeted, single-use invite** — your *own* linked device, whose durable key you
  already hold in the device-group workspace: the grant **names that key directly and declares
  it a member**, single-use, signed by an existing member device that vouches. **No
  self-authored join** — the key is known and an authority admits it. This one-step grant is
  what makes mirroring possible; it is the "different kind of invite."

**Adding a workspace is one command that spans scopes and fills a whole row.** Because you hold
every device's key, `add(W)` writes, atomically at the authoring client:

- into object workspace `W` — a device-targeted grant for **each** linked device key (online or
  not), plus the `content_key(W)` facts wrapped to each device's `dev_box`;
- into the device-group workspace — a `workspace_added(W)` fact recording W in the group roster.

Linking a *new* device is the symmetric command: grants admitting it into **every** workspace in
the group roster, plus a `device_added` fact. These one-shot admissions keep the whole
(device × workspace) matrix full.

**Authority stays in the target tree; the meta workspace holds only information.** Each grant is
a normal, independently-valid fact in `W`, signed by a member of `W` (member-can-invite). The
device-group workspace contributes only the *device roster* (which keys), the *workspace roster*
(which Ws), and the remove tombstones — no reach into `W`. So it is the **client command** that
spans scopes, not any cross-tree authority; structural independence (§0) is intact. The only
change from a pure self-authored picture is *who* authors the membership fact: an existing member
device vouching for a known sibling key, instead of the new device signing for itself — your own
devices need no self-authoring because you already know and trust their keys; a stranger still
does, because you don't.

**Removal is one monotone tombstone that wipes.** `remove(W)` is a single grow-only
`workspace_removed(W)` fact in the device-group workspace; every device honors it by **wiping W
from local scope** — dropping its treap, its projection rows, and ceasing to sync it. That's all.
(Removing a *device* is the separate `revoke_device` tombstone: instant local distrust
everywhere, plus an ordinary `admin`-evict authored in each shared W by a surviving member
device — no cross-tree reach, and its liveness in W needs a device to act there.)

**The reconcile tail.** The one-shot command fills every cell it can see, so the only residual
gap is genuinely-concurrent additions — device D linked on one device while W is added on
another, neither aware of the other's new cell. Any member device closes it: seeing "roster
device D is not yet a member of roster workspace W," it mints the device-targeted grant. The
common path is the single command; this is just the tail.

Three properties hold, the trio you named:

- **Idempotent** — every device-targeted grant is content-addressed (a deterministic function
  of device key + workspace + admitting member), so re-issuing it is a no-op. Replay, restart,
  and re-sync are safe; the reconcile tail can run every turn.
- **Monotone** — the device and workspace rosters are grow-only with terminal tombstones
  (remove-wins). Nothing is mutated in place, so no device observes an add→remove→add flap; a
  removal is one tombstone every device honors, forever.
- **Atomic at the client, eventually convergent across trees** — the multi-scope `add`/`link`
  command authors all its facts in one local step; there is no torn state to observe. They then
  propagate per-tree and converge — deliberately **not** a distributed transaction, the thing
  that would bring back the concurrency hell. Convergence without a coordinator.

**Coordination is stigmergic**: shared monotone rosters + independently-valid grants. No tree
grants another authority; the binding you feel as "magic" is one client command writing valid
facts into several trees at once. Causal safety is free from dep-closure — a `content_key(W,·)`
can't validate before the grant it depends on, and a device's later facts in W can't validate
before the grant that admitted it.

This is the same primitive as multi-hop delegation: a member device minting a device-targeted
grant for a sibling key **is** member-can-invite (the Phase-1 unlock in `CHAINED_AUTH_PLAN.md`),
just aimed at a key you already know. Cross-device mirroring and deep delegation are one
mechanism.

---

## 4. Keys and secure enclaves

| Key | Lives | Can | Notes |
|---|---|---|---|
| `dev_sign` (Ed25519) | **enclave** | sign every fact | never leaves the device |
| `dev_box` (X25519) | **enclave** | ECDH → unwrap key material | content key exits enclave for bulk decrypt (honest limit) |
| device-group / "user" | **not a key** — the set of device facts | — | enclave-friendly: no shared private key to copy |
| workspace structure | clear envelope, or a broadly-shared metadata key | read refs+offers, validate the auth chain, run closure/sync | held by **all** participants incl. infra; this is the **infra tier**, and it is **not** the content key |
| content key(s) | app memory, wrapped-at-rest to `dev_box`, distributed as **facts** | decrypt payloads | given to full members only; an infra node is simply never wrapped one; rotated on removal (epochs) |
| ephemeral invite key | transient | one mint; secret is the link | discarded after redemption; not enclave |
| founder/root key | transient | bootstrap only | dropped after genesis (poc-13 pattern); never durable |

The **user is a flat device set, not a durable key** — the single most enclave-friendly
decision: identity is the mutually-cross-signed roster of per-device enclave keys, so no
private key is ever shared, exported, or escrowed. **All devices are equal — there is no
ruler/primary device**: any device may admit or revoke another, and any device may author the
group's desired-state facts. **Recovery is by readmission**: any *surviving* device re-admits
a fresh one, so a single remaining device recovers the whole identity; if *no* device
survives there is no key to restore, so you rejoin through the normal invite gate as a new
member. That is the honest cost of holding no shared secret — and it is the intended
behavior, not a gap.

**The infra read boundary lives at the fact layer, not in the mint.** The mint is a uniform
**auth gate**: it authorizes a key to participate and carries **no content keys**. Content
keys are **facts**, wrapped to a participant's `dev_box` and distributed only to those who
should read. An infra/sync node is an authorized participant to whom content-key facts are
simply **never wrapped**, so:

- it holds the workspace *structure* (clear/broadly-readable envelopes + dep-refs, per the
  closure-aug split) and can validate the auth chain and run closure/sync;
- it serves opaque encrypted payload blobs to real members;
- it **cannot read a message**, because no content-key fact was ever delivered to it.

The boundary is enforced by *which key-facts get wrapped to whom* — a fact-layer distribution
decision — not by anything the mint contains. (An optional `role` on the invite — member vs
sync-only — can additionally constrain what an unread node may *author*; that is a refinement,
still not a key in the mint. Prerequisite either way: the closure-aug clear-envelope/dep-refs
split, so structure is readable without the content key.)

---

## 5. The infrastructure handshake (cross-workspace, same pattern)

Your sharpest framing, made concrete. A workspace admits *another workspace* (a provider org)
as an infra grantee; the grant fans out to that org's nodes:

1. **Self-present.** In object workspace `W`, a candidate node authors
   `infra_offer(org=P, node_pk, terms)` — "provider org P, node N, offers infra here."
   (Or an out-of-band application carrying P's control-workspace anchor.)
2. **Admit.** W's admin authors `infra_admit(P, scope=auth_only, at)` — monotone, revocable —
   and mints an **infra-scope** invite for P (envelope key only).
3. **Cross to P.** The admit + infra mint reach P's control workspace (in-band API on P's
   endpoint), becoming a desired-state fact `grant(W, envelope_key)` in P.
4. **Reconcile.** Every node of P sees `grant(W)` and pulls W in **auth-only**: syncs W's
   treap (structure + encrypted blobs), validates its auth chain, serves it. No content keys.
5. **Report back.** Nodes author `stat(W, residency, bytes, latency…)` facts into W (or a
   W-scoped side stream) — "share statistics to the original workspace."
6. **Revoke** from either side → tombstone → nodes drop W. Monotone, no race.

This is identical in shape to the device group: a control workspace declares desired
memberships, its targets reconcile. Device group = you admitting your own devices; provider
org = a workspace admitting an org's nodes.

Downstream capabilities this unlocks, all as more facts in the same trees:
- **Cross-provider FaaS/cloud control plane** — the provider-org workspace is a portable,
  auth-in-band manifest of who serves what across AWS/GCP/lambda/volunteers.
- **In-band volunteer infra** — communities delegate hosting by admitting an org; management
  (add/remove/observe) is just facts.
- **Automatic sharding of cold data** — with many always-on infra nodes in W, residency
  facts (poc-13 memory-limiting lineage) let cold ranges of W's treap be assigned across
  nodes and old data offloaded; the assignment is desired-state, reconciled the same way.

---

## 6. What reuses existing machinery vs. what is new

**Reuses (no new subsystem):** treap per workspace; RBSR + hoisting sync; dep-closure /
causal order; the fact/family kernel; member-can-invite; per-ws index + one scoped SQLite
projection. Control workspaces are ordinary workspaces; their families are ordinary families.

**New (small, additive):**
- `keychain` above workspaces (plural enclave device keys; §4). Generalizes today's
  single-`sk` `keyring.json`.
- Two control-workspace family sets: **device group** (`device`, `device_invite`, `enroll`,
  `content_key`, `leave`, `revoke_device`) and **provider org** (`node`, `grant`,
  `revoke_grant`, `stat`) — plus object-workspace `infra_offer` / `infra_admit` /
  `infra_revoke`.
- The **inbox agent** (lighter than a controller): a per-node loop that (a) *projects*
  delivered offers into surfaced notifications, (b) authors the local join only on a **user
  tap or standing policy** — never autonomously, (c) honors revocations (local distrust +
  key-wrap exclusion) and, where it holds authority in the target ws, authors the ordinary
  evict. It reaches into no other tree; it only turns delivered offers into ordinary
  target-ws facts. Idempotent by construction (`m(d,t)` content-addressed).
- **Content keys as wrapped facts** (`content_key(W, epoch, wraps-to-`dev_box`)`), and the
  fact-layer policy of *not* wrapping them to infra/sync participants — that non-wrapping,
  not the mint, is the infra read boundary. The mint stays uniform (auth only); an optional
  invite `role` can constrain authoring.

---

## 7. Removal, forward secrecy, causal safety

- **Removal is a tombstone**, honored by every reconciler forever (monotone). A removed
  device/node is excluded from *future* key wraps and its future authorship is rejected.
- **The flat-model tension (stated honestly).** With no ruler, a compromised device is an
  equal peer *until revoked* — it can admit and revoke like any other. Revocation is
  remove-wins and any surviving device authors it; **mutual** revocation (A revokes B while B
  revokes A) removes *both* — a fail-safe that collapses toward readmission rather than a
  split with two contested halves. There is no asymmetry to break ties because we chose not
  to have one; the price of "all devices equal" is that a stolen unrevoked device is fully
  powerful, so revoke-then-rotate promptly.
- **Forward secrecy** on removal ⇒ rotate the content key: author `content_key(W, epoch+1,
  wraps)` wrapped only to remaining devices. Epochs are monotone (added, never removed). Past
  data a removed party already synced cannot be clawed back — **state this limit honestly.**
- Epoch/rotation keys are just facts with an **applicability range** (unbounded future), so
  they hoist to their lowest level of applicability (the workspace, later a channel) — the
  same puncturable-key idea from the hoisting discussion, not special machinery.
- **Causal safety** is inherited from dep-closure: desired-state facts and their induced
  local facts are ordered by refs, so nothing applies before its prerequisite.

---

## 8. Open decisions (need your steer before the port)

1. ~~Identity model.~~ **RESOLVED.** Flat, egalitarian **device set** — all devices equal,
   no ruler/primary. Recovery by **readmission**: any surviving device re-admits a fresh one;
   with none left, rejoin as a new member (no key to restore). No durable user key, no
   designated recovery device, no escrowed seed. (§4, §7.)
2. **May infra blindly relay the *device-group* workspace?** If your devices are rarely
   online together they need a relay to exchange the meta-log. Its facts are already wrapped
   to device box-keys, so a blind auth-only relay leaks only the membership graph, not keys
   or content. OK, or keep device groups strictly device-to-device?
3. **Content-key granularity now:** per-workspace epoch (simple) vs. per-channel (finer
   forward secrecy, more wraps). Recommend per-workspace now, per-channel when the
   applicability-range/two-tree suppression work lands.
4. **~20 workspaces/node, arbitrarily-many/lambda:** confirm the reconciler runs one shared
   turn loop across all joined workspaces (fair-scheduled), not a thread per workspace — the
   lambda case makes per-ws threads untenable.
5. **Does `infra_offer` require the node already be an (auth-only) participant to self-present,
   or is self-presentation an out-of-band application first?** (Bootstrap ordering of step 1.)

---

## 9. Concurrency & confluence — many lambdas, one store

Many lambdas can process the pipeline concurrently with **no coordination and no lock**, because
the authoritative state is an **append-only, content-addressed set of piles** and the tree is a
**deterministic fold** of it. The convergence is by construction, not by luck.

- **Everything is content-addressed, so there is no write race on data.** Every pile and every
  treap node is named by its own hash and names its children by theirs; putting an object is
  idempotent, and two lambdas writing the same or different objects never conflict.
  Double-processing a pile is a no-op (the seen-set dedups).
- **Authoritative state = the grow-only pile set** — a CRDT: conflict-free, order- and
  timing-independent. That is *why* lambdas converge. The same accepted set yields a
  **byte-identical root** whatever order or subset each lambda saw it in — *given the same layout
  params/version* (CUT/COLD_CUT/GUARD); a config roll diverges roots transiently until all are
  on it.
- **The tree is a derived cache, not authoritative.** A lambda's root is a checkpoint of a pure
  function of the pile set; a stale or clobbered root loses **nothing** — anyone recomputes it.
- **No manifest of the *tree* is needed.** The structure lives entirely in the content-addressed
  child hashes; the whole state is one **root hash** (a git-HEAD-like ref). The shipped flat
  fence manifest is a *tiered-sync optimization* (O(log n) range fingerprints for the paged
  cold/tail layout), not a requirement — the pure treap needs none. The only set you must be able
  to enumerate is the **incoming piles**, and that is just the store's hash-named keyspace, not a
  written manifest.
- **The "current root" pointer is the only mutable cell, and it is optional.** It is a cache of a
  deterministic function: **CAS** it (read → fold → compare-and-swap) to avoid redundant
  re-folding, or drop it and let readers fold from the pile set. Losing a root update costs
  *work, never data*.

**On S3 (the target store) this is strong, not eventual.** Same-region GET/PUT/DELETE/LIST have
been strongly read-after-write consistent since Dec 2020, so a `LIST` of `pile/` sees every pile
`PUT` before it — the divergence window is your poll/event cadence (S3 Event Notifications fire in
~seconds), not store lag. Single-key **CAS is native**: `PUT root` with `If-Match: <etag>` (or
`If-None-Match: *` for write-if-absent) returns `412` on a losing race — the root-pointer CAS
above, with no external lock or DynamoDB. The only async surface left is **cross-region
replication** (seconds–minutes) and any CDN in front; S3-compatible stores without conditional
writes fall back to strongly-consistent last-writer-wins, which is safe here because the root is a
derived cache.

**On Cloudflare (R2 + Workers) the story is the same, with a nicer coordinator.** R2 gives strong
read-after-write on objects and native conditional writes (`If-Match` / `onlyIf: {etagMatches}`),
so the pile set is strongly consistent and single-key CAS on `root` works as above. The
difference: **Durable Objects** — a per-workspace, single-threaded, strongly-consistent actor —
can *serialize* root updates (and hold the in-memory fold + transactional storage), replacing
CAS-retry with a clean linearizable point that S3 lacks (optional — the chosen default is
non-serialized; see below). Workers are the stateless compute
(≈ lambdas), triggered by **R2 event notifications → Queues** (~seconds). Watch-outs: **Workers KV
is eventually consistent (~60 s) — never put `root` in KV**; R2 is largely single-location per
bucket (location hints, no built-in cross-region replication lag); Worker CPU limits (~30 s) mean
big cold folds belong in a Durable Object or chunked. Bonus: R2 has **zero egress** — a real win
for infra nodes serving pile bytes to members.

So the additive path is safe and convergent for free. **The one real hazard is GC**, and it is
exactly Merkle-store reachability GC (git gc): never delete an object still reachable from a root
anyone may use, and never delete an incoming pile before its facts are folded into a reachable
tree. Drive GC from *committed/converged* state, never a lambda's partial view — the
residency ⊇ coverage / evict-before-flush discipline (poc-13 memory-limiting lineage). Removals
converge too, because tombstones are monotone (remove-wins), independent of order.

**The non-serialized design (chosen).** No single-owner funnel — any Worker folds and
publishes; nothing routes through a per-workspace actor. Because *no operation is
non-commutative* (facts additive, tombstones remove-wins, fold deterministic), coordination is
never required for correctness — only, optionally, for freshness or to damp wasted work.

- **The root is an append-only *set* of checkpoints, not one mutable cell.** Each folder
  publishes its root as a content-addressed object and appends the hash to a grow-only `roots/`
  set; the true state is `merge(live roots)`, always well-defined and **never clobbered** (no
  overwrite ⇒ no lost update, not even transient). A background **sweep** merges them into one
  canonical root and tombstones the subsumed ones. *(Simpler variants, still non-serialized, no
  DO: a single `root` key updated by CAS — `If-Match`/`onlyIf`, optimistic and retry-on-conflict;
  or blind last-writer-wins healed by the sweep.)*
- **Folding is idempotent and multiply-triggered:** an R2 event per new pile, plus any reader's
  reconciliation (which discovers unfolded piles), plus a periodic backstop sweep. Overlapping
  folds are safe — path-copy gives structural sharing, and two roots **merge to a unique third in
  O(diff)** via the same RBSR descent (no re-fold from scratch). Piles are closed, so folds carry
  no cross-pile ordering dependency.
- **Readers pick their guarantee.** Fast path: read any recent root and serve it (may lag new
  piles by ~fold latency). Authoritative path: merge the `roots/` set / reconcile against peers.
  **Read-your-writes needs no server coordination** — the writer folds its own pile locally (or
  checks its hash is reachable) right after the PUT.
- **GC is the one remaining discipline, made generational.** Reclaim a pile only once it is
  reachable from a durable root, and treat **every root within a grace window as live** (Merkle
  mark-and-sweep from all recent roots — `git gc` with a reflog window); never collect newer than
  the window. That is residency ⊇ coverage without needing a commit point.

**Give up:** an instant shared "latest" pointer (mitigated client-side), a single clean commit
moment for GC (replaced by the grace window), and some redundant folding (cheap + idempotent).
**Gain:** horizontal scaling with **no per-workspace bottleneck**, pure Workers + R2 (no DO
dependency), and no single point of contention or failure. A Durable Object stays available as a
*per-workspace opt-in* — for instant-fresh reads or folding-suppression on a hot workspace — but
is **never the default**.

**Structure & prior art.** With **fat B-tree Merkle nodes** — each node carrying its children's
`(hash, fingerprint)` — the tree is self-describing and shallow (log_B N levels, ~2–3 at scale),
so the **flat manifest is unnecessary**: walk the fat root, prune children by fingerprint, fetch
the differing subtrees in parallel. A `Range` read of a node's fingerprint region trims bytes,
and because one fat node holds *all* its children's fingerprints, one fetch prunes many children
— round-trips drop too. Trade vs. the flat manifest: a 2–3-level fat walk instead of one manifest
GET, bought with structural sharing on writes and unbounded scale (the flat manifest itself grew
with page count); keep a cached top node as a manifest-equivalent only if single-fetch full
catch-up matters. None of this is novel — it is the **Merkle Search Tree** (Auvolat & Taïani,
SRDS 2019) / **prolly tree** (Noms → **Dolt**, which `bd` runs on) line: history-independent,
content-addressed, content-defined chunking (à la **LBFS**, SOSP 2001). Reconciliation is
**Range-Based Set Reconciliation** (Meyer 2023; Willow/Earthstar), with **Dynamo** Merkle
anti-entropy (SOSP 2007) as the binary special case; **CPISync** (Minsky et al. 2003) and
**IBLT / "What's the Difference?"** (Eppstein et al., SIGCOMM 2011) are the O(diff)-communication
alternatives without ordered scans. The **static-source** enabler is baking **precomputed
fingerprints into the immutable nodes**, so a dumb store supports a reader-driven pruned walk with
only GETs — exactly git's **"dumb HTTP"** over a Merkle object DAG.

**Consistency verdict.** The tree is a **state-based CRDT (CvRDT)**: roots form a join-semilattice
under set-union, `merge` is the deterministic O(diff) tree-join, every update is monotone (MSTs
are *defined* as state-based CRDTs). So we get **Strong Eventual Consistency** (Shapiro et al.):
two participants that have observed the same set of updates hold a **bit-identical root** — "same
state" is one hash compare — with no conflict resolution, no divergence, only staleness that
self-heals on the next merge. The sole mutable state is a **32-byte root hash per workspace**, and
even that is optional (state ≡ `⊔(all published roots)`, computable by anyone). Convergence is
bounded by **anti-entropy cadence** (events/gossip/poll), not store lag. Client-tunable on top:
**read-your-writes** (merge your write locally), **monotonic reads** (merge, never replace; track
a watermark), and **causal** consistency free from dep-closure. Only linearizability needs a
per-workspace serialization opt-in (DO/CAS); everything up to causal + SEC is coordination-free.

What you deliberately forgo — and never need: a global total order of piles, synchronized
delivery, or a lock. Transient divergence (lambdas mid-catch-up) is **stale, never wrong**, and
self-heals as each absorbs the rest of the pile set.
