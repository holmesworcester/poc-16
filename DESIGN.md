# POC-16 design

This document describes the code on `main`. It distinguishes running behavior
from limits and future work; it is not a backlog.

## Goal and trust boundary

POC-16 asks whether peers can reconcile an authenticated workspace against a
counterpart that mostly serves immutable bytes. The active peer performs the
walk, verifies hashes, validates fact closures, and updates local projections.
The responder supplies a small authentication gate plus an object-store-shaped
HTTP surface.

The prototype provides integrity, deterministic reconciliation, logical
suppression, and bounded request-time authorization reads. It does not provide
body confidentiality, physical erasure, production-grade garbage collection,
or compatibility across format stamps.

Fact bodies are plaintext JSON. Signatures authenticate facts. Only invite
blobs are encrypted with a secret carried in the invite link. Attachment bytes
are content addressed and Bao verified, but the surrounding file facts are not
encrypted.

## Authority flow and code map

The runtime is a downward authority chain, not a collection of peer managers:

```text
daemon / local command                         host adapters
        ↓
WorkspaceRuntime.turn                          one socket-free turn
        ↓
kernel → registered fact family                judgment and policy
        ↓
Catalog.settle                                 admitted receipt → eligibility
        ↓
Publisher.publish                              snapshot → one root CAS
        ↓
pump                                            disposable client read model

root + immutable-object fetches → WorkerView   database-free CF authorization
```

`Node` composes local identity, workspace handles, diagnostics, and these
boundaries. It does not define family policy. Sync and local authorship both
enqueue the same pile bytes; `WorkspaceRuntime` is the normal coordinator,
`Catalog` alone decides current standing, and `Publisher` alone advances
`root`. The daemon handles HTTP and token sealing. Its node-local control
surface dispatches one qualified command path through the checked
`facts.COMMANDS` registry; typed application commands remain beside their fact
families, and adding one does not add a CLI or daemon branch.

An engineer should read the running path in this order:

1. `core/fact.py` and `core/suppression.py`;
2. `facts/__init__.py`, then one auth and one content family;
3. `core/kernel.py`;
4. `core/runtime.py` and `core/catalog.py`;
5. `core/publication.py`, `core/manifest.py`, and `core/indexes.py`;
6. `core/worker.py` and `core/mint.py`;
7. `core/sync.py`, `core/walk.py`, then `core/daemon.py`.

## Facts and the kernel

A fact is a canonical JSON value containing:

- a type tag;
- an integer timestamp;
- clear-envelope atoms for references, offers, and suppression policy; and
- a family-owned body.

Its `fid` is the SHA-256 hash of those canonical bytes. Its reconciliation key
is the fixed-width string `(timestamp, fid)`. Timestamps primarily provide
locality and deterministic ordering; the prospective admission rule described
under “Action timing” also compares that key.

A pile is a canonical, topologically ordered, dependency-closed collection of
facts plus optional blobs. The same pile codec is used for ingress, sync, and
resident leaf objects.

The family-neutral kernel processes a pile in one pass. A `ref` carries its
own role and must name an earlier fact. Each family returns named `Need`
values; the kernel selects each canonical provider by shortest proof rank and
then fid. There is no second tag-indexed role table. Every family module owns
one `POLICY` beside its behavior, and `facts/__init__.py` is the one checked
registry. `facts/_policy.py` supplies the vocabulary for selectors, direct
targets, guards, liveness, and typed principal/action offers.

Persistent validity is immutable and does not read wall-clock state. An
ephemeral request family owns its database-free Worker authorization hook,
including verb and expiry checks against trusted service time.

Ingress dependency choices are hints, not authority. The client catalog
resolves every named edge again against its complete local candidate set and
runs the same family validator before granting standing. A sender therefore
cannot preserve a losing ownership or membership edge when the receiver has a
better canonical provider.

## Store and publication

Each workspace store exposes:

```text
root                         one mutable, CAS-written composite root
obj/<sha256>                 immutable pages, piles, facts, and blobs
pile/<member>/<sha256>       idempotent ingress
invite/<unguessable-id>      encrypted invite blob
failed/...                   node-local quarantine diagnostics
```

The workspace SQLite database contains a stable local admission catalog plus
derived eligibility and reverse indexes. A kernel-valid durable receipt is
stored once; losing canonical standing removes its proof row, not its bytes or
offers. The separate application database is disposable and rebuilt by the
projection pump. Deleting the workspace catalog can lose node-local,
currently ineligible receipts that were deliberately never published.

The root uses layout stamp `composite-btreap-v4` and atomically binds:

```text
anchor          workspace genesis fid
manifest        range-sync manifest root
layout_seed     deterministic authenticated-tree seed
trees           FactTree, SuppTree, AuthorityTree descriptors
action_etag     non-authoritative cache key for active-action sync
stamp           exact format identity
```

One compare-and-swap publishes the range manifest and all three authenticated
trees. There is no second mutable removal root and therefore no two-root
transaction. `action_etag` only avoids enumerating SuppTree when ordinary facts
change but actions do not; Workers never trust it, and action evidence remains
authoritative only through the authenticated trees.

The range manifest partitions sorted fact keys with the shared stable boundary
rule. A leaf is a closed pile; a closure sibling lists transitive dependencies
whose home is outside the leaf. Equal subtrees have equal object ids, so sync
prunes them by oid. On append, unchanged ranges are reused without decoding
their facts.

## The three authenticated trees

All logical indexes use one persistent Merkle treap codec. The priority of a
row is `H(layout_seed, key)`, which gives a unique Cartesian tree independent
of insertion history. Each immutable page stores one row and its child object
ids. An update path-copies only search and rotation paths. A Worker read is
bounded by the published depth and the hard depth cap; it never enumerates a
tree.

The schemas are:

- **FactTree** — `fact:<fid>` maps to the bounded Worker record it consumes:
  offers, selectors, continuing liveness scopes, and optional action evidence.
  `action:<sid>` mirrors a known direct/principal action slot so sync can
  corroborate a SuppTree witness through an independently addressed record.
  Raw facts remain in manifest piles and are not emitted again as one object
  per record.
- **SuppTree** — a suppression id maps directly to CLEAR or to ACTIVE with its
  effective action fid. CLEAR is a positive authenticated statement that this
  known, reserved id has no effective action in this snapshot; it is not the
  same as a missing row. ACTIVE names the action whose evidence is named by
  its FactRecord. Missing required rows fail closed.
- **AuthorityTree** — a canonical `NeedKey` maps to the selected provider and
  rank. A missing address is not inferred from submitted facts; family
  authorization decides whether bootstrap absence is allowed.

This answers distinct bounded questions rather than keeping two mutable
suppression roots. SuppTree answers “is this explicit id active?”; FactTree
answers “what does this exact fact require and offer?” and corroborates the
action witness; AuthorityTree answers “which committed fact provides this
need?” The immutable action fid and evidence are reachable from the ACTIVE
slots and FactRecord.

Local SQLite retains `action_proposals` and their targets alongside the stable
catalog. It derives `actions(sid, fid, evidence)` as the current effective
frontier and `supp(fid, sid)` as the reverse map used to retract resident
victims. Only the proposals are retained input; the latter two tables are
rebuildable projections. None is a second published authority index, and the
database-free Worker never reads them.

An action, its `action:<sid>` slot, its `sid` suppression slot, the fact and
authority updates, and the range manifest all become visible under the same
root CAS.

## Shared-bucket concurrency contract

Concurrent database-free services are modeled as three pieces:

```text
O : oid → bytes       grow-only, content-addressed immutable objects
R : root bytes        one linearizable compare-and-swap register
H : root versions     the sequence of successful CAS values
```

A publisher pins one exact `(base root, base ETag)`, derives a deterministic
candidate from that snapshot plus its durable intent, makes every object
reachable from the candidate visible with atomic put-if-absent, and only then
attempts `CAS(R, base ETag, candidate)`. The CAS is the sole linearization
point. A loser retains its intent, rereads the winning root, derives the union,
and retries. Objects written by a crash or losing attempt are harmless
unreachable history; they are never overwritten or deleted.

A reader pins root bytes once. A later root is allowed to make that decision
stale, but every manifest, tree page, fact record, suppression slot, authority
slot, and action witness used by the decision must remain explainable by the
one pinned root. Re-reading `root` for individual components is incoherent,
even when each component is independently valid.

The safety laws are:

1. every object key equals the hash of its bytes;
2. the object map only grows and an existing key never changes;
3. root changes only through one successful whole-value CAS;
4. every successful root names a complete, hash-valid closure already in `O`;
5. every successful read decodes under exactly one root from `H`; and
6. every fair retry sequence converges to the deterministic union of the
   surviving publishers' intents.

`tests/shared_bucket_model.py` is the executable small-state definition.
Its breadth-first explorer covers two writers and one reader and returns the
shortest schedule for a violated law. Mutation tests prove the laws reject
root-before-objects publication, split composite roots, and a reader that
repins halfway through a decision. Concrete Store, Publisher, Worker, and
authenticated-tree schedules refine this model.

## Explicit suppression

Suppression is offered by the target fact, not guessed from arbitrary
dependencies. A registered family declares either no suppression policy or an
exact list composed from:

```text
SELF
PARENT(named_role, parent_fid)
ANCESTOR(named/path, ancestor_fid)
```

`SELF` is serialized as a non-circular marker and expands to the fact’s fid
after hash integrity succeeds. All selectors resolve into one typed namespace:

```text
SELF(f)                 -> fact:<fid(f)>
PARENT(_, p)            -> fact:<p>
ANCESTOR(_, a)          -> fact:<a>
member principal        -> member:<public-key>
device principal        -> device:<public-key>
```

A fact may offer several selectors. A family with no policy offers none and
cannot be a direct suppression target. This is separate from authorization:
an untargetable action fact can still require live admin authority.

Current content policies are explicit:

- messages and file descriptors offer `SELF`;
- Bao files additionally carry their member parent;
- chunks offer `SELF`, their file parent, and their file/member ancestor;
- deleting a file descriptor therefore suppresses its chunks without the
  deleter enumerating descendants;
- deletion and eviction facts offer no selector and cannot themselves be
  deleted.

The selector count is capped and checked both when authored and independently
at admission.

## Deletion, eviction, and authority

An exact content deletion contains an exact target key, a hard target ref, and
the `SELF` selector token. The target family’s `DIRECT_TARGETS` entry must allow
that action and mode. Supplying a bare suppression id is not a capability.

The ordinary fact graph authorizes the action:

- `OWNER` requires an author signature and a member provider whose durable
  principal equals the target’s owner principal;
- all devices belonging to one user resolve to that user principal, so sibling
  devices can remove the user’s content;
- `ADMIN` requires an author signature and a live admin provider and can remove
  every directly deletable family;
- an unrelated ordinary member satisfies neither path.

These checks live in the content-delete handler and family-owned policies
compiled by the checked registry. The core does not special-case message or
file ownership.

Member eviction is an admin-authored fact offering `removed(target_pk)`. It
activates `member:<target_pk>`, a terminal key-wide tombstone that covers
existing and future membership providers. A Worker checks that exact key when
minting a grant, so it does not load the fact set or rebuild a database.

Authorization has two intentionally distinct concepts:

- an `authorization_guard` must be live when admitting a new irreversible
  effect;
- an `authority_liveness_guard` continues to mask an already-published
  authority provider.

A delegated admin grant uses the grantor admin as a one-time admission guard
and the grantee membership as its continuing liveness guard. Evicting the
grantee disables the grant. Liveness follows only the family-declared guard
edges, transitively and under a hard bound, so an admin grant to a child device
also inherits that device set's user liveness. Later loss of the grantor does
not retroactively undo a grant that was validly committed.

## Action timing

Validated action proposal bytes are retained monotonically in the local
catalog; effective action state is derived and is not assumed monotone across
root versions. For example, a later-arriving, shallower ownership claim can
make a previously plausible OWNER deletion ineligible. The next root then
publishes CLEAR for that id and restores the victim to the active client view.
Workers enforce each current snapshot strictly: an ACTIVE principal or
selector always refuses the request.

Replica admission must also converge when an old fact and an action arrive in
opposite orders. Settlement therefore computes one deterministic fixed point:

1. resolve and validate canonical local edges for every candidate;
2. fold currently eligible action proposals in canonical `(fact key, fid,
   evidence)` order;
3. accept a proposal only if an earlier active target does not intersect its
   transitive, family-declared authorization scopes;
4. let each accepted proposal activate all of its explicit target ids; and
5. rebuild eligibility under that frontier until neither proofs nor actions
   change, failing closed on a cycle.

The earliest effective proposal wins a duplicate id. An action blocks an
ordinary candidate whose canonical fact key is later; an earlier candidate
remains admissible history. Retaining inactive receipts makes fact-first,
action-first, and later canonical-winner changes converge without a
descendant lookup or sender-selected edge.

This ordering is deterministic, but timestamps are author-controlled. A
colluding live relay can therefore present a newly signed, backdated durable
effect as historical. Remote minting still refuses the removed principal
itself. Closing the stronger “authored before, not merely ordered before”
distinction requires a service-issued admission frontier or receipt; it
cannot be inferred from an asynchronous signed fact alone.

## Worker authorization

`WorkerView` opens the composite root and performs exact authenticated reads:

1. decode and kernel-validate the submitted closure (maximum 64 facts);
2. dispatch exactly one ephemeral family authorization hook, which checks its
   allowed verb and service-time deadline;
3. check committed authority winners and family-required co-offers;
4. read only the request/provider FactRecords and their declared liveness
   scopes;
5. read the corresponding SuppTree slots; and
6. return `(public_key, verb)` for sealing by the daemon.

`core/mint.py` contains only this path. The CF path is `root bytes + immutable
object fetches + submitted closure`: no SQLite, client catalog, compatibility
projection, or full-tree fallback. A cached view is reusable only while its
root ETag matches.

The daemon seals a short-lived bearer grant to the requester’s public key.
The grant TTL is a deliberate revocation leakage window. After expiry, an
evicted member cannot mint another remote grant. The trusted local `ctl/*`
surface is not an authentication boundary: an evicted replica that missed its
own action may continue writing isolated local state, but authorized peers
refuse delivery.

## Sync and recovery

A dial reads the remote root conditionally. A 304 against an unchanged local
root is O(1) after blob completeness has been stamped for that ETag.

When roots differ, sync reconciles admitted actions first. Each ACTIVE slot and
its evidence closure are hash-checked and kernel-validated independently; one
missing or poisoned witness is skipped without blocking honest actions. The
ordinary range manifest is then diffed by oid, local-only facts are pushed as
one closed pile, remote ranges are assembled, and missing live blobs are
fetched. Push happens before draining the pull so canonical pruning cannot
remove a precomputed difference before delivery.

Malformed ingress failures and sync failures are quarantined and visible through
`status`. Malformed roots, pages, facts, selectors, action evidence, or
authority rows fail closed. A root format mismatch forces a wholesale rebuild
from the current derived index; there is no ongoing dual decoder.

Application tables are insert-only source rows plus a projection cursor.
Suppression appends retractions to the delivery log. Rebuild replays the
authenticated resident facts together with the stable local catalog,
reconstructs eligibility, action and selector reverse maps, and then
reproduces the application view.

## Performance

`bench/bench_latency.py` measures the running paths. On the development host on
2026-07-28, five hot posts at each scale produced:

| Seed facts | Post p50 | Post p95 | sorted-key scan p50 | immutable KiB/post |
|---:|---:|---:|---:|---:|
| 1,000 | 20.55 ms | 21.20 ms | 0.98 ms | 58.6 |
| 5,000 | 36.34 ms | 37.30 ms | 5.07 ms | 74.6 |
| 10,000 | 50.42 ms | 58.11 ms | 10.60 ms | 69.5 |

The authenticated trees and changed manifest ranges update in logarithmic
paths. One index-only sorted-key scan remains to derive the canonical range
partition, so post time is not perfectly flat; the benchmark makes that slope
visible. A primed same-root idle dial measured about 0.007 ms p50/p95 locally
and performed no fact, tree, object, or blob-demand scan. These numbers are
diagnostic, not cross-machine service guarantees.

## Limits and future decisions

- Ordinary bodies are plaintext. End-to-end body encryption needs a separate
  design and implementation.
- Logical deletion stops projection, authorization, and future blob demand; it
  does not erase immutable objects already stored. Physical GC is unbuilt.
- The canonical range manifest still performs an O(n) index-only key scan per
  commit.
- Strong authorship-time revocation needs serialized admission receipts, as
  described under “Action timing.”
- A removed node may not learn its own terminal action if it has no inbound
  peer and its cached grant expires first. The remote door is still closed;
  explicit tombstone delivery is a separate availability feature.
- The current prototype assumes one workspace per store directory. Shared
  multi-workspace buckets, lifecycle policy, and production cloud deployment
  are out of scope.
