# POC-16 design

This document describes the code on `main`. It distinguishes running behavior
from limits and future work; it is not a backlog.

## Goal and trust boundary

POC-16 asks whether peers can reconcile an authenticated workspace against a
counterpart that mostly serves immutable bytes. The active peer performs the
walk, verifies hashes, validates fact closures, and settles its local catalog.
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

root + immutable-object fetches → WorkerView   database-free CF authorization

generic type/ref/offer index → family query    client read assembly
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

The writable ObjectStore API enforces the authoritative-key rules: `root`
rejects ordinary put and delete, `obj/*` rejects replacement and delete,
object creation is conditional, and only root CAS may replace the composite
snapshot. A separate ObjectReader interface covers HTTP peer/root/object
reads; its HTTP cache tag is never a writable-store CAS token. Provider SDKs
and deployment code stay outside `core/`.

`read_versioned(root)` atomically returns either `ABSENT` or exact root bytes
paired with an opaque `VersionToken`. The token is only a comparison
capability to pass back to CAS. It is not SHA-256, an HTTP cache tag, an ETag
algorithm promise, or a globally unique generation. `cas` returns
`Applied(new_token)` or definitive `STALE`; a mutation rejected before its
linearization point raises `RetryableStoreError`, while a lost response after
a possible mutation raises `OutcomeUnknown`.

Immutable creation returns `CREATED` or `EXISTS`. The shared
`ensure_object(oid, bytes)` boundary accepts `EXISTS` only after fetching and
byte-verifying the incumbent. It reconciles an unknown outcome by direct read
and never lets root CAS run until every referenced object is known present.
FsStore refines atomic comparison/creation locally with a stable flock and
atomic link/replace, but does not yet claim power-loss durability because it
omits the required file and parent-directory fsync sequence. S3/R2 adapters
use their acknowledged durable conditional writes; neither copies the POSIX
mechanism.

The authoritative access path requires acknowledged durability and strong
direct-API visibility. Current general-purpose S3 and direct R2 Worker/S3
APIs provide the strong per-key reads and conditional writes this design
uses. Cached custom domains and asynchronous replicas are not conforming
authoritative adapters. LIST is strong but paginated, and several pages are
not one transaction. Piles, invites, and quarantine records remain
non-authoritative operations with explicitly idempotent handling.

Each workspace SQLite database contains one stable local fact catalog plus
family-neutral derived indexes:

```text
facts(fid, blob)                 one canonical encoded body
fact_index(kind, k0, k1, src)   key + type + explicit refs + declared offers
proofs / edges                   current eligibility and resolved authority
actions / supp                   suppression frontier and selector reverse map
```

There is no application projection database and no family-owned durable
table. A kernel-valid durable receipt is stored once; losing canonical
standing removes its proof row, not its bytes or index rows. Every fact gets a
`fact.key` reconciliation row, a `fact.type` row, one `fact.ref` row for each
explicit `(role, target fid)` reference, and one row for each declared offer.
Family queries intersect those generic addresses before loading canonical
blobs, then apply suppression and assemble their view. For example, a file
read selects only `chunk --file→ descriptor` rows and verifies those immutable
Bao objects after releasing the catalog lock. The reference rows are local
query routes, not dependency offers or additional authority. Deleting the
workspace catalog can still lose node-local, currently ineligible receipts
that were deliberately never published.

### Fact versions and derived replay

POC-16 does not yet accept multiple fact versions. When it does, the canonical
blob catalog remains an immutable record of the originally admitted bytes, but
derived tables must never replay that historical shape directly. Replay first
decodes and hydrates each blob through the current version adapter, in the
same context and into the same current form exposed when that fact is supplied
as context to another fact. Type, dependency-key, and explicit-reference
index rows, eligibility, and query views are then derived from that hydrated
form.

Thus a version/schema change is an explicit derived-index version change:
discard the old derived rows and replay the retained canonical blobs through
the new hydrator. The original bytes and fid do not change, while every
consumer sees one current contextual form. A future adapter must be
deterministic and must not consult replica-local arrival order or wall-clock
state.

The root uses layout stamp `composite-btreap-v5` and atomically binds:

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

Catalog settlement returns a publication plan pinned to the exact root bytes
and opaque provider token returned by one read. Object and tree compilation
never rereads `root` to adopt a newer base. A successful publisher stores
`h(root bytes)`, not the provider token, as its local derived-index stamp. If
another writer advances root after that stamp, the stamp is honestly stale
and the next index synchronization rebuilds. It can never falsely label old
local state as the later writer's root.

Receipts staged before a failed or lost CAS remain in the catalog but are not
eligible merely because a read triggers repair. Rebuild first restores the
published root plus already committed local receipts and keeps staged intent
behind that snapshot. The next explicit workspace turn retries the staged
set—even if another worker already retired its original ingress key. On a
successful CAS, only then are its staged markers cleared. A rebuild whose
compiled bytes equal its pinned root performs a token-checked no-op before
stamping it; a rootless no-op similarly rechecks that `root` is still absent.

The range manifest partitions canonical fact keys with the stable boundary
rule. A leaf is a closed pile; a closure sibling lists transitive dependencies
whose home is outside that exact leaf. **RangeTree** is a logical map from each
opaque ordered range separator to its leaf and closure oids. It uses the same
persistent Merkle-treap primitive as every other authenticated tree; it is not
a second tree implementation. On an additions-only commit the publisher
performs one bounded authenticated predecessor/successor search per new key,
verifies the selected old leaf pile, unions its members with the new keys, and
path-copies the replacement wire-map rows. It neither enumerates RangeTree nor
consults a SQLite range directory, calls `Node.keys`, or runs an unconditional
corpus-wide ordered fact-key query. Equal subtrees have equal object ids, so
sync descends only remote paths whose oids are not present in the local
RangeTree. Repair, format cutover, deactivation, and canonical-authority
changes deliberately retain the full SQLite-backed reference build: those
operations reconstruct client-local standing and have no CF authorization
counterpart.

RangeTree is an authenticated wire map for synchronization and store recovery,
not a fourth authorization index. A read-only database-free Worker does not
need it and never scans timestamp/fid keys: `WorkerView` exact-reads only
FactTree, SuppTree, and AuthorityTree. A store-backed publisher, whether
locally hosted or moved to an edge later, can use the same bounded RangeTree
neighbor operation without constructing SQLite. An edge responder may also
serve RangeTree objects by oid without interpreting them.
FactTree cannot substitute for this map without also gaining ordered raw-fact
residency and pile/closure routing; object-store LIST cannot substitute
because object names are content hashes and include unreachable history.

## The three authenticated trees

Wire RangeTree and the three Worker indexes share one persistent Merkle-treap
codec, but only the latter are Worker-readable. The priority of a row is
`H(seed, key)`, which gives a unique Cartesian tree independent of insertion
history. Each immutable page stores one row and its child object ids. An
update path-copies only search and rotation paths. A Worker read is bounded by
the published depth and the hard depth cap; it never enumerates a tree.

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
frontier and `supp(fid, sid)` as the selector reverse map. Only the proposals
are retained input; the latter two tables are rebuildable indexes. None is a
second published authority index, and the database-free Worker never reads
them.

An action, its `action:<sid>` slot, its `sid` suppression slot, the fact and
authority updates, and the range manifest all become visible under the same
root CAS.

## Shared-bucket concurrency contract

Concurrent store users are modeled as three pieces:

```text
O : oid → bytes       grow-only, content-addressed immutable objects
R : root bytes        one linearizable compare-and-swap register
T : opaque tokens     sound comparison capabilities for values of R
H : root versions     the sequence of successful CAS values
```

A publisher pins one exact `(base root, base token)`, derives a deterministic
candidate from that snapshot plus its durable intent, makes every object
reachable from the candidate visible with atomic put-if-absent, and only then
attempts `CAS(R, base token, candidate)`. The CAS is the sole linearization
point. A loser retains its intent, rereads the winning root, derives the union,
and retries. Objects written by a crash or losing attempt are harmless
unreachable history; they are never overwritten or deleted.

Tokens obey one law: within one `(store, key)`, the same token never denotes
different bytes. The converse is unnecessary. An `X → Y → X` value-ABA may
reuse X's token and is safe here because root bytes completely define the
published state and every referenced object is immutable. This must be
revisited if later generations gain deletion, GC, or history-dependent side
effects.

A lost mutation response is not a stale precondition. Publication rereads:
candidate bytes mean the CAS succeeded; the exact unchanged base permits one
safe retry; any other value means rebase while retaining staged intent. If
reconciliation itself fails, no receipt or ingress key is retired.

A reader pins root bytes once. A later root is allowed to make that decision
stale, but every manifest, tree page, fact record, suppression slot, authority
slot, and action witness used by the decision must remain explainable by the
one pinned root. Re-reading `root` for individual components is incoherent,
even when each component is independently valid.

The writer-side client catalog is an optimization and durable-intent cache;
the CF authorization reader has no database at all. It needs only pinned root
bytes, immutable object fetches, the submitted bounded closure, and trusted
service time.

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
authenticated-tree schedules refine this model in
`tests/test_shared_bucket_node.py`: every successful root is fully walked,
competing suppression winners are observed under whole roots, a stale mint is
run with SQLite disabled, and the terminal concurrent result must equal a
serial canonical rebuild.

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
remains admissible history. Retaining inactive receipts locally makes
fact-first, action-first, and later canonical-winner changes converge without
a descendant lookup or sender-selected edge.

This ordering is deterministic, but timestamps are author-controlled. That is
intentional: removal is a knowledge and connectivity boundary, not a global
authorship-time cutoff. A peer whose pinned snapshot still authorizes a member
may accept that member’s fact, and the accepted fact is legitimate workspace
history even if another peer already knows the member is removed. Once a peer
learns the removal, grant expiry and exact Worker checks stop that member from
directly opening a new authorized sharing channel to that peer. There is no
serialized admission frontier and no attempt to distinguish signing time from
first delivery.

Inactive receipts are likewise local durable intent, not a second replicated
fact set. They are absent from the eligible manifest and need not be copied to
every fresh replica. If a retaining node later finds one eligible, ordinary
publication can share it then; if every holder disappears first, losing that
inactive candidate is acceptable. Convergence applies to facts replicas have
actually exchanged, not to hypothetical equality of their latent candidates.

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

`core/mint.py` contains only this path. The edge path is `root bytes + immutable
object fetches + submitted closure`: no SQLite, client catalog, client query
state, or full-tree fallback. A cached view is reusable only while its
SHA-256 root content tag matches; provider CAS tokens never enter this path.

The daemon seals a short-lived bearer grant to the requester’s public key.
The grant TTL is a deliberate revocation leakage window. After expiry, an
evicted member cannot mint another remote grant from a peer that knows the
removal. The trusted local `ctl/*` surface is not an authentication boundary:
an evicted replica that missed its own action may continue writing isolated
local state. It need not receive a special terminal tombstone. A still-stale
peer may legitimately accept that state; an informed peer refuses a new grant
and therefore eventually closes the sharing boundary.

## Sync and recovery

A dial reads the remote root conditionally. A 304 against an unchanged local
root is O(1) after blob completeness has been stamped for that HTTP content
tag.

When roots differ, sync reconciles admitted actions first. Each ACTIVE slot and
its evidence closure are hash-checked and kernel-validated independently; one
missing or poisoned witness is skipped without blocking honest actions. The
RangeTree is then compared by oid: shared pages are read from the authenticated
local tree, while only novel remote paths and their changed piles are fetched.
Local-only facts are pushed as one closed pile, remote ranges are assembled,
and missing live blobs are fetched. Push happens before draining the pull so
canonical pruning cannot remove a precomputed difference before delivery.

Malformed ingress failures and sync failures are quarantined and visible
through `status`. Malformed roots, pages, facts, selectors, action evidence,
or authority rows fail closed. A root format mismatch may be republished from
the current derived index only when its known snapshot fields equal the exact
root bytes that index recorded; a different or unreadable snapshot is never
clobbered. There is no ongoing dual decoder.

Rebuild replays authenticated resident facts together with the stable local
catalog and reconstructs eligibility, action state, and selector reverse maps.
Queries need no replay phase or cursor: once the workspace index is stamped
for the pinned root, they select and decode the same canonical catalog rows
used by settlement. Blob-bearing queries verify currently resident object
bytes on demand.

## Performance

`bench/bench_latency.py` measures the running paths. On the development host on
2026-07-29, five hot posts at each scale produced:

| Seed facts | Post p50 | Post p95 | object touches/post | immutable KiB/post |
|---:|---:|---:|---:|---:|
| 1,000 | 15.41 ms | 16.34 ms | 84.9 | 48.0 |
| 5,000 | 27.98 ms | 31.10 ms | 114.1 | 67.0 |
| 10,000 | 19.40 ms | 27.24 ms | 127.1 | 55.4 |

Every measured post performed zero `Node.keys` calls. Authenticated-tree and
RangeTree touches grow with their paths (85–127 here), not with the
1,000–10,000-fact corpus. A primed same-root idle dial measured 0.008–0.013 ms
p50/p95 locally and performed no fact, tree, object, or blob-demand scan.
These numbers are diagnostic, not cross-machine service guarantees.

## Limits and future decisions

- Ordinary bodies are plaintext. End-to-end body encryption needs a separate
  design and implementation.
- Logical deletion stops query visibility, authorization, and future blob
  demand; it does not erase immutable objects already stored. Physical GC is
  unbuilt.
- The current prototype assumes one workspace per store directory. Shared
  multi-workspace buckets, lifecycle policy, and production cloud deployment
  are out of scope.
