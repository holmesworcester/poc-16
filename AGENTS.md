# POC-16 engineer guide

`README.md` is the operating guide and `DESIGN.md` defines the protocol and
trust boundaries. Those files and this guide are the repository's only
Markdown authorities. Track unfinished work in beads, never in a Markdown TODO
ledger.

POC-16 has no backwards-compatibility surface. A protocol cut deletes old
wire, route, storage, and deployment shapes instead of retaining readers or
migrations. The only upgrade mechanism is application-version replay of the
disposable full-peer SQL projection from accepted writer trees.

Start a work session with:

```sh
bd prime
bd ready
git status --short
```

## Authority and data flow

Ordinary content is a forest of independently advancing device logs. There is
no workspace-global mutable content root.

```text
local command
  -> PileSender closes dependencies
  -> WriterLog signs one independently closed pile leaf
  -> immutable pile/tree/head objects
  -> authority proof binds one exact proposed head
  -> CAS heads/<workspace>/<device>

peer pull
  -> list/open changed writer slots
  -> verify signed head and Merkle extension
  -> fetch each complete signed pile
  -> ClosedPileEvaluator
  -> optional FactConsumer

hosted owner publication
  -> direct create-only immutable object PUTs
  -> the same exact owner-head proof
  -> CAS only the caller's writer slot
```

The logical `AuthorityGate` is actor-neutral. Hosted and full peers use the
same pile codec, removal-path verifier, family queries, and `OpaqueHeadGate`.
It has two device-signed, discarded proof turns. First, a historical-member
proof containing the owning member's signature over the requesting device may
fetch only that member/device pair's path from the recipient's current removal
tree. Second, a current-member proof carries that path and binds an exact mint,
read, sync, or head action. Neither turn installs authority facts or asks the
recipient to synchronize an authority repository. A head proof can authorize
only the proposed head OID named in the request and never validates the
advertised content tree.

Removal state is private point-read state. Never store or serve its roots/pages
through generic `obj/`, pack, direct-open, or public LIST paths. A writer slot's
recorded removal-root hash is audit identity, not a read capability. Path
responses contain only the requested member/device values and non-disclosing
sibling commitments; dense leaves with neighboring members are forbidden.

Cloud publication is owner-confined. A device may create immutable objects and
advance only its own writer slot. Hosted storage need not inspect its content
piles. Full-peer replication is validate-first peer sync: a full peer may
relay any original writer tree it has consumed successfully, preserving the
writer's pile signature, signed head, and identity. It may not rewrite a
relayed pile into its own or another writer's cloud log.

P2P exchanges the per-device directory and runs range-based set
reconciliation only for changed writer roots. Do not add a combined P2P
content log, a workspace content root, a second publication algorithm, or one
sync session per pile without measurements that invalidate the forest.

## Read the code in this order

1. `core/fact.py` and `facts/`: canonical bytes and family-owned behavior and
   policy.
2. `core/kernel.py` and `core/close.py`: closed-pile judgment and the signed
   pile boundary.
3. `core/writer_tree.py`, `core/writer_head.py`, and
   `core/writer_repository.py`: writer logs, owner publication, mirroring, and
   optional consumption.
4. `core/authority.py` and `core/suppression.py`: the two discarded proof
   purposes and bounded verification against the recipient's pinned removal
   tree.
5. `core/http.py`: the one route and grant gate used by every runtime.
6. `full_peer/pile_sender.py`, `full_peer/node.py`, and
   `full_peer/sql_store.py`: stateful authorship, composition, and the sole SQL
   boundary.
7. `full_peer/daemon.py`, `full_peer/iroh_process.py`, and `full_peer/iroh/`:
   process ownership and the connection-only Iroh byte wrapper.
8. `adapters/` and `deploy/`: object-store adaptation and isolated provider
   packaging.
9. `notifications/`: post-publication scanning, durable cursor state,
   disposable wakes, current-authority delivery, and provider effects.

`FullPeer` is a composition root, not a policy owner. It combines every core
path with identities, local scheduling, Bao I/O, and disposable SQL. It must
not duplicate head validation, pile admission, grants, suppression, HTTP
routes, or sync logic.

## Closed piles and residence

Every semantic input is one bounded, topologically ordered, device-signed
closed pile. Heads, Merkle pages, pack indexes, SQL rows, and provider metadata
can locate bytes but cannot introduce a fact.

```text
wire:             complete signed closed pile
accepted content: original signed pile in one writer-tree leaf
local query state: fid -> canonical fact bytes plus generic current indexes
```

If one member of a pulled pile fails, its entire candidate writer suffix
fails and no prefix becomes resident. Once a receiver accepts and CASes a
writer slot, that slot and its reachable immutable objects are the durable
admission certificate. Projection replay must not consult present-day
membership or retain a historical validation chain.

Do not store selected dependency edges, proof DAGs, ranks, winners, dormant
candidates, eligibility labels, or a second settlement state. Validated facts
are monotone; current suppression and authority affect visibility and future
operations, not historical residence.

Writer-tree leaves are independently closed. Range and diff pagination may
stop only between leaves. Source-local layout pages and concat packs are
replaceable locators, never log authority. A cold receiver verifies the pile
signature, signed head, inclusion, content address, and full closure without
an adjacent leaf or prior cache.

Bao descriptors and slices are ordinary facts. Large pile and pack bodies use
the streaming/direct-object path and must not widen buffered semantic-object
or `HttpGate` response limits.

## Facts, suppression, and deletion

One module under `facts/auth/` or `facts/content/` owns each family's
constructor, exact shape, Needs, refs/offers, durability, suppression policy,
commands, and queries. `facts/__init__.py` is the checked
registry. Core may dispatch through the registry but must not import concrete
families or switch on their tags.

Needs use complete offer addresses. If provider identity matters, immutable
fact bytes must select it explicitly. Suppression selectors are explicit:
SELF, one named parent, an immutable-ref ancestor path, several selectors, or
none. A family offering no suppression key cannot be directly suppressed.

`SuppTree` maps a known suppression ID to `CLEAR` or
`ACTIVE(action_fid)`. Absence is not clear. This lets a database-free node
answer exact suppression and principal-liveness questions with authenticated
point reads.

Deletion and removal are ordinary facts. Their Needs prove the actor and their
offers must match a selector declared by the target family. Admins may delete
every directly deletable fact; an owner may delete facts owned by that member,
including facts authored by any of the member's devices. Family handlers own
these rules; core and `FullPeer` do not special-case them.

## SQL and application-version replay

`full_peer/sql_store.py` contains only canonical fact blobs, one combined
generic index, and per-writer projection checkpoints. It is never receiving
authority and may be deleted at any time. Startup replays accepted local
writer slots through the same `FactConsumer` used for network pulls.

`facts.APP_VERSION` is the application projection version. A mismatch deletes
the disposable database and replays exact source events through the running
family re-extraction and indexing code. A family may explicitly retain an old
source tag in `SHAPES` and purely reconstruct its current form; all other old
protocol values remain rejected. SQL serializes that current form under the
immutable source fid and retains the exact source only as provenance for
signatures and future closed-pile authorship. Do not add table migrations,
version graphs, selected-edge history, or ambient-context migrations.

## Object-store and concurrency rules

The protocol relies on bounded exact reads, create-only immutable writes with
collision verification, paginated LIST for candidate discovery, and
linearizable conditional replacement of one exact small key. Provider version
tokens are opaque compare capabilities, never content hashes.

Stable mutable keys are:

- `removal`, for the recipient's small authenticated removal-tree root;
- `heads/<workspace>/<device>`, one independent slot per writer;
- source-local layout slots; and
- `cursor` only in the separate notification-state store.

Ordinary content has no mutable workspace root. LIST grants no membership,
authorship, liveness, or fact validity. Immutable objects must exist before a
head advertises them. Stale workers may duplicate bounded creates or delay
convergence; they may not overwrite another value, roll back a writer slot,
delete canonical data, or mint against a caller-selected or stale removal root.

Iroh carries opaque ordinary HTTP bytes only. Endpoint IDs, tickets, ALPN, and
connection success grant no repository authority. Provider adapters translate
storage calls, budgets, and deployment configuration only; they add no
semantic branch.

## Change rules

- Add realistic tests with every behavior change. Prefer actual sockets,
  restart/replay, provider fakes, concurrency schedules, crash points, and
  hostile inputs over placeholder assertions.
- Keep structural authority ratchets in `tests/test_repository_layout.py`.
- Constants own all protocol and resource ceilings; do not add magic sizes.
- Preserve unrelated user changes. In a worktree, edit only that worktree and
  commit completed work on its branch before handoff or review.
- Close or supersede beads whose architecture no longer exists. Push the Dolt
  ledger after reconciling it.

Run the repository-owned gate before handoff:

```sh
python3 tools/preflight.py
```

It includes syntax checks, the complete test suite, layout ratchets, patch
whitespace, and beads integrity checks.
