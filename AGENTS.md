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

Ordinary content is a forest of independently advancing dense device logs.
Facts are the log leaves and the only semantic storage unit; there is no
workspace-global mutable content root.  Signed closed piles survive only as
ephemeral gate-proof requests and are never stored in writer logs.

```text
local command
  -> family command emits canonical facts
  -> WriterLog assigns a contiguous writer sequence
  -> deterministic fact/tree/queue objects
  -> signed head authenticates the log root and control subsequence
  -> current access proof binds one exact proposed head
  -> CAS heads/<workspace>/<device>

P2P initiator
  -> one-sided GET/PUT RBSR over its peer-local (ts, fid) treap
  -> symmetric difference moves news both ways; responder never walks
  -> fetch/push contiguous writer-sequence runs with one head + boundary paths
  -> verify each complete run atomically
  -> file facts into local per-writer log copies
  -> fold accepted control facts into the recipient's private removal tree
  -> optional FactConsumer

hosted owner publication
  -> append to the writer-owned queue layout with create-only immutable PUTs
  -> ordinary head: the same exact owner-head proof
  -> control head: POST /head/<oid>/permit with proof + exact controls
  -> POST /head/<oid>/commit joins private removal state before its bound CAS
  -> CAS only the caller's writer slot
```

The logical `AccessGate` is actor-neutral. Hosted and full peers use the
same pile codec, removal-path verifier, family queries, and `OpaqueHeadGate`.
It has two device-signed, discarded proof turns. First, a historical-member
proof containing the owning member's signature over the requesting device may
fetch only that member/device pair's path from the recipient's current removal
tree. Second, a current-member proof carries that path and binds an exact mint,
read, sync, or head action. Neither turn installs authority facts or asks the
recipient to synchronize an authority repository. A head proof can authorize
only the proposed head OID named in the request and never validates the
advertised content tree.

A control-bearing head is the one removal-state exception. While the ordinary
current proof still succeeds, the gate issues a stateless permit bound to that
writer, base, proposed head, and bounded set of original control-pile OIDs.
Commit re-evaluates exactly those control-only piles, joins their mechanical
CLEAR/ACTIVE cells first, then attempts the bound slot CAS. Never add a
bearer-only removal update, accepted-leaf poke, scan, cursor, or cached repair
state. Removal may be ahead after a crash; an accepted head may never be ahead
of its removal effects.

Removal state is private point-read state. Never store or serve its roots/pages
through generic `obj/`, pack, direct-open, or public LIST paths. A writer slot's
recorded removal-root hash is audit identity, not a read capability. Path
responses contain only the requested member/device values and non-disclosing
sibling commitments; dense leaves with neighboring members are forbidden.

Cloud publication is owner-confined. A device may create immutable objects and
advance only its own writer slot. The passive store never maintains a shared
fact index: it exposes the writer forest through GET/PUT and clients consume it
by head/sequence diff plus a demand-driven dependency pump. The target queue
layout is a create-only micro-tail, a client-folded binary ladder below the
provider's multipart threshold, and server-side part-copy mono-log segments
above it; deterministic tree summaries ride in object footers. This cloud
layout is phase 2 (`poc-16-6j4.31`) and follows the P2P cut.

P2P deliberately restores the previously tested one-sided Merkle RBSR walk
over a peer-local, history-independent `(ts, fid)` treap. The session initiator
drives; simultaneous dials collapse by endpoint ID. Leaf exchange reveals the
symmetric difference, so that one driver both pulls missing facts and pushes
facts missing at the responder while the responder serves stable self-addressed
pages and verifies PUT runs. A peer fingerprints only timestamp ranges it
holds completely; partial islands are exchanged as exact sets. Transfers are
closed contiguous writer-sequence runs and are accepted all-or-nothing. The
treap is derived discovery state, never canonical residence and never a cloud
object; received facts are filed into their original writers' local log copies.

Every peer also exposes the passive writer-forest interface, so ordinary
clients use the same sequence-diff recipes against a peer and the cloud. Do not
add a canonical combined P2P content log, a workspace content root, a shared
cloud treap, one sync session per fact, or a compatibility reader for stored
closed piles. The governing decision is `poc-16-6j4.29`; implement
`poc-16-6j4.30` before `poc-16-6j4.31`.

## Read the code in this order

1. `core/fact.py` and `facts/`: canonical bytes and family-owned behavior and
   policy.
2. `core/kernel.py` and `core/close.py`: closed-pile judgment and the signed
   pile boundary.
3. `core/writer_tree.py`, `core/writer_head.py`, and
   `core/writer_repository.py`: the current writer forest, owner publication,
   mirroring, and optional consumption.
4. `peerlog/`: the hybrid target's facts-as-leaves writer logs, peer-local
   RBSR index, coverage honesty, closed-run proofs, and one-sided walk. Reuse
   the pre-forest implementation from git history where its shape still fits;
   do not revive its passive-store mutable manifest or stored pile format.
5. `core/access.py`, `core/removal_path.py`, `core/removal_state.py`, and
   `core/suppression_tree.py`: the two discarded proof purposes and bounded
   verification against the recipient's private pinned removal tree. P2P peers
   and cloud gates use the same ACI fold but never synchronize these trees.
6. `core/http.py`: the one route and grant gate used by every runtime.
7. `full_peer/pile_sender.py`, `full_peer/node.py`, and
   `full_peer/sql_store.py`: stateful authorship, composition, and the sole SQL
   boundary.
8. `full_peer/daemon.py`, `full_peer/iroh_process.py`, and `full_peer/iroh/`:
   process ownership and the connection-only Iroh byte wrapper.
9. `adapters/` and `deploy/`: object-store adaptation and isolated provider
   packaging.
10. `notifications/`: post-publication scanning, durable cursor state,
   disposable wakes, current-authority delivery, and provider effects.

`FullPeer` is a composition root, not a policy owner. It combines every core
path with identities, local scheduling, Bao I/O, and disposable SQL. It must
not duplicate head validation, pile admission, grants, suppression, HTTP
routes, or sync logic.

## Facts, closed requests, and residence

Canonical writer logs contain facts as leaves, not stored piles. Heads, Merkle
pages, queue objects, pack indexes, SQL rows, and provider metadata can locate
or authenticate bytes but cannot introduce a fact. A signed head authenticates
ordinary facts by residence and inclusion. Control families that must travel
outside their home log carry companion signature facts; do not add one
signature fact per ordinary message.

Signed closed piles remain the bounded, topologically ordered format only for
ephemeral mint, path, and control gate requests. They are judged against the
recipient's current private state and discarded. Reuse their codec for those
requests only; never put them back into writer leaves, RBSR pages, or the cloud
queue.

```text
gate wire:         complete signed closed request pile, discarded after judgment
P2P wire:          contiguous fact run + signed head + boundary inclusion paths
accepted content: canonical facts in one original writer's dense sequence
local query state: fid -> canonical fact bytes plus generic current indexes
```

If one member or proof component of a pulled run fails, the complete run fails
and no prefix becomes resident. Once a receiver accepts the run and advances
its local writer copy, that writer residence and its reachable immutable
objects are the durable admission certificate. Projection replay must not
consult present-day membership or retain a historical validation chain.

Do not store selected dependency edges, proof DAGs, ranks, winners, dormant
candidates, eligibility labels, or a second settlement state. Validated facts
are monotone; current suppression and authority affect visibility and future
operations, not historical residence.

Writer-sequence runs are independently authenticated and accepted atomically.
Range and diff pagination may stop only between facts and may transfer only
complete proved runs. Queue pages, footers, spans, and packs are replaceable
locators, never log authority. A cold receiver verifies canonical fact bytes,
the signed head, boundary inclusion paths, sequence density, and control
signatures without trusting an adjacent range or prior cache.

Refs on the passive path are located `(writer, seq)` addresses. A target at or
below the stored target head is fetchable; one above it is a pending interval,
not a failed-GET event. Validity-critical control refs cite visible targets or
carry exact proof material inline beside the citing fact (Rule 2); render refs
may remain pending. Handoff facts are explicitly parked and require a separate
decision before the cloud phase closes.

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

`SuppressionTree` maps a known suppression ID to `CLEAR` or
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
writer sequences through the same `FactConsumer` used for network pulls.

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
