# POC-16 design

This document states the running architecture and its correctness boundary.
Future work is called out explicitly.

## 1. Authority and capability flow

The repository has three data capabilities plus one shared HTTP gate:

```text
PileSender
    local intent -> one ordinary closed pile

RepositoryApplier
    exact closed pile -> immutable objects -> one root CAS

RepositoryReader
    one pinned root -> authenticated, side-effect-free answers

HttpGate
    peer HTTP request -> authorized Applier or Reader operation
```

`RepositoryApplier` and `RepositoryReader` are the complete database-free
repository engine. `HttpGate` applies the one peer route and authorization
policy over those capabilities. A hosted peer can stop there. A full peer
adds `PileSender`, local identity, scheduling, attachment I/O, local control,
and disposable SQL. Its receiving side still invokes the same Applier used by
Lambda and Cloudflare Workers; there is no second pile-to-root algorithm.

Provider deployments may isolate a read/signing broker from the Applier.
That is a least-privilege compartment boundary, not another repository
algorithm. The broker can read a pinned canonical root and mint confined
create-only ingress capabilities. It cannot mutate canonical state. The
Applier can mutate canonical state and has no alternate fact validation
policy.

Each effect has one owner:

| effect | owner |
| --- | --- |
| construct family fact bytes | fact family |
| close and encode outbound intent | `PileSender` |
| judge an incoming pile | `kernel`, invoked by `RepositoryApplier` |
| establish immutable repository objects | `RepositoryApplier` |
| compile authenticated maps | `repository_snapshot` |
| compare-and-swap `root` | `RepositoryApplier` |
| retire an internal pile generation | `RepositoryApplier` |
| answer from a pinned root | `RepositoryReader` |
| assemble local presentation | family queries over disposable SQL |

`FullPeer` is the stateful composition root. `core/` does not import it,
SQLite, keychains, local control, or attachment presentation. `FullPeer` may
schedule turns and translate results, but it is not a fact-policy, compiler,
suppression, or CAS authority. `full_peer/sql_store.py` is the sole SQL
module, and deleting its database changes no repository answer.

Family modules own commands as well as validation policy, but depend only on
the host capabilities passed as `node`: clock, peer reachability/sync,
attachment I/O, and direct-upload journal/runtime. `facts/` imports neither
`full_peer` nor provider/deployment packages. This keeps commands reusable
without moving their semantic decisions into the host composition.

The direct-upload client is stateful-peer state:
`full_peer/upload_journal.py` owns crash-safe source/progress persistence,
`full_peer/upload_client.py` owns the bounded resumable transition, and
`full_peer/upload_client_http.py` owns its outbound HTTP effects. Provider
brokers, signers, and deployment packaging remain under `deploy/`; only the
shared `upload_session.py` and `upload_wire.py` values cross that boundary.
Each content-addressed source has one cross-process writer for the complete
resume transition. Session replacement retains the maximum expiry of every
issued capability, progress only advances, and lifecycle discovery is a
bounded manifest page. Active, expired, abandoned, and completed describe
local delivery only. Collection atomically hides one exact source before
deleting it and is allowed only after pile-last delivery was durably recorded,
or explicit abandonment and the retained capability-expiry bound; none of
these records is repository, root-CAS, or read authority.
Legacy v1 progress may resume, but its erased session history makes abandoned
collection permanently ineligible unless delivery later completes.

### 1.1 Iroh is connection only

The optional full-peer path is deliberately a wrapper around the existing
HTTP byte seam:

```text
ordinary HTTP GET/PUT/mint bytes
    -> loopback forwarder
    -> one Iroh bidirectional stream
    -> supervised Iroh acceptor
    -> loopback core/http_stdlib listener
    -> the one HttpGate
    -> RepositoryReader or RepositoryApplier
    -> the configured object store
```

Only `full_peer` owns Iroh endpoint keys, tickets, child processes, and
connection lifecycle. The Rust crate under `full_peer/iroh/` copies bytes; it
has no HTTP parser, route table, grant codec, workspace model, repository
operation, object-store client, or CAS. Iroh endpoint identity encrypts and
reaches a peer but grants no fact, bucket, or workspace authority. Every
request must independently pass the normal `HttpGate` grant decision.
Full-peer host configuration becomes one validated immutable gate-options
value at startup (grant lifetime and bounded mint fetch count/bytes);
`core.http_stdlib` passes it into `HttpGate` without interpreting it.

The peer-data listener behind an Iroh acceptor is unconditionally loopback.
Local control is a second, unconditionally loopback listener and is never an
Iroh upstream. A stopped Iroh child or peer-data listener stops the service;
normal process shutdown reaps the child. The endpoint key is stable across
restart, but that stable identity is still not an authorization principal.

Inbound connection permits are acquired without waiting: an attempt observed
while every configured permit is occupied is refused before a per-connection
task, bidirectional stream, or loopback upstream is created. Each admitted
task has one aggregate setup deadline and one complete byte-session deadline,
so hostile handshakes and half-closed streams return their exact permit. The
transport advertises exactly that one peer-initiated bidirectional stream and
no unidirectional streams; dialing-only endpoints advertise neither, and
application datagrams are disabled everywhere.

Full-peer keyring state stores bounded out-of-band records of the form
`{kind: iroh, endpoint, ticket}`. It never stores a generated loopback URL.
The endpoint field is a stable replacement/removal key for reachability only;
the ticket is the current address. The wrapper rejects a ticket whose encoded
endpoint does not match that local configuration key, but this consistency
check still grants nothing. Ordinary invitations carry this same record.
Their redemption asks `FullPeer` for a private URL, while the fact family
remains unaware of Iroh. The daemon starts and monitors one outbound
forwarder per configured workspace/endpoint and passes its loopback URL to
the unchanged sync HTTP client.

Startup registers every configured peer before scheduling. The monitor starts
at most one due child per turn, and sync may resolve its selected peer on
demand; neither path can wait beyond the bounded outbound-start and shutdown
budget. Replacing a ticket stops and reaps the old child; removal both deletes
the durable record and reaps the child. Unexpected outbound-child death closes
the old local dial, is visible in local status, discards the exact obsolete
URL-keyed sync walk, and retries with bounded backoff. It is a peer-local
reachability failure, not a reason to stop the accepting service or grant
access. Accepting-child death remains process-fatal because it would otherwise
leave the daemon falsely advertised. Iroh mode rejects plain HTTP peer records
and `--url`, so private loopback seams cannot become remote configuration.

## 2. Facts and closed piles

A fact has a canonical clear envelope and a canonical body:

```text
e = (workspace, type, timestamp, clear-envelope atoms, body-hash)
b = body
```

Its `fid` is the SHA-256 address of the canonical envelope, which commits to
the body through `body-hash`. The immutable object ID is the SHA-256 address
of the full canonical `{e,b}` encoding. `FactTree` therefore stores
`fid -> object_oid`. Ordinary facts name their workspace. The workspace
genesis is the sole exception: its own `fid` is the workspace anchor, so it
omits `ws`.

The clear envelope contains only generic protocol atoms:

- exact named refs;
- named offers with one or two address values;
- explicit suppression selectors or actions.

Every fact type is a module under `facts/`. A family owns construction, exact
shape validation, declared `Need`s, durability, suppression and direct-action
policy, liveness guards, commands, queries, and inline payload validation.
Core dispatches through the checked family registry and contains no tag switch.
Registry compilation rejects malformed or ambiguous selector, action,
liveness, and typed-suppression declarations before a family can be admitted.

### 2.1 The closed-pile boundary

A pile is one canonical, workspace-bound, topologically ordered fact closure.
Dependencies precede dependents. Pile bytes, aggregate fact count, each fact's
dependency count, and per-fact transitive closure are independently bounded.
The count is checked lexically before generation reservation, then rechecked
by the exact decoder and kernel. Each canonical fact and public invite envelope
also fits the smallest hosted Reader's single-object response ceiling. Detached
Bao proofs therefore fit inside ordinary fact bodies. Authenticated-root
traversal reads only `MAX_REPOSITORY_OBJECT_BYTES`; the larger generic object
ceiling remains an outer HTTP/storage bound.

The database-free kernel streams the pile into a temporary `MemoryContext`.
For each fact it:

1. proves workspace binding and canonical identity;
2. resolves exact refs and family-declared Needs;
3. invokes family shape validation;
4. independently checks family policy;
5. enforces dependency and closure bounds;
6. emits an ephemeral `Valid(fact, named_edges)` judgment value.

Named edges exist only inside that judgment and its ephemeral authorization
hook. Fresh synchronization closures are assembled again from immutable refs
and declared Needs. The judgment's selected edges are never stored, sent as
sync state, ranked, or treated as historical winners.

The pile is atomic. If any fact fails, no fact in the pile is published,
including a valid prefix. If it succeeds, every durable fact joins the
validated set. Ephemeral request facts are judged but not stored.

### 2.2 Monotone validated storage

The repository theorem is:

```text
if f validates against S,
then f remains valid in every validated superset S'
```

The wire closure is evidence supplied by the sender for the one validation
event. After root CAS, its incidental dependency selection has done its job:

```text
wire:    closed pile = facts plus enough dependencies to validate
stored:  fid -> canonical fact bytes
```

There is no losing, dormant, inactive, or second-class validated fact. Current
suppression can hide a fact from a query or disable authority without revoking
its residence.

### 2.3 Inline Bao slices

A signed `file_bao` descriptor commits the file root, length, 256 KiB width,
and slice count. Each unsigned `file_slice` names that exact descriptor with a
`file` ref and carries its index plus canonical Bao range proof in its ordinary
fact body. The descriptor signature and Bao root are sufficient authority;
signing every slice would add no claim. The slice handler verifies the proof in
the database-free kernel with the small pure-Python verifier adapted from Bao
0.13.1's readable reference implementation. The Rust binding only authors
roots and proofs and is cross-tested against that verifier.

The descriptor and every slice travel as separate closed piles. A slice
inherits only its descriptor's suppression ID, so deleting the descriptor
hides every range without individual deletion actions. After admission there
is no detached object, completion scan, or alternate sync path. Stateful file
queries count the generic `file` ref index and load proof-bearing fact bodies
only for the selected descriptor.

The 256 KiB width keeps one encoded slice below 512 KiB while reducing fact,
kernel-turn, and root-CAS count fourfold versus POC-17's 64 KiB geometry. A
4 MiB + 17 byte local comparison produced 65 versus 17 facts; total proof wire
bytes and pure-verifier throughput were effectively equal (5.98/5.95 MB of
base64 and 1.65/1.64 MiB/s respectively). The larger width therefore buys
simplicity and fewer turns without increasing total verification work.

Provider identity follows one rule:

- if one provider matters semantically, immutable fact bytes name its exact
  provider ID or complete offer address;
- otherwise all providers at the complete address are validation-equivalent.

For membership the complete address is:

```text
member(concrete_signing_key, durable_owner_principal)
```

A direct user has the same value in both positions. A device names its device
key first and its owner second. Content persists `owner` and declares an exact
membership Need. A later affiliation at another complete address therefore
cannot rewrite content ownership, delete authority, device descendants, or a
delegated admin's liveness.

Human-readable workspace/member names and device labels are family-owned
presentation fields, not authority addresses. Each is nonempty and at most 255
UTF-8 bytes so every worst-shaped current-authority closure remains mintable by
the smallest supported hosted gate.

Fresh sync closures may choose any finite acyclic provider closure for an
interchangeable address. Explicit provider selectors remain exact.

## 3. Authenticated repository state

One canonical root names three Merkle maps and their authenticated metadata.

### 3.1 FactTree

`FactTree` is the validated residence and generic lookup map.

```text
fact:<fid> -> object_oid
index:<kind>:<k0>:<k1>:<fid> -> validated posting
```

The object is exactly the canonical fact bytes; its digest must match the
object ID, and decoding must reproduce `fid`.

Mechanical postings are derived from immutable bytes:

- fact type;
- canonical reconciliation key;
- every explicit ref;
- every offer address;
- every explicit suppression selector;
- every family-declared principal and continuing-liveness scope.

FactTree contains no admission proof, dependency edge, rank, eligibility
label, or query verdict. A posting is useful for discovery only after its
authenticated value and referenced canonical fact have been checked.

### 3.2 FactOrder

`FactOrder` maps the canonical timestamp/fid key to the fact object's OID. It
supports deterministic reconciliation order. It is not a validation log and
does not introduce another fact body.

### 3.3 SuppTree

Every known suppression ID has exactly one authenticated state:

```text
CLEAR
ACTIVE(action_fid)
```

`CLEAR` means the ID is known and no effective action exists at this root.
`ACTIVE` names the immutable action. Its ordinary FactTree residence and
canonical bytes prove that it declares this exact suppression ID; duplicating
the slot in FactTree would add no authority. Missing is distinct from `CLEAR`;
an exact liveness check which needs a missing slot fails closed.

Selectors may name SELF, a parent, an ancestor path, several IDs, or none.
PARENT pins its one direct dependency. ANCESTOR traverses only exact named
refs at every hop; the registry distinguishes that promise and admission
checks the actual ref chain. The descendant can therefore carry the final
ancestor ID without storing selected Need providers or historical admission
edges. A later deleter never enumerates descendants.

SuppTree supports exact fact deletion, member removal, device/owner liveness,
and bounded Worker authorization reads without a database or fact-set scan.

### 3.4 Direct provider reads

A closed proof already names the exact fact that supplied each Need. A hosted
Reader therefore authenticates `fact:<provider_fid>` directly, checks that its
canonical offers contain the complete requested address, and point-reads each
of its declared SuppTree scopes. There is no materialized authority winner.

This supports the required invariants with less state:

- the provider is a resident validated fact;
- its immutable bytes offer the requested complete address;
- every current scope is `CLEAR`;
- an action changes one SuppTree route, regardless of how many historical
  providers name that scope.

A stateful peer may discover interchangeable candidates through its disposable
SQL projection. A database-free proof path never scans candidates because the
proof supplies the provider it asks the Reader to authenticate.

## 4. Suppression, deletion, and removal

Deletion and removal are ordinary validated facts.

A direct deletion binds:

- the target's exact canonical key and `fid`;
- the target family's SELF selector;
- an OWNER or ADMIN authority Need;
- the immutable `owner` principal copied from the target.

The target family must explicitly allow direct deletion. ADMIN is permitted
for every directly deletable family. OWNER requires the author to offer the
complete `member(author_key, target_owner)` address. Thus sibling devices share
ownership, while a later unrelated device claim cannot change it.

Removal activates a typed member suppression ID. It affects current sharing
authority after propagation. It does not rewrite history or make already
validated facts disappear. A peer unaware of removal may still accept a
properly closed pile; those facts are legitimate workspace facts and converge
later. Once aware, a peer refuses new local authoring and remote minting for
that principal.

Delegated admin liveness is family-declared. An admin fact's grantee membership
Need includes the durable owner principal, so removing the owner disables an
admin granted to any of that owner's devices. The admin fact itself remains
resident.

## 5. RepositoryApplier transition

For one exact logical delivery the Applier:

1. creates or recovers its stable create-only generation reservation;
2. bounded-decodes the marker and pile;
3. validates the entire pile before reading a potentially large root;
4. pins `root` bytes and the provider's opaque CAS token;
5. point-checks incoming residences against the pinned FactTree;
6. path-copies each newly validated fact and affected suppression route through
   the three authenticated maps;
7. conditionally establishes immutable objects with collision checks;
8. performs one CAS on `root`;
9. records durable rejection evidence, or returns a process-local applied
   receipt bound to the committed root;
10. create-only spends that exact outcome and issues DELETE only when the
    spend is definitely fresh.

The pure full compiler remains the repair and test oracle. Normal publication
path-copies affected authenticated routes and must produce its byte-identical
root without enumerating unrelated validated facts.

A CAS loser keeps its work and retries from the newer root. An unknown CAS
result is reconciled by reading root. A crash after CAS but before a spend
re-proposes against the committed root and receives a process-local no-op
receipt. An ambiguous spend never grants DELETE; the source may remain as
bounded, already-discharged garbage, but every restart observes terminal state.
No LIST result, notification, SQL row, cursor, path segment, provider ETag, or
process-local lock authorizes root mutation or deletion.

Piles carry facts, not delivery events. The generation reservation is the
stable digest of workspace, member, exact payload, and—when present—the
direct-upload marker. Thus byte-identical redelivery is one logical generation
rather than an indistinguishable ABA instance. Reservation and spend records
are never deleted. A valid receipt binds workspace, source, payload,
reservation, exact outcome, and the applicable base/result-root or rejection
evidence. Permanent rejection evidence is bounded, content-addressed, and binds
the exact workspace, source, generation, payload, and verdict. The sole running
delete path requires its exact read-backs and a definitely created outcome
spend; `EXISTS` and outcome-unknown both deny deletion. This remains correct
when provider ETags repeat for byte-identical values.

HTTP receipt acknowledges once the exact generation is durably staged, even
when its first apply attempt fails transiently. The retained generation is the
database-free retry record and a later poke or scheduled turn retries it.
`FullPeer` may additionally show failures observed by its own local scheduler;
that process-local diagnostic is not repository state and is not required of a
hosted recipient.

Concurrent workers may observe slightly delayed roots. They may duplicate
bounded immutable work. They cannot overwrite immutable objects with different
bytes, clobber a newer root, retire another generation, or corrupt a Merkle
tree.

## 6. RepositoryReader and sync

`RepositoryReader` pins exact root bytes. Its subordinate views are:

- `WorkerView` for bounded fact, suppression, and mint reads;
- `ValidatedView` for authenticated fact residences and fresh closure assembly.

Neither view writes or consults SQLite.

Synchronization compares validated fact IDs and canonical object IDs. A shared
`fid` with different bytes is poison. Differences are sent as ordinary closed
piles and received through `RepositoryApplier`. There is no proof-root join,
selected historical edge, or alternate sync settlement.

The correctness baseline enumerates validated residences from both pinned
roots. A future Merkle diff may avoid corpus enumeration, but it must preserve
the same fid/bytes theorem and aggregate two-root budgets.

## 7. Disposable full-peer SQL

SQLite is a local query and authorship accelerator:

```text
facts(fid, blob)
fact_index(kind, k0, k1, src)
meta(k, v)
```

It mirrors canonical fact bytes and the same mechanical rows used by
FactTree, plus current action bindings for local queries. It has no family
tables, validation verdict, dependency graph, rank, eligibility state, or root
publication authority.

Deleting the database changes no repository answer. Rebuild reads a pinned
`RepositoryReader` and replaces the projection transactionally.

### 7.1 Fact-form versioning

Future fact-form upgrades must hydrate old canonical bytes in the surrounding
fact context and store the current form in disposable SQL. The repository
still retains canonical validated bytes for its layout version. This is a
projection codec change, not a second validation path.

## 8. Direct object-store ingress

Ordinary clients upload directly to isolated object-store ingress:

1. ask a read-only broker for exact short-lived create-only capabilities;
2. PUT one exact fact-only closed-pile marker;
3. optionally send a wake hint.

The Applier fetches the marker itself, verifies workspace/member/session/path
bindings, uses that marker as the stable identity of a durably reserved
internal generation, and runs the same pile transition as P2P receipt. It
never deletes client-writable ingress. F10 spends and retires only the
internal generation.

Acknowledgement creates an availability obligation for the exact client
marker. No receipt, F10 spend, Worker teardown, or unproved age heuristic may
retire it. AWS confines the broker parent to conditional `PutObject` and
requires an exact no-lifecycle audit of its externally owned ingress bucket.
Later S3 bucket-configuration mutation is outside broker-parent compromise;
that authority is deploy-only and absent from both Lambda roles. R2's S3
parent necessarily has broader verbs, so a provider bucket lock retains the
complete ingress prefix indefinitely; the lock applies to existing and future
objects and takes precedence over lifecycle. Deployment verifies that exact
lock before either Worker is installed and removal leaves it in place. The
lock API replaces the complete rule document without CAS. R2 REST
configuration authority is account-scoped. Its deploy-only control token is
not a Worker secret, and
`exclusive-dedicated` is an operator invariant: one deployment process is the
sole designated lock writer for the dedicated ingress bucket. Concurrent
same-owner installers write the same document; a racing account administrator
or compromised control token is outside the broker-parent boundary. A future
collector must first prove a separate, exact abandoned-session lifecycle and
cannot impersonate F10.

Notifications and paginated LIST are discovery hints only. Scheduled bounded
rescans are the progress path. Each marker is already the complete fact-only
work unit; duplicate discovery is harmless because its internal generation and
terminal outcome are immutable. There is no second completion state.

The broker grants one fixed-expiry resumable authorization lease. `OPEN`
alone reads a pinned `RepositoryReader` snapshot and proves current upload
authority. Its authenticated cursor fixes workspace, uploader path component,
provider, finite source commitment, progress, quotas, issue time, and expiry.
`ISSUE` and `FINALIZE` perform no later liveness lookup: they accept only an
unmodified cursor, a monotonic committed prefix, remaining quota, and trusted
time strictly before that expiry. A removal committed before `OPEN` denies the
lease; one committed after `OPEN` cannot revoke already-issued provider
requests and therefore takes effect for this path no later than the lease
expiry. Each provider request has its own immutable deadline no later than the
same expiry. Restart, retry, key-ring rotation, notification delay, and a
changed default TTL cannot extend an existing lease.

This cursor is ingress authority only. It cannot address canonical objects,
`root`, or an Applier internal generation, and the broker never turns its
pinned observation into admission state. `RepositoryApplier` independently
verifies staged bytes and the closed pile before the sole root CAS.

## 9. Object-store contract

The database-free engine requires:

- bounded strong read of an exact key;
- conditional create for immutable values;
- one linearizable conditional replace register named `root`;
- durable values after acknowledged writes;
- opaque CAS tokens kept separate from root content hashes;
- bounded paginated LIST only where discovery is required.

S3 and R2 conditional writes provide the root register. ETags are opaque
version tokens, not content hashes. The filesystem adapter is a stronger local
implementation of the same interface.

Fault tests should explore everything the contract permits: CAS races, unknown
outcomes, stale cache layers, short/paginated LIST, repeated notifications,
opaque tokens, delayed visibility outside the canonical store contract, and
crash points. A small live-provider conformance suite verifies each adapter;
the seeded adversarial fake provides reproducible correctness coverage.

## 10. Core invariants

The implementation and tests enforce:

- one closed-pile validation boundary;
- all-or-nothing pile publication;
- monotone `fid -> canonical bytes` residence;
- complete semantic authority addresses in immutable bytes;
- suppression changes current use, never validated residence;
- one pure repository compiler and one root CAS owner;
- one receiving path for full peers, Lambda, and Workers;
- database-free hosted authorization and application;
- stable generation reservation plus one outcome-bound retirement spend;
- opaque-token CAS and immutable collision checks;
- byte-identical convergence across arrival orders and concurrent workers.
