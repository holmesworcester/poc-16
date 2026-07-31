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
| describe notification routing | triggering and preference fact families |
| derive and deliver notifications | post-publication worker |
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
`full_peer/upload_journal.py` retains one exact pile and its current lease,
`full_peer/upload_client.py` owns the small `OPEN -> PUT -> FINALIZE` retry
transition, and `full_peer/upload_client_http.py` owns its outbound HTTP
effects. Provider brokers, signers, private Applier invocation, and deployment
packaging remain under `deploy/`. Local progress is delivery state only and
may be discarded when the user abandons it; an in-flight request can create at
most one immutable staging object and cannot mutate canonical state.

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
policy, liveness guards, commands, queries, and inline authenticated payloads.
Core dispatches through the checked family registry and contains no tag switch.
Registry compilation rejects malformed or ambiguous selector, action,
liveness, and typed-suppression declarations before a family can be admitted.

### 2.1 The closed-pile boundary

A pile is one canonical, workspace-bound, topologically ordered fact closure.
Dependencies precede dependents. Pile bytes, aggregate fact count, each fact's
dependency count, and per-fact transitive closure are independently bounded.
The count is checked lexically before full JSON decoding or kernel allocation,
then rechecked by the exact decoder and kernel. `receive_pile` performs that
check before retaining its exact local source. Each canonical fact and public invite envelope
also fits the smallest hosted Reader's single-object response ceiling. A Bao
file descriptor and every verified Bao slice are ordinary facts. A slice
carries its payload and range proof inline, names the exact descriptor, and
may arrive in a different closed pile. Authenticated-root traversal reads only
bounded ordinary fact and map objects; there is no detached completion store.

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

For one caller-named create-only source key the Applier:

1. bounded-reads exactly that pile, with no LIST or discovery step;
2. verifies the workspace, uploader, session, path, digest, and canonical pile;
3. validates the entire closed pile before publication;
4. pins `root` bytes and the provider's opaque CAS token;
5. point-checks incoming residences against the pinned FactTree;
6. path-copies each newly validated fact and affected suppression route through
   the three authenticated maps;
7. conditionally establishes immutable facts and map pages with collision
   checks;
8. performs one CAS on `root` and reconciles an unknown result;
9. returns `applied`, `noop`, `rejected`, or `retryable`.

The pure full compiler remains the repair and test oracle. Normal publication
path-copies affected authenticated routes and must produce its byte-identical
root without enumerating unrelated validated facts.

A CAS loser retries from the newer root. If that root already contains every
durable fact from the exact pile, the result is `noop`; otherwise the same
bounded transition proposes the missing union. A crash after CAS is therefore
recovered by the sender repeating `FINALIZE`. The exact immutable ingress pile
remains available until a provider retention policy collects it.

`RepositoryApplier` has no ingress DELETE, queue, scheduled drain, completion
cursor, durable receipt, internal pile copy, or SQL state. No notification,
LIST result, cursor, path segment, provider ETag, process-local lock, or broker
observation authorizes root mutation. The closed-pile kernel and root CAS do.

Concurrent workers may observe slightly delayed roots. They may duplicate
bounded immutable work. They cannot overwrite immutable objects with different
bytes, clobber a newer root, delete ingress, or corrupt a Merkle tree.

### 5.1 Mobile-notification derivation

Notification preferences and endpoints are authenticated facts. Delivery is
durable operational work outside core, never repository state, admission
evidence, or a condition of publication or source retention:

```text
closed pile -> RepositoryApplier -> root CAS succeeds
scheduled scanner -> FactTree(base, target) diff -> durable pending cursor
disposable carrier wake -> exact pending body
historical event root + separately pinned current root -> bounded join -> FCM
```

`push_endpoint` binds one installation to its owning user and device, selected
push-node public key, platform, application/environment, and a provider target
sealed to that push node. The plaintext target is never replicated. Endpoint
rotation is a new endpoint plus ordinary exact deletion of the old fact; member
and device liveness determine whether an endpoint is currently usable.

`notification_preference` is user state. A cell is either global or scoped to
one channel. Any enrolled device for the user may replace its observed values
using ordinary exact deletion in the same pile. Concurrent active values meet
restrictively (`none < mentions < all`); channel `inherit` falls back to the
global value, whose absence means `none`. Preferences do not inherit device
liveness, so removing one device does not erase the user's shared setting.

A triggering fact family owns a small pure `notification_trigger` hook. Message
facts carry canonical mentioned-user IDs explicitly; display text is never
parsed. Families without that hook cannot trigger notifications.

An `ApplyResult`'s admitted closure is not an event set: it includes old
dependencies and does not prove which trigger facts became newly resident.
There is therefore no post-CAS emitter. `NotificationDiscovery` keeps a
separate operational `(base, target, continuation)` CAS cursor and performs a
bounded authenticated Merkle diff of `FactTree`. It examines only newly
resident `fact.type` postings for families with notification hooks. It never
fetches fact blobs or consults `FactOrder`, SQL, ingress, or the Applier.

Bootstrap is an explicit compare-and-swap into either `current` mode, which
skips existing history, or deliberate `backfill` mode. An absent cursor never
silently initializes during scanning. Each successful bootstrap creates a
fresh random generation, preventing a paused pre-recovery worker from
completing byte-identical work after state loss and changed current authority.

For a page with triggers, the scanner copies the exact target root bytes into
content-addressed notification state and encodes one bounded body containing
workspace, deployment owner, bootstrap generation, target-root OID, and sorted
FIDs. It creates that body at `obj/<sha256(body)>`, then CASes the cursor to one
pending body OID plus the page's exact successor, and only then publishes a
wake. The scanner cannot pass pending work. Every fair turn republishes its
exact stored bytes, so a crash, dropped publish, expired queue item, or unknown
carrier response cannot lose work. Pages without triggers advance directly.

The carrier is a disposable opaque wake, not the durable work owner. On
delivery, the handler first compares `sha256(body)` with the sole pending OID.
A noncurrent body is acknowledged; a future legitimate body will be published
again after its pending CAS. For the exact current body,
`NotificationWorker` resolves and hash-verifies the historical event root,
authenticates each event there, and pins the current repository root
separately. Missing or corrupt state now retries rather than clearing the
pending item. The current root alone selects current preferences, suppression,
member/device liveness, unambiguous endpoint cells, and push-node ownership.
Delayed work therefore cannot resurrect historical delivery authority.

Each request has a deterministic installation-cell delivery ID derived from
workspace, event, user, installation, and payload. FCM uses that value for
platform collapse and the application must deduplicate it. Only after FCM
acceptance, a current-authority cancellation, or an explicit unregistered FID
or locally malformed sealed endpoint does the handler CAS the exact pending
cursor to its stored successor. A stale or unknown completion CAS is reconciled
by rereading that exact OID. Transient, configuration, missing-state, and
unknown outcomes leave it pending and retry. A crash after FCM acceptance or
partial acceptance can resend the same delivery ID; FCM acceptance is not
evidence of device presentation.

AWS uses S3 notification state, a scheduled scanner Lambda, SQS, and a
delivery Lambda. Cloudflare uses segregated Workers, R2 notification state,
and Cloudflare Queues. FullPeer may compose the same scanner and worker with a
filesystem state store and in-process carrier. These deployments are outside
core and remain disabled until real iOS and Android launch tests pass. Queue
and DLQ retention may be finite without weakening correctness; fair scheduled
scans republish durable pending state. The separate cursor and its immutable
root/body objects are deployment continuity and must not be silently replaced.

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

1. `OPEN` presents current upload authority plus one pile digest and size;
2. the broker returns one fixed-expiry cursor and one exact create-only PUT;
3. the client PUTs that pile directly to S3 or R2;
4. the client calls broker `FINALIZE` with the cursor;
5. the broker invokes the hosted Applier over a provider-private binding with
   the exact key and digest.

`OPEN` is the only current-liveness read. Its authenticated cursor fixes the
workspace, uploader path component, provider, session, pile digest, size,
issue time, and expiry. `FINALIZE` cannot change those values or extend the
lease. A removal committed before `OPEN` denies a new lease; a removal after
`OPEN` leaves only that already-confined pile usable until expiry. The
provider PUT expires no later than the same lease.

The broker is a pinned `RepositoryReader`, an exact PUT signer, and a narrow
private invocation client. It cannot read ingress bytes or mutate canonical
objects and has no validation or compiler. Lambda invocation permission or a
Cloudflare service binding lets it request work, not choose the result: the
database-free Applier independently reads the exact key, rehashes and decodes
the pile, runs the kernel, and owns the sole root CAS.

There is no `ISSUE`, object vector, detached upload, queue, bucket notification,
cron, LIST drain, or server-side retry record. A large file is a descriptor
fact followed by as many independent Bao slice-fact piles as the sender needs.
The sender retries `FINALIZE` after retryable or lost results and opens a new
lease if the old one expires. An upload is complete only after `applied` or
`noop`, so a time-based staging lifecycle may remove abandoned or old sources
without violating repository correctness; a sender whose unpublished source
expired simply uploads a new exact session.

## 9. Object-store contract

The database-free engine requires:

- bounded strong read of an exact key;
- conditional create for immutable values;
- one linearizable conditional replace register named `root`;
- durable values after acknowledged writes;
- opaque CAS tokens kept separate from root content hashes.

S3 and R2 conditional writes provide the root register. ETags are opaque
version tokens, not content hashes. The filesystem adapter is a stronger local
implementation of the same interface.

Fault tests should explore everything the contract permits: CAS races, unknown
outcomes, stale cache layers, opaque tokens, delayed visibility outside the
canonical store contract, and crash points. A small live-provider conformance
suite verifies each adapter; the seeded adversarial fake provides reproducible
correctness coverage.

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
- exact sender-triggered application with no LIST, queue, or ingress DELETE;
- independently admissible ordinary Bao slice facts;
- opaque-token CAS and immutable collision checks;
- byte-identical convergence across arrival orders and concurrent workers.
