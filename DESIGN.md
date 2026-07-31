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
policy, liveness guards, commands, queries, and detached blob references.
Core dispatches through the checked family registry and contains no tag switch.
Registry compilation rejects malformed or ambiguous selector, action,
liveness, and typed-suppression declarations before a family can be admitted.

### 2.1 The closed-pile boundary

A pile is one canonical, workspace-bound, topologically ordered fact closure.
Dependencies precede dependents. Pile bytes, each fact's dependency count, and
per-fact transitive closure are bounded. An independent aggregate fact-count
ceiling is future hardening; the current byte ceiling is the aggregate pile
bound. Each canonical fact and public invite envelope also fits the smallest
hosted Reader's single-object response ceiling. Detached Bao objects use their
separate direct-upload and completion path. Authenticated-root traversal reads
only `MAX_REPOSITORY_OBJECT_BYTES`; the larger generic object ceiling is
reserved for detached ingress and exact collision/retirement work.

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

One canonical root names four Merkle maps and their authenticated metadata.

### 3.1 FactTree

`FactTree` is the validated residence and generic lookup map.

```text
fact:<fid> -> object_oid
index:<kind>:<k0>:<k1>:<fid> -> validated posting
action:<suppression_id> -> current action slot
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
`ACTIVE` names the immutable action. Missing is distinct from `CLEAR`; an
exact liveness check which needs a missing slot fails closed.

Selectors may name SELF, a parent, an ancestor path, several IDs, or none.
PARENT pins its one direct dependency. ANCESTOR traverses only exact named
refs at every hop; the registry distinguishes that promise and admission
checks the actual ref chain. The descendant can therefore carry the final
ancestor ID without storing selected Need providers or historical admission
edges. A later deleter never enumerates descendants.

SuppTree supports exact fact deletion, member removal, device/owner liveness,
and bounded Worker authorization reads without a database or fact-set scan.

### 3.4 AuthorityTree

`AuthorityTree` maps a complete or base offer address to the deterministic
current live provider, or `none` when the address is known but all providers
are suppressed.

```text
need(name, a0, a1) -> provider(fid) | none
need(name, a0, *)  -> provider(fid) | none
```

It is a current projection, not an admission record. The compiler derives it
from validated offers and each provider's declared current scopes. A Worker
fetches and checks the provider fact before using the row.

The invariants are:

- every provider is a resident validated fact;
- it offers the queried address;
- every current scope is `CLEAR`;
- ties affect only the mechanical provider returned for an equivalent address,
  never stored fact validity or semantics.

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

For one exact internal generation the Applier:

1. bounded-decodes the marker and pile;
2. validates the entire pile before reading a potentially large root;
3. pins `root` bytes and the provider's opaque CAS token;
4. reconstructs the current validated set from authenticated residences;
5. unions every durable `Valid.fact`;
6. purely compiles the four maps;
7. conditionally establishes immutable objects with collision checks;
8. performs one CAS on `root`;
9. records durable rejection evidence, or returns a process-local applied
   receipt bound to the committed root;
10. retires only the exact internal generation bound by that receipt.

The current full compiler is deliberately simple: it reconstructs the complete
validated set and emits a history-independent root. Future incremental
compilation must path-copy affected authenticated routes and produce
byte-identical roots.

A CAS loser keeps its work and retries from the newer root. An unknown CAS
result is reconciled by reading root. A crash after CAS but before retirement
re-proposes against the committed root and receives a fresh process-local
no-op receipt. No LIST result, notification, SQL row, cursor, or process-local
lock authorizes root mutation or deletion.

HTTP receipt acknowledges once the exact generation is durably staged, even
when its first apply attempt fails transiently. The retained generation is the
database-free retry record and a later poke or scheduled turn retries it.
`FullPeer` may additionally show failures observed by its own local scheduler;
that process-local diagnostic is not repository state and is not required of a
hosted recipient.

Concurrent workers may observe slightly delayed roots. They may duplicate
bounded immutable work. They cannot overwrite immutable objects with different
bytes, clobber a newer root, retire another generation, skip detached-object
completion, or corrupt a Merkle tree.

## 6. RepositoryReader and sync

`RepositoryReader` pins exact root bytes. Its subordinate views are:

- `WorkerView` for bounded fact, suppression, authority, and mint reads;
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
2. PUT detached objects first;
3. PUT one exact closed pile marker last;
4. optionally send a wake hint.

The Applier fetches the marker itself, verifies workspace/member/session/path
bindings, copies it behind an Applier-minted internal generation, and runs the
same pile transition as P2P receipt. It never deletes client-writable ingress.
Provider lifecycle policy may expire those objects independently.

Notifications and paginated LIST are discovery hints only. Scheduled bounded
rescans are the progress path. Missing attachments do not block fact
validation; detached completion uses immutable page receipts and a
non-authoritative cursor.

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
- exact-generation retirement with durable evidence;
- opaque-token CAS and immutable collision checks;
- byte-identical convergence across arrival orders and concurrent workers.
