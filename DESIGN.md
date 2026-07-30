# POC-16 design

This document states the current architecture and its correctness boundary.
It is descriptive of running code unless a section is explicitly marked
future work.

## 1. Authority map

The system has exactly three capabilities:

```text
PileSender
    local intent -> one ordinary closed pile

RepositoryApplier
    exact ordinary pile -> immutable objects -> one root CAS

RepositoryReader
    one exact root -> authenticated, side-effect-free answers
```

They form exactly two actors:

```text
hosted repository = RepositoryApplier + RepositoryReader

full P2P node     = PileSender + RepositoryApplier + RepositoryReader
```

`PileSender` may use SQLite. `RepositoryApplier` and `RepositoryReader` may
not. A full node does not gain a second receiving algorithm: its receiving
side calls the same `RepositoryApplier` used by Lambda and Workers.

Provider least-privilege packaging may place the hosted repository's
Reader-facing broker and Applier in separate processes. They remain two
compartments of the one hosted composition: the broker has no repository
mutation state, while the Applier has no alternative read/query authority.
Physical deployment separation is not a third repository actor.

Subordinate views do not add authority:

- `WorkerView` is a bounded policy/query view under one `RepositoryReader`.
- `CandidateView` reads retained candidate records under the same root.
- a broker is one `RepositoryReader` plus a provider-specific upload signer.

The following operations have one owner:

| operation | owner |
| --- | --- |
| close and encode outbound facts | `PileSender` |
| judge one exact incoming pile | `RepositoryApplier` via `kernel` |
| establish immutable canonical objects | `RepositoryApplier` |
| compile repository state | `repository_snapshot.compile_snapshot` |
| compare-and-swap `root` | `RepositoryApplier` |
| retire an internal pile generation | `RepositoryApplier` |
| answer from a pinned root | `RepositoryReader` |
| assemble client presentation | fact-family queries over the disposable index |

`Node` is a composition root and turn coordinator. It may construct these
capabilities and translate results into client diagnostics. It does not own
fact policy, settlement, storage layout, root publication, or a second
receiving loop.

## 2. Facts and families

A fact is a canonical serialization of:

```text
(workspace, type, timestamp, clear-envelope atoms, body)
```

Its `fid` is the SHA-256 address of that serialization. Ordinary facts carry
their workspace ID. The workspace-genesis family is the sole exception: its
own `fid` is the workspace anchor, so it may omit `ws`.

The clear envelope contains:

- named refs;
- named offers;
- explicit suppression selectors or actions.

Bodies are family-shaped but are not inspected to discover generic refs,
offers, or suppression IDs.

Every fact type is a module under `facts/`. A family owns:

- construction and shape validation;
- named needs and offers;
- durable versus ephemeral mode;
- suppression-selector policy;
- direct-action and owner policy;
- continuing authority-liveness guards;
- commands and queries.

Core dispatches through the family registry. Adding a family should not add a
type branch to `Node`, the CLI, the repository compiler, or the object-store
adapters.

### 2.1 Closed piles

A pile is one canonical, workspace-bound, topologically ordered closure.
Dependencies precede dependents. Running code bounds pile bytes and each
fact's resolved-edge and transitive-closure size. An aggregate fact-count
limit for a byte-valid pile is additional resource hardening tracked in
beads; it is not an admission invariant today.

The database-free kernel builds a `MemoryContext` while streaming the pile:

```text
known facts
proof rank
resolved named edges
transitive closure
canonical offers
```

For each fact it:

1. proves workspace binding;
2. resolves refs and family-declared needs;
3. runs family validation;
4. checks family policy;
5. assigns a well-founded rank;
6. emits a `Valid` receipt with exact named edges.

An unexpected family/program error is retryable work, not permission to
destroy the pile. A permanent malformed or semantically invalid pile receives
typed rejection evidence before its internal generation can be retired.

## 3. Suppression and actions

Suppression is explicit, typed, and family-owned.

A family can declare:

- `Self()`;
- `Parent(role)`;
- `Ancestor(role, ..., role)`;
- several selectors;
- no selectors.

At authorship the fact serializes the exact IDs resolved along those named
paths. Ancestors already exist because piles are topological. A later deleter
does not enumerate descendants. A child can therefore carry SELF plus a
parent or grandparent ID, while a family that offers no selector is
unsuppressible.

This is not a guess based on fact type at read time. Admission independently
recomputes the selector list from the family policy and resolved edges and
requires exact equality.

### 3.1 SuppTree

For every declared suppression ID, `SuppTree` contains exactly one state:

```text
CLEAR
ACTIVE(action_fid)
```

`CLEAR` means the ID is authenticated and no action is effective at this
root. `ACTIVE(action_fid)` names the exact effective immutable action.
Missing is distinct from `CLEAR`; a reader requiring a missing slot fails
closed.

This map supports:

- an exact fact-liveness check by `fid`;
- member/device liveness during authentication;
- parent and ancestor cascades;
- multiple independent suppression keys;
- a bounded Worker read without loading all facts.

The old split between a direct removal index and another suppression index
does not exist. The explicit suppression ID is the lookup key; the action
`fid` is the authenticated value.

### 3.2 Deletion

A deletion is an ordinary `delete` fact, not a privileged imperative.

It contains:

- an exact target ref;
- the target's canonical key;
- a suppression action offered to the target's SELF ID;
- named needs proving its author and OWNER or ADMIN authority.

Validation requires the offered action to match a direct target permitted by
the victim family's policy.

- ADMIN may delete every family marked directly deletable.
- OWNER may delete a fact whose `owner_edge` resolves to the same durable
  member principal.
- devices linked to one member share that principal, so a user may delete
  their facts written by any of their devices.
- deletions and other families with no direct-target policy cannot be deleted.

These are ordinary family handlers over named reqs/offers. No special
deletion permission branch belongs in `Node`.

### 3.3 Removal and delegated admins

Member removal activates the family-declared member principal ID. It affects
future authorization once observed; it does not rewrite history or declare
every fact authored after some wall-clock point illegitimate. A peer that
validly accepted a message before learning the removal has accepted a
workspace fact.

An admin grant proves the grantor's admin authority at admission, but its
continuing liveness follows the grantee:

```text
admin grant
    named admission Need -> grantor_admin
    liveness guard       -> grantee_member
```

Removing the grantor does not revoke every delegated admin. Removing the
grantee does remove that grantee's live admin authority. Device-derived admin
use also follows the device/user liveness declared by the device families.
Every current command and remote mint resolves authority through the pinned
repository's liveness rows before it can author or accept new work.

Infrastructure-provider membership is a separate concern from content-admin
authority. The current deploy adapters receive an operational workspace and
least-privilege provider configuration out of band. A future in-band provider
community can model support as an invitation for an infrastructure node:
joining grants service for a workspace; leaving severs support. That provider
community does not silently become a content admin in the serviced workspace.

## 4. Candidate state and settlement

Historical admission and current authority are different. In the serialized
candidate record, the legacy state label `eligible` means *structurally
standing*; it does not mean currently usable:

- a candidate is a durable, valid fact plus its admission proof and exact
  named edges;
- a structurally standing candidate has canonical standing under immutable
  validation, its named needs, and deterministic provider selection;
- a dormant candidate remains retained because it cannot currently fit that
  canonical dependency graph, and may become structurally standing after
  another valid arrival changes provider selection;
- suppression and authority-liveness rows describe what may be used now.
  They do not retroactively change an admitted candidate's standing.

Settlement is a pure, one-way projection over the candidate set:

```text
candidate set
    -> canonical standing and ranks
    -> effective actions
    -> authenticated suppression and authority-liveness rows
```

The earliest canonical action wins a suppression ID. Provider selection is by
proof rank and then `fid`, making it independent of delivery order. A
candidate's selected named edges are its historical admission witness. A
later member-removal action can stop current authoring, minting, or delegated
authority without making that candidate dormant. A genuinely different
canonical provider may still change the dependency graph and therefore
eligibility; that is not removal screening.

## 5. Published repository

The canonical store contains:

```text
root                       one mutable CAS register
obj/<sha256>               immutable content-addressed objects
pile/<member>/<gen>/<hash> Applier-owned internal work
failed/...                 noncanonical immutable rejection evidence
staged/...                 noncanonical immutable staging receipts
applier/cursor/...         nonauthoritative discovery hints
```

The root authenticates four descriptors:

```text
FactTree
SuppTree
AuthorityTree
FactOrder
```

Every descriptor uses the same bounded Merkle-map shape. Readers descend the
tree directly; no range directory and no rebuilt database are required.

### 5.1 FactTree

`FactTree` is the candidate and generic posting map.

For each candidate it authenticates a bounded record containing:

- fact object ID and canonical fact key;
- structurally-standing/dormant state and proof rank;
- admission-proof object ID;
- exact named dependencies;
- declared suppression and authority-liveness IDs;
- clear-envelope offers.

It also contains mechanical postings by:

- type;
- canonical fact key;
- every ref;
- every offer;
- suppression scope;
- dependency target.

Why it exists:

- exact fact lookup without a manifest scan;
- bounded typed and offer queries;
- candidate sync and dormant reactivation;
- deterministic closure and range comparison.

Invariant: every posting is a mechanical function of one checked candidate
record and fact serialization. A forged extra posting or omitted required
posting invalidates reconstruction.

### 5.2 SuppTree

`SuppTree` maps each explicit suppression ID directly to `CLEAR` or
`ACTIVE(action_fid)`.

Why it exists:

- exact authentication/liveness reads by ID;
- descendant suppression through explicit parent/ancestor IDs;
- no read-time fact-DAG walk;
- no full fact-set or SQL dependency at an edge.

Invariant: every ID declared by any retained candidate has a row. Required
absence fails closed. Every active value is corroborated by the corresponding
candidate/action state.

### 5.3 AuthorityTree

`AuthorityTree` maps a canonical base family-need address to the selected
provider and rank.

The authenticated address is exactly:

```text
(offer name, a0, optional a1)
```

Why it exists:

- authorization can resolve member/admin/device providers by point read;
- provider choice is visible and authenticated;
- a Worker need not enumerate all offerers.

Invariant: the selected provider is the minimum structurally-standing
`(rank, fid)` for the base address. A need's required co-offers are
conjunctive checks against that exact selected provider's authenticated
`FactTree` record. They do not create a second address and do not permit
fallback to a later provider.

### 5.4 FactOrder

`FactOrder` maps canonical fact key to fact object ID for structurally
standing facts.

Why it exists:

- deterministic ordered reconciliation;
- bounded range diff;
- fact bodies have one canonical content-addressed residence;
- no second pile/body serialization is introduced.

Invariant: keys are direct fact keys, values name exact verified fact bytes,
and the order contains precisely structurally standing facts. Current
suppression and authority liveness are separate authenticated lookups; they
do not rewrite historical order.

### 5.5 Candidate archive

The root-reachable archive is enough for a cold `RepositoryApplier` to
reconstruct every candidate, admission witness, and edge without SQLite. Its
reconstruction cross-checks all four maps rather than trusting one map as a
manifest for the others.

## 6. Root compilation and CAS

`compile_snapshot(workspace, candidates)` is pure. Given the same candidate
set it returns byte-identical:

- immutable object outbox;
- tree descriptors;
- root bytes;
- checked candidate records.

`RepositoryApplier` interprets that result:

```text
read exact (root bytes, opaque version token)
load root-reachable candidate archive
join valid candidates from the exact pile
compile
conditionally establish every outbox object
CAS root using the token from the original read
mint exact internal-retirement authority
```

The Applier never repins midway through a proposal. If root changes, its CAS
loses and the exact pile remains for a fresh proposal.

Only one literal semantic `cas("root", ...)` exists in production. Provider
adapters implement the token mechanics; they do not compile or choose facts.

### 6.1 Apply outcomes

The typed outcomes are:

- `applied`: CAS definitely installed the proposed root;
- `confirmed`: CAS response was lost and an exact read found that root;
- `noop`: the candidate set was already present and the original root token
  still identifies the same root;
- `stale`: another root won; retain and rebase;
- `rejected`: immutable typed rejection evidence exists;
- retryable error: exact work remains.

An ephemeral `ApplyProposal` is bound to:

- workspace;
- exact pile payload hash;
- exact base root/token;
- minting Applier instance.

It cannot commit another pile, another workspace, or through another
Applier.

## 7. Exact retirement

Retirement is a capability, not “DELETE after trying.”

For an internal pile generation, deletion is permitted only after:

1. `applied`, `confirmed`, or token-checked `noop`; or
2. durable typed rejection evidence for that exact source and payload.

The capability binds:

```text
(workspace, source key, payload hash, generation, root/outcome, issuer)
```

It is ephemeral and one-use. A crash after root CAS leaves the immutable
internal pile. A cold Applier reconstructs the same result as `noop`, obtains
a fresh capability, and retires it.

Running code binds and rechecks every field above plus the exact current
source bytes. Provider stores do not yet expose an atomic
delete-if-incarnation operation, however. Recreating identical bytes at the
identical source key after deletion would therefore be an ABA that those
checks cannot distinguish. Until the tracked F10 incarnation work lands,
exact internal-generation key non-reuse is an explicit store/Applier
assumption, not an enforced theorem.

Client ingress is different. `RepositoryApplier` does not delete client
markers or staged objects. Their retention/lifecycle is an isolated-ingress
policy and is never justified by the internal retirement capability.

Operational `failed/*`, `staged/*`, and cursors are not part of
`RepositoryReader`. An admin diagnostic adapter may inspect them, but pinned
repository answers depend only on `root` and `obj/`.

## 8. Direct upload

Direct upload uses two provider compartments:

```text
canonical bucket
    reader: exact root/object reads
    applier: root/object/internal-work authority

isolated ingress bucket
    client: broker-issued exact create-only PUTs
    broker parent: minting only
    applier: bounded LIST + exact GET
```

The client uploads objects first and the exact pile marker last:

```text
ingress/v1/workspaces/<ws>/objects/<session>/<sha256>
ingress/v1/workspaces/<ws>/piles/<session>/<member>/<pile-sha256>
```

The marker, not a notification, is durable intent. A notification or poke can
reduce latency. A bounded scheduled scan recovers dropped, duplicated,
reordered, or delayed hints.

The ordinary pile inside the marker has exactly `ws` and `facts`. It cannot
embed an object map. Detached bytes have one ingress path: exact object
delivery through `RepositoryApplier`, either directly or through validated
same-session staging.

### 8.1 Staging door

For one marker the Applier proves:

- configured workspace equals the key workspace;
- key digest equals exact marker bytes;
- marker is canonical;
- envelope workspace is exact;
- every ordinary fact is bound to that workspace;
- only the workspace-genesis family may omit `ws`;
- the key's session/member components are canonical and remain bound to the
  exact broker-granted ingress capability and the Applier-minted internal
  source;
- every attachment key is derived from a blob ref and the same session.

The member component identifies the authenticated uploader session; it does
not claim that uploader authored every dependency relayed in the pile.
Family needs and signatures judge each fact's authority. The marker is then
copied behind one fresh internal generation. A durable claim ensures
concurrent/replayed handlers recover that same generation. Fact application
uses the ordinary `RepositoryApplier.apply` path.

### 8.2 Attachment completion

Facts commit before detached attachment promotion. This prevents a slow or
missing file body from blocking otherwise valid workspace facts.

Attachment work is bounded:

- at most one fixed-size object page is processed per marker turn;
- each object gets immutable promoted/poisoned evidence;
- each fully terminal page gets an immutable page receipt;
- a mutable cursor is only a round-robin liveness hint;
- completion is recorded only after every page receipt exists.

Concurrent Workers may process the same object/page and may briefly regress
the cursor. They cannot falsely complete a page, skip an unfinished page
forever once interference stops, overwrite a canonical object, or corrupt a
tree.

## 9. Object-store mathematics

For each key, model the provider as a linearizable register. The repository
requires:

### 9.1 Bounded exact read

```text
get_bounded(k, max_bytes) -> bytes | absent | over-limit
```

The implementation must enforce the bound while reading. Fetching an
unbounded body and checking its length afterward does not satisfy this
operation.

### 9.2 Immutable create

```text
put_if_absent(k, v) -> CREATED | EXISTS | unknown
```

`EXISTS` is success only after a strong read proves the incumbent bytes equal
`v`. An unknown response is reconciled by an exact read. `obj/<h(v)>` is never
overwritten.

### 9.3 Root CAS

```text
read_versioned(root) -> ABSENT | (bytes, opaque_token)
cas(root, opaque_token_or_ABSENT, new_bytes) -> APPLIED | STALE | unknown
```

The token is a comparison capability for the exact read, not a content hash.
An unknown result is reconciled by reading root:

- proposed bytes present -> `confirmed`;
- exact base still present -> retryable unknown;
- another root present -> `stale`.

### 9.4 LIST

LIST is discovery only:

```text
list_page(prefix, opaque_cursor, limit) -> bounded keys + cursor
```

Correctness is not derived from a single complete listing. Cursors are
persisted as hints, scans wrap, each item is isolated, and retained work plus
immutable receipts make replay safe. `list_page` is mandatory; an adapter may
not implement it by materializing and sorting a whole LIST.

### 9.5 Concurrent-worker theorem

Let `O` be the content-addressed object map and `R` the root register.

- `O` grows monotonically by verified conditional create.
- a committed `R` references only objects already established in `O`.
- successful root CAS operations impose a total order on roots.
- a stale worker does not delete its exact work.
- replay from any later root computes a serial union or remains retryable.

Therefore concurrent Appliers can waste work but cannot produce a root that
references absent compiler output, clobber an immutable object, or lose an
unapplied pile. Readers pin one root and never mix answers across that total
order.

The filesystem adapter provides stronger local behavior but runs the same
algorithm. S3 and R2 adapters must pass both a deterministic adversarial
contract suite and a small live-provider conformance suite.

## 10. RepositoryReader

A reader is constructed from:

```text
(workspace, exact root bytes, immutable-object fetch)
```

It validates the root anchor at construction. It has no store-wide handle,
LIST, PUT, DELETE, CAS, turn, or SQL connection.

A read decision pins this root for its whole duration. Even if another
Applier commits concurrently, the decision either completes against the
pinned object graph or fails closed. It never adopts a later root halfway
through authentication.

Workers answer:

- exact fact and candidate reads;
- suppression state by explicit ID;
- selected authority provider;
- bounded generic postings;
- upload/auth minting policy.

They walk the authenticated Merkle trees directly. Rebuilding a database on
each request is neither required nor allowed.

## 11. Disposable client projection

The full node may maintain SQLite:

```sql
facts(fid PRIMARY KEY, blob)
fact_index(kind, k0, k1, src,
           PRIMARY KEY(kind, k0, k1, src))
meta(k PRIMARY KEY, v)
```

`facts.blob` is the canonical serialization produced by the same fact codec
used everywhere else.

`fact_index` contains:

- `fact.type`;
- `fact.key`;
- `fact.ref`;
- every family offer kind;
- `projection.state` with eligibility and rank;
- `projection.edge` with exact typed named edges;
- `projection.action` with current suppression-action bindings.

There are no application tables and no separate proofs, edges, actions, or
suppression databases. Queries join the generic index and assemble their own
views.

The projection is replaced from one `RepositoryReader`. It is never an input
to incoming pile judgment, repository settlement, canonical object creation,
root CAS, or retirement. Deleting it cannot change repository state.

### 11.1 Versioning

Current fact IDs bind the current serialization. When contextual fact-form
versioning is added, projection rebuild must:

1. read the historical root-reachable fact;
2. hydrate it as the form current in the context of surrounding facts;
3. serialize and store that current hydrated form in `facts.blob`;
4. derive index rows from that form.

The original obsolete form is not copied into the current projection merely
because it was the first encoding received. Repository-format migration and
client projection migration remain separate decisions.

## 12. P2P sync

Reconciliation pins a `RepositoryReader` on each side, compares their
authenticated `CandidateView`s, selects the lower complete admission witness
for each difference, and asks `PileSender` to coalesce the verified closures
into bounded ordinary piles. Coalescing is legal only when judging the union
preserves every fact's exact named dependency edges from its selected
historical witness. A merely valid union is insufficient: if canonical offer
selection would rewire a fact, or make the union invalid, the closures remain
separate ordinary piles. Candidate/proof state and newly authored facts
therefore use the same wire unit without manufacturing new admission proofs.

`PileSender` owns every outbound peer object/pile delivery. The receiving side
always stages those bytes for `RepositoryApplier`; it never installs a remote
root, candidate record, page, or diff result directly. A hosted recipient and
a full P2P peer therefore land the same pile with the same database-free
algorithm and produce the same root.

The current correctness baseline enumerates candidate IDs from the pinned
views. Future range-diff optimization may descend the same authenticated
Merkle maps, but it must select the same witnesses and emit the same ordinary
piles; it does not become another receiving protocol.

Detached objects are sent before the fact-only pile when pushed directly.
Missing objects may be fetched later by hash. No alternative fact-application
path is introduced for sync.

## 13. Provider packaging

Provider code is segregated:

- `adapters/s3/`: S3 request/response and opaque-token translation;
- `adapters/r2/worker.py`: native R2 binding translation;
- `deploy/aws_repository_applier/`: DB-free Lambda artifact and SAM template;
- `deploy/cloudflare_upload/worker/applier*.py`: DB-free Worker entry/runtime;
- `deploy/aws_upload_broker/` and Cloudflare broker modules: signer/front door.

Provider packages do not contain `Node`, SQLite projection code, daemon code,
or a second compiler.

AWS installs scheduled bounded recovery; the Lambda handler also accepts S3
event records as hints. Cloudflare installs a one-minute cron. Both use
separate canonical and ingress buckets.

Deploy artifacts are implemented and build-tested. Live-provider correctness
is claimed only after the selected account passes the conformance suite;
generated Cloudflare claims retain `live_verified: false` until then.

## 14. Invariants

The test suite and structural ratchets enforce:

1. exactly three capability class definitions;
2. exactly two actor compositions;
3. one outbound pile encoder owner;
4. one root compiler;
5. one semantic root CAS call;
6. only `RepositoryApplier` establishes canonical objects;
7. only `RepositoryApplier` retires internal generations;
8. `RepositoryReader` is side-effect-free and database-free;
9. a full-node turn delegates to exactly one Applier turn;
10. every ordinary fact is workspace-bound;
11. proposals bind workspace, payload, base, and issuer;
12. root references are established before CAS;
13. CAS losers retain exact work;
14. rejection retirement follows immutable exact evidence;
15. client ingress is never retired by application/F10 code;
16. concurrent replay converges to a serial union;
17. explicit suppression IDs map to authenticated `CLEAR`/`ACTIVE` states;
18. required missing suppression state fails closed;
19. SQLite has one fact table and one combined index only;
20. root docs are exactly `README.md`, `DESIGN.md`, and `AGENTS.md`.

Item 7 enforces ownership of the retirement call. Items 11, 14, and the
running source-byte checks enforce its current evidence binding. They do not
yet prove exact storage incarnation across identical key/byte recreation; the
open F10 ABA work described in §7 is the remaining boundary.

## 15. Open performance work

The current compiler reconstructs and recompiles the complete candidate
archive for each accepted pile. This gives a simple deterministic reference
implementation, but repeated commits become expensive as the archive grows.

The incremental compiler must:

- update only authenticated affected paths;
- remain byte-identical to a full compile for every arrival order;
- preserve stale-CAS retry behavior;
- eliminate commit-time whole-key scans;
- report facts/s at 50k and 200k facts;
- report file throughput in MiB/s.

Until those criteria pass, the full compiler remains the correctness oracle
and no optimistic large-scale number belongs in the documentation.
