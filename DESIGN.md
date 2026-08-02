# POC-16 design

This document defines the accepted target architecture. Current `main` still
implements the predecessor in which one `RepositoryApplier` compiles all
workspace facts under one mutable content root. The transition is tracked by
`poc-16-iq2`; until its cutover child closes, statements about writer logs and
the head directory describe the target rather than running deployment claims.

The central decision is:

```text
one workspace-wide mutable content root
    becomes
one independently advancing log per device writer
    plus
one shared directory containing one small head per device
```

Normal content publication therefore has no workspace-wide mutable key. The
remaining shared state is a small authority/removal projection, changed by
membership and administration rather than by every message or file.

## 1. Goals and non-goals

The design must provide:

- the same fact bytes, closed-pile judgment, and suppression rules everywhere;
- cloud gates and readers with no persistent database or durable projection;
- direct object-store upload of large immutable data;
- independently writable device logs, with no cross-device content CAS;
- deterministic convergence from mixed but individually valid log views;
- one implementation of validation and reconciliation shared by hosted and
  full peers;
- bounded operations under Lambda and Cloudflare Worker limits;
- no destructive action in the publication path.

The design does not provide a globally atomic view of every writer at one
instant. That property would require a shared manifest and recreate the
contention this design removes. A reader may observe Alice's newest head and
Bob's preceding head. Each observation is safe; a later scan discovers Bob's
advance.

The directory is not a queue, database, global log, or validation certificate.
It is a bounded way to discover signed candidate heads.

## 2. Authority and data flow

There are five logical capabilities:

```text
LogWriter
    local intent -> bounded closed piles -> immutable per-device Merkle log

CloudGate
    membership + non-removal proof -> writer-confined head-slot CAS

RepositoryMirror
    listed head pointers -> missing content-addressed writer-tree objects

FactConsumer
    mirrored closed piles -> ordinary kernel -> local validated union

HttpGate
    peer HTTP request -> authorized object, head, authority, or mirror operation
```

`LogWriter` normally lives in a stateful full peer and may use SQLite for local
authorship and presentation. It uploads immutable objects directly to its
registered store. It does not need a cloud process to rebuild its tree.

`CloudGate` has no persistent database. For one request it projects the supplied
authority facts and removal paths into a fresh in-memory or temporary SQLite
transaction and asks the ordinary fact queries whether the requester and the
recipient node are currently eligible. Its only configured protocol identity
input is the recipient node's root public key. A successful requester proof
binds the exact proposed head OID. The gate confines the update to that device's
stable slot and performs its CAS. It trusts the writer to maintain the writer
tree: it does not validate the head, log shape, content piles, sequence,
predecessor, or closure, and it never compiles a workspace content root.

`RepositoryMirror` is database-free and runs on every peer, including the
cloud peer. It lists directory slots, learns their head OIDs, and mirrors only
content-addressed head and writer-tree objects absent from its local store. It
may enforce byte, request, hash, and storage-integrity bounds while copying;
that is not semantic fact or log admission.

`FactConsumer` runs wherever mirrored content is used as workspace state. It
validates every new closed pile through the ordinary kernel before projecting
facts. A full peer always consumes this way and may project the validated union
into disposable SQLite. A cloud peer that only mirrors, gates, and serves data
does not consume the content and therefore does not validate it.

`HttpGate` owns the common HTTP operations and grant checks. AWS Lambda,
Cloudflare Workers, a plain HTTP peer, and a peer reached through Iroh invoke
the same core capabilities. Provider adapters translate storage calls and
deployment configuration only.

## 3. Facts and closed piles

A fact retains the existing canonical clear envelope and canonical body:

```text
e = (workspace, type, timestamp, clear-envelope atoms, body-hash)
b = body
```

The `fid` is the SHA-256 address of the canonical envelope. The immutable fact
object ID is the SHA-256 address of the canonical `{e,b}` encoding. Ordinary
facts name their workspace; workspace genesis remains the sole exception
because its own `fid` is the workspace anchor.

Fact families own construction, exact shape validation, declared `Need`s,
durability, immutable refs and offers, suppression selectors and actions,
liveness scopes, commands, and query assembly. Core dispatches through the
checked family registry and contains no fact-type switch.

### 3.1 A log stores independently valid wire units

A writer log is an authenticated ordered map from a writer-local publication
sequence to an immutable closed-pile object or a verified slice of a pile pack.
Every pile is independently bounded, topologically ordered, and workspace
bound. Dependencies precede dependents.

The intended split is:

```text
writer log: closed piles containing the writer's facts plus required closure
local state: fid -> canonical fact bytes after successful validation
```

A pile may repeat dependency facts already present in another writer's log.
That is expected. Duplicate canonical `fid` values meet idempotently. The log
writer is not presumed to be the author of every fact in a relayed closure;
ordinary fact signatures and family policy retain that distinction.

For each incoming pile the kernel:

1. proves canonical identity and workspace binding;
2. resolves exact refs and family-declared Needs from the supplied closure;
3. invokes family shape and policy checks;
4. enforces fact, dependency, depth, byte, and closure bounds;
5. admits every durable fact only if the entire pile succeeds.

An already validated resident may make replay cheaper, but correctness and
cold reconstruction cannot require it: every published log unit carries the
closure a fresh receiver needs. Local-only authority anchors are confined to
the separate authority gate and never silently complete an ordinary content
pile.

The selected dependency edges are ephemeral judgment values. They are not
stored as proof DAGs, ranks, winners, or admission witnesses. An invalid pile
admits nothing from that pile; because later log entries are independently
closed, it need not poison an unrelated later pile.

Once a peer validates a fact, its local validated set is monotone:

```text
if f validates against S,
then f remains valid in every validated superset S'
```

Remote log inclusion proves only authenticated publication by that log writer.
It does not let an untrusted writer bypass the receiving kernel.

## 4. Per-device writer logs

Every enrolled device has its own logical writer ID and its own log. Separate
devices of one user have separate logs so the normal case has one human process
contending with nobody, including the user's other devices.

A writer update proceeds in this order:

1. construct one or more bounded closed piles;
2. establish fact, pile, pack, and Merkle objects immutably in the writer's
   registered store;
3. construct the new cumulative writer-log root;
4. construct and sign one immutable successor head record;
5. prove current membership and non-removal to `CloudGate`, binding that proof
   to the proposed head OID;
6. conditionally replace only this device's stable head slot.

The log root is content addressed. It is not the provider ETag, and no code may
derive one from the other. Writer-log pages and pile objects are immutable and
must exist before the head can become visible.

The honest writer maintains a cumulative log. Each signed head links to the
preceding immutable head record, making rollback and forks visible. A provider
directory cannot force a user-controlled bucket to retain data forever; cloud
storage availability is therefore distinct from fact validity. Replication to
other peers supplies independent durability.

Writers may pack many small pile or Bao-slice objects into one immutable object
with a compact range index. A pack index is only a locator. Each extracted pile,
fact, payload hash, and Bao proof is checked normally. Packing changes request
economics, not authority or closure.

## 5. Canonical writer heads

One canonical head record binds at least:

```text
format version
workspace fid
device-writer fid
durable owner principal
writer-local sequence
previous immutable head oid, or genesis
current writer-log root oid
registered store-binding fid
device signature
```

The exact codec and bounds belong to `poc-16-iq2.1`. These semantic fields are
not provider metadata. In particular, a head contains a registered store
binding, never an arbitrary URL supplied to a cloud fetcher.

The directory and writer store use two forms:

```text
head-objects/<head-oid>          immutable writer-supplied head record
heads/<workspace>/<device-fid>  mutable {head_oid, accepted_authority_root}
```

The stable slot makes listing compact: one entry per enrolled device rather
than one entry per update. Its body is content hashed independently; its
provider version token is used only to conditionally replace that exact slot.

`CloudGate` accepts an exact slot update only when:

- the submitted proof authenticates the workspace device as a member and not
  removed at the authority root the gate itself pins;
- the proof binds the exact proposed head OID;
- the deterministic slot belongs to that same workspace device;
- the request and slot body fit fixed mechanical bounds;
- the per-device conditional replace succeeds.

The caller cannot select an older authority root. The gate records the exact
root it used beside the head OID. It does not fetch or interpret the head or
writer tree, verify its signature or predecessor, or establish that its objects
exist. Those are writer responsibility until another peer consumes the log.

A consuming peer, not the cloud gate, verifies the head object's content hash,
device signature, workspace, owner, store binding, sequence, predecessor chain,
and named log root before validating every closed pile it has not already
validated.

An unknown CAS result is reconciled by rereading the stable slot. An exact
head-OID match is success; otherwise the writer repins and retries. No path
deletes a head, log object, pile, or ingress object.

## 6. The shared workspace directory

The directory is an object-store prefix, not a separately maintained manifest:

```text
heads/<workspace-fid>/<device-fid>
```

Concurrent writes to different keys are independent. Two Lambdas updating
Alice and Bob never compare against the same token. Only duplicate or genuinely
concurrent updates for one device contend on one slot.

If users keep content in physically separate buckets, the provider-operated
directory bucket holds only these small slot records. Each writer head points
through a registered store binding to the user's content bucket. Every peer,
including the cloud peer, mirrors the per-writer trees it learns through this
directory; no peer combines them beneath another content root.

### 6.1 LIST discovers candidates; it grants nothing

S3 and R2 supply strongly consistent prefix listing. The portable contract is
bounded cursor pagination returning at most 1,000 entries per page, ordered by
key. The implementation must also tolerate a valid short page.

A workspace mirror turn is:

1. list every page under the exact workspace head prefix;
2. reject malformed keys and filter candidates through the known device-writer
   registry;
3. compare each listed opaque slot token with the locally observed token;
4. conditionally read only a new or changed tiny slot to learn its head OID;
5. if that immutable head OID is already local, perform no head fetch;
6. otherwise mirror the missing content-addressed head, Merkle pages, and pile
   objects from that writer tree;
7. stop there on a cloud peer;
8. on a consuming peer, validate the head and every previously unvalidated
   closed pile, then union its durable facts.

A head learned through P2P and already present locally is not fetched again
merely because this provider directory slot was first observed later. The
provider token optimizes the tiny mutable slot read; content OIDs determine
whether any immutable head or tree object is missing.

LIST output is never accepted as membership, authorship, liveness, workspace
binding, or fact validity. A forged extra object is ignored. An absent object
means only that no content was observed for that writer.

### 6.2 A directory observation is intentionally not transactional

We do not assume that a multi-page LIST plus subsequent GETs is one global
snapshot. A head can advance during pagination. A conditional GET either pins
the exact listed version or fails and causes that one key to be reconsidered.

Mixing head versions cannot create a torn object or authorize a fact. The cloud
peer merely mirrors opaque content-addressed objects. A consuming peer admits
only piles it has independently validated, so a mixed observation can only
delay valid additions. Periodic full scans plus fair retry converge.

Initial discovery costs roughly one LIST request per 1,000 device writers plus
one small slot read per writer. A warm peer still lists the directory but reads
only changed slots and mirrors only head/tree objects it does not already have.
This is measured before introducing any second index.

## 7. Ephemeral authority verification and removal refresh

Ordinary content logs do not update shared workspace authority. Membership,
device enrollment, delegated administration, registered store bindings,
infrastructure-node join, leave, self-removal, and administrative removal are
facts projected into a small authenticated authority/removal root.

### 7.1 One request-local proof transaction

An authorization request carries a bounded set of canonical facts and exact
authenticated removal paths. The verifier creates a fresh SQLite database in
memory or provider-local temporary storage, decodes those facts through the
ordinary family serializers, projects them with the ordinary fact handlers,
queries the projected state inside that isolated authorization transaction,
and discards the database.

Before projection, core mechanically verifies canonical fact identities,
signatures, workspace bindings, and each removal path against the authority
root currently pinned by the recipient. SQLite therefore receives authenticated
proof inputs rather than caller-invented `CLEAR` rows. This proof verification
is the cloud's authority job; it still never traverses the advertised content
log.

No prior request rows, persistent SQL, provider account, API token, cache, or
ambient Iroh identity enter the verdict. The only locally configured protocol
identity supplied to the transaction is the recipient node's root public key.
The workspace, requester, owner, requester device, operation, object or head
OID, and proof root are all bound by the submitted canonical facts and signed
request.

For ordinary publication or content access the resulting state must prove:

1. the requester user was admitted as a workspace member;
2. that member is not currently removed and has not left;
3. the signing requester device joined under that member;
4. that requester device is not removed and has not removed itself;
5. the recipient node's configured root public key names an infrastructure
   device that joined the required provider community, with an in-band binding
   offering service to this workspace;
6. that recipient device and its owning infrastructure member are not removed
   and have not left either the community or that service binding;
7. the exact requested operation and, for publication, proposed head OID are
   bound to the requester device.

The recipient-device checks prevent a removed or retired provider replica from
continuing to mint grants in a multi-node deployment. They are part of the
target verifier even if the first single-node implementation lands them as a
separate follow-up. A deployment cannot claim multi-node readiness without
them.

This transaction validates authority proof facts only. It does not open or
validate the writer's advertised head, Merkle tree, content piles, or facts.
The cloud mirror trusts each writer to maintain those objects; every consuming
peer validates them before use.

### 7.2 Self-confined removal-path recovery

A client cannot prove current non-removal without a path from the current
removal root, but a removed client must still be able to learn that it was
removed. A second, strictly weaker operation therefore asks only:

```text
was this signed requester device once admitted under this workspace member?
```

If so, the service may return the current authenticated removal paths for that
same member and requester device. It does not return another member's path, a
workspace-wide removal dump, a content-read grant, a head-write grant, or any
other authority. Historical membership is therefore a discovery capability
for the caller's own current status, not continuing workspace access.

The historic-membership proof uses retained canonical membership and device
join facts. Current removal and self-leave facts do not erase that history; they
appear in the returned path and cause the stronger current-operation query to
fail.

### 7.3 Cached proof retry

Clients retain their last successful authority fact bundle and removal paths.
They submit that proof directly on later operations. The gate pins the current
authority/removal root and accepts the cached proof while it is current and all
required member and device states remain clear.

If the proof is stale or lacks a current path, the gate returns a typed
`proof_refresh_required` result without performing the requested operation.
The client invokes the historical-membership endpoint, replaces only its own
removal paths, and retries. If the refreshed paths show removal or self-leave,
the retry receives a permanent authority denial. No proactive proof push,
polling queue, or persisted gate session is required.

This intentionally favors the simplest correct cache rule: an older removal
root may be rejected even when an unrelated member changed. A more selective
freshness proof is an optimization, not part of the initial protocol.

### 7.4 One protocol identity per node

A node needs one device root secret and invite links to join communities. Its
root public key is named by the device or infrastructure membership facts, and
all subsequent proofs, head updates, removal-path requests, and grants derive
from that fact state. Provider credentials needed to call S3, R2, Lambda, or a
Worker remain deployment effects; they are not additional protocol principals.

Iroh endpoint keys remain connection material only. A separate HMAC user
database, provider-admin identity, API-token membership system, or persisted
cloud account table must not appear beside the fact proof universe.

### 7.5 Removal and deletion semantics

The important content rules remain:

- an administrator may delete every fact family that declares itself directly
  deletable;
- a user may delete facts owned by that user, including facts authored through
  any of the user's devices;
- the delete fact's ordinary Needs and offers must validate, and its offered
  suppression ID must exactly match a selector declared by the target fact.

The directory slot records the authority root under which its head OID was
accepted. If removal and publication race, a head accepted from the preceding
authority view remains available for peers to validate as historical workspace
content. Removal governs later sharing, grants, and publication after
propagation; it does not rewrite already validated history.

The authority root may still use one conditional register because its write
rate follows uncommon control changes rather than all content. If measurements
later show control contention, the same per-writer-log technique can shard it;
ordinary publication must not wait for that optimization.

## 8. Suppression and deterministic union

Facts retain explicit suppression selectors: SELF, one named parent, one named
ancestor path, several IDs, or none. A family that offers no selector cannot be
directly suppressed. Every PARENT or ANCESTOR selector follows immutable named
refs declared by the fact; a deleter never enumerates descendants.

Deletion and removal remain ordinary facts. Across writer logs, canonical fact
residence meets by `fid`, and suppression actions meet by the existing
deterministic family rule. Arrival order, directory order, page boundaries, and
which peer relayed a closure cannot change the result.

A consuming stateful peer projects the combined validated union and generic
indexes into SQLite for queries. A consuming database-free peer can point-query
authenticated per-writer indexes or validate streamed pile deltas without
creating a hidden database. The cloud peer mirrors the same writer trees but
does not run this content projection; its gate needs only the separate
authority/removal proof.

## 9. Sync and range behavior

The unit of workspace discovery is a device head. The unit of incremental sync
is the Merkle difference between two roots of that device's log. The unit of
semantic admission remains one closed pile.

```text
LIST workspace head slots
    -> unchanged slot token: no slot read
    -> changed slot token: read head oid
    -> known head oid: no immutable fetch
    -> unknown head oid: mirror missing head/tree/pile objects
    -> cloud peer stops
    -> consuming peer validates every new closed pile
    -> durable facts join that peer's local validated set
```

The first sync visits all registered writer slots. Later sync cost is the fixed
directory scan plus unknown head OIDs and missing log ranges, not the entire
workspace fact corpus. Every peer retains mirrored head OIDs and Merkle objects
in its ordinary object store. A full peer may retain traversal frontiers outside
SQL so deleting the presentation database does not destroy sync correctness.

Facts with large payloads, Bao slices, key wraps, and history-key material may
be co-packed for S3/R2. P2P peers may transfer the same individual verified
objects. Both paths expose identical canonical facts and proofs to the kernel.

## 10. Object-store contract

The portable store contract becomes:

- bounded strong read of one exact object and its opaque version token;
- bounded conditional read of the exact listed version;
- create-only immutable write with collision verification;
- conditional replace of one exact per-device head slot;
- conditional replace of the separate authority root;
- strongly consistent, lexicographically ordered, bounded prefix LIST with an
  opaque continuation cursor;
- no correctness dependence on delete, rename, ETag content semantics, object
  notification, queue delivery, or provider-global transactions.

The filesystem adapter is a stronger local implementation of this contract.
S3 uses conditional HTTP requests; the Cloudflare runtime uses native R2
conditionals. Provider adapters must preserve the same typed outcomes:
applied, noop, stale/retryable, permanent rejection, and unknown-result
reconciliation.

Bulk objects are uploaded directly under writer-confined grants. The small
head-slot operation passes through `CloudGate`; the gate validates only the
ephemeral requester/recipient membership and non-removal proof bound to the
exact head OID, confines the slot, and performs CAS. It is not a content
validator, proxy, or tree builder.

## 11. Concurrency and failures

For `N` different device writers there are `N` mutable head slots. Their
updates commute. Adding Lambdas increases useful parallelism because each
successful request normally targets a different object key.

For two requests targeting the same device head:

1. both may establish harmless immutable objects;
2. exactly one conditional replacement of the observed version succeeds;
3. the loser returns retryable, repins that one head, and retries with bounded
   exponential backoff and full jitter;
4. readers see either complete head, never partial bytes.

A crash before head CAS leaves unreachable immutable objects. A crash after an
ambiguous CAS is reconciled by exact reread. The cloud may publish a malformed
head from a currently authorized writer because it deliberately trusts writers
to maintain their trees. Bounded mirroring and per-device isolation ensure that
such a tree can make only that writer's content unusable; a consuming peer
rejects it, and it cannot wedge another slot, delete another writer's data, or
corrupt the authority root.

The concurrency proof and deterministic tests must cover:

- many different-key writers;
- duplicate same-key writers;
- head creation and update at every pagination boundary;
- short pages, opaque cursors, stale tokens, throttling, and lost responses;
- authority removal racing publication and read grants;
- crashes at every external effect;
- full-scan repair after every permitted delayed observation.

The safety theorem is per object and per closed pile. The liveness theorem is
eventual discovery under fair retry and complete scans. No global serial order
of unrelated content heads is claimed or needed.

## 12. Recency is an optional hint

S3 and R2 list by key, not by update time. Their returned metadata can be sorted
only after all pages have been fetched. The initial design therefore performs
the complete stable-head scan and measures it under `poc-16-iq2.10`.

If that scan becomes material, a provider gate may append hints shaped like:

```text
recent/<workspace>/<day>/<inverse-provider-time>-<device>-<head-oid>
```

Every marker has a unique immutable key, so markers do not contend. Provider
time, not an untrusted device clock, determines ordering. Markers may be
duplicated, delayed, omitted, cached, or lifecycle-expired. They grant nothing,
and a periodic complete `heads/` scan repairs every failure. No recency
mechanism is part of the initial correctness boundary.

## 13. FullPeer, SQL, HTTP, and Iroh

Every peer composes the same core directory and mirroring behavior. `FullPeer`
adds content consumption and local state:

- device keys and registered store bindings;
- log construction and resumable object upload;
- cached head/frontier progress;
- ordinary HTTP fetches;
- disposable combined SQLite projection;
- attachment presentation and local control;
- Iroh connection lifecycle.

It must not implement a second head codec, directory mirror, pile validator,
authority rule, or Merkle reconciliation algorithm. The cloud peer and full
peer store and exchange the same head and tree objects; the difference is only
that FullPeer consumes mirrored piles through the kernel and projects them for
the client. Deleting SQLite changes no writer log, head, authority root, or
validated answer. Rebuild hydrates each fact into the form current for its
surrounding context before storing the current serialized SQL form.

Iroh remains connection-only:

```text
ordinary HTTP bytes -> Iroh encrypted stream -> ordinary HTTP gate
```

Iroh endpoint identity, tickets, ALPN, and connection success grant no
workspace, bucket, head, or fact authority.

## 14. Notifications

Notification delivery remains durable operational work outside fact
publication. The scanner is a content consumer: it validates triggering piles
and never relies on the cloud mirror having done so. It no longer advances one
workspace `FactTree` cursor. It retains per-writer acknowledged head OIDs,
lists the directory, and performs bounded diffs only for unknown writer heads.

A pending notification page pins the exact writer heads and triggering facts
it represents. Delivery separately pins current authority, preferences, and
endpoints. SQS, Cloudflare Queue, or FullPeer wakes remain disposable. Only a
typed terminal outcome or provider acceptance advances durable notification
progress. The migration is tracked by `poc-16-iq2.8`.

## 15. Transition from the current global root

Current `main` has valuable components that survive:

- canonical facts and family policy;
- the closed-pile kernel;
- explicit suppression selectors and actions;
- immutable object codecs and Merkle primitives;
- provider-neutral bounded reads and conditional writes;
- the shared HTTP gate;
- disposable full-peer SQL;
- Bao verification and packing work;
- Iroh as a byte connection wrapper.

The following assumptions do not survive:

- one workspace-wide mutable content `root`;
- a cloud `RepositoryApplier` rebuilding the shared workspace tree for every
  pile;
- one global `FactTree` cursor for sync or notifications;
- cross-device root-CAS contention and its orphan-amplification work;
- a deployment configured around one canonical content snapshot per workspace.

The migration order is:

1. freeze canonical writer-head, log, and directory fixtures;
2. implement writer-local log construction and the authority projection;
3. implement persistence-free multi-head mirroring, content consumption, and
   request-local authority verification;
4. implement FS, S3, and R2 directory adapters;
5. move FullPeer and notifications to the shared multi-head core;
6. run deterministic and live provider concurrency tests;
7. switch deployments once;
8. delete the global content-root path and its compatibility code.

There will not be two permanent publication algorithms. A one-time exporter or
migration fixture may read the predecessor repository, but normal runtime code
must end with only the writer-log/head path. `poc-16-iq2.9` is the cutover gate.

## 16. Core invariants

1. Every semantic admission uses the same closed-pile kernel.
2. Every peer mirrors the same independently rooted per-writer trees through
   the same core object protocol.
3. Every ordinary content update mutates at most one device head slot.
4. Different device writers share no mutable content key.
5. Immutable objects exist before a writer advertises a head that names them.
6. A provider version token is opaque and never a content hash.
7. LIST output is candidate discovery, never authority.
8. The cloud gate projects only request-local proof facts and proves requester
   and recipient membership, device join, and non-removal bound to the exact
   operation; it does not validate writer content.
9. Every consuming peer validates head, tree, and closed-pile semantics before
   using mirrored content as state.
10. Mixed head observations may delay facts but cannot fabricate or invalidate
    them.
11. Removal governs current publication and access without rewriting validated
    history.
12. Request-local SQLite is discarded after one proof transaction; persistent
    SQLite, caches, cursors, hints, queues, and Iroh identities are
    non-authoritative.
13. Provider adapters add no semantic branch.
14. FullPeer reuses the complete core mirror and consume paths.
15. Every optional recency hint is repairable by a complete stable-head scan.
16. No core publication path deletes ingress, heads, logs, or canonical
    objects.
17. Historical membership exposes only the caller's own current removal paths
    and never grants content or publication access.
18. One device root secret plus invite-derived facts is the complete protocol
    identity bootstrap for a node.
19. After cutover, no workspace-global mutable content root remains.
