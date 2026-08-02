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
- database-free cloud gates and readers;
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

There are four logical capabilities:

```text
LogWriter
    local intent -> bounded closed piles -> immutable per-device Merkle log

HeadGate
    signed next head + pinned authority -> one per-device head CAS

WorkspaceReader
    pinned authority + listed heads -> verified log deltas -> validated union

HttpGate
    peer HTTP request -> authorized object, head, authority, or reader operation
```

`LogWriter` normally lives in a stateful full peer and may use SQLite for local
authorship and presentation. It uploads immutable objects directly to its
registered store. It does not need a cloud process to rebuild its tree.

`HeadGate` is database-free. It receives only a small canonical head proposal,
checks the writer and its current authority, establishes the immutable head
record, and conditionally replaces that writer's stable directory slot. It
does not ingest file bytes, enumerate the workspace fact set, or compile a
workspace content root.

`WorkspaceReader` is database-free. It pins authority, lists candidate head
slots, verifies their exact bodies, and consumes changed writer logs through
the ordinary closed-pile kernel. A full peer may project the resulting union
into disposable SQLite, but SQL never changes an authenticated answer.

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
5. ask `HeadGate` to replace only this device's stable head slot.

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
authority root used for publication
device signature
```

The exact codec and bounds belong to `poc-16-iq2.1`. These semantic fields are
not provider metadata. In particular, a head contains a registered store
binding, never an arbitrary URL supplied to a cloud fetcher.

The directory uses two forms:

```text
head-objects/<head-oid>          immutable canonical head record
heads/<workspace>/<device-fid>  mutable stable slot containing that record
```

The stable slot makes listing compact: one entry per enrolled device rather
than one entry per update. Its body is content hashed independently; its
provider version token is used only to conditionally replace that exact slot.

`HeadGate` accepts a successor only when:

- the key, signed workspace, device, owner, and registered store agree;
- the proposer proves the device's publication authority at one pinned
  authority root;
- the predecessor and sequence match the current stable head;
- the immutable head record and named log root are present under their exact
  registered bindings;
- all bytes and traversals fit protocol bounds;
- the per-device conditional replace succeeds.

The gate itself reads and pins the provider's current authority root; the
caller cannot select an older root. The accepted head records that exact root
for audit and race semantics.

The gate may exact-probe the named root but does not enumerate or semantically
revalidate the complete user log. Consumers still validate closed piles before
using them.

An unknown CAS result is reconciled by rereading the stable slot. An exact
candidate match is success. A newer signed successor makes repeating the old
request harmless; otherwise the writer repins and retries. No path deletes a
head, log object, pile, or ingress object.

## 6. The shared workspace directory

The directory is an object-store prefix, not a separately maintained manifest:

```text
heads/<workspace-fid>/<device-fid>
```

Concurrent writes to different keys are independent. Two Lambdas updating
Alice and Bob never compare against the same token. Only duplicate or genuinely
concurrent updates for one device contend on one slot.

If users keep content in physically separate buckets, the provider-operated
directory bucket holds only these small head records. Each verified head points
through a registered store binding to the user's content bucket. This permits
one workspace LIST without proxying content through the directory service.

### 6.1 LIST discovers candidates; it grants nothing

S3 and R2 supply strongly consistent prefix listing. The portable contract is
bounded cursor pagination returning at most 1,000 entries per page, ordered by
key. The implementation must also tolerate a valid short page.

A workspace observation is:

1. pin one authority/removal root;
2. list every page under the exact workspace head prefix;
3. reject malformed keys and filter candidates through the authenticated
   device-writer registry;
4. compare each listed opaque version token with the local cached token;
5. conditionally fetch and verify every new or changed exact head;
6. Merkle-diff the corresponding writer log from the last accepted head;
7. validate discovered closed piles and union their durable facts.

LIST output is never accepted as membership, authorship, liveness, workspace
binding, or fact validity. A forged extra object is ignored. An absent object
means only that no content was observed for that writer.

### 6.2 A directory observation is intentionally not transactional

We do not assume that a multi-page LIST plus subsequent GETs is one global
snapshot. A head can advance during pagination. A conditional GET either pins
the exact listed version or fails and causes that one key to be reconsidered.

Because every accepted writer root contains independently valid closed piles,
mixing head versions cannot create a torn Merkle tree or authorize a fact. It
can only delay observing some valid additions. Periodic full scans plus fair
retry converge.

Initial discovery costs roughly one LIST request per 1,000 device writers plus
one small head read per writer. A warm reader still lists the directory but
fetches bodies and diffs only for changed version tokens. This is measured
before introducing any second index.

## 7. Workspace authority and removal

Ordinary content logs do not update a shared workspace state. Membership,
device enrollment, delegated administration, registered store bindings,
infrastructure membership, leave, and removal are projected separately into a
small authenticated authority/removal root.

This projection uses the same canonical facts, closed-pile kernel, and explicit
suppression semantics as every peer. A cloud validator may add only its local
`invite_accepted` anchor and the authority/removal roots it has already
authenticated. It does not acquire a parallel IAM or Iroh identity model.

The important checks are:

- publishing a writer head requires current member and device liveness;
- obtaining a content-read grant requires current member and device liveness;
- proving historical membership is sufficient only to fetch the caller's
  confined current removal proof, so a peer can determine whether it is still
  eligible;
- an administrator may delete every fact family that declares itself directly
  deletable;
- a user may delete facts owned by that user, including facts authored through
  any of the user's devices;
- the delete fact's ordinary Needs and offers must validate, and its offered
  suppression ID must exactly match a selector declared by the target fact.

A head records the authority root under which it was accepted. If removal and
publication race, a head validly accepted from the preceding authority view is
historical workspace content. Removal governs later sharing, grants, and
publication after propagation; it does not rewrite already accepted history.

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

A stateful peer projects the combined validated union and generic indexes into
SQLite for queries. A database-free reader can point-query authenticated
per-writer indexes or validate streamed pile deltas without creating a hidden
database. The cloud authority gate needs only the separate authority/removal
projection; it does not scan arbitrary message logs to authenticate a request.

## 9. Sync and range behavior

The unit of workspace discovery is a device head. The unit of incremental sync
is the Merkle difference between two roots of that device's log. The unit of
semantic admission remains one closed pile.

```text
LIST workspace heads
    -> unchanged token: no work
    -> changed token: verify head
    -> diff old and new writer-log roots
    -> range-fetch missing pile or pack slices
    -> kernel validates each closed pile
    -> durable facts join the local validated set
```

The first sync visits all registered writer heads. Later sync cost is the fixed
directory scan plus changed writers and changed log ranges, not the entire
workspace fact corpus. A full peer may retain cached head OIDs and Merkle
frontiers outside SQL so deleting the presentation database does not destroy
sync correctness.

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
head operation may pass through `HeadGate`; this is intentional because the
gate checks signed semantic bindings and current authority. It is not a content
proxy or tree builder.

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
ambiguous CAS is reconciled by exact reread. A poisoned or malformed head can
deny only its own acceptance; it cannot wedge another device's slot, delete
another writer's data, or corrupt the authority root.

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

`FullPeer` composes the same core behaviors with local state:

- device keys and registered store bindings;
- log construction and resumable object upload;
- cached head/frontier progress;
- ordinary HTTP fetches;
- disposable combined SQLite projection;
- attachment presentation and local control;
- Iroh connection lifecycle.

It must not implement a second head codec, pile validator, directory filter,
authority rule, or Merkle reconciliation algorithm. Deleting SQLite changes no
writer log, head, authority root, or validated answer. Rebuild hydrates each
fact into the form current for its surrounding context before storing the
current serialized SQL form.

Iroh remains connection-only:

```text
ordinary HTTP bytes -> Iroh encrypted stream -> ordinary HTTP gate
```

Iroh endpoint identity, tickets, ALPN, and connection success grant no
workspace, bucket, head, or fact authority.

## 14. Notifications

Notification delivery remains durable operational work outside fact
publication. The scanner no longer advances one workspace `FactTree` cursor.
It retains per-writer acknowledged head OIDs, lists the directory, and performs
bounded diffs only for changed writer logs.

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
3. implement database-free multi-head reading;
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
2. Every ordinary content update mutates at most one device head slot.
3. Different device writers share no mutable content key.
4. Immutable objects exist before any head references them.
5. A provider version token is opaque and never a content hash.
6. LIST output is candidate discovery, never authority.
7. Every accepted head is signed, workspace-bound, writer-bound,
   store-bound, predecessor-bound, and authorized at a pinned authority root.
8. Mixed head observations may delay facts but cannot fabricate or invalidate
   them.
9. Removal governs current publication and access without rewriting validated
   history.
10. SQLite, caches, cursors, hints, queues, and Iroh identities are
    non-authoritative.
11. Provider adapters add no semantic branch.
12. FullPeer reuses the complete core receive and read path.
13. Every optional recency hint is repairable by a complete stable-head scan.
14. No core publication path deletes ingress, heads, logs, or canonical
    objects.
15. After cutover, no workspace-global mutable content root remains.
