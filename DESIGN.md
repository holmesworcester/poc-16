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

There are two deliberately different distribution rules. A hosted store is an
owner-confined publication target: one device may upload and advertise only
its own writer log, and the hosted data path may keep those content bytes
opaque. A consuming full peer is a peer-sync participant: after it has verified
and consumed an original writer-device-signed pile, it may relay those exact
bytes together with that writer's signed head and Merkle evidence. Relaying
never turns the relay into the writer and never mutates the original writer's
cloud log.

## 1. Goals and non-goals

The design must provide:

- the same fact bytes, closed-pile judgment, and suppression rules everywhere;
- one device-signed closed pile as the input to every semantic evaluation,
  whether pushed or pulled;
- hosted gates and readers with no persistent database or durable projection;
- direct object-store upload of large immutable data;
- independently writable device logs, with no cross-device content CAS;
- owner-confined cloud publication without hosted content validation;
- origin-preserving P2P sync of locally validated, writer-device-signed piles;
- deterministic convergence from mixed but individually valid log views;
- maximal isomorphism between hosted and full peers: one pile codec, evaluator,
  authority gate, mirror, consumer, and condition-query implementation;
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

There are six logical capabilities:

```text
LogWriter
    local intent -> bounded signed closed piles -> immutable per-device Merkle log

ClosedPileEvaluator
    canonical closed-pile bytes -> bounded kernel/family judgment

AuthorityGate
    pushed pile judgment -> ephemeral conditions -> exact bounded action

RepositoryMirror
    listed head pointers -> missing content-addressed writer-tree objects

FactConsumer
    pulled pile judgment -> local validated union

HttpGate
    peer HTTP request -> authorized object, head, authority, or mirror operation
```

`LogWriter` normally lives in a stateful full peer and may use SQLite for local
authorship and presentation. It uploads immutable objects directly to its
registered store. A hosted grant confines it to that device's own registered
writer store and stable slot; it cannot append to or advance another device's
log. It does not need a cloud process to rebuild its tree.

`ClosedPileEvaluator` is the one semantic input door. Hosted and full peers
invoke the same canonical decoder, outer writer-device signature check, bounded
kernel, and family dispatch for every pushed or pulled pile. No actor may accept
loose facts, caller-projected rows, or a claimed validation result.

`AuthorityGate` runs unchanged in a hosted peer, a full peer, or an in-process
local call. For one pushed signed closed pile it evaluates that pile, projects
its valid judgment and authenticated removal paths into a fresh in-memory or
temporary SQLite transaction, and asks ordinary fact queries whether the
requester and recipient node satisfy the requested conditions. Its only
configured protocol-identity input is the recipient node's root public key. A
successful request binds the exact proposed head OID. The gate may then perform
only that exact bounded operation, such as replacing the requester's device
slot or returning a confined removal path. It discards the pile judgment and
SQL state and never admits the pushed facts to the recipient's content state.
It trusts the writer to maintain the writer tree: it does not validate the
head, log shape, content piles, sequence, or closure, and it never
compiles a workspace content root.

`RepositoryMirror` is database-free and runs on every peer, including hosted
peers. It lists directory slots, learns their head OIDs, and mirrors only
content-addressed head and writer-tree objects absent from its local store. It
may enforce byte, request, hash, and storage-integrity bounds while copying;
that is not semantic fact or log admission. An opaque hosted mirror may serve
owner-confined objects without claiming they passed consumer validation.

`FactConsumer` runs wherever mirrored content is used as workspace state. It
pulls complete closed-pile leaves and invokes the same `ClosedPileEvaluator`
before joining their durable facts to the local validated union. A full peer
always consumes this way and may project the validated union into disposable
SQLite. A hosted peer that only mirrors, gates, and serves data does not consume
the content and therefore does not validate it. Successful consumption also
makes the original writer-device-signed pile eligible for P2P sync. It does not
authorize the consuming peer to rewrite that pile, its tree leaf, or its signed
head.

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

### 3.1 One evaluator, two retention modes

At the semantic protocol boundary, nodes communicate only canonical signed
closed piles. They never send or accept a loose fact list, selected dependency
edges, SQL rows, a materialized view, or a claim that some predicate already
passed. Heads, Merkle pages, pack indexes, and authenticated removal paths are
bounded retrieval or index evidence; they cannot introduce fact state except
through a successful closed-pile judgment.

The same evaluator has exactly two uses:

```text
pull signed closed pile
    -> canonical decode + writer signature + bounded kernel/family judgment
    -> join durable facts to the receiver's validated fact space

push signed closed pile
    -> the same canonical decode + writer signature + bounded kernel/family judgment
    -> project only that judgment into fresh temporary state
    -> check the exact requested conditions
    -> discard the judgment, facts, and temporary state
```

Pull is replication. Push is not. A pushed pile may authorize only the exact
operation bound by its request fact, such as a writer-confined head CAS, grant,
or self-confined removal-path response. It never enters a recipient log or
validated fact space and can never become a second publication route.

This distinction is about retention, not validation. Hosted peers, full peers,
plain HTTP, HTTP over Iroh, and local in-process calls all feed identical
canonical bytes to `ClosedPileEvaluator`. An in-process caller may not bypass
the codec with Python objects or consult the full peer's existing SQL rows.

### 3.2 Every pile is signed directly by its publishing device

The canonical semantic unit is a signed closed pile:

```text
SignedPile = {
    format,
    workspace_fid,
    writer_device_fid,
    facts,
    device_signature
}
```

The signature covers a domain-separated hash of every preceding canonical
field, including the exact ordered fact closure. The pile OID hashes the whole
signed encoding. The exact codec, signature domain, and byte bounds are frozen
beside the writer-head fixtures. Push and pull use these same signed bytes; a
pushed authority pile's writer is its requesting device.

The outer signature means only "this device published this exact closed pile."
It does not claim that the device authored every fact inside it. A legitimate
closure normally contains workspace, membership, key, or other dependency
facts authored by other principals; ordinary fact signatures and family policy
still decide fact authorship and validity.

The pile signature and tree authentication have different jobs. The pile
signature makes one immutable pile portable through cloud storage and any
number of peer relays. Separately, the device signature on a canonical writer
head commits to that device's exact Merkle root, and a verified inclusion path
binds one writer-local key to that signed pile OID. A consumer checks both. A
relay preserves the original pile bytes and never signs on behalf of the
writer.

The hosted content path is intentionally opaque. A cloud store grants immutable
upload and head-slot mutation only to the matching workspace device and may
store the resulting head, pile, and Merkle objects without opening them or
checking their signatures. `AuthorityGate` still evaluates the separate signed
authority pile that grants this writer-confined operation. Opaque treatment
applies to stored writer content, not to the authority request. Malformed
content can therefore make only its owner's log unusable; every consuming peer
rejects it before admission or onward sync.

### 3.3 A writer tree stores independently closed leaves

A writer log is physically the same canonical, history-independent, bounded
persistent Merkle-map style used by the other authenticated trees. It is an
ordered map from a fixed writer-local publication key to an immutable closed-
pile OID whose bytes carry that tree writer's device signature. This reuses one
page codec, branch geometry, path-copy update, range walk, and two-root diff;
there is no bespoke append-log tree engine.

Each logical leaf is exactly one independently bounded, directly signed,
topologically ordered, workspace-bound closed pile. Its outer writer device
must match the tree/head writer. Physical Merkle pages may batch several leaf
descriptors, and an object-store pack may co-locate several pile bodies, but
neither packing layer changes the logical leaf or permits a range to cut through
a pile. The union referenced by a physical leaf page is therefore also closed.
Dependencies precede dependents inside every logical leaf.

A half-open key range or Merkle diff therefore returns zero or more complete
closed-pile leaves. A cold receiver can evaluate every returned leaf alone:
closure may not depend on a neighboring leaf, an earlier range, or receiver
cache state. When the same dependency is needed by several leaves, its
canonical fact bytes are repeated and meet idempotently after validation.

The intended split is:

```text
writer log: closed piles containing the writer's facts plus required closure
local state: fid -> canonical fact bytes after successful validation
```

A pile may repeat dependency facts already present in another writer's log.
That is expected. Duplicate canonical `fid` values meet idempotently. The log
writer is not presumed to be the author of every fact in a relayed closure;
ordinary fact signatures and family policy retain that distinction.

For every pushed or pulled pile the shared evaluator:

1. proves canonical pile identity, writer-device signature, and workspace
   binding;
2. resolves exact refs and family-declared Needs from the supplied closure;
3. invokes family shape and policy checks;
4. enforces fact, dependency, depth, byte, and closure bounds;
5. returns a valid judgment only if the entire pile succeeds.

An already validated resident may make pull deduplication cheaper after
judgment, but correctness and cold reconstruction cannot require it: every
published log leaf and every pushed proof pile carries the fact closure a fresh
receiver needs. The recipient root public key and verifier-pinned authenticated
roots are explicit verification context; neither they nor local SQL may
silently complete a `Need` absent from the pile.

The selected dependency edges are ephemeral judgment values. They are not
stored as proof DAGs, ranks, winners, or admission witnesses. An invalid pull
leaf admits nothing from that leaf, and an invalid push authorizes nothing.
Because every later leaf is independently closed, one invalid leaf cannot
poison an unrelated later leaf or range.

Once a peer validates a fact, its local validated set is monotone:

```text
if f validates against S,
then f remains valid in every validated superset S'
```

Remote log inclusion proves only authenticated publication by that log writer.
It does not let an untrusted writer bypass the receiving kernel.

### 3.4 Validate before onward peer sync

A full peer may advertise or send a remote writer's pile during later syncs
only after completing the ordinary pull path for that leaf: verify the direct
pile signature, writer-head signature, and leaf inclusion; evaluate the
complete closed pile; and join its valid facts to the local validated set. A
receiver repeats every check. The sender's prior judgment is never an
admission certificate.

The origin writer follows the same rule locally before first publication: it
constructs and signs the closed pile, evaluates those exact bytes, includes the
pile in its tree, signs the new head, and then advances its own log. A non-
consuming hosted mirror is the sole opaque storage case. It can return the
owner's stored bytes under the normal grant gate, but it does not claim that
those bytes have passed consumer validation.

## 4. Per-device writer logs

Every enrolled device has its own logical writer ID and its own log. Separate
devices of one user have separate logs so the normal case has one human process
contending with nobody, including the user's other devices. Only that device
may add leaves to or advance that cloud writer log. Other full peers may serve
its accepted signed-head/tree/pile tuples during ordinary sync without changing
their origin.

The directory may group these trees under their durable user for discovery,
but the mutable root remains per device. A literal one-tree-per-user layout
would make that user's independent devices contend on one CAS key and is not
the initial design.

A writer update proceeds in this order:

1. construct and device-sign one or more bounded closed piles;
2. locally evaluate those exact signed bytes;
3. append those pile OIDs to the cumulative logical Merkle tree;
4. establish the signed piles and reachable Merkle objects immutably in the
   writer's registered store;
5. construct and sign one immutable head record over the cumulative logical
   tree;
6. push one closed authority pile to `AuthorityGate`, binding its signed request
   fact to the proposed head OID;
7. conditionally replace only this device's stable head slot.

Before or after that semantic publication, the source may independently pack
contiguous complete piles and CAS only the directly addressed layout page for
that fixed publication window. The immutable pack must exist before the page
names it. A lagging or absent page leaves the newly published pile available by
its normal OID; layout failure never rolls back or invalidates the writer head.

The log root is content addressed. It is not the provider ETag, and no code may
derive one from the other. Writer-log pages and pile objects are immutable and
must exist before the head can become visible.

The honest writer maintains one cumulative sequence of closed-pile identities,
ordered by publication rather than by a fact's semantic timestamp. The
cumulative Merkle tree is the authority for that sequence. A head carries that
tree and a writer-local sequence exactly equal to its logical leaf count. It
does not link a permanent chain of historical heads. A peer proves that a
candidate tree is an exact append-only extension of its last accepted tree. A
lower sequence is rollback, an equal sequence with different bytes is a fork,
and a higher sequence may never remove, reorder, or replace an accepted leaf.
Repacking does not create a writer head because it changes no logical fact.

A fresh peer validates the current signed head, selected tree paths, and every
selected signed closed pile. Historical head records and superseded path-copy
pages are not protocol history and need not be retained after no active sync or
local checkpoint pins them.

A provider directory cannot force a user-controlled bucket to retain data
forever; cloud storage availability is therefore distinct from fact validity.
Replication to other peers supplies independent durability.

When a consumer accepts a successor head, the two-tree RBSR difference supplies
exactly the newly published closed-pile leaves. `AuthorityGate` deliberately
does not perform this check.

Logical history and physical transfer shape are separate:

```text
logical writer tree
    publication sequence -> signed closed-pile OID

source-local optional physical layout
    fixed publication window -> bounded flat layout page

layout page
    nonoverlapping interval -> pack OID + byte lengths for complete piles
```

A pack body is a concatenation of complete signed pile bytes. Its locator is
only a hint for finding those bytes: every extracted pile, fact, payload hash,
and Bao proof is checked normally. Repacking a logical interval must not change
any writer-tree leaf. Recent piles remain loose until a source seals a fixed
pack.

The layout is local to the serving store, not a writer-head field and not an
origin signature. A cloud bucket and several relaying full peers may advertise
different packs for the same authenticated pile OIDs. This is safe because a
receiver first selects the expected sequence/OID from the signed logical tree,
then treats the locator as an untrusted fetch hint. A bad or stale locator can
cause only a bounded miss. It cannot add, omit, reorder, or validate a logical
publication. Missing layout falls back to the pile's ordinary immutable object
or another source.

Layout pages cover fixed writer-local publication windows and are addressed by
arithmetic from a sequence number; the initial bound is 16,384 publications per
page, subject to an exact four-MiB codec ratchet. There is no layout root, LIST
scan, predecessor search, global manifest, or second Merkle tree. Placements in
one page are sorted, nonoverlapping, wholly inside that window, and may leave
holes. A hole means "fetch the normal pile object," not deletion. Pack bodies
never cross writer or layout-window boundaries.

Large pack bytes use a control/data split. The common gate handles one small,
authenticated `PackOpen` value bound to method, pack OID, declared bytes, and
an optional exact range. It returns a short-lived `ScopedRequest` containing an
ordinary HTTP URL and required headers. S3 and R2 normally point that request
at provider object HTTP; FullPeer points it at a same-origin streaming route,
which Iroh may carry unchanged. The client performs the returned ordinary HTTP
request in every composition.

Neither `ObjectStore.get_bounded`, the four/five-MiB semantic-object limits,
`HttpGate.Response`, Lambda response bodies, nor Worker buffered-body helpers
may be widened to 95 MiB. Whole GETs stream to a sink and verify declared size
and pack hash before acceptance. Exact range GETs are bounded by one signed
pile, require exact HTTP range/length metadata, and verify the tree-selected
pile OID, workspace/device signature, and ordinary closed-pile judgment. PUTs
are immutable/create-only, and the layout page is CASed only after the pack is
established.

This is an unavoidable storage tradeoff rather than a protocol ambiguity. One
ever-growing object minimizes cold GET count but rewrites the writer's entire
history on each append. One immutable object per pile writes each byte once but
makes cold catch-up request-bound. The initial policy therefore uses fixed
immutable packs plus one asynchronously packed loose suffix: ordinary append
never touches layout, while a background or sender-side packer takes a bounded
uncovered contiguous prefix, uploads one at-most-95-MiB pack, and CASes only its
window page. Each pile is copied into established packing at most once.

If cold request count later matters, a source may perform one final coalescing
pass when a publication window closes, replacing its several small placements
with the minimum number of at-most-95-MiB packs. That makes older windows dense
and leaves only the current window fragmented, matching the useful part of
"larger packs toward the past" without an unbounded merge ladder. It costs at
most one additional copy of that closed window and changes only its local
layout page; it is an optimization, not required protocol state.

Geometric recent runs can reduce a live suffix from linear to logarithmic GETs,
but copy each pile at every merge level, make some appends rewrite a large run,
and create more CAS/GC states. They are not part of the initial protocol. Add
them only if corrected measurements show the bounded loose suffix dominates
latency; doing so would change source-local packing policy, not the logical log.

Cold catch-up derives the finite layout-page keys from the signed head count,
opens those pages in parallel, fetches whole packs for their dense placements,
and fetches uncovered holes loosely. From the ordered slices it may hash each
pile, rebuild the canonical logical tree locally, and accept that shortcut only
when root, count, and depth exactly equal the signed head. It need not download
every remote Merkle page merely to learn the same rows. An incomplete or
inconsistent layout falls back to the ordinary authenticated tree walk.

RBSR or a resumed/selective sync starts with the signed tree, identifies
missing logical leaf ranges, and then reads only the corresponding complete-
pile slices. It must not reconstruct a cold full history with one range request
per pile. Semantic timestamps do not control placement: a backdated message
still appends at the next publication sequence, and a semantic deletion is
another appended fact. No packing policy therefore assumes that users never
write "into the past."

## 5. Canonical writer heads

One canonical head record binds at least:

```text
format version
workspace fid
device-writer fid
durable owner principal
writer-local sequence equal to logical leaf count
cumulative logical writer-tree root oid
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

`AuthorityGate` accepts an exact slot update only when:

- the submitted closed pile authenticates the workspace device as a member and
  not removed at the authority root the gate itself pins;
- the pile's signed request fact binds the exact proposed head OID;
- the deterministic slot belongs to that same workspace device;
- the request and slot body fit fixed mechanical bounds;
- the per-device conditional replace succeeds.

The caller cannot select an older authority root. The gate records the exact
root it used beside the head OID. It does not fetch or interpret the head or
writer tree, verify its signatures, or establish that its objects exist. Those
are writer responsibility until another peer consumes the log.

A consuming peer, not `AuthorityGate`, verifies the head object's content hash,
device signature, workspace, owner, store binding, sequence, and named log root;
compares it with the peer's last accepted head; verifies each selected pile's
direct writer signature and Merkle inclusion; and then evaluates every pile it
has not already validated.

An unknown CAS result is reconciled by rereading the stable slot. An exact
head-OID match is success; otherwise the writer repins and retries. The
publication path deletes nothing. A separate reachability collector may later
remove superseded, unpinned head and internal-page objects, but never a signed
pile or anything reachable from a current/pinned head.

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
including each hosted peer, mirrors the per-writer trees it learns through this
directory; no peer combines them beneath another content root.

Cloud mutation is origin-confined. The authenticated device may establish
objects in its registered store and conditionally replace only
`heads/<workspace>/<that-device>`. Another member may read granted objects but
may not upload a relayed pile into that cloud writer log or advance its slot.
The cloud therefore never has to decide whether arbitrary third-party content
is a faithful relay. Ordinary P2P sync supplies cross-peer replication after
consumer validation instead.

### 6.1 LIST discovers candidates; it grants nothing

S3 and R2 supply strongly consistent prefix listing. The portable contract is
bounded cursor pagination returning at most 1,000 entries per page, ordered by
key. The implementation must also tolerate a valid short page.

A workspace mirror turn is:

1. list every page under the exact workspace head prefix;
2. reject malformed keys and filter candidates through the known device-writer
   registry;
3. open all independent tiny slots in that bounded page as one parallel or
   bundled read phase, never as one sequential RTT per writer;
4. compare each opened head OID with that writer's locally accepted head OID;
5. if the immutable head OID is already local, perform no tree or pile fetch;
6. otherwise mirror the missing content-addressed head and logical writer-tree
   pages, then open only the source-local layout pages needed by the tree
   difference;
7. stop there on a non-consuming hosted peer;
8. on a consuming peer, recover every previously unvalidated complete signed
   pile from a loose object, whole pack, or exact pack range, evaluate it
   through the shared consumer, and union
   its durable facts.

A head learned through P2P and already present locally is not fetched again
merely because this provider directory slot was first observed later. An
adapter may compare a cached, source-specific opaque slot token before opening
the slot body. An HTTP peer may instead bundle the bounded page's small slot
bodies with the directory response. These are equivalent read optimizations,
not repository state: in both cases the portable comparison is the individual
signed head OID. There is no hash, manifest, or CAS register over all heads.

LIST output is never accepted as membership, authorship, liveness, workspace
binding, or fact validity. A forged extra object is ignored. An absent object
means only that no content was observed for that writer.

### 6.2 A directory observation is intentionally not transactional

We do not assume that a multi-page LIST plus its parallel or bundled slot reads
is one global snapshot. Each slot read linearizes independently, and a head can
advance during pagination. The mirror may consume the complete old or new slot;
a later complete scan catches an update that linearized after its read.

Mixing head versions cannot create a torn object or authorize a fact. A
non-consuming peer merely mirrors opaque content-addressed objects. A consumer
admits only piles it has independently validated, so a mixed observation can
only delay valid additions. Periodic full scans plus fair retry converge.

Initial discovery costs one bounded head-page round per page when HTTP bundles
the tops, or one LIST round followed by one parallel slot-read round for a
direct provider adapter. It must never cost one sequential RTT per writer. A
warm peer still scans the directory but mirrors only head/tree objects whose
individual head OIDs changed. This is measured before introducing any second
index.

## 7. Ephemeral authority verification and removal refresh

Ordinary content logs do not update shared workspace authority. Membership,
device enrollment, delegated administration, registered store bindings,
infrastructure-node join, leave, self-removal, and administrative removal are
facts projected into a small authenticated authority/removal root.

### 7.1 One request-local proof transaction

An authorization request pushes exactly one bounded canonical signed closed
pile. The pile contains the signed request fact, every authority fact and
dependency needed to judge it, and the exact bounded removal-path evidence
named by those facts. There is no parallel fact-array, SQL-row, bearer-claim,
or precomputed verdict argument.

`AuthorityGate` first invokes the ordinary `ClosedPileEvaluator`. Core verifies
canonical fact identities, signatures, workspace bindings, and each named
removal path against the authority root currently pinned by the recipient. The
gate then creates a fresh SQLite database in memory or provider-local temporary
storage, projects only the valid pile judgment through ordinary family
handlers, queries the projected state inside that isolated authorization
transaction, and discards the database and judgment.

SQLite therefore receives authenticated facts from one valid closed pile
rather than caller-invented `CLEAR` rows. This authority-proof evaluation is
the gate's job; it still never traverses the advertised content log. A rejected
pile authorizes no condition query or external effect.

No prior request rows, persistent SQL, provider account, API token, cache, or
ambient Iroh identity enter the verdict. The only locally configured protocol
identity supplied to the transaction is the recipient node's root public key.
The workspace, requester, owner, requester device, operation, object or head
OID, and proof root are all bound by the pile's signed request fact and its
closed dependencies.

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

This pushed evaluation checks authority conditions only. Its facts and derived
rows are always thrown away after the exact answer or bounded action. It does
not open or validate the writer's advertised head, Merkle tree, content piles,
or facts. A hosted mirror trusts each writer to maintain those objects; every
consuming peer validates pulled pile leaves before use.

### 7.2 Self-confined removal-path recovery

A client cannot prove current non-removal without a path from the current
removal root, but a removed client must still be able to learn that it was
removed. A second, strictly weaker pushed closed pile therefore asks only:

```text
was this signed requester device once admitted under this workspace member?
```

If so, the service may return the current authenticated removal-path objects
for that same member and requester device. The client encloses that evidence in
its next closed proof pile. The service does not return another member's path,
a workspace-wide removal dump, a content-read grant, a head-write grant, or any
other authority. Historical membership is therefore a discovery capability
for the caller's own current status, not continuing workspace access.

The historic-membership proof uses retained canonical membership and device
join facts. Current removal and self-leave facts do not erase that history; they
appear in the returned path and cause the stronger current-operation query to
fail.

### 7.3 Cached proof retry

Clients retain the last successful canonical closed proof pile, including its
removal-path evidence. They push those exact bytes again on later operations.
The gate pins the current authority/removal root and accepts the cached pile
while its evidence is current and all required member and device states remain
clear.

If the proof is stale or lacks a current path, the gate returns a typed
`proof_refresh_required` result without performing the requested operation.
The client invokes the historical-membership endpoint, rebuilds one closed
proof pile with only its refreshed removal paths, and retries. If the refreshed
paths show removal or self-leave, the retry receives a permanent authority
denial. No proactive proof distribution, polling queue, or persisted gate
session is required.

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
which peer served a writer-device-signed closure cannot change the result.

A consuming stateful peer projects the combined validated union and generic
indexes into SQLite for queries. A consuming database-free peer can point-query
authenticated per-writer indexes or validate streamed pile deltas without
creating a hidden database. A non-consuming hosted peer mirrors the same writer
trees but does not run this content projection; its gate needs only the separate
pushed closed authority pile.

## 9. Sync and range behavior

The unit of workspace discovery is a device head. The unit of incremental sync
is the Merkle difference between two roots of that device's logical pile tree.
The unit of transfer may be a whole physical pack or an exact range within one.
The unit of semantic judgment remains one complete writer-device-signed closed
pile.

```text
LIST/open one bounded page of independent workspace head slots
    -> compare every writer's remote head oid with its local head oid
    -> known head oid: no immutable fetch
    -> unknown head oid: RBSR missing logical closed-pile leaves
    -> use the current layout to fetch whole packs for dense missing history
       or exact closed-pile ranges for sparse/resumed history
    -> non-consuming peer stops
    -> consuming peer verifies and evaluates every new signed closed pile
    -> durable facts join that peer's local validated set
```

The first sync visits all registered writer slots. Later sync cost is the fixed
directory scan plus unknown head OIDs and missing tree ranges, not the entire
workspace fact corpus. Every peer retains mirrored head OIDs and Merkle objects
in its ordinary object store. A full peer may retain traversal frontiers outside
SQL so deleting the presentation database does not destroy sync correctness.

P2P uses the same forest and range-based set reconciliation (RBSR), not one sync
session per pile and not a second combined content log. Peers first exchange
their per-device head directories. For each device root that differs, they
compare logical pile-tree range fingerprints, prune equal subtrees, and descend
only differing leaf ranges. Running the diff in both directions reconciles
arbitrary overlap rather than assuming either peer has a prefix of the other.
Each receiver verifies and evaluates every missing pile independently before
serving it in a later sync.

One two-way turn reuses the remote per-writer slots opened during its pull when
deciding what to offer back. It does not probe every unchanged remote slot a
second time. This observation is only a disposable optimization: `/mirror`
reopens the receiver's current slot and acknowledges success only when the
proposed exact bytes are installed. A receiver advance after the directory
scan therefore produces an exact no-op, a stale/retry result, or validation
against the newer head—never an overwrite authorized by the cache.

This per-device RBSR forest is the initial and only required P2P index. Measure
directory exchange and per-changed-device turns before adding a combined peer
inventory tree. If such an index is ever justified, it remains a rebuildable,
untrusted discovery accelerator and cannot become a publication root,
validation certificate, or second pile format.

Thus a full peer participates in sync for all validated writers it knows, not
merely its own writer log. Repeated ordinary sync is the entire propagation
mechanism; there is no separate gossip, broadcast, queue, or propagation
protocol. The cloud path remains owner-push-only. Both paths deliver the same
directly signed pile, signed head, and Merkle evidence to the same consumer;
only discovery and eligibility to upload differ.

Logical tree rows and pack locators index only complete pile boundaries. Range
pagination and pack byte ranges therefore stop between independently closed
evaluations; no receiver must chase a dependency into an adjacent slice or
retain a preceding slice to validate the next one. Tree fingerprints, expected
pile OIDs, and layout pages prune or locate identical ranges; they never stand
in for evaluating the returned pile bytes.

Facts with large payloads, Bao slices, key wraps, and history-key material may
be co-packed for S3/R2. P2P peers may transfer the same individual verified
objects. Both paths recover identical canonical closed-pile bytes for the same
logical leaves and feed them to the same evaluator.

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

Bulk objects are uploaded directly under writer-confined, owner-only grants.
No grant permits one device to populate or advance another device's cloud log.
The hosted data path mechanically enforces store, namespace, size, hash, and
write-condition bounds but does not decode writer content, verify the head
or pile signatures, walk Merkle inclusion, or verify fact signatures. The
small head-slot operation passes through `AuthorityGate`; the gate evaluates one
pushed closed pile, checks only the ephemeral requester/recipient membership
and non-removal conditions bound to the exact head OID, confines the slot, and
performs CAS. It is not a content validator, proxy, or tree builder, and the
pushed pile never enters repository state.

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
ambiguous CAS is reconciled by exact reread. `AuthorityGate` may publish a
malformed head from a currently authorized writer because it deliberately
trusts writers to maintain their trees. Bounded mirroring and per-device
isolation ensure that such a tree can make only that writer's content unusable;
a consuming peer rejects it, and it cannot wedge another slot, delete another
writer's data, or corrupt the authority root.

Because a cloud grant and slot request are confined to the authenticated
device, an unrelated peer cannot race that writer's mutable key. Duplicate or
concurrent updates to one slot come only from that writer's own processes. P2P
transfer is immutable and cannot create a slot race: duplicate head, tree, and
pile OIDs meet idempotently, while a forged or context-mismatched leaf is
rejected by the consumer.

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

Every peer composes the same `ClosedPileEvaluator`, `AuthorityGate`, directory
mirror, object codecs, and condition queries. `FullPeer` enables content
consumption and adds local state:

- device keys and registered store bindings;
- log construction and resumable object upload;
- cached head/frontier progress;
- ordinary HTTP fetches;
- disposable combined SQLite projection;
- attachment presentation and local control;
- Iroh connection lifecycle.

`FullPeer` may serve verified original signed heads and corresponding Merkle
evidence for discovery. It serves a remote signed pile during peer sync only
after consuming that leaf successfully. It does not wrap those piles in a
combined log, attribute them to its own device, or expose opaque unconsumed
mirror entries as validated content.

It must not implement a second head codec, directory mirror, pile evaluator,
authority gate, condition query, or Merkle reconciliation algorithm. A hosted
peer and full peer store and exchange the same head, tree, and closed-pile
objects. A hosted deployment may choose not to enable `FactConsumer`; that is
the absence of a capability, not an alternate content-validation path.
Deleting FullPeer SQLite changes no writer tree, head, authority root, or
validated answer. Rebuild hydrates each fact into the form current for its
surrounding context before storing the current serialized SQL form.

### 13.1 Hosted and local turns are isomorphic

| Turn | Hosted peer | Full peer | Shared authority |
|---|---|---|---|
| pushed condition check | canonical pile bytes enter `AuthorityGate` | the same bytes enter the same gate, even in process | `ClosedPileEvaluator` + fresh proof SQLite + family queries |
| pulled content | mirror full pile leaves; optionally stop | mirror the same leaves, then consume | `RepositoryMirror` + `ClosedPileEvaluator` + `FactConsumer` |
| pushed state afterward | none | none | pushed facts and rows are discarded |
| pulled state afterward | retained only if consumer is enabled | validated fact union plus rebuildable client projection | the same consumer judgment |

Provider bindings, process scheduling, and local presentation are effects at
the outside edge. They may change how canonical pile bytes arrive or where
immutable objects live, never the evaluated value, family handlers, SQL schema,
condition query, or typed result. Tests must run the same fixtures through an
in-process full peer, plain HTTP, HTTP over Iroh, packaged Lambda, and workerd
and require byte-identical judgments and typed decisions.

Iroh remains connection-only:

```text
ordinary HTTP bytes -> Iroh encrypted stream -> ordinary HTTP gate
```

Iroh endpoint identity, tickets, ALPN, and connection success grant no
workspace, bucket, head, or fact authority.

## 14. Notifications

Notification delivery remains durable operational work outside fact
publication. The scanner is a content consumer: it validates triggering piles
and never relies on `RepositoryMirror` having done so. It no longer advances one
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
- pushing ordinary content into a recipient's durable fact space; target push
  is a discarded condition evaluation, while ordinary replication is pull;
- one global `FactTree` cursor for sync or notifications;
- cross-device root-CAS contention and its orphan-amplification work;
- a deployment configured around one canonical content snapshot per workspace.

The migration order is:

1. freeze canonical signed-pile, writer-head, closed-leaf tree, and directory
   fixtures;
2. implement writer-local tree construction and the shared `AuthorityGate`;
3. implement persistence-free multi-head mirroring, content consumption, and
   pushed closed-pile authority evaluation;
4. implement FS, S3, and R2 directory adapters;
5. move FullPeer and notifications to the shared multi-head core;
6. run deterministic and live provider concurrency tests;
7. switch deployments once;
8. delete the global content-root path and its compatibility code.

There will not be two permanent publication algorithms. A one-time exporter or
migration fixture may read the predecessor repository, but normal runtime code
must end with only the writer-log/head path. `poc-16-iq2.9` is the cutover gate.

## 16. Core invariants

1. Every semantic evaluation begins with exactly one canonical device-signed
   closed pile and uses the same `ClosedPileEvaluator` and family handlers.
2. A valid pulled pile may join durable facts to a consumer's validated space;
   a pushed pile and every row derived from it are always discarded after
   checking the exact bound conditions.
3. Hosted and full peers use the same `AuthorityGate`, temporary SQL schema,
   condition queries, mirror, and consumer; local SQL is never an authority
   shortcut.
4. Every accepted writer-tree leaf contains a pile signed directly by that
   tree's writer device and has a valid inclusion path to its canonical signed
   head.
5. Every logical writer-tree leaf is independently closed, and no range or
   page boundary splits a pile or requires neighboring receiver state.
6. Cloud publication grants let a device populate and advance only its own
   writer log; hosted content storage need not validate those opaque bytes.
7. A full peer serves a remote pile only after successful consumption,
   preserves its original pile signature, signed head, and writer identity, and
   never treats the sender's prior judgment as an admission certificate.
8. Every peer mirrors the same independently rooted per-device trees and runs
   RBSR per changed device through the same core object protocol. No combined
   P2P inventory tree exists until measurements justify one.
9. Every ordinary content update mutates at most one device head slot.
10. Different device writers share no mutable content key.
11. Immutable objects exist before a writer advertises a head that names them.
12. A provider version token is opaque and never a content hash.
13. LIST output is candidate discovery, never authority.
14. `AuthorityGate` evaluates only one request-local closed pile and proves
   requester and recipient membership, device join, and non-removal bound to
   the exact operation; it does not validate writer content.
15. Every consuming peer validates pile signature, head signature, tree
    inclusion, and closed-pile semantics before using mirrored content as state.
16. Mixed head observations may delay facts but cannot fabricate or invalidate
    them.
17. Removal governs current publication and access without rewriting validated
    history.
18. Request-local SQLite is discarded after one proof transaction; persistent
    SQLite, caches, cursors, hints, queues, and Iroh identities are
    non-authoritative.
19. Provider adapters add no semantic branch.
20. FullPeer reuses the complete core gate, mirror, and consume paths.
21. Every optional recency hint is repairable by a complete stable-head scan.
22. No core publication path deletes ingress, heads, logs, or canonical
    objects. Separate reachability collection may remove only superseded,
    unpinned head and internal-page versions, never signed piles or current
    reachable objects.
23. Historical membership exposes only the caller's own current removal paths
    and never grants content or publication access.
24. One device root secret plus invite-derived facts is the complete protocol
    identity bootstrap for a node.
25. After cutover, no workspace-global mutable content root remains.
