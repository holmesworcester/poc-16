# POC-16 design

This document defines the running architecture. The writer-forest cut is
complete: ordinary workspace content is published through independently
advancing device logs, and no predecessor-format content root or ingress path
is accepted. Remaining measurement and live-deployment work is tracked in
beads; it is not a compatibility switch.

The central decision is:

```text
one independently advancing log per device writer
    plus
one shared directory containing one small head per device
```

Normal content publication therefore has no workspace-wide mutable key. The
remaining shared state relevant to access is each recipient's small
authenticated removal tree, changed by membership and administration rather
than by every message or file. An access caller never installs, republishes, or
synchronizes that tree before content sync.

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
  access gate, mirror, consumer, and condition-query implementation;
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

AccessGate
    signed request -> UNKNOWN, CLEAR, or ACTIVE lookup at recipient pin
    ACTIVE -> caller-confined rejection path + current tip

RepositoryMirror
    listed head pointers -> missing content-addressed writer-tree objects

FactConsumer
    pulled pile judgment -> local validated union

HttpGate
    peer HTTP request -> rejection, authorized object, head, or mirror operation
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

`AccessGate` runs unchanged in a hosted peer, a full peer, or an in-process
local call. An UNKNOWN subject may present its positive admission chain once;
the gate evaluates and discards those facts after creating the exact CLEAR
subject row. Every later action carries only its outer device signature and
last-seen basis. The recipient's own lookup decides UNKNOWN, CLEAR, or ACTIVE;
an ACTIVE rejection includes only rows belonging to that subject and the
recipient's current tip. The gate never asks the caller to synchronize
authority state, never admits proof facts to content state, and never validates
the advertised main writer log. A head write opens only its small signed
head/control declaration to select the
ordinary or fenced permit route.

`RepositoryMirror` is database-free and runs on consuming peers. It lists a
source directory, learns its head OIDs, and copies only content-addressed head,
writer-tree, and pile objects absent from the local store. It enforces byte,
request, hash, tree-extension, and storage-integrity bounds and hands each
changed writer suffix to `FactConsumer` as one atomic candidate. A hosted owner
target does not mirror or validate content: it exposes the same immutable
object and head-slot surface through `HttpGate` and `OpaqueHeadGate`.

An accepting mirror also owns that recipient's removal state. It independently
classifies the validated suffix and requires the writer head's signed control
subsequence to name exactly the control-only pile OIDs it found before it can
publish the slot. It applies the aggregate control plan first and then performs
one base-guarded CAS of the sole final slot shape. Removal-root contention gets
only `MAX_CONTROL_APPLY_ATTEMPTS` in one turn. A crash may leave removal ahead
with no local slot; the next source sync recomputes and idempotently reapplies
the plan before retrying the final CAS. There is no cursor or retry journal. The
only mirrors allowed to observe controls without applying
them are discarded notification projections and an outbound relay whose source
was already accepted; neither target is exposed as an `AccessGate`, and the
receiving peer repeats the accepting check.

`FactConsumer` runs wherever mirrored content is used as workspace state. It
pulls complete closed-pile leaves and invokes the same `ClosedPileEvaluator`
before joining their durable facts to the local validated union. A full peer
always consumes this way and may project the validated union into disposable
SQLite. A hosted peer that only gates and serves owner-uploaded data does not
consume the content and therefore does not validate it. Successful consumption also
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

The evaluator has two semantic uses:

```text
pull signed closed pile
    -> canonical decode + writer signature + bounded kernel/family judgment
    -> join durable facts to the receiver's validated fact space

push signed closed pile
    -> the same canonical decode + writer signature + bounded kernel/family judgment
    -> evaluate an UNKNOWN admission chain or an exact control sink
    -> join only the family-selected recipient judgment rows
    -> discard the judgment and supplied facts
```

Pull is replication. Push is not. A pushed pile never enters a recipient log or
validated fact space and can never become a second publication route. Admission
and control pushes retain only their bounded canonical removal-tree rows. A
steady request verifies its outer signature, performs the subject lookup, and
may authorize only the exact operation bound by its request fact, such as a
writer-confined head CAS, grant, or mirror turn.

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
pushed proof pile's writer is its requesting device.

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
checking their signatures. `AccessGate` still evaluates the separate signed
proof pile that grants this writer-confined operation. Opaque treatment applies
to stored writer content, not to the access request. Malformed
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
receiver needs. The recipient root public key and recipient-pinned removal root
are explicit verification context after that judgment; neither the removal
path nor local SQL may silently complete a `Need` absent from the pile.

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
pile in its tree, signs the new head, and then advances its own log. A hosted
owner target is the sole opaque storage case. It can return the owner's stored
bytes under the normal grant gate, but it does not claim that those bytes have
passed consumer validation.

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
3. append those pile OIDs to the cumulative logical Merkle tree and append
   every control-only pile OID to the head's separate signed control-subsequence
   Merkle tree;
4. establish the signed piles and reachable Merkle objects immutably in the
   writer's registered store;
5. construct and sign one immutable head record over both cumulative logical
   trees;
6. push one device-signed proof pile to `AccessGate`, binding its request
   fact to the observed base and proposed head OID;
7. for an ordinary head, conditionally replace only this device's stable slot;
   for a control-bearing head, issue one exact control permit, apply the
   permit's aggregate removal plan, and perform one base-guarded CAS of the
   final slot only after those effects.

Before or after that semantic publication, the source may independently pack
contiguous complete piles and CAS only the directly addressed layout page for
that fixed publication window. The immutable pack must exist before the page
names it. A lagging or absent page leaves the newly published pile available by
its normal OID; layout failure never rolls back or invalidates the writer head.

The log root is content addressed. It is not the provider ETag, and no code may
derive one from the other. Writer-log pages and pile objects are immutable and
must exist before the head can become visible.

The honest writer maintains one cumulative sequence of closed-pile identities,
ordered by publication rather than by a fact's semantic timestamp. Its main
Merkle tree is the authority for that sequence. The head also signs a second
append-only tree containing only the ordered control-pile subsequence. That
small tree is a routing and fencing declaration, not an admission certificate:
an ordinary head transition must have an empty control delta, while a control
permit must carry exactly the declared pile OIDs. A consuming peer validates
the main suffix, independently recomputes control classification through fact
families, and rejects an omitted, extra, mixed-content, or malformed control
declaration. Duplicate identical pile OIDs are harmless and their ACI effects
are applied once.

A head carries the main tree and a writer-local sequence exactly equal to its
main logical leaf count. It does not link a permanent chain of historical
heads. A peer proves that both candidate trees are exact append-only extensions
of their last accepted trees. A lower sequence is rollback, an equal sequence
with different bytes is a fork, and a higher sequence may never remove,
reorder, or replace an accepted leaf. Repacking does not create a writer head
because it changes no logical fact.

A fresh peer validates the current signed head, selected tree paths, and every
selected signed closed pile. Historical head records and superseded path-copy
pages are not protocol history and need not be retained after no active sync or
local checkpoint pins them.

A provider directory cannot force a user-controlled bucket to retain data
forever; cloud storage availability is therefore distinct from fact validity.
Replication to other peers supplies independent durability.

When a consumer accepts a successor head, the two-tree RBSR difference supplies
exactly the newly published closed-pile leaves. `AccessGate` deliberately
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

Large pile and pack bytes use a control/data split. A fact remains bounded at
four MiB. `MAX_SEMANTIC_PILE_BYTES` is 11,491,734 bytes (about 10.96 MiB),
derived from the 128,000,000-byte hosted peak-memory model at the worst legal
fact and JSON-value counts. `MAX_DIRECT_OBJECT_BYTES` and the physical pack
ceiling remain 95 MiB, so several smaller complete piles may share one pack.
The ability to stream or range-read a physical object does not make that whole
object one evaluable pile. Discarded membership/removal proofs retain their
separate five-MiB evaluation budget.

The common gate handles one small authenticated `ObjectOpen` or `PackOpen`
value bound to the content-addressed OID, method, declared ceiling, and, for a
pack, an optional exact range. It returns a short-lived `ScopedRequest`
containing an ordinary HTTP URL and required headers. S3 points both methods at
presigned provider HTTP. R2 points GET at its S3/SigV4 endpoint and PUT at a
minimal HMAC-ticketed streaming Worker backed by the native binding. FullPeer
points both at a same-origin streaming route, which Iroh may carry unchanged.
The client performs the
returned ordinary HTTP request in every composition. Same-origin FullPeer
routes retain the dial's scheme (including local or Iroh-carried HTTP), while
an origin-changing hosted target requires HTTPS; direct requests never follow
redirects. A peer that does not
implement `ObjectOpen` may still serve ordinary four-MiB fact and page reads,
but it cannot serve writer piles. Pile reads require the direct route even
when a particular pile happens to be small; there is no capability probe,
old-protocol fallback, or large body in a buffered response.

Neither `ObjectStore.get_bounded`, the named four-MiB fact and Merkle-object
limit, `HttpGate.Response`, Lambda response bodies, nor Worker buffered-body
helpers may be widened to 95 MiB. Whole GETs stream to a sink and verify
declared size and object or pack hash before acceptance. Exact range GETs are
bounded by one signed pile, require exact HTTP range/length metadata, and
verify the tree-selected pile OID, workspace/device signature, and ordinary
closed-pile judgment. Object and pack PUTs are immutable/create-only and use
the same small OPEN-to-ordinary-HTTP split at every size; there is no buffered
`PUT /obj/<oid>` fallback. A writer head or layout page is CASed only after
every object it advertises is established.

This is an unavoidable storage tradeoff rather than a protocol ambiguity. One
ever-growing object minimizes cold GET count but rewrites the writer's entire
history on each append. One immutable object per pile writes each byte once but
makes cold catch-up request-bound. The initial policy therefore uses fixed
immutable packs plus one asynchronously packed loose suffix: ordinary append
never touches layout, while a background or sender-side packer takes a bounded
uncovered contiguous prefix, uploads one at-most-95-MiB pack, and CASes only its
window page. Each pile is copied into established packing at most once.

No immutable object layout can simultaneously provide one-GET unbounded cold
history, write only the new bytes on append, and independently address every
range: after the second append, at least one of those requirements must become
a manifest traversal or a rewrite. The target is the simple Pareto point. With
Merkle page fanout `B`, a normal append writes one new pile, `O(log_B n)`
path-copy pages, and one writer-head CAS. For `H` packed bytes under pack cap
`C` and `Q` occupied fixed windows, dense cold transfer approaches
`Q + ceil(H/C)` layout/body GETs plus the bounded head/tree work. Sparse sync
pays only the RBSR frontier, affected layout pages, and selected complete-pile
ranges. These are transfer packs growing denser toward the past; the signed
semantic piles themselves never grow or change.

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
cumulative control-subsequence tree root, count, and depth
registered store-binding fid
device signature
```

The exact codec and bounds are frozen beside their fixtures. These semantic
fields are not provider metadata. In particular, a head contains the
protocol-derived store binding, never an arbitrary URL supplied to a cloud
fetcher.

The directory and writer store use two forms:

```text
obj/<head-oid>                   immutable writer-supplied head record
heads/<workspace>/<device-fid>  mutable {head_oid, accepted_removal_root}
```

The stable slot makes listing compact: one entry per enrolled device rather
than one entry per update. Its body is content hashed independently; its
provider version token is used only to conditionally replace that exact slot.

`AccessGate` accepts an exact slot update only when:

- the submitted device-signed closed pile authenticates the workspace device
  as a member and not removed at the removal root the gate itself pins;
- the pile's signed request fact binds the exact proposed head OID;
- the deterministic slot belongs to that same workspace device;
- the signed base/proposed heads and control-subsequence extension are valid,
  with no control delta on the ordinary route and an exact declared tuple on
  the permit route;
- the request and slot body fit fixed mechanical bounds;
- the per-device conditional replace succeeds.

The caller cannot select an older removal root. The gate records the exact root
it used beside the head OID. It opens and verifies only the small signed
base/proposed head records and the secondary control-tree pages needed to prove
that declaration. It does not walk the main writer tree, inspect ordinary pile
bytes, verify content signatures, or prove closure. Those remain writer
responsibility until another peer consumes the log.

That opacity is an explicit hosted trust boundary. The hosted owner gate trusts
the writer's signed classification of its own log; omitting a control pile can
only leave that writer's opaque hosted log unusable to a consuming peer, which
recomputes the classification and rejects the head. Hosted storage never
performs that recomputation itself; detection happens only where a log is
consumed, and until then a misdeclared log is merely unusable. An omission cannot name
another writer's slot or inject an undeclared removal effect, because only the
exact signed control-tree delta can enter permit evaluation.

A consuming peer, not `AccessGate`, verifies the head object's content hash,
device signature, workspace, owner, store binding, sequence, and named log root;
compares it with the peer's last accepted head; verifies each selected pile's
direct writer signature and Merkle inclusion; and then evaluates every pile it
has not already validated.

An unknown CAS result is reconciled by rereading the stable slot. An exact
head, permit, and recorded-root match is success; otherwise the writer rebases
or returns a bounded retryable result. The
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
through a registered store binding to the user's content bucket. Consuming
peers mirror the per-writer trees they learn through this directory; an opaque
hosted owner target only stores, lists, and serves them. No actor combines the
forest beneath another content root.

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
7. recover every previously unvalidated complete signed
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

## 7. Closed access proofs and removal-path refresh

Each recipient owns and pins its current authenticated removal tree. That tree
is verifier state, not state supplied by an access caller. A caller never
publishes authority facts into the recipient, asks it to adopt the caller's
root, compares whole authority roots, or synchronizes an authority repository
before content sync. The only bootstrap mutation is the direct-member
CLEAR-only exception below; the only bootstrap read is a self-confined path
from the recipient's removal tree.

Advancing the recipient's own removal tree is a separate recipient-owned
operation. A pushed access proof can never advance it. There are exactly two
inputs, and hosted and full peers run the same database-free implementation:

1. A fresh recipient may bootstrap a direct member from that member's original
   device-signed, control-only closed pile. The pile must prove its outer writer
   as `member(writer, writer)` and may introduce only CLEAR cells. It is
   evaluated and discarded; no fact repository is created.
2. A writer head that introduces control piles uses one exact two-step permit
   turn. While the writer is still current, the ordinary strong head proof
   binds its observed base and proposed head. The gate verifies the head's
   signed append-only control-subsequence delta and evaluates each member of
   that exact bounded set of original writer-signed control-only piles once.
   Fact-family handlers select one semantic removal sink per fact. The gate
   canonicalizes and joins those sinks into one bounded aggregate CLEAR/ACTIVE
   plan and returns a self-contained HMAC-authenticated permit. The proof,
   control piles, and evaluation receipts are then discarded. Commit verifies
   the permit's issue-time root, applies that authenticated plan, and performs
   one final writer-slot CAS after the effects.

The two transport-neutral operations are exposed consistently as
`POST /head/<proposed-head-oid>/permit` and
`POST /head/<proposed-head-oid>/commit`. The permit request uses one bounded
binary frame containing the current access-proof pile and ordered control-pile
tuple. The commit body is exactly the returned bounded permit bytes; it never
resends or re-evaluates the proof or control piles.

One transition is capped by `MAX_HEAD_CONTROL_PILES`,
`MAX_HEAD_CONTROL_FACTS`, `MAX_HEAD_REMOVAL_UPDATES`, and the permit byte
ceiling; a one-over request fails before provider mutation. The current
prototype therefore requires a writer to publish before its cumulative unseen
control delta crosses those bounds. `poc-16-6j4.26` tracks a sparse signed
control-checkpoint chain for larger offline gaps without widening one Worker or
Lambda turn or retaining ordinary historical heads.

The permit is a self-contained capability for one workspace, device, observed
base, proposed head, issue-time removal root, and canonical aggregate plan. It
is authenticated by a stable recipient permit
secret that is distinct from short-lived bearer-grant material and persists
across process or serverless-instance replacement. It is not a bearer grant
for a namespace and has no expiry that could strand a writer after
self-removal. Replaying it can only finish or observe that one exact slot
transition. A writer removed before permit issuance fails the normal strong
proof. A different removal root observed before commit makes the permit
retryable unless its exact ACI rows are already subsumed, which is the bounded
crash-replay case.

Commit applies the ACI rows and then conditionally replaces the device's exact
observed final slot with one final value containing the proposed head, resulting
removal root, and permit hash. A competing same-base permit may apply fail-safe
removal rows before it loses the slot CAS; it can deny but never grant. Those
slot fields are recipient-local audit and exact-replay metadata. They are not
caller-selected authority, object addresses, grants, or historical admission
proofs.

The caller retains the permit until it observes the exact slot outcome; the
recipient deliberately stores no permit journal. Retryable removal-root
contention, a provider 5xx, and an unknown transport outcome reuse those same
bytes for only a named bounded number of attempts. A competing head is a
terminal HTTP 412 and requires the writer to rebase; it is never retried as the
same transition. A live FullPeer turn applies bounded exponential full jitter
and never reissues authorization.

All family-selected state-affecting rows are joined into the one canonical
permit plan before commit. An exact replay proves its rows already subsumed
without a cursor or scan. A crash may leave removal state ahead of the final
slot CAS, but the new head can never become visible before all its control
effects. Ordinary content piles are never opened by
this control path. No SQL projection, LIST scan, re-closed authority pile,
caller root, separate authority service, queue, or provider-specific
coordinator participates. There is no `POST /authority`,
`AuthorityRepository`, or mirror/replay authority-publication hook.

Every semantic evaluation consumes exactly one bounded canonical closed pile
signed by its outer writer device and runs the ordinary
`ClosedPileEvaluator`. Historical/current requests are requesting-device piles;
each permitted control input is an original writer-device pile. A permit may
bind several such independently evaluated piles, but it never turns them into
one ambient fact set or claimed verdict. The gate's only trusted context is the
recipient's configured root public key, its local invite-acceptance/workspace
anchor, and the exact removal root it pins. There is no parallel fact array,
SQL row, caller-selected root, or retained proof judgment.

Permit issuance is the only closed-pile evaluation in this turn. Commit trusts
only the authenticated permit fields and performs no fact-family dispatch.

### 7.1 Admission creates the exact subject row once

The initial handoff is entirely out of band. One compact compressed binary
frame, base64url-encoded within the standard version-40 QR byte capacity,
carries the invitation facts together with their signature facts and
peer reachability. It is never uploaded as a recipient-addressed cloud object,
and acceptance performs no author or cloud read. The beneficiary validates the
closed pile, then first publishes those exact bytes in its own writer log along
with its countersigned membership. Signatures identify authorship while the
writer log identifies residence; stable fact IDs deduplicate a later author
publication. From that point invite/device facts are ordinary control families
under Rule 2. The gate-facing mint proof may carry the same facts ephemerally,
unchanged, but no handoff ticket or redemption state exists.

An UNKNOWN subject may present one device-signed mint request closed over its
positive workspace admission and device-ownership chain. `AccessGate`
evaluates that carriable chain once and joins CLEAR rows for the exact member,
device, and device/owner subject tuple into the recipient's removal tree.
Relabeling a known device as another owner is therefore UNKNOWN, even if both
individual principal rows exist. `POST /removal/bootstrap` remains the narrow
public exception for introducing the original direct-member closure before any
subject can mint.

After admission, requests contain only the action fact and the outer device
signature. A mint binds the workspace and purpose; a head request additionally
binds the base and proposed head OIDs. The gate never validates ordinary
content while authorizing access. Full peers still validate every transferred
head, range proof, pile, and dependency before admitting data.

### 7.2 One lookup authorizes access or one exact write

The gate pins its recipient-owned removal tree and looks up the exact subject.
UNKNOWN fails closed with no body. CLEAR proceeds. ACTIVE fails with the
current tip and an authenticated path containing exactly the rows present for
that subject (at minimum the ACTIVE row). A nonempty basis that names an older
CLEAR tip receives `proof_refresh_required` and the current tip; the client
re-signs its action at that basis and retries. The client never presents a
removal path as a credential, and there is no `POST /removal/path` route.

For hosted publication, a successful ordinary head request can conditionally
replace only the requesting device's deterministic slot. Before exposing a
head with new control piles, the writer obtains an exact permit at
`POST /head/<oid>/permit` and commits it at `POST /head/<oid>/commit`. There is
no bearer-only removal update, accepted-leaf scan, replay cursor, reservation,
or second control envelope.

### 7.3 Fetchable-whole state keeps requests bounded

The private root value contains the complete sorted hashed row set under the
same bounded root envelope. A gate caches the decoded tree by root entity tag,
so steady authorization performs one request signature verification, one
in-memory lookup, and at most one conditional root read. Immutable Patricia
nodes remain private path commitments used to build ACTIVE rejection stories;
authorization must never walk one provider object per branch.

Removal roots and nodes are not generic objects: `/obj`, packs, direct-open,
and LIST cannot address them. A writer slot may record a root hash for audit,
but that hash is not a read capability. Rejection witnesses contain only the
requesting subject's values and opaque siblings, never dense leaves or adjacent
subjects.

### 7.4 Pins make races and commits explicit

One lookup is answered against one immutable pin. A concurrent update may make
that answer stale afterward, but cannot tear it across roots. An ordinary final
writer slot records the pin that authorized its head. A control permit binds
its issue-time live root and bounded canonical missing-row plan; commit applies
those ACI rows first, pins the result, and then attempts one base-guarded slot
CAS. A losing permit may leave fail-safe removal effects, but never a grant. A
crash may leave removal ahead while a visible head is never ahead of its
effects, and an exact retry succeeds when its rows are already subsumed. There
is no workspace-global transaction or pending-head journal.

### 7.5 One protocol identity per node

A node needs one device root secret and invite-derived facts. Provider
credentials needed to call S3, R2, Lambda, or a Worker remain deployment
effects; they are not a second fact-authority universe. Iroh endpoint keys are
connection material only. A separate HMAC user database, provider-admin
identity, API-token membership system, or persisted cloud account table must
not appear beside the fact proof universe.

Provider-community membership and service withdrawal can later be expressed
as another ordinary workspace and another lookup-gate condition. It is not
implemented by trusting an Iroh identity or by adding a special provider ACL
to core.

### 7.6 Removal and deletion semantics

The important content rules remain:

- an administrator may delete every fact family that declares itself directly
  deletable;
- a user may delete facts owned by that user, including facts authored through
  any of the user's devices;
- the delete fact's ordinary Needs and offers must validate, and its offered
  suppression ID must exactly match a selector declared by the target fact.

Deletion permission is not a hardcoded core role table. The delete fact has
ordinary `Need`s, signatures, and family policy; when valid, its offered
suppression action must match a selector explicitly declared by the target
family. The rules above are therefore facts-and-offers policy executed by the
same simple handlers, not a second administrative deletion subsystem.

### 7.7 The lookup gate

Steady-state authorization is one lookup, and the same gate function runs at
the hosted worker and at every full peer. A request is bound to a device
signature; the recipient derives the subject id from that signature and reads
`h(sid)` from its own pinned removal tree. The ACI row answers everything at
once: UNKNOWN was never admitted and fails closed, CLEAR proceeds, ACTIVE is
removed and may retrieve exactly its own path. A proof whose basis is older
than the recipient's pin receives `proof_refresh_required` together with the
recipient's current tip.

Admission is the one moment the positive chain is presented: mint evaluates
the carriable invite evidence once, and its judgment mints the subject's
CLEAR row. After that, no request re-presents or re-verifies the chain to a
recipient that holds the tree. The governing principle: a recipient's
persistent judgment state is exactly the non-carriable claims. Positive
existential claims — admission chains — are self-authenticating and travel
with their subject, so they are evaluated once to create state. Negative
universal claims — the absence of a removal — can only be folded from the
control record, so they are the state.

Carried non-removal credentials (an exclusion proof, or an inclusion proof of
a CLEAR row, against a known tip) are deliberately not used on the gate path.
The gate necessarily holds the tree — the permit turn above is where tips
come from — and for a tree-holder, verifying a carried proof is a lookup plus
redundant sibling checks. Worse, every control change moves the tip and
invalidates every outstanding carried proof at once: honoring a tip window
would delay removal enforcement by exactly that window, while refusing one
generates a refresh round per subject per change. Tip-anchored inclusion
proofs remain the recorded option for a future stateless edge verifier, with
that enforcement-window trade stated. Tips otherwise serve as deterministic
cache keys: identical control coverage yields identical tips at every holder,
so equal tips short-circuit whole subjects.

There is no separate weak tier. Because the recipient judges by lookup, a
caller proves nothing in order to be told its standing: every request is
answered from its row, and the answer's richness follows the row. UNKNOWN
fails closed and learns nothing. ACTIVE is rejected, and the rejection itself
carries the caller's own removal path and the recipient's tip — the tree row
is the historical record of admission, so no historical-membership credential
is verified and no standalone read route exists. CLEAR proceeds. The old
bootstrap cycle — proving standing would require reading removal state —
dissolves rather than being broken: subjects never construct standing proofs,
so they never need removal state. A past member can only ever learn its own
story, delivered inside its own rejection; population privacy needs no
scoping rule because there is no readable surface to scope.

The lookup must stay zero-to-one store reads. The judgment tree is stored
fetchable-whole and cached against the pin's entity tag, revalidated with one
conditional read; a per-request walk of sequential node reads is forbidden on
the request path. Steady state is one signature verification, one memory
lookup, and a conditional read that usually returns not-modified.

Row sources differ by capability and nothing else. A full peer parses control
subsequences from the logs it consumes — the head's control root makes those
slices extractable and verifiable without content — and folds its own rows.
The hosted store deliberately parses nothing, so its rows arrive as the
bounded canonical plan inside the permit turn above. Both apply control
effects before exposing the transition they authorize.

Status: this section is the running implementation. Hosted workers and full
peers construct the same `AccessGate`; only their store adapters differ. Tips
are disclosed pairwise in refresh and ACTIVE responses, while the
population-privacy floor remains hashed subject ids plus
own-story-in-own-rejection.

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
indexes into SQLite for queries. A consuming database-free peer can keep the
same `FactConsumer` union in memory and validate streamed pile deltas without
creating a hidden database. A hosted owner target neither mirrors nor builds a
combined content projection; its gate needs only its pinned removal tree,
local trust anchors, and each ephemeral signed request pile.

## 9. Sync and range behavior

Canonical residence is a forest of dense, independently advancing device
logs. A transfer is a contiguous writer-sequence `Run`: canonical fact bytes,
one signed writer head, and boundary inclusion paths. Verification proves the
writer, sequence density, fact bytes, head signature, and inclusion before the
whole run is installed. No page, segment, footer, or discovery index can
introduce a fact, and a failed run installs no prefix.

Every logical writer-tree leaf is independently closed for authenticated
admission: accepting its proved run never depends on an unproved neighboring
range. That admission closure is distinct from materializing ordinary render
refs, which the bounded dependency pump below may fetch after the citing fact
is resident.

For the separate ephemeral gate codec, no range or page boundary splits a pile;
each signed closed request is judged whole and then discarded.

P2P discovery uses range-based set reconciliation (RBSR) over the peer-local
`(ts, fid)` Merkle treap. One initiator walks
the responder's immutable pages, computes the symmetric difference, and both
pulls and pushes missing facts in the same session. Complete timestamp ranges
may be fingerprint-pruned; partial coverage islands travel as exact sets.
Selected facts are then grouped into proved original-writer runs. The treap is
derived local discovery state, not canonical residence and not a cloud object.
This is one session over the symmetric difference, not one sync session per
pile.

Cloud discovery is one conditional read of the derived workspace directory.
The directory contains each signed writer slot and its contiguous immutable
segment spans. It is LIST-repairable and grants no authority. A client request
is either a timestamp hint or one bounded canonical `CloudDemand`. Each writer
in a `CloudDemand` independently requests either:

- its newest `N` facts, resolved as `[max(0, writer_hi - N), writer_hi)`; or
- normalized exact half-open sequence intervals.

There is no workspace-wide scalar sequence window. The client subtracts its
held coverage intervals per writer and opens only segments intersecting the
remaining demand. A segment is the physical read unit: suffix range GETs read
timestamp footers, but selected bodies are fetched whole. Facts neighboring a
logical interval are authenticated and ingested as measured segment overfetch;
they do not silently widen the logical request.

Every cloud micro is closed over transitive cross-writer refs before its
create-only write. The owner supplies local `PeerState` holdings; the publisher
adds one deduplicated exact authenticated `Run` for every cross-writer target,
recursively, bounded by `CLOUD_ANNEX_MAX_RUNS`. Folded ladder, mono, and epoch
artifacts preserve those adjacent annex runs. Same-writer refs remain sequence
cites and are not copied into annexes. Consequently a cold cloud range is
judgeable and renderable from its selected artifacts, earlier same-writer
artifacts, writer authentication, and the consumer's current control state. A
cross-writer ref without either an explicit carry or local target holding is
rejected before object creation.

Requested segment bodies are read with bounded 64-way concurrency and ingested
as each completes. Physical arrival therefore need not be topological. Once
the requested roots are resident, the client closes their exact transitive
`(writer, seq)` references with a deduplicated breadth pump:

```text
directory -> requested segments -> referenced containing segments -> repeat
```

Each dependency segment uses the same signed `Run` decoder and atomic
publication ingest as the initial range. Adjacent Rule-2 carries are installed
with their citing publication. A cloud-visible out-of-window target is located
from its writer's authenticated slot span; absent writers and refs above the
visible head remain explicit pending refs rather than speculative failed GETs.
Cycles and duplicate refs terminate by address deduplication. Depth, ref,
segment, and byte ceilings bound the pump.

A recent view is interactive only when its pending set is empty and no closure
ceiling was exhausted. Reports separate initial segment GETs/bytes and logical
facts from closure GETs/bytes/facts, segment-granularity overfetch, closure
depth, total rounds, and exhaustion. Corrupt proofs, missing advertised
objects, forks, and containing segments that omit their addressed target fail
closed and never produce an interactive-ready result. A conditional no-change
poll preserves an incomplete cache result; it cannot turn pending into ready.

For a cloud-fetched citing artifact, the annex normally makes cross-writer
closure chase-free. The demand pump remains necessary for same-writer
backfills, refs originating in facts already held from P2P, and bounded
unresolved outcomes. Full catchup is the same demand with all visible writer
intervals. Repeated sync is the propagation mechanism. There is no combined canonical P2P log,
shared cloud content index, cloud treap, per-fact session, or stored closed-pile
format. Signed closed piles remain only the ephemeral gate-proof boundary.

## 10. Object-store contract

The portable store contract becomes:

- bounded strong read of one exact object and its opaque version token;
- bounded conditional read of the exact listed version;
- create-only immutable write with collision verification;
- conditional replace of one exact per-device head slot;
- conditional replace of the separate removal-tree root;
- private bounded reads of removal proof nodes, unavailable to generic object
  GET, direct-object grants, and public prefix LIST;
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
small head-slot operation passes through `AccessGate`; the gate evaluates one
pushed proof pile, checks only the ephemeral requester/recipient membership
and non-removal conditions bound to the exact head OID, confines the slot, and
performs CAS. For a control-bearing head, its exact permit additionally
authenticates the canonical aggregate removal plan produced by the sole issue-
time evaluation. Commit verifies the issue-time root, applies the plan, and
performs one CAS of the final slot. The gate is not an ordinary content
validator, proxy, or tree builder, and no pushed pile enters repository fact
state.

## 11. Concurrency and failures

For `N` different device writers there are `N` mutable head slots. Their
updates commute. Adding Lambdas increases useful parallelism because each
successful request normally targets a different object key.

For two requests targeting the same device head:

1. both may establish harmless immutable objects;
2. exactly one conditional replacement of the observed version succeeds;
3. an exact replay reconciles or finishes the same transition, while a
   different competing head or permit returns terminal conflict and rebases;
4. readers see either complete head, never partial bytes.

A crash before an ordinary head CAS leaves unreachable immutable objects. A
crash after an ambiguous CAS is reconciled by exact reread. For a control turn,
a crash after the aggregate removal update may leave removal state ahead with
no new writer slot. Exact permit replay proves those ACI rows are already
subsumed and retries the one bound final-slot CAS. The head can never become
visible ahead of its removal effects, and a losing same-base permit can leave
only fail-safe removal rows. `AccessGate` may accept a
malformed head from a currently authorized writer because it deliberately
trusts writers to maintain their trees. Bounded mirroring and per-device
isolation ensure that such a tree can make only that writer's content unusable;
a consuming peer rejects it, and it cannot wedge another slot, delete another
writer's data, or corrupt the removal tree.

The cloud queue's deterministic range-keyed micro is a more specific case. A
crash after micro create but before its writer-slot CAS leaves an authenticated
orphan. An identical retry reuses those bytes and finishes the CAS. A divergent
retry raises `CloudMicroFork` with the range key and both SHA-256 hashes; it
never loops or overwrites. `readmit_orphan()` decodes and verifies the stored
publication, checks the exact current sequence base, and performs the missing
slot CAS. That explicitly chooses the orphan branch, after which a divergent
local restart must import/rebase it or rotate writer identity.

A consuming mirror uses the same effects-before-one-CAS ordering, with a local
identity derived from the exact signed base/head and canonical control plan
rather than a caller permit. One invocation has a fixed retry bound. On
restart, the mirror recomputes the plan from its copied head, tree, and closed
piles, idempotently joins it, and retries the final slot CAS.

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
- removal-tree advancement racing publication and read grants;
- terminal self-removal crashing before permit issue, after permit issue, after
  its aggregate removal CAS, and after final slot publication;
- crashes at every external effect;
- full-scan repair after every permitted delayed observation.

The safety theorem is per object and per closed pile. The liveness theorem is
eventual discovery under fair retry and complete scans. No global serial order
of unrelated content heads is claimed or needed.

## 12. Recency is an optional hint

S3 and R2 list by key, not by update time. Their returned metadata can be sorted
only after all pages have been fetched. The initial design therefore performs
the complete stable-head scan and measures it before adding another index.

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

Every deployment composes the same `ClosedPileEvaluator`, bounded authenticated
object reads, object codecs, `AccessGate`, `OpaqueHeadGate`, and HTTP
routes. `FullPeer` additionally enables directory mirroring and content
consumption, and adds local state:

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
Deleting FullPeer SQLite changes no writer tree, head, removal root, or
validated answer. On an application-version change the peer discards the whole
projection and replays every accepted writer tree through pure current-family
re-extraction. SQL stores the current serialized form under the immutable
source fid, and its generic index and queries use that same form. When a family
explicitly retains a legacy source tag, the projection envelope also retains
the exact source value needed by signatures and later closed piles. There are
no table migrations, version graphs, or selected dependency histories.

### 13.1 Hosted and local turns are isomorphic

| Turn | Hosted peer | Full peer | Shared core |
|---|---|---|---|
| pushed condition check | canonical pile bytes enter `AccessGate` | the same bytes enter the same gate, even in process | `ClosedPileEvaluator` + pinned removal-path verifier + family query |
| pulled content | mirror full pile leaves; optionally stop | mirror the same leaves, then consume | `RepositoryMirror` + `ClosedPileEvaluator` + `FactConsumer` |
| pushed state afterward | no fact state; permitted control deltas may join private removal state | the same | proof/control facts are discarded |
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
it represents. Delivery separately pins current membership/removal state,
preferences, and endpoints. SQS, Cloudflare Queue, or FullPeer wakes remain
disposable. Only a
typed terminal outcome or provider acceptance advances durable notification
progress. Live provider and device launch work remains tracked in beads.

## 15. Hard protocol cut and application-version replay

This prototype has one publication algorithm and no predecessor-format
reader. Old ingress namespaces, upload sessions and journals, workspace-wide
content roots, former HTTP routes, broker deployments, and historical local
schemas are absent. Unknown old values are rejected or disposable state is
discarded; running code never translates them into the writer forest.

The sole upgrade mechanism retained is current-form replay:

1. canonical fact bytes remain immutable because `fid` is their identity;
2. every accepted writer slot remains the durable admission certificate;
3. `facts.APP_VERSION` names the current family/query projection contract;
4. when that value or the exact SQL shape changes, `SqlStore` removes its whole
   disposable database;
5. `RepositoryMirror.replay_local()` walks the accepted writer trees through
   the current pile decoder, kernel, family registry, and generic index
   extraction, then recreates `facts`, `fact_index`, and `projected_heads`;
6. `family.SHAPES` routes each explicitly retained source tag to one owner, and
   its pure `reextract(source)` reconstructs and checks that exact old source
   before returning an ordinary current-shape fact;
7. the current semantic view keeps the source fid/key, while its type, atoms,
   body, needs, offers, indexes, and query interpretation use current code.

This proves event-sourced application upgrades without table migrations, dual
writes, stored validation chains, ambient provider selection, or a global
compatibility layer. A changed wire form gets a new explicit source tag and a
branch confined to its owning family; it may not mutate bytes addressed by an
existing `fid`. Unknown predecessor protocol values remain rejected.

## 16. Core invariants

1. Every semantic evaluation begins with exactly one canonical device-signed
   closed pile and uses the same `ClosedPileEvaluator` and family handlers.
2. A valid pulled pile may join durable facts to a consumer's validated space;
   pushed proof and control facts are discarded. Only a v2 permit's
   authenticated bounded aggregate CLEAR/ACTIVE rows may remain in private
   removal state.
3. Hosted and full peers use the same database-free `AccessGate`, removal-
   path verifier, request-family queries, object contract, and HTTP routes;
   local SQL is never an authority shortcut.
4. Every accepted writer-log fact is canonical, occupies its original writer's
   dense sequence, and is authenticated by a valid boundary path to that
   writer's signed head.
5. Writer-sequence runs are verified and installed atomically. Physical range
   and diff pagination stops between facts and never makes a partial run
   resident; render refs may remain explicitly pending until demand closure.
6. Cloud publication grants let a device populate and advance only its own
   writer log; hosted content storage need not validate those opaque bytes.
7. A full peer serves remote facts only from accepted original-writer runs,
   preserves their writer identity and signed-head evidence, and never treats
   the sender's prior judgment as an admission certificate.
8. Every full peer files accepted facts into independently rooted per-device
   log copies and uses one peer-local `(ts, fid)` treap only for one-sided RBSR
   discovery. No combined canonical P2P content log exists.
9. Every ordinary content update mutates at most one device head slot.
10. Different device writers share no mutable content key.
11. Immutable objects exist before a writer advertises a head that names them.
12. A provider version token is opaque and never a content hash.
13. LIST output is candidate discovery, never authority.
14. `AccessGate` checks one outer device signature and one exact subject lookup
   against a recipient-pinned removal root. Only UNKNOWN admission additionally
   evaluates its positive chain; the gate never validates writer content.
15. A control-bearing head is preauthorized while current and binds its exact
    base, proposed head, issue-time root, and canonical aggregate removal plan.
    Commit applies those ACI rows before one final slot CAS; replay may leave
    removal ahead but never the visible head ahead.
16. Every signed head carries an append-only control-only pile subsequence.
    Ordinary publication requires an empty delta, a permit accepts exactly the
    declared delta, and every consuming peer recomputes the declaration from
    its independently validated main-tree suffix.
17. Every consuming peer validates canonical fact bytes, writer-head signature,
   sequence density, boundary inclusion, control signatures, and Rule-2
   adjacency before using a received run as state.
18. Mixed head observations may delay facts but cannot fabricate or invalidate
    them.
19. Removal governs current publication and access without rewriting validated
    history.
20. Authority proof evaluation is database-free. FullPeer SQLite, caches,
    cursors, hints, queues, and Iroh identities are non-authoritative.
21. Provider adapters add no semantic branch.
22. FullPeer reuses the complete core gate, writer, mirror, and consume paths.
23. Every optional recency hint is repairable by a complete stable-head scan.
24. No publication path deletes heads, logs, or canonical objects. Separate
    reachability collection may remove only superseded, unpinned head and
    internal-page versions, never signed piles or current reachable objects.
25. A final directory slot's removal root and optional permit hash are
    recipient-local audit, replay, and fencing metadata. They disclose no
    private removal nodes, confer no read authority, and store no historical
    validation chain.
26. One device root secret plus invite-derived facts is the complete protocol
    identity bootstrap for a node.
27. No workspace-global mutable content root exists.
28. Removal-root/node bytes are non-enumerable private verifier state; only an
    ACTIVE caller receives its authenticated available subject rows, inside
    that caller's rejection.
29. There is no `POST /authority`, `AuthorityRepository`, authority-root sync,
    or mirror/replay authority-publication hook in the running protocol.
