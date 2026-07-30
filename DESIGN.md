# POC-16 design

This document describes the code on `main`. It distinguishes running behavior
from limits and future work; it is not a backlog.

## Goal and trust boundary

POC-16 asks whether peers can reconcile an authenticated workspace against a
counterpart that mostly serves immutable bytes. The active peer performs the
walk, verifies hashes, validates fact closures, and settles its local catalog.
The responder supplies a small authentication gate plus an object-store-shaped
HTTP surface.

The prototype provides integrity, deterministic reconciliation, logical
suppression, and bounded request-time authorization reads. It does not provide
body confidentiality, physical erasure, production-grade garbage collection,
or compatibility across format stamps.

Fact bodies are plaintext JSON. Signatures authenticate facts. Only invite
blobs are encrypted with a secret carried in the invite link. Attachment bytes
are content addressed and Bao verified, but the surrounding file facts are not
encrypted.

## Authority flow and code map

The runtime is a downward authority chain, not a collection of peer managers:

```text
daemon / local command                         host adapters
        ↓
WorkspaceRuntime.turn                          one socket-free turn
        ↓
kernel → registered fact family                judgment and policy
        ↓
Catalog.settle                                 admitted receipt → eligibility
        ↓
Publisher.publish                              snapshot → one root CAS

root + immutable-object fetches → WorkerView   database-free CF authorization

generic type/ref/offer index → family query    client read assembly
```

`Node` composes local identity, workspace handles, diagnostics, and these
boundaries. It does not define family policy. Sync and local authorship both
enqueue the same pile bytes; `WorkspaceRuntime` is the normal coordinator,
`Catalog` alone decides current standing, and `Publisher` alone advances
`root`. The daemon handles HTTP and token sealing. Its node-local control
surface dispatches one qualified command path through the checked
`facts.COMMANDS` registry; typed application commands remain beside their fact
families, and adding one does not add a CLI or daemon branch.

An engineer should read the running path in this order:

1. `core/fact.py` and `core/suppression.py`;
2. `facts/__init__.py`, then one auth and one content family;
3. `core/kernel.py`;
4. `core/runtime.py` and `core/catalog.py`;
5. `core/publication.py`, `core/manifest.py`, and `core/indexes.py`;
6. `core/worker.py` and `core/mint.py`;
7. `core/sync.py`, `core/walk.py`, then `core/daemon.py`.

## Facts and the kernel

A fact is a canonical JSON value containing:

- a type tag;
- an integer timestamp;
- a workspace genesis fid `ws`;
- clear-envelope atoms for references, offers, and suppression policy; and
- a family-owned body.

The workspace-genesis fact is the sole exception: it has no `ws`, and its own
`fid` defines the workspace anchor. The checked family registry requires
exactly one family to declare that genesis role. Every ordinary fact carries
`ws=W` in its clear envelope, so the workspace participates in the `fid` and
in every signature over that fid. Consequently the same author, timestamp,
atoms, and body in two workspaces produce different facts and signatures.

Its `fid` is the SHA-256 hash of the canonical envelope bytes. Its
reconciliation key is the fixed-width string `(timestamp, fid)`. Timestamps
primarily provide locality and deterministic ordering; the prospective
admission rule described under “Action timing” also compares that key.

A pile is a canonical, topologically ordered, dependency-closed collection of
facts plus optional blobs. The same pile codec is used for ingress, sync, and
resident leaf objects. Its outer envelope names exactly one `ws=W`; every fact
must carry `ws=W`, except the sole genesis fact whose `fid` must equal `W`.
There is no decoder for the previous workspace-ambient fact or pile format.
Invite bootstraps carry this same canonical pile, rather than a second raw fact
list, and must pass outer-link/inner-pile workspace equality plus a complete
kernel judgment before local workspace or keyring state is mutated.

The family-neutral kernel processes a pile in one pass. A `ref` carries its
own role and must name an earlier fact. Each family returns named `Need`
values; the kernel selects each canonical provider by shortest proof rank and
then fid. There is no second tag-indexed role table. Every family module owns
one `POLICY` beside its behavior, and `facts/__init__.py` is the one checked
registry. `facts/_policy.py` supplies the vocabulary for selectors, direct
targets, guards, liveness, and typed principal/action offers.

Persistent validity is immutable and does not read wall-clock state. An
ephemeral request family owns its database-free Worker authorization hook,
including verb and expiry checks against trusted service time.

Ingress dependency choices are hints, not authority. The client catalog
resolves every named edge again against its complete local candidate set and
runs the same family validator before granting standing. A sender therefore
cannot preserve a losing ownership or membership edge when the receiver has a
better canonical provider.

Workspace identity is checked before those choices or family dispatch can
matter. At an authenticated write door, request workspace, grant workspace,
uploader path, pile workspace, and every ordinary fact workspace must agree.
Foreign and mixed piles are typed permanent rejections before catalog staging.
The same expected-anchor pile decoder is used by host ingress, sync, invite
redemption, manifest leaves, suppression evidence, database-free mint, and
rebuild. The kernel remains database-free and family-neutral: it compares the
canonical anchor, then asks the one registered genesis family whether the
single ws-less exception is actually genesis.

## Store and publication

Each workspace store exposes:

```text
root                         one mutable, CAS-written composite root
obj/<sha256>                 immutable pages, piles, facts, and blobs
pile/<member>/<sha256>       idempotent ingress
invite/<unguessable-id>      encrypted invite blob
failed/pile/<sha256>         shared immutable rejected bytes
failed/meta/<sha256>         shared immutable typed-rejection record
```

The writable ObjectStore API enforces the authoritative-key rules: `root`
rejects ordinary put and delete, `obj/*` rejects replacement and delete,
object creation is conditional, and only root CAS may replace the composite
snapshot. A separate ObjectReader interface covers HTTP peer/root/object
reads; its HTTP cache tag is never a writable-store CAS token. Provider SDKs
and deployment code stay outside `core/`.

`read_versioned(root)` atomically returns either `ABSENT` or exact root bytes
paired with an opaque `VersionToken`. The token is only a comparison
capability to pass back to CAS. It is not SHA-256, an HTTP cache tag, an ETag
algorithm promise, or a globally unique generation. `cas` returns
`Applied(new_token)` or definitive `STALE`; a mutation rejected before its
linearization point raises `RetryableStoreError`, while a lost response after
a possible mutation raises `OutcomeUnknown`.

Immutable creation returns `CREATED` or `EXISTS`. The shared
`ensure_object(oid, bytes)` boundary accepts `EXISTS` only after fetching and
byte-verifying the incumbent. It reconciles an unknown outcome by direct read
and never lets root CAS run until every immutable page reachable from that
candidate root is known present. Detached attachment blobs are not
root-reachable pages: their absence makes a file incomplete, not its signed
facts invalid.
FsStore refines atomic comparison/creation locally with a stable flock and
atomic link/replace, but does not yet claim power-loss durability because it
omits the required file and parent-directory fsync sequence. S3/R2 adapters
use their acknowledged durable conditional writes; neither copies the POSIX
mechanism.

The authoritative access path requires acknowledged durability and strong
direct-API visibility. Current general-purpose S3 and direct R2 Worker/S3
APIs provide the strong per-key reads and conditional writes this design
uses. Cached custom domains and asynchronous replicas are not conforming
authoritative adapters. LIST is strong but paginated, and several pages are
not one transaction. Piles, invites, and rejection records remain
non-authoritative operations with explicitly idempotent handling. Rejection
evidence nevertheless participates in a destructive safety obligation: exact
pile bytes and a content-addressed typed-reason record are read back before
any worker may retire malformed ingress. The evidence is shared because host
workers share the workspace prefix; node-local status for retryable provider,
publication, root, CAS, and program failures is a separate in-memory view.
A later strong `pile/` listing clears a local attempt row when another worker
has already retired that shared obligation; this changes presentation only
and performs no deletion.

The running cloud deployment is read-only: a host daemon still receives remote
object/pile PUTs and performs publication. The target write path removes that
proxy without giving clients root authority. After authorization, a broker
signs short-lived, exact-key conditional PUT capabilities. A client uploads
objects first and a closed-pile intent last into session-scoped isolated
ingress on both S3 and R2. This is the one selected client protocol.
Provider object-created events, an authenticated poke, and a scheduled fallback
may all wake interchangeable database-free publishers. Wakeups are advisory;
the durable pile is the work item. Publishers verify workspace, uploader,
checksums, and closure; promote every present referenced attachment object;
then update the authenticated trees and CAS root. A missing detached blob does
not block valid facts—the file remains incomplete exactly as it does after
ordinary peer sync. Throttling, crashes, and CAS loss retain the pile. Clients
can neither list/delete the namespace nor write root.

The split follows the authority actually required by each step:

```text
client     exact create-only object and closed-pile upload capabilities
broker     validates upload authority and attenuates it to exact requests
publisher  verifies/promotes ingress, derives pages, CASes root, proves retirement
reader     reads only the pinned root and its authenticated closure
```

The target implementation keeps that authority flow visible in the module
graph:

```text
core/staged_intent     untrusted ingress key + bytes -> typed workspace intent
core/settlement        pure admitted-candidate fixed point
core/snapshot          pure authenticated-tree proposal + immutable outbox
core/store_publisher   async outbox/CAS/F10/retirement interpreter
deploy/*               provider events, configuration, and store construction
```

The client catalog and the database-free publisher use the same executable
settlement and snapshot functions through different query adapters. SQLite may
answer a client query; authenticated FactTree postings and candidate
residences answer the cloud query. Neither adapter owns a second validity or
settlement rule. `Node` is not packaged into Lambda or a Worker, and an
in-memory SQLite reconstruction is not the edge implementation. Missing
root, proof, fact-residence, or tree-page objects suspend the pure computation
through a bounded cache-miss driver, are awaited exactly once, and then rerun
the same function. A missing attachment blob does not suspend fact
settlement. Provider entrypoints contain no family policy, tree construction,
staging grammar, or retirement decision.

Proxying the client upload through the publisher adds bandwidth and failure
surface but no serialization point: the client writes its exact granted
object-store key directly. A staging deployment may require the publisher to
read, verify, and promote that stored value before it becomes canonical; that
is a bounded validation step, not a client-to-function upload path.
Publication itself is different. It combines a validated pile with the current
authenticated snapshot and therefore remains behind the one root CAS
authority. A presigned request is a bearer capability, not workspace
membership; the broker derives its exact key and signed constraints from a
fresh workspace-bound authorization decision, and a publisher repeats all
semantic validation before accepting the resulting pile.

Exact-key attenuation is sufficient only for the untrusted ingress boundary.
The capability binds the staging key containing the declared digest, the
create-only condition, and the byte bound, but a provider need not prove that
the received body has that digest. Before immutable canonical creation, the
publisher streams and hashes the staged body under the same bound. Otherwise
an authorized but malicious uploader could occupy an absent legitimate
`obj/<sha256>` name with different bytes and turn immutability into a permanent
denial of publication. A provider-checked SHA-256 checksum is useful defense in
depth; `Content-MD5` alone is not the canonical content-address proof.

The current Cloudflare primitives make the distinction concrete. R2's
[S3-compatible `PutObject` surface][r2-s3-api] advertises `Content-MD5`, not a
flexible SHA-256 checksum, while the [native Worker binding][r2-worker-api]
accepts a `sha256` put option and a conditional. Thus a raw presigned canonical
R2 PUT is not assumed safe or needed: Cloudflare accepts the exact PUT into
isolated staging, and the publisher verifies it before canonical promotion.

Provider credentials must preserve the same separation. AWS can give a
presigner a PutObject-only resource policy. R2 can attenuate a child
credential to exact object paths and actions, but its parent Object Read and
Write token is bucket-scoped and also reads, lists, and deletes objects. A
Cloudflare broker therefore must not hold such a parent token for the
canonical workspace bucket. Unless a narrower parent primitive is
live-proven, Cloudflare uses a separate ingress bucket: clients upload there
directly, while only the publisher can validate/promote objects into the
canonical bucket and CAS its root. The extra bucket is an authority boundary,
not a second database. It protects canonical integrity, but does not by itself
protect acknowledged staging from a compromised parent; that residual
availability boundary must be either accepted explicitly with client retry
until root publication or removed with a put-only verifier/parent.

The generated Cloudflare isolated-ingress package refines that split into
three provider identities:

```text
broker canonical reader  exact canonical bucket, Object Read only, no writes
broker ingress parent    exact ingress bucket, bucket-item read/write/list
publisher bindings       ingress read/retire + canonical promote/root CAS
```

The broker Worker has no native R2 binding. Its only write-capable secret is
the ingress parent; a distinct read-only S3 credential supplies canonical DAG
reads. Local HS256 temporary-credential signing fixes each child JWT to the
ingress bucket, one `objectPath`, `actions=[PutObject]`, issuer, audience,
issued time, and expiry. The child is not a body-integrity proof. It targets
only
`ingress/v1/workspaces/<workspace>/objects/<session>/<digest>` or
`.../piles/<session>/<member>/<digest>`, whose bytes remain untrusted until
the publisher hashes and validates them. Object class precedes session so a
provider lifecycle prefix can collect loose objects without ever matching a
durable pile marker, and scheduled work discovery can list only piles. The
broker mints and pins the session; it is not a caller-selected path fragment.
Objects arrive first. The closed pile/intention arrives last, commits the
workspace, member, session, and declared object digests, and is the only
durable ready marker; loose staged objects and event notifications are not
publication work by themselves.

Objects-first/pile-last is a client delivery guarantee, not a new fact
validity rule. The publisher verifies and promotes each referenced staged
object that is present, one at a time, but it may settle and root the canonical
facts when a detached Bao object is absent. The authenticated chunk facts then
express the durable missing-object demand and file queries report incomplete,
just as they do on an ordinary replica. Once F10 proves that every admitted
fact from the pile is represented by the committed root, the pile may retire;
an object that lands only afterward is unreachable staging garbage and cannot
manufacture work without a marker. The client can retry that content through a
new session or ordinary peer blob sync.

The logical protocol uses isolated ingress on both providers. “Direct” means
the client sends immutable bytes to S3 or R2 itself; the authorization broker
does not proxy the body, and the later publisher only validates and promotes
the stored value. Provider-specific signing and wakeup mechanics do not create
a second client protocol.

Large sessions stay database-free by fixing their complete authority set
before any PUT is issued:

1. `OPEN` validates one workspace-bound `upload` proof and commits a bounded,
   strictly digest-sorted, unique vector of `(sha256, size)` leaves, its count
   and total bytes, and one pile digest and size. The broker chooses the
   session nonce and fixed expiry and returns an authenticated cursor at index
   zero.
2. `ISSUE` accepts a contiguous range of at most `PAGE_BATCH` leaves plus a
   Merkle range proof against that fixed commitment. It derives exact object
   keys and advances only the committed prefix. Every signer request carries
   the session's fixed `not_after_ms`; provider capabilities must expire no
   later. S3 lifetimes are rounded down to whole seconds and issuance fails
   closed when less than one whole second remains.
3. `FINALIZE` requires the complete committed prefix and derives the sole pile
   key fixed by `OPEN`; it accepts no replacement descriptor or path.

The constant-size cursor binds protocol version, issuer/provider, key id,
workspace, member, session, fixed manifest root/count/bytes, pile digest/size,
next index, issued bytes, last digest, issued time, and fixed expiry under an
HMAC-SHA-256 deployment key. Old keys remain available for at least the
maximum session lifetime plus skew. Merkle leaves and internal nodes are
domain-separated and include the leaf position; the wrapped root also commits
count and total bytes. This provider-neutral state machine now runs in
`deploy/upload_session.py` and `deploy/upload_broker.py`; it has no database or
provider session state. There is not yet a deployed broker route, end-user
uploader, or database-free publisher.

An advancing rolling HMAC without the fixed Merkle vector is insufficient: an
old cursor can be replay-forked into arbitrarily many different suffixes under
one session. With the fixed vector, all forks are confined to the same finite
keys and valid batch partitions converge to the same cursor. Exact batch and
finalization replay deliberately reissue the same authority so a lost response
is recoverable. Rejecting such replay while remaining stateless is impossible;
provider state is introduced only if the product later requires exactly-once
quota charging or recovery after a client loses its cursor. Authorization
order does not prove network completion and does not need to: missing detached
blob bytes affect file completeness, while the pile remains sufficient to
publish its independently authenticated facts.

R2 long-lived bucket-item credentials cannot be restricted to a workspace
prefix. `Object Read only` also includes LIST. Consequently the generated
read policy is tenant-safe only when the canonical bucket is dedicated to the
one configured workspace. A string `CANONICAL_PREFIX` narrows application
lookups but is not provider enforcement. A shared canonical bucket requires a
different provider-enforced read path before a broker compromise can be
claimed workspace-confined.

The package also emits one lifecycle input scoped only to that workspace's
`objects/` staging prefix; the disjoint `piles/` prefix is excluded because
provider lifecycle is not an F10 witness. Compute deploy/remove never owns
either bucket or applies or removes bucket configuration: it deploys publisher
before broker, stops broker before publisher, and deletes only Workers whose
exact owner and role markers were observed before the first delete. Applying
and live-verifying the lifecycle remains a separate privileged provisioning
step because replacing a bucket's whole lifecycle document from a compute
deploy could clobber unrelated rules. The current entries are non-public
fail-closed stubs. These generated documents and credential-free JWT mutation
tests establish the intended authority shape, not a live-provider or
completed-publisher claim.

[r2-s3-api]: https://developers.cloudflare.com/r2/api/s3/api/
[r2-worker-api]: https://developers.cloudflare.com/r2/api/workers/workers-api-reference/

The production profile also treats each provider's documented RFC 9110 strong
ETag behavior as a refinement axiom: an ETag accepted as a root CAS token must
change when the root bytes change. Adapters reject missing, empty, and `W/`
weak validators, and the conformance harness records every observed
token-to-bytes pairing so a fake that aliases one token across distinct bytes
fails deterministically. This is the same kind of provider assumption as
acknowledged durability; a live test can exercise it but cannot prove it for
all values. Deliberately constructing a collision in a provider's underlying
ETag algorithm is outside this profile. That stronger threat model would need
an independent conditional generation register, such as DynamoDB on AWS or a
Durable Object on Cloudflare, because a content hash or R2's non-conditional
`version` field is not itself a CAS capability.

The Cloudflare authorization deployment is a Python Worker at compatibility
date `2026-07-29`, selecting Python 3.13 and the Pyodide 0.28.3 dependency
index through `workers-py` 1.16.0. This choice was made only after a clean
pywrangler artifact and local workerd loaded the real `core`, `facts`, R2
adapter, and shared gateway, then completed Ed25519 sign/verify and a
sealed-box round trip. A generated build stage copies the selected canonical
source files on every build; there is no checked-in security-core fork.
Its import-graph ratchet excludes `fcntl`, `sqlite3`, `threading`, and
`multiprocessing`, plus the host-only S3 compatibility adapters.

Pyodide's PyNaCl 1.5.0 wheel contains libsodium browser-randomness `EM_ASM`
exports. Workerd deliberately rejects their eager dynamic registration.
The deployment build checks the pinned wheel layout, disables only those
exports and PyNaCl's eager RNG initialization, and obtains ephemeral
sealed-box seeds from request-context `os.urandom`. Ed25519 and the
deterministic Curve25519/XSalsa20-Poly1305 box operations remain PyNaCl
primitives, and interoperability tests compare both directions with native
PyNaCl's sealed-box wire format. The first request runs the cryptographic
self-test because Workers intentionally deny entropy during top-level
snapshot construction.

The Worker receives one direct `BUCKET` R2 binding, one exact `WORKSPACE`,
one exact `STORE_PREFIX`, and one required encrypted `GRANT_SECRET`. Production
config generation requires an explicit route and leaves workers.dev disabled.
The host-side deployment tool also puts a stable, non-secret ownership marker
in the Worker bindings. It reads that marker through Cloudflare's direct
settings API before every update or delete and verifies it after deployment;
absence permits creation only with an explicit create flag. Smoke deployments
use a random name whose absence was established before upload, then treat the
upload as possibly applied until that exact name has been deleted.
Cloudflare exposes no conditional script mutation coupled to that settings
read, so this protects against accidental targets under one trusted,
externally serialized deployment administrator; it does not claim safety
against a concurrent administrator replacing a script in the preflight gap.
All Wrangler mutation subprocesses have finite deadlines.
The application caps request bodies at 512 KiB while streaming, root at
64 KiB, individual objects at 4 MiB, object batches at 48 items/4 MiB, and
mint authorization at 48 unique fetches/384 KiB. It rejects raw queries above
4 KiB or eight fields before percent decoding or gateway/R2 work. It exposes
only health,
mint, invite, root, and authenticated object reads; the R2 capability passed
to the gateway has only `get` and `has`. The opt-in live smoke command uses a
unique workers.dev deployment, never mutates R2, and removes the Worker even
when authorization fails.

Each workspace SQLite database contains one stable local fact catalog plus
family-neutral derived indexes:

```text
facts(fid, blob)                 one canonical encoded body
fact_index(kind, k0, k1, src)   key + type + explicit refs + declared offers
proofs / edges                   current eligibility and resolved authority
actions / supp                   suppression frontier and selector reverse map
```

There is no application projection database and no family-owned durable
table. A kernel-valid durable receipt is stored once; losing canonical
standing removes its proof row, not its bytes or index rows. Every fact gets a
`fact.key` reconciliation row, a `fact.type` row, one `fact.ref` row for each
explicit `(role, target fid)` reference, and one row for each declared offer.
Family queries intersect those generic addresses before loading canonical
blobs, then apply suppression and assemble their view. For example, a file
read selects only `chunk --file→ descriptor` rows and verifies those immutable
Bao objects after releasing the catalog lock. The reference rows are local
query routes, not dependency offers or additional authority. Deleting the
workspace catalog can still lose node-local, currently ineligible receipts
that were deliberately never published.

### Fact versions and derived replay

POC-16 does not yet accept multiple fact versions. When it does, the canonical
blob catalog remains an immutable record of the originally admitted bytes, but
derived tables must never replay that historical shape directly. Replay first
decodes and hydrates each blob through the current version adapter, in the
same context and into the same current form exposed when that fact is supplied
as context to another fact. Type, dependency-key, and explicit-reference
index rows, eligibility, and query views are then derived from that hydrated
form. Hydration must preserve the immutable workspace binding: an ordinary
fact's current contextual form still names the `ws` committed by its original
bytes, while genesis remains the sole ws-less form whose fid is the anchor.

Thus a version/schema change is an explicit derived-index version change:
discard the old derived rows and replay the retained canonical blobs through
the new hydrator. The original bytes and fid do not change, while every
consumer sees one current contextual form. A future adapter must be
deterministic and must not consult replica-local arrival order or wall-clock
state.

The root uses layout stamp
`composite-btreap-v7-generic-candidate-index` and atomically binds:

```text
anchor          workspace genesis fid
manifest        range-sync manifest root
layout_seed     deterministic authenticated-tree seed
trees           FactTree, SuppTree, AuthorityTree descriptors
action_etag     non-authoritative cache key for active-action sync
stamp           exact format identity
```

One compare-and-swap publishes the range manifest and all three authenticated
trees. There is no second mutable removal root and therefore no two-root
transaction. `action_etag` only avoids enumerating SuppTree when ordinary facts
change but actions do not; Workers never trust it, and action evidence remains
authoritative only through the authenticated trees.

Catalog settlement returns a publication plan pinned to the exact root bytes
and opaque provider token returned by one read. Object and tree compilation
never rereads `root` to adopt a newer base. A successful publisher stores
`h(root bytes)`, not the provider token, as its local derived-index stamp. If
another writer advances root after that stamp, the stamp is honestly stale
and the next index synchronization rebuilds. It can never falsely label old
local state as the later writer's root.

Receipts staged before a failed or lost CAS remain in the catalog but are not
eligible merely because a read triggers repair. Rebuild first restores the
published root plus already committed local receipts and keeps staged intent
behind that snapshot. The next explicit workspace turn retries the staged
set—even if another worker already retired its original ingress key. On a
successful CAS, only then are its staged markers cleared. A rebuild whose
compiled bytes equal its pinned root performs a token-checked no-op before
stamping it; a rootless no-op similarly rechecks that `root` is still absent.

The range manifest partitions canonical fact keys with the stable boundary
rule. A leaf is a closed pile; a closure sibling lists transitive dependencies
whose home is outside that exact leaf. **RangeTree** is a logical map from each
opaque ordered range separator to its leaf and closure oids. It uses the same
persistent Merkle-treap primitive as every other authenticated tree; it is not
a second tree implementation. An ordinary commit passes the exact added,
removed, and edge/closure-refreshed keys derived by settlement. Each key needs
one bounded authenticated predecessor/successor search and one verified old
leaf pile. Addition splits at a content-derived boundary; ordinary removal
rewrites one home leaf; removing the fact that formed a boundary joins only
that leaf and its immediate successor. Refresh keeps the same members and
re-encodes their fact/closure bytes. Overlapping windows merge before one
path-copy batch, while unrelated windows remain independent.

This works for activation, deactivation, restoration, and canonical-authority
rewiring. The ordinary publisher neither enumerates RangeTree nor consults a
SQLite range directory, calls `Node.keys`, or runs an unconditional
corpus-wide ordered fact-key query. Only repair and format cutover retain the
full SQLite-backed reference build. Equal subtrees have equal object ids, so
sync descends only remote paths whose oids are not present in the local
RangeTree. The three Worker indexes are separate: once settlement has derived
the same exact transition sets, their logical rows path-copy those deltas.
Incremental and full compilation produce byte-identical roots.

RangeTree is an authenticated wire map for synchronization and store recovery,
not a fourth authorization index. A read-only database-free Worker does not
need it and never scans timestamp/fid keys: `WorkerView` exact-reads only
FactTree, SuppTree, and AuthorityTree. The bounded RangeTree neighbor
operation itself is store-only, and an edge responder may serve RangeTree
objects by oid without interpreting them. That does not make the current
publisher database-free: canonical eligibility, action state, and all four
tree inputs are compiled from the client catalog. A future edge publisher
must reconstruct an equivalent admitted-candidate and durable-intent view
from authenticated objects before it can reuse this placement operation; it
may not treat RangeTree alone as publication authority. FactTree now bounds
discovery for current rooted/eligible candidates, but it does not authenticate
every receipt retained only in a client's SQLite catalog. Today a losing or
inactive receipt can outlive its retired ingress pile only on that client.
Cold database-free publication therefore remains incomplete until dormant,
restorable candidate bytes have a durable root-or-intent retention law.
FactTree cannot substitute for this map without also gaining ordered raw-fact
residency and pile/closure routing; object-store LIST cannot substitute
because object names are content hashes and include unreachable history.

### Dormant-candidate retention target

The target law is stronger than “keep the bytes.” The committed root
authenticates a monotone set of **kernel-admitted** durable candidates, and
eligibility is a reversible derived subset of that set. Every candidate has
exactly one raw residence in the current snapshot:

- an eligible candidate occurs once in a RangeTree leaf;
- a dormant candidate occurs once at `obj/H(encode(fact))`.

Old immutable objects may remain as unreachable history. SQLite, provider
events, and object-store LIST are never admission evidence or candidate
authority.

A dormant blob pointer proves only that some bytes exist. It does not prove
that those bytes passed the family-neutral kernel. Durable admission must
therefore consume the kernel's `Valid` receipt rather than a raw `Fact`.
Scratch loading and tests may not share an unchecked route that can populate
the durable candidate catalog.

Each candidate record also names a content-addressed, raw-free admission-proof
DAG node. A node binds the workspace and fid to the exact resolved dependency
edges from one kernel judgment; every edge pins the corresponding parent proof
oid from that same judgment. This path-shares old closure, prevents unrelated
parent witnesses from being spliced into a proof, and avoids retaining another
copy of a closed pile. A cold verifier follows the pinned proof DAG, obtains
each fact from its one current residence, and reruns the actual kernel. An
abstract proof mirror is not sufficient.

FactTree will cover both eligible and dormant candidates. Its generic postings
remain a mechanical projection of every candidate, while application reads
filter for current eligibility. Dormant rows have an explicit dormant state
and fid ordering; they never carry a sentinel or stale value that could be
mistaken for a current proof rank. Full repair may page the authenticated
`fact:` prefix, but ordinary store-only publication follows only the bounded
type/key/ref/offer/scope/dependency postings affected by its intent.

Publication writes a dormant blob before a CAS that deactivates an eligible
candidate, and writes the new RangeTree leaf before a CAS that restores one.
The single composite-root CAS atomically binds residence, admission proof,
candidate postings, current eligibility, suppression, and authority. Ingress
retirement is allowed only when that root represents every durable `Valid`
receipt in the exact pile, whether eligible or dormant. Candidate deletion is
out of scope until a separate proof can establish that a candidate can never
regain standing.

## The three authenticated trees

Wire RangeTree and the three Worker indexes share one persistent Merkle-treap
codec, but only the latter are Worker-readable. The priority of a row is
`H(seed, key)`, which gives a unique Cartesian tree independent of insertion
history. Each immutable page stores one row and its child object ids. An
update path-copies only search and rotation paths. A Worker read is bounded by
the published depth and the hard depth cap; it never enumerates a tree.

The schemas are:

- **FactTree** — `fact:<fid>` maps to one bounded record containing the
  reconciliation key, proof rank, resolved dependency edges, offers,
  selectors, continuing liveness scopes, and optional action evidence.
  Collision-free `index:...` rows are ordered by
  `(kind, k0, k1, rank, fid)`. The immutable contribution mechanically mirrors
  client `fact_index`: type, reconciliation key, every explicit role/target
  reference, and every declared offer. Two family-neutral derived kinds add
  `suppression scope -> fid` and `resolved dependency target -> fid`, so a
  changed suppression id or authority winner can discover its reverse impact
  without a corpus scan. There is one row per posting; no B-tree page contains
  an unbounded candidate list. A paged half-open range fetches at most two
  boundary paths, the returned rows, and one continuation lookahead, with a
  hard 256-row page ceiling.
  `action:<sid>` mirrors a known direct/principal action slot so sync can
  corroborate a SuppTree witness through an independently addressed record.
  Raw facts remain in manifest piles and are not emitted again as one object
  per record.
- **SuppTree** — a suppression id maps directly to CLEAR or to ACTIVE with its
  effective action fid. CLEAR is a positive authenticated statement that this
  known, reserved id has no effective action in this snapshot; it is not the
  same as a missing row. ACTIVE names the action whose evidence is named by
  its FactRecord. Missing required rows fail closed.
- **AuthorityTree** — a canonical `NeedKey` maps to the selected provider and
  rank. A missing address is not inferred from submitted facts; family
  authorization decides whether bootstrap absence is allowed. This cache is
  deliberate: an exact winner read costs one tree path, while deriving it from
  the generic index costs the boundary paths plus every conflicting candidate.
  It stays until measurements show that ordinary reads do not benefit.

This answers distinct bounded questions rather than keeping two mutable
suppression roots. SuppTree answers “is this explicit id active?”; FactTree
answers “what does this exact fact require and offer?”, “which current facts
have this type/key/ref/offer/scope or dependency?”, and corroborates the action
witness; AuthorityTree answers “which committed fact provides this need?” The
immutable action fid and evidence are reachable from the ACTIVE slots and
FactRecord.

Catalog settlement compares both proof ranks and resolved edges before and
after a rebuild, then transitively closes that delta over reverse dependencies.
The closure is required even when a descendant's direct edge and rank do not
change: its declared authority-liveness guards can inherit different scopes
through a rewired ancestor. FactRecord and `fact.scope` postings are updated
for that entire affected closure, while unrelated rows remain shared by oid.

Local SQLite retains `action_proposals` and their targets alongside the stable
catalog. It derives `actions(sid, fid, evidence)` as the current effective
frontier and `supp(fid, sid)` as the selector reverse map. Only the proposals
are retained input; the latter two tables are rebuildable indexes. None is a
second published authority index, and the database-free Worker never reads
them.

An action, its `action:<sid>` slot, its `sid` suppression slot, the fact and
authority updates, and the range manifest all become visible under the same
root CAS.

## Shared-bucket concurrency contract

Concurrent store users are modeled as three pieces:

```text
O : oid → bytes       grow-only, content-addressed immutable objects
R : root bytes        one linearizable compare-and-swap register
T : opaque tokens     sound comparison capabilities for values of R
H : root versions     the sequence of successful CAS values
```

A publisher pins one exact `(base root, base token)`, derives a deterministic
candidate from that snapshot plus its durable intent, makes every object
reachable from the candidate visible with atomic put-if-absent, and only then
attempts `CAS(R, base token, candidate)`. The CAS is the sole linearization
point. A loser retains its intent, rereads the winning root, derives the union,
and retries. Objects written by a crash or losing attempt are harmless
unreachable history; they are never overwritten or deleted.

Tokens obey one law: within one `(store, key)`, the same token never denotes
different bytes. The converse is unnecessary. An `X → Y → X` value-ABA may
reuse X's token and is safe here because root bytes completely define the
published state and every referenced object is immutable. This must be
revisited if later generations gain deletion, GC, or history-dependent side
effects. The direct S3/R2 implementation refines this law under the strong-ETag
provider axiom above; the abstract model itself does not assume any ETag
algorithm.

A lost mutation response is not a stale precondition. Publication rereads:
candidate bytes mean the CAS succeeded; the exact unchanged base permits one
safe retry; any other value means rebase while retaining staged intent. If
reconciliation itself fails, no receipt or ingress key is retired.

A reader pins root bytes once. A later root is allowed to make that decision
stale, but every manifest, tree page, fact record, suppression slot, authority
slot, and action witness used by the decision must remain explainable by the
one pinned root. Re-reading `root` for individual components is incoherent,
even when each component is independently valid.

Published-state semantics do not depend on a private database, but the
running writer implementation does: its SQLite catalog is both a derived
eligibility index and the durable home of local staged intent. The checked-in
Lambda and Cloudflare deployments are therefore readers, not publishers.
Their authorization path has no database at all and needs only pinned root
bytes, immutable object fetches, the submitted bounded closure, and trusted
service time. Moving publication to an edge is a separate construction, not
an alternate configuration of the current Worker.

The safety laws are:

1. every object key equals the hash of its bytes;
2. the object map only grows and an existing key never changes;
3. root changes only through one successful whole-value CAS;
4. every successful root names a complete, hash-valid closure already in `O`;
5. every successful read decodes under exactly one root from `H`; and
6. every fair retry sequence converges to the deterministic union of the
   surviving publishers' intents.

`tests/shared_bucket_model.py` is the executable small-state definition.
Its breadth-first explorer covers two writers and one reader and returns the
shortest schedule for a violated law. Mutation tests prove the laws reject
root-before-objects publication, split composite roots, and a reader that
repins halfway through a decision. Concrete Store, Publisher, Worker, and
authenticated-tree schedules refine this model in
`tests/test_shared_bucket_node.py`: every successful root is fully walked,
competing suppression winners are observed under whole roots, a stale mint is
run with SQLite disabled, and the terminal concurrent result must equal a
serial canonical rebuild.

## Explicit suppression

Suppression is offered by the target fact, not guessed from arbitrary
dependencies. A registered family declares either no suppression policy or an
exact list composed from:

```text
SELF
PARENT(named_role, parent_fid)
ANCESTOR(named/path, ancestor_fid)
```

`SELF` is serialized as a non-circular marker and expands to the fact’s fid
after hash integrity succeeds. All selectors resolve into one typed namespace:

```text
SELF(f)                 -> fact:<fid(f)>
PARENT(_, p)            -> fact:<p>
ANCESTOR(_, a)          -> fact:<a>
member principal        -> member:<public-key>
device principal        -> device:<public-key>
```

A fact may offer several selectors. A family with no policy offers none and
cannot be a direct suppression target. This is separate from authorization:
an untargetable action fact can still require live admin authority.

Current content policies are explicit:

- messages and file descriptors offer `SELF`;
- Bao files additionally carry their member parent;
- chunks offer `SELF`, their file parent, and their file/member ancestor;
- deleting a file descriptor therefore suppresses its chunks without the
  deleter enumerating descendants;
- deletion and eviction facts offer no selector and cannot themselves be
  deleted.

The selector count is capped and checked both when authored and independently
at admission.

## Deletion, eviction, and authority

An exact content deletion contains an exact target key, a hard target ref, and
the `SELF` selector token. The target family’s `DIRECT_TARGETS` entry must allow
that action and mode. Supplying a bare suppression id is not a capability.

The ordinary fact graph authorizes the action:

- `OWNER` requires an author signature and a member provider whose durable
  principal equals the target’s owner principal;
- all devices belonging to one user resolve to that user principal, so sibling
  devices can remove the user’s content;
- `ADMIN` requires an author signature and a live admin provider and can remove
  every directly deletable family;
- an unrelated ordinary member satisfies neither path.

These checks live in the content-delete handler and family-owned policies
compiled by the checked registry. The core does not special-case message or
file ownership.

Member eviction is an admin-authored fact offering `removed(target_pk)`. It
activates `member:<target_pk>`, a terminal key-wide tombstone that covers
existing and future membership providers. A Worker checks that exact key when
minting a grant, so it does not load the fact set or rebuild a database.

Authorization has two intentionally distinct concepts:

- an `authorization_guard` must be live when admitting a new irreversible
  effect;
- an `authority_liveness_guard` continues to mask an already-published
  authority provider.

A delegated admin grant uses the grantor admin as a one-time admission guard
and the grantee membership as its continuing liveness guard. Evicting the
grantee disables the grant. Liveness follows only the family-declared guard
edges, transitively and under a hard bound, so an admin grant to a child device
also inherits that device set's user liveness. Later loss of the grantor does
not retroactively undo a grant that was validly committed.

## Action timing

Validated action proposal bytes are retained monotonically in the local
catalog; effective action state is derived and is not assumed monotone across
root versions. For example, a later-arriving, shallower ownership claim can
make a previously plausible OWNER deletion ineligible. The next root then
publishes CLEAR for that id and restores the victim to the active client view.
Workers enforce each current snapshot strictly: an ACTIVE principal or
selector always refuses the request.

Replica admission must also converge when an old fact and an action arrive in
opposite orders. Settlement therefore computes one deterministic fixed point:

1. resolve and validate canonical local edges for every candidate;
2. fold currently eligible action proposals in canonical `(fact key, fid,
   evidence)` order;
3. accept a proposal only if an earlier active target does not intersect its
   transitive, family-declared authorization scopes;
4. let each accepted proposal activate all of its explicit target ids; and
5. rebuild eligibility under that frontier until neither proofs nor actions
   change, failing closed on a cycle.

The earliest effective proposal wins a duplicate id. An action blocks an
ordinary candidate whose canonical fact key is later; an earlier candidate
remains admissible history. Retaining inactive receipts locally makes
fact-first, action-first, and later canonical-winner changes converge without
a descendant lookup or sender-selected edge.

This ordering is deterministic, but timestamps are author-controlled. That is
intentional: removal is a knowledge and connectivity boundary, not a global
authorship-time cutoff. A peer whose pinned snapshot still authorizes a member
may accept that member’s fact, and the accepted fact is legitimate workspace
history even if another peer already knows the member is removed. Once a peer
learns the removal, grant expiry and exact Worker checks stop that member from
directly opening a new authorized sharing channel to that peer. There is no
serialized admission frontier and no attempt to distinguish signing time from
first delivery.

Inactive receipts are likewise local durable intent, not a second replicated
fact set. They are absent from the eligible manifest and need not be copied to
every fresh replica. If a retaining node later finds one eligible, ordinary
publication can share it then; if every holder disappears first, losing that
inactive candidate is acceptable. Convergence applies to facts replicas have
actually exchanged, not to hypothetical equality of their latent candidates.

## Worker authorization

`WorkerView` opens the composite root and performs exact authenticated reads:

1. decode and kernel-validate the submitted closure (maximum 64 facts);
2. dispatch exactly one ephemeral family authorization hook, which checks its
   allowed verb and service-time deadline;
3. check committed authority winners and family-required co-offers;
4. read only the request/provider FactRecords and their declared liveness
   scopes;
5. read the corresponding SuppTree slots; and
6. return `(public_key, verb)` for sealing by the daemon.

`core/mint.py` contains only this path. The edge path is `root bytes + immutable
object fetches + submitted closure`: no SQLite, client catalog, client query
state, or full-tree fallback. A cached view is reusable only while its
SHA-256 root content tag matches; provider CAS tokens never enter this path.

The daemon seals a short-lived bearer grant to the requester’s public key.
The grant TTL is a deliberate revocation leakage window. After expiry, an
evicted member cannot mint another remote grant from a peer that knows the
removal. The trusted local `ctl/*` surface is not an authentication boundary:
an evicted replica that missed its own action may continue writing isolated
local state. It need not receive a special terminal tombstone. A still-stale
peer may legitimately accept that state; an informed peer refuses a new grant
and therefore eventually closes the sharing boundary.

## Sync and recovery

A dial reads the remote root conditionally. A 304 against an unchanged local
root is O(1) after blob completeness has been stamped for that HTTP content
tag.

When roots differ, sync reconciles admitted actions first. Each ACTIVE slot and
its evidence closure are hash-checked and kernel-validated independently; one
missing or poisoned witness is skipped without blocking honest actions. The
RangeTree is then compared by oid: shared pages are read from the authenticated
local tree, while only novel remote paths and their changed piles are fetched.
Local-only facts are pushed as one closed pile, remote ranges are assembled,
and missing live blobs are fetched. A full-profile sender first delivers each
locally available referenced blob as an idempotent, hash-verified immutable
object, then delivers the fact-only pile. That order matters in a directed
peer graph: an object-transfer failure cannot leave the receiver with a fact
difference that only the one-way sender could satisfy. A replica that does
not yet have a blob may still relay the fact so another source can complete
it. Push happens before draining the pull so canonical pruning cannot remove
a precomputed difference before delivery.

Only typed, input-local pile-codec and immutable-kernel rejections are
quarantined. Exact bytes plus content-addressed reason records become durable
before retirement. Provider, publication, root, CAS, and unexpected program
failures retain the exact live pile without a retry-count shortcut; they are
visible as node-local attempt failures, and an authoritative restore isolates
their staged candidates before the turn continues with another independent
pile. Sync failures are likewise visible through `status`. Malformed roots,
pages, facts, selectors, action evidence, or authority rows fail closed. A
root format mismatch may be republished from the current derived index only
when its known snapshot fields equal the exact root bytes that index recorded;
a different or unreadable snapshot is never clobbered. There is no ongoing
dual decoder.

Rebuild replays authenticated resident facts together with the stable local
catalog and reconstructs eligibility, action state, and selector reverse maps.
Queries need no replay phase or cursor: once the workspace index is stamped
for the pinned root, they select and decode the same canonical catalog rows
used by settlement. Blob-bearing queries verify currently resident object
bytes on demand.

## Performance

`bench/bench_latency.py` measures the running paths. On the development host on
2026-07-29, five hot posts at each scale produced:

| Seed facts | Post p50 | Post p95 | object touches/post | immutable KiB/post |
|---:|---:|---:|---:|---:|
| 1,000 | 15.41 ms | 16.34 ms | 84.9 | 48.0 |
| 5,000 | 27.98 ms | 31.10 ms | 114.1 | 67.0 |
| 10,000 | 19.40 ms | 27.24 ms | 127.1 | 55.4 |

Every measured post performed zero `Node.keys` calls. Authenticated-tree and
RangeTree touches grow with their paths (85–127 here), not with the
1,000–10,000-fact corpus. A primed same-root idle dial measured 0.008–0.013 ms
p50/p95 locally and performed no fact, tree, object, or blob-demand scan.
These numbers are diagnostic, not cross-machine service guarantees.

## Limits and future decisions

- Ordinary bodies are plaintext. End-to-end body encryption needs a separate
  design and implementation.
- Logical deletion stops query visibility, authorization, and future blob
  demand; it does not erase immutable objects already stored. Physical GC is
  unbuilt.
- A local filesystem workspace still has its own store directory. Provider
  adapters isolate workspaces under validated bucket prefixes, while each
  read-only Lambda or Worker deployment is intentionally bound to one exact
  workspace and prefix. Publishing remains a separate host operation. A
  bucket-wide S3 guard can freeze lifecycle mutation plus authoritative-key
  deletion, ACL mutation, tag mutation, direct annotation mutation, and
  ETag-preserving encryption-key mutation while attached. Pre-existing
  lifecycle rules and metadata, replication principals, KMS administrators,
  and administrators able to replace that policy remain trusted at the
  provider substrate.
- That provider boundary is distinct from application-level infrastructure
  authority. The intended control plane is a two-community link. A separate
  operations workspace admits infrastructure principals; a target workspace
  invites one of those principals for an exact service scope; and the node
  accepts and publishes its deployment binding. The binding remains active
  only while both DAGs support it, and either the workspace or the
  infrastructure node may end it through ordinary facts. This role does not
  imply content membership. An idempotent external reconciler must turn that
  desired state into IAM/R2 credentials, grant-secret rotation, deployment
  creation, and teardown. Until revocation has been observed at that external
  plane, an in-band leave fact alone cannot make a former provider credential
  harmless. Bucket garbage collection and a writable serverless publisher
  remain future work.
