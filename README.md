# tiny p2p, POC-16

POC-16 is a fact-DAG repository with one storage format and one receiving
algorithm across a full peer, AWS Lambda, and a Cloudflare Worker. A hosted
recipient needs an object store but no database. SQLite exists only as a
disposable full-client query and authorship accelerator.

The implementation is deliberately strict about authority and direction:

- `RepositoryApplier` is the only fact-pile-to-root capability. It is
  database-free and owns closed-pile validation, immutable establishment, and
  the root CAS. It never deletes ingress.
- `RepositoryReader` is a pinned, database-free, side-effect-free read
  capability.
- `HttpGate` is the one peer route and authorization capability over those
  database-free repository capabilities.
- `PileSender` is the only close/encode/delivery capability. It may use the
  full peer's disposable SQL projection and local identities.
- `FullPeer` composes all of the above for a stateful local peer; its receiving
  side still invokes `RepositoryApplier`.

A hosted peer needs `RepositoryApplier`, `RepositoryReader`, and `HttpGate`.
A full peer adds `PileSender`, local identity, scheduling, control, attachment
I/O, and disposable SQL. There is no second receiving path. A provider may
place its read/signing broker and Applier in separate least-privilege
processes or stacks without creating another repository state machine.

## Read the code in this order

1. `core/fact.py`, then `facts/`: wire facts and family-owned policy.
2. `core/kernel.py`: the bounded, database-free closed-pile judgment.
3. `core/repository_snapshot.py`: the pure validated-fact-set compiler.
4. `core/repository_applier.py`: storage effects and the sole root CAS.
5. `core/repository_reader.py`, `core/worker.py`: pinned authenticated reads.
6. `core/http.py`, `core/http_stdlib.py`: the shared peer gate, then its
   standard-library HTTP server/byte adapter.
7. `full_peer/pile_sender.py`: stateful-client authorship and closure.
8. `full_peer/node.py`: `FullPeer`, the composition root, not a policy owner.
9. `full_peer/upload_journal.py`, `full_peer/upload_client.py`,
   `full_peer/upload_client_http.py`: durable outbound state, the resumable
   state machine, then its narrow HTTP effects.
10. `full_peer/sql_store.py`: the sole SQL boundary.
11. `full_peer/daemon.py`, `full_peer/iroh_process.py`, `full_peer/iroh/`:
    process composition, child lifecycle, then the connection-only Iroh byte
    wrapper.
12. `deploy/` and `adapters/`: shared upload wire/session values, provider
    adaptation, and packaging—never full-peer-local client state.

[DESIGN.md](DESIGN.md) gives the data model, invariants, and failure
semantics. [AGENTS.md](AGENTS.md) contains repository ratchets.

## Local use

Run the authoritative repository preflight:

```sh
python3 tools/preflight.py
```

It checks Python syntax, the structural authority ratchets, the full test
suite, patch whitespace, uncommitted beads-export pollution, and beads ledger
integrity. The external `bd preflight --check` in beads v1.1.0 is
Go-repository-specific and is not this project's gate.

To run only the tests:

```sh
python3 -m pytest -q
```

Build the optional native Bao verifier used by attachment I/O:

```sh
python3 -m pip install ./native/bao_py
```

Start a local node:

```sh
python3 -m full_peer daemon ./state --port 7100
```

List family-owned commands:

```sh
python3 -m full_peer --commands
```

The CLI passes a command path and raw arguments through one generic binder.
Fact-family modules declare their own commands; `full_peer/cli.py` does not
grow a branch for every new family.

For example:

```sh
python3 -m full_peer auth.workspace.create ./alice
python3 -m full_peer content.message.post WORKSPACE_PREFIX general hello
python3 -m full_peer content.message.list WORKSPACE_PREFIX
```

Use `--node URL` to target a non-default local daemon.

At startup the daemon reads `TINYP2P_GRANT_TTL`,
`TINYP2P_MINT_MAX_FETCHES`, and `TINYP2P_MINT_MAX_FETCH_BYTES` once into one
validated immutable `HttpGateOptions` value. The stdlib adapter passes those
limits to the same `HttpGate` for every request; the full peer does not
implement grant or mint policy.

### Iroh connection mode

Iroh is only an encrypted connection and reachability layer. The Rust code
does not parse HTTP, grants, workspaces, object keys, or facts and never opens
the bucket. It forwards one byte stream to the loopback
`core/http_stdlib.py` listener. That listener still invokes the one
`HttpGate`, whose bearer grant checks and normal GET/PUT/mint operations reach
the same object-store and `RepositoryApplier` interfaces as plain HTTP.
Endpoint IDs, tickets, ALPN, and connection success confer no repository
authority.

Build the small wrapper:

```sh
cargo build --release --locked \
  --manifest-path full_peer/iroh/Cargo.toml
```

Run one supervised full peer:

```sh
python3 -m full_peer daemon ./state --port 0 --iroh \
  --iroh-binary ./full_peer/iroh/target/release/poc16-iroh
```

The command starts the peer-data gate on loopback, starts local control on a
different loopback listener, starts and monitors Iroh, persists the endpoint
key at `./state/iroh/endpoint.key`, and prints `IROH ... peer=TICKET`. If the
accepting Iroh child or data listener dies, the whole service fails shut.
SIGINT and SIGTERM stop and reap every child. Add `--iroh-loopback` only for
a single-machine test; normal mode enables Iroh's production reachability
preset.

An invite created by this daemon carries a bounded out-of-band peer record:

```json
{"kind":"iroh","endpoint":"ENDPOINT_ID","ticket":"TICKET"}
```

It never carries the private peer-data URL. The joiner stores that record in
its full-peer keyring, registers a supervised outbound forwarder, and gives
only the resulting `http://127.0.0.1:...` URL to the existing sync HTTP
client. On restart it registers durable peers before scheduling and recreates
each disposable forwarder on its next bounded scheduler or sync turn. Iroh
mode rejects legacy plain-HTTP peer records, so an Iroh-enabled daemon cannot
silently dial around the wrapper.

Tickets are reachability data and can change while the endpoint ID remains
stable. Refresh or remove a configured peer through local control:

```sh
python3 -m full_peer peer.iroh.set WORKSPACE ENDPOINT_ID NEW_TICKET
python3 -m full_peer peer.iroh.remove WORKSPACE ENDPOINT_ID
```

Refresh stops and reaps the superseded child before using the new ticket.
Removal deletes the durable record and reaps its child. An unexpected
outbound-child exit closes that private dial, appears under
`peer.status` → `iroh_connections`, and is recreated with bounded backoff;
it does not stop unrelated peers or bypass a failed request. Configuration is
bounded to 64 peers per workspace, 128 Iroh peers per full peer, one 64-hex
endpoint ID, and the Rust wrapper's 4 KiB decoded ticket ceiling.
The wrapper admits at most its configured connection count; it immediately
refuses overflow Iroh attempts before they can open a stream or loopback
upstream. One setup deadline covers handshake, first stream, and upstream
connect together, and one session deadline bounds the complete byte copy.
Each admitted connection allows only its one protocol bidirectional stream;
extra bidirectional and all unidirectional streams remain flow-control blocked,
and application datagrams are disabled.
Only one due background connection start is attempted per monitor turn, and
an outbound child that never reports readiness is terminated and reaped
inside the daemon's shutdown budget.
The wrapper checks that a ticket names its configured endpoint, but endpoint
IDs still select local reachability only and never enter a grant.

The standalone commands remain useful for diagnosis. This creates a local
HTTP seam whose bytes traverse Iroh to the accepting peer:

```sh
./full_peer/iroh/target/release/poc16-iroh forward --peer=TICKET
```

`--url` remains rejected in Iroh mode. Plain-HTTP mode remains available for
local deployments and compatibility, but one daemon configuration cannot mix
plain remote URLs with Iroh peer records.

## Repository flow

An authored unit follows one path:

```text
facts command
    -> PileSender closes dependencies and encodes one fact-only {ws,facts} pile
    -> RepositoryApplier reads one exact create-only source key
    -> kernel judges the exact closed pile
    -> pure compiler path-copies FactTree, SuppTree, and FactOrder
    -> immutable objects are conditionally established
    -> one CAS advances root
    -> applied, noop, rejected, or retryable result
    -> RepositoryReader pins the resulting root
```

The exact key and digest identify one delivery attempt; they do not grant
admission. Root-CAS losers retry from the newer root, and a lost CAS response
is reconciled by reading the root. Repeating an already-applied pile returns
an idempotent result. The source remains immutable staging for provider
retention, so concurrent workers have no destructive ingress action to race.
One bad pile cannot wedge a later exact request.

## Facts, suppression, and deletion

Each fact family declares its own:

- shape and validation;
- named needs, refs, and offers;
- durability;
- explicit suppression selectors;
- ownership and direct-action policy;
- continuing authority liveness.

A pile must contain enough facts to validate as a closed unit. Stored state
does not retain that incidental validation path:

```text
wire:    one closed pile of facts and dependencies
stored:  fid -> canonical fact bytes, plus mechanical indexes
```

Validation is monotone: once a fact validates against a validated set, adding
more validated facts cannot invalidate it. If one exact provider is
semantically significant, the fact names the complete offer address or an
explicit provider ID in its immutable bytes. Otherwise providers at the same
complete address are interchangeable. For membership the complete address is
`member(device_key, durable_owner)`, so later device affiliations cannot
rewrite ownership.

A suppressible family serializes the exact IDs that may suppress each fact.
Selectors can name SELF, a parent, a grandparent/ancestor path, or several
such IDs. A family with no suppression policy serializes no suppression key
and its facts cannot be directly suppressed. Parent selectors pin one direct
dependency. Ancestor paths are chains of immutable named refs, so adding an
interchangeable provider cannot rewire a stored fact's suppression IDs.
That is a visibility rule:
separately, a family may declare current principal/authority scopes whose
suppression makes the fact unusable as an authority provider without removing
the fact from validated storage.

`SuppTree` maps a known suppression ID to one of:

- `CLEAR`: the ID exists and has no effective action at this root;
- `ACTIVE(action_fid)`: the named immutable action is effective.

Absence is not `CLEAR`; a reader that needs an absent slot fails closed.
This lets a Worker answer exact liveness or suppression questions without
loading the fact set or rebuilding a database.

Deletion is an ordinary fact. Its named needs prove the author, its action
offer names the exact target selector, and the target family must permit that
action. An admin may delete every directly deletable fact. An owner may
delete facts owned by the same durable member principal, including facts
written by any of that member's devices. These are ordinary family checks,
not special cases in `FullPeer`.

Removal does not retroactively revoke validated storage. Once removal has
propagated, peers stop granting that principal new sharing authority. Facts
accepted by a peer that had not yet learned the removal remain legitimate
workspace facts. The closed pile was the validation certificate; no selected
dependency path is retained afterward. A remote proof names its exact provider;
the hosted Reader authenticates that FactTree residence and its current
SuppTree scopes. Stateful commands assemble interchangeable candidates from
their disposable SQL projection.

## Client persistence

`full_peer/sql_store.py` is the sole SQLite boundary, and its projection is
intentionally small:

```text
facts(fid, blob)                  one current canonical serialization
fact_index(kind, k0, k1, src)    every lookup and derived projection row
meta(k, v)                        pinned-root/cache version only
```

The combined index includes type, canonical fact key, every explicit ref,
every family offer, every declared suppression/current-liveness scope, and
current action bindings. It contains no validation verdict, proof, rank,
selected dependency edge, eligibility label, or dormant state. Family queries
assemble views from those rows. There are no family-specific application
tables and no SQL receiving authority.

The database can be deleted and rebuilt from a pinned `RepositoryReader`
without changing `root`. When fact-form versioning is introduced, rebuild
must hydrate a fact in the current surrounding context and store the current
serialized form, not preserve an obsolete original encoding.

## Direct object-store upload

Peers do not proxy pile bytes through Lambda or a Worker. The entire hosted
upload protocol is:

```text
OPEN(proof, pile digest, pile size)
    -> exact fixed-expiry create-only PUT plus cursor
client PUTs the pile directly to S3/R2
FINALIZE(cursor)
    -> broker privately invokes Applier(exact key, digest)
    -> applied | noop | rejected | retryable
```

There is no `ISSUE`, detached-object vector, upload group, Queue/SQS message,
bucket notification, cron, or LIST drain. A file descriptor and each Bao
slice are ordinary facts; the slice contains its payload and range proof and
can be sent in its own closed pile. Large uploads are therefore just repeated
instances of the same small protocol.

The stateful client retains one exact pile and, while useful, its current
lease. `full_peer/upload_journal.py` owns that local crash state,
`full_peer/upload_client.py` owns `OPEN -> PUT -> FINALIZE`, and
`full_peer/upload_client_http.py` owns the HTTP effects. If a response is lost,
the client repeats `FINALIZE`; if a lease expires, it opens a new exact session.
Local active, abandoned, and completed states never grant repository
authority, and abandoning local state is safe because an outstanding request
can write only one isolated immutable staging key.

`OPEN` reads one pinned repository root and checks current upload authority.
The cursor fixes workspace, uploader, provider, session, pile digest, size,
issue time, and expiry. `FINALIZE` changes none of those and does not reread
liveness. Removal before a new `OPEN` denies it; removal afterward leaves only
that already-confined pile usable until its fixed expiry.

The broker has read-only canonical access, an exact ingress PUT signer, and a
narrow provider-private invocation of the Applier. It never receives pile
bytes and cannot mutate canonical storage directly. The Applier bounded-reads
the exact key, checks its workspace/session/member/digest binding, decodes the
whole closed pile, invokes the ordinary kernel, and owns the only root CAS.
The member path component identifies the authenticated uploader, not every
fact author in a legitimate relayed closure.

`RepositoryApplier` never deletes ingress. A configured S3/R2 lifecycle may
eventually collect old staging because the client reports success only after
`applied` or `noop`; if an unpublished staging key expires, the sender simply
opens and uploads a new exact session. Retention is storage hygiene, not a
server-side work queue or a correctness precondition.

## Object-store contract

The algorithm depends on properties available from current S3 and R2
adapters:

- bounded strong reads of an exact key, rejecting one-over before full
  materialization;
- create-only immutable writes with collision verification;
- one linearizable conditional replace of `root`;
- an opaque version token returned with the exact root bytes.

`get_bounded` is mandatory and cannot be a compatibility wrapper around an
unbounded whole-object GET. The receive algorithm does not require LIST.

The opaque provider version token is not the root content hash. Readers use
the content hash as snapshot identity; Appliers use the opaque token only as
the compare capability for CAS. Correctness never depends on ETag being
MD5-like, bucket enumeration, or a database.

The filesystem adapter is a stronger local implementation of the same
contract. S3 uses conditional requests through `adapters/s3`; the Cloudflare
runtime uses the native R2 binding through `adapters/r2/worker.py`.

## AWS deployment

AWS uses two externally owned buckets:

- canonical: `root`, immutable `obj/`, internal `pile/`, and evidence;
- ingress: client-created objects and pile markers.

The upload broker and repository Applier are separate Lambda stacks so their
IAM authorities do not overlap.

Prerequisites:

- Python 3.13, AWS CLI, SAM CLI, and credentials for the target account;
- two distinct buckets;
- a Secrets Manager upload-session key ring;
- deployment credentials allowed to read the ingress bucket lifecycle;
- bucket policies that allow clients only their broker-issued create-only
  PUTs and allow the Applier role the exact canonical/ingress operations in
  its template.

Create the broker key ring:

```sh
python3 -m deploy.aws_upload_broker.manage keyring-create \
  --name poc16/upload-keyring \
  --deployment-id DEPLOYMENT \
  --issuer ISSUER \
  --ingress-bucket INGRESS_BUCKET \
  --region REGION \
  --expected-owner ACCOUNT_ID
```

That command prints the secret ARN and version ID. Deploy the broker with
those values:

```sh
python3 -m deploy.aws_upload_broker.manage deploy --create \
  --stack poc16-upload-broker \
  --deployment-id DEPLOYMENT \
  --workspace WS64 \
  --canonical-bucket CANONICAL_BUCKET \
  --prefix workspaces/WS64 \
  --ingress-bucket INGRESS_BUCKET \
  --issuer ISSUER \
  --keyring-secret-arn SECRET_ARN \
  --keyring-version-id VERSION_ID \
  --expected-owner ACCOUNT_ID \
  --region REGION
```

Deployment refuses an ingress bucket with any lifecycle rules:
[S3 bucket policies do not stop lifecycle actions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html),
so a rule could otherwise hide or expire acknowledged work. Stack removal
never adds one and leaves the bucket intact. The bucket is externally owned;
later lifecycle or bucket-policy mutation by its storage administrator is
outside broker-parent compromise, so that configuration authority must remain
deploy-only and absent from both Lambda roles.

Deploy the database-free Applier:

```sh
python3 -m deploy.aws_repository_applier.manage deploy \
  --stack-name poc16-repository-applier \
  --deployment-id DEPLOYMENT \
  --workspace WS64 \
  --canonical-bucket CANONICAL_BUCKET \
  --canonical-prefix workspaces/WS64 \
  --ingress-bucket INGRESS_BUCKET \
  --expected-owner ACCOUNT_ID \
  --region REGION
```

The template installs a one-minute recovery schedule. The handler also
accepts bounded S3 notification records as hints. Stack removal deletes
compute and logs only; it does not delete either bucket or the external
secret.

## Cloudflare deployment

Cloudflare likewise uses distinct canonical and ingress R2 buckets. The
broker has no native R2 binding: it receives a read-only canonical S3 token
and an ingress S3 signing token, while its code surface mints only exact
create-only PUTs. R2 gives that parent credential broad object mutation
verbs, so deployment first installs and reads back an indefinite provider
bucket lock over the complete ingress prefix. The lock prevents overwrite,
DELETE, and lifecycle expiry after an acknowledged PUT even if the parent
credential is compromised, following the provider's
[bucket-lock contract](https://developers.cloudflare.com/r2/buckets/bucket-locks/).
The Applier has native bindings to both buckets and a one-minute cron.

Set the non-secret deployment inputs:

```sh
export CLOUDFLARE_ACCOUNT_ID=ACCOUNT32
export CF_UPLOAD_WORKSPACE=WS64
export CF_UPLOAD_CANONICAL_BUCKET=CANONICAL_BUCKET
export CF_UPLOAD_INGRESS_BUCKET=INGRESS_BUCKET
export CF_UPLOAD_DEPLOYMENT_OWNER=OWNER
export CF_UPLOAD_CANONICAL_BUCKET_PROFILE=dedicated-workspace
export CF_UPLOAD_INGRESS_BUCKET_PROFILE=exclusive-dedicated
export CF_R2_BUCKET_ITEM_READ_PERMISSION_ID=READ_PERMISSION_ID32
export CF_R2_BUCKET_ITEM_WRITE_PERMISSION_ID=WRITE_PERMISSION_ID32
export CF_UPLOAD_ISSUER=ISSUER
```

Set a deploy-only `CLOUDFLARE_API_TOKEN` with account-scoped Workers Scripts
Edit and Workers R2 Storage Edit, the two canonical/ingress S3 credential
pairs, and `UPLOAD_SESSION_KEYRING`. Cloudflare's REST configuration authority
is [account-scoped](https://developers.cloudflare.com/r2/api/tokens/); its
bucket-scoped object tokens cannot call this API. The
`exclusive-dedicated` profile is therefore an operator invariant: this
deployment is the sole lock-configuration writer for its dedicated ingress
bucket, and the control token is never a Worker secret. Lock update replaces
one whole document and exposes no CAS precondition. Concurrent instances of
this same deployment write the same document; deployment refuses a foreign
document already present, but does not claim to defeat a racing account
administrator or compromised control token. For first creation set:

```sh
export CF_UPLOAD_CREATE=1
```

Render and inspect the exact Worker configs and policy inputs, then test and
deploy:

```sh
python3 -m deploy.cloudflare_upload.manage render
python3 -m deploy.cloudflare_upload.manage test
python3 -m deploy.cloudflare_upload.manage deploy
```

Deployment installs the ingress lock before the Applier and broker. Removal
reverses the compute order and preserves both R2 buckets and the lock:

```sh
python3 -m deploy.cloudflare_upload.manage remove
```

Generated provider claims intentionally say `live_verified: false` until the
live S3/R2 conformance suite has been run for the selected account and
credential profile. Building the adapters and deploy artifacts is not a claim
that this checkout has deployed them.

## Current performance status

The honest `PileSender -> RepositoryApplier -> RepositoryReader` benchmark
path is wired. It exposed that the snapshot compiler still reconstructs the
full validated fact set for each commit. That is a correctness-preserving but
expensive baseline. Incremental insertion must be byte-identical to a full
compile before it replaces the baseline.

No 50k/200k fact-rate or file-throughput number is asserted here until the
incremental compiler lands and the benchmark is rerun. The corresponding bead
requires facts/s at both sizes and MiB/s for file transfer.
