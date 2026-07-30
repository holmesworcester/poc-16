# POC-16

POC-16 is a small peer-to-peer workspace engine built around immutable,
content-addressed facts. Peers reconcile through a passive object-store
interface; a daemon or edge worker only authenticates requests and serves
bytes. The implementation includes users and devices, delegated admins,
messages, Bao-backed attachments, logical deletion, member eviction, rebuild,
and one-sided synchronization.

The current format is intentionally not backward compatible. `DESIGN.md`
describes the running format and its remaining limits.

Every ordinary fact and every closed pile canonically names one workspace.
The sole exception is workspace genesis: it omits `ws` because its own fact id
is the workspace id. This binding is covered by fact ids and signatures and is
checked before family dispatch, catalog staging, sync, invite redemption, and
database-free edge authorization. State written by the earlier ambient-
workspace format must be rebuilt or migrated out of band; there is no dual
decoder.

> **Privacy warning:** ordinary fact bodies are plaintext JSON in the object
> store. Signatures authenticate them but do not encrypt them. Invite blobs
> are encrypted; message and attachment metadata are not. Do not treat this
> prototype as an encrypted production messenger.

## Install

Python 3 and PyNaCl are required:

```sh
python3 -m pip install pynacl pytest
```

Attachments use the vendored Bao extension:

```sh
python3 -m pip install ./native/bao_py
```

The extension is loaded only by attachment operations. Auth, messages, sync,
and most tests run without it.

The local filesystem and Cloudflare Worker do not import AWS SDK packages.
Only a host daemon configured for S3 or R2's S3-compatible API needs the
optional, known-capable provider pair:

```sh
python3 -m pip install "boto3==1.43.51" "botocore==1.43.51"
python3 -m adapters.s3.sdk_smoke
```

## Run

Start a node:

```sh
python3 -m core daemon ./state/alice --port 7100
```

In another shell:

```sh
python3 -m core auth.workspace.create alice
python3 -m core core.status
```

`create` prints the workspace id. Commands accept a unique workspace-id
prefix:

```sh
python3 -m core content.message.post WORKSPACE general "hello"
python3 -m core content.message.list WORKSPACE
python3 -m core content.file.send WORKSPACE general ./photo.jpg
python3 -m core content.file.list WORKSPACE
python3 -m core content.file.save WORKSPACE FILE_FID ./photo.jpg
python3 -m core content.delete.remove WORKSPACE FACT_FID
python3 -m core auth.removal.evict WORKSPACE MEMBER_NAME
```

To add a peer, create an invite on the existing node and redeem it against a
second daemon:

```sh
python3 -m core auth.user_invite.create WORKSPACE
python3 -m core --node http://127.0.0.1:7200 auth.user.join INVITE_LINK bob
```

Nodes synchronize on their daemon cadence. `python3 -m core core.sync
WORKSPACE` requests an immediate dial, and `core.rebuild WORKSPACE`
reconstructs eligibility and authenticated/generic indexes around the stable
local fact catalog and published root. Family queries assemble views directly
from that catalog. Published-state decisions shared with the CF path use the
same authenticated trees; SQLite is reserved for client-local intent, query
assembly, and full repair.

FactTree is also the authenticated generic query index for current standing.
It maps a fid to its reconciliation key, rank, resolved dependencies, offers,
and suppression scopes, and carries ordered posting rows for fact type, key,
explicit reference, offer candidates, reverse dependencies, and suppression
impact. A store-only reader can page one address in bounded
`O(tree depth + returned rows)` object reads; it does not enumerate FactTree,
RangeTree, or rebuild SQLite. AuthorityTree remains the exact winner cache for
ordinary authorization, where reading every conflicting candidate would be
wasteful.

The single `ctl/command` endpoint is a trusted node-local control plane.
Remote peers use the authenticated `root`, `page`, `pile`, `poke`, and `mint`
protocol routes.
Consequently `content.file.send` and `content.file.save` paths are resolved by
the daemon process, just like the POC-17 local command model.

### Host S3/R2 object stores

Pass a strict JSON file to `--store-config`; credentials stay outside the file
and come from boto's environment, shared-config, container, or instance
credential chain. An Amazon S3 configuration is:

```json
{
  "schema": "poc16-host-store-v1",
  "backend": "s3",
  "bucket": "my-bucket",
  "base_prefix": "poc16/tenant",
  "region_name": "us-west-2"
}
```

R2 uses the direct account endpoint derived from `account_id`:

```json
{
  "schema": "poc16-host-store-v1",
  "backend": "r2",
  "account_id": "0123456789abcdef0123456789abcdef",
  "bucket": "my-bucket",
  "base_prefix": "poc16/tenant"
}
```

After saving one of those documents as `store.json`, start the host with:

```sh
python3 -m core daemon ./state/alice --store-config store.json
```

### Upload path: current and target

The status boundary is:

- **Complete writable production path:** a host daemon receives file objects
  on its `page` route and a closed fact pile on its `pile` route, then validates,
  indexes, and publishes them to its configured filesystem, S3, or R2 store.
- **Implemented but not deployed:** the resumable client sends bodies directly
  to exact S3/R2 ingress PUT URLs returned by the database-free broker protocol.
  The strict provider-neutral broker HTTP membrane and both SigV4 translators
  exist and have realistic fake-provider coverage. An isolated AWS Lambda
  Function URL adapter and least-privilege SAM stack now serve that membrane.
- **Still required for a writable serverless path:** the Cloudflare Worker
  broker adapter, the database-free publisher on both providers,
  notification/scheduled draining, and live end-to-end conformance.

Consequently, the Lambda and Cloudflare deployments below remain read-only and
the writable host daemon is still the only complete production publication
boundary.

The end-to-end direct-to-object-store cloud path is not deployed yet. Its
kernel-authorized broker core, strict transport-neutral HTTP membrane,
resumable multi-batch client, and exact AWS and R2 SigV4 translators now exist
under `deploy/upload_broker.py`, `deploy/upload_broker_http.py`,
`deploy/upload_wire.py`, `deploy/upload_client.py`,
`deploy/upload_journal.py`, `deploy/aws_upload_broker`, and
`deploy/cloudflare_upload`. The endpoint serves only canonical, bounded
`POST /upload/open`, `/upload/issue`, and `/upload/finalize` metadata
documents and returns the broker's exact bearer PUT requests; provider object
and pile bodies never cross it.

The endpoint is now wired into a separate AWS upload-broker Lambda package but
has not been live-deployed; the Cloudflare broker still has a fail-closed stub.
Neither provider has the database-free publisher yet. The broker and publisher
remain absent from the read-only serverless gateway artifacts, so the writable
host path above remains the only complete production path today.

Once such an endpoint is deployed, the existing generic command transport
exposes family-owned direct commands:

```sh
python3 -m core content.message.upload WORKSPACE general "hello" \
  BROKER_URL PROVIDER_ORIGIN
python3 -m core content.file.upload WORKSPACE general ./photo.jpg \
  BROKER_URL PROVIDER_ORIGIN
python3 -m core content.file.resume_upload WORKSPACE UPLOAD_ID \
  BROKER_URL PROVIDER_ORIGIN
```

The local client process authors the ordinary fact closure and keeps an
immutable source journal under its node directory; it does not admit those
facts locally or need S3/R2 credentials. The source manifest is separate from
the mutable session record. That record retains the most advanced
authenticated cursor, the prefix covered by it, and the smaller prefix whose
PUTs were acknowledged. A crash after `ISSUE` therefore reissues covered
authority instead of skipping unuploaded bytes. A create precondition failure
is never guessed to mean equal: because the PUT capability has no read
authority, the client abandons that staging session and opens a fresh one.
`PROVIDER_ORIGIN` is the independently configured exact HTTPS provider
endpoint for this deployment and ingress bucket (the account endpoint for
R2). The client rejects a capability for any other origin before opening
source bytes, so even a compromised broker cannot redirect a PUT to itself or
an internal HTTPS service.

After proving workspace upload authority, the client receives short-lived
capabilities for exact broker-chosen upload keys, upload file objects first,
and finally upload one exact closed-pile publication intent. The selected
common flow uses session-scoped isolated ingress on both S3 and R2, then lets
the publisher promote only verified SHA-256 objects. This is the one cloud
upload protocol, not a fallback from an AWS-specific canonical-write path:
abandoned and adversarial client bytes remain outside the canonical namespace,
and clients have one recovery model on both providers.

This is still direct-to-object-store upload: the file and pile bytes travel
from the client to the ingress bucket, not through the broker, Lambda, or
Worker. The broker handles only a bounded authorization proof and returns
bearer PUT requests. Each request binds the exact staging key containing the
declared SHA-256, an exact length or hard byte ceiling, expiry, and create-only
semantics; clients receive no LIST, DELETE, or `root` permission. S3 may also
verify a signed SHA-256 checksum. R2 staging bytes are deliberately treated as
untrusted until publication. An S3/R2 object-created event, authenticated poke,
or scheduled scan wakes a database-free publisher. That publisher hashes every
present object before canonical promotion and validates the pile. It then
copies the exact verified pile to a fresh internal
`pile/<member>/<generation>/<sha256>` key that client credentials cannot name.
The internal generation updates the authenticated trees, CASes `root`, and
retires only after the committed root proves publication. The original
client-writable session marker is retained for a separate provider lifecycle
policy; capability expiry alone is not a deletion proof because a request may
start before expiry and complete afterward. A lost event or poke affects
latency, not durability.

Attachment bytes remain detached from fact validity. A missing Bao object
does not block signed file/chunk facts from publication; the file is simply
incomplete until a later direct upload or peer sync supplies it. This is the
same rule used by ordinary replicas. F10 retirement therefore proves durable
coverage of every admitted fact, not that every attachment byte exists.
Client-writable staging is not retired by this receipt; its retention and
eventual cleanup are a separate provider lifecycle obligation.

The AWS translator signs the exact `Content-Length`, `Content-Type`,
`If-None-Match: *`, and `x-amz-checksum-sha256` headers of one S3 `PutObject`
request. Browser JavaScript cannot set `Content-Length` itself, so browser
support remains an opt-in live conformance check: the user agent must emit the
signed length and the configured S3 CORS policy must admit every
client-controlled signed header. The deterministic botocore tests do not
claim to prove that browser/provider boundary.

The pure-stdlib R2 translator returns the same bearer `PUT` shape. It signs the
path-style account endpoint, ingress bucket, exact class-first key,
`Content-Length`, `Content-Type`, `If-None-Match: *`, credential scope
`auto/s3/aws4_request`, and a lifetime rounded down beneath the session
deadline. Its canonical payload is explicitly `UNSIGNED-PAYLOAD`: the URL is
an exact staging capability, not proof of the declared SHA-256. Cloudflare's
[presigned URL documentation][r2-presigned] recommends this single-operation,
single-object shape and documents `Content-Type`; its presign page does not
explicitly guarantee signed `Content-Length`, so the checked-in opt-in live
test remains the direct-provider conformance gate for that header. That urllib
probe is not browser evidence; browser `Content-Length` and CORS behavior
remain a separate live obligation.

Every valid candidate that may later regain standing remains durably
root-reachable. Every kernel-admitted candidate has a stable canonical blob at
`obj/H(encode(fact))`; eligible facts are also materialized in derived
RangeTree sync piles. Its authenticated FactTree record names the
lexicographically smallest complete historical admission-proof DAG the
replica has verified. Candidate state is exact bytes plus that selected
witness; current eligibility and dependency edges are a separate derived
projection. Sync min-joins witnesses for eligible and dormant candidates, and
a cold reader verifies each selected proof by rerunning the actual kernel.

Ingress retirement uses a typed compiler/publication result. Every durable
`Valid` in the exact pile must be constructed into the proposal or inherited
from its pinned authorized base; only Applied, byte-identical ambiguous-CAS
readback, or a token-verified no-op can mint the exact source/hash-bound
retirement receipt. No post-CAS fact scan grants deletion authority. Wiping
SQLite and rebuilding from root-reachable objects preserves dormant
candidates and later restoration; proof-less legacy rows are never inferred
admitted.

The archive removes the persistence blocker for a database-free publisher,
but the checked-in Lambda and Cloudflare artifacts are not yet wired as
publishers. They remain readers until their turn coordinator consumes this
archive, stages direct-upload intent, emits the derived objects, and performs
the same root-CAS/retirement protocol as the client runtime.

There is no correctness reason to proxy immutable bytes through the publisher
when the client can write an isolated ingress object directly. The narrower
boundary is intentional: uploaders may create only the staging objects named
by their grants, while publishers alone may list ingress, read workspace
state, create canonical objects and derived index pages, retire proven internal
piles,
and CAS `root`. If a provider cannot enforce the exact staging key,
create-only condition, byte bound, and expiry, the deployment must keep the
host daemon or put a narrow streaming upload verifier in front of the object
store rather than grant a broader bucket credential.

The canonical boundary is stricter. As checked on 2026-07-29, R2's
[S3-compatible `PutObject` table][r2-s3-api] advertises conditional writes and
`Content-MD5`, but not the flexible SHA-256 checksum needed to protect a
canonical `obj/<sha256>` name. The [native R2 Worker `put` API][r2-worker-api]
does accept a SHA-256 checksum and a conditional. POC-16 does not require
either primitive on the client path: the client writes only isolated ingress,
and the publisher hashes the stored value before it conditionally creates a
canonical `obj/<sha256>`. Raw presigned canonical R2 PUTs remain outside the
selected protocol.

Cloudflare also requires provider-level separation. The broker's parent
read/write token can read, list, and delete within its bucket even though each
returned presigned URL authorizes only one exact `PUT`. The parent therefore
targets only the separate ingress bucket and never the canonical workspace
bucket. Parent compromise could still erase pre-publication staging. A
successful staging `PUT` is only a retryable receipt; observation of the
published root is the durable workspace acknowledgement.

[r2-s3-api]: https://developers.cloudflare.com/r2/api/s3/api/
[r2-worker-api]: https://developers.cloudflare.com/r2/api/workers/workers-api-reference/
[r2-presigned]: https://developers.cloudflare.com/r2/api/s3/presigned-urls/

### Prepared AWS upload broker

`deploy/aws_upload_broker/` is a real metadata-only Lambda adapter, not a body
proxy. It normalizes bounded Function URL v2 events into the shared
`UploadBrokerEndpoint`, reads the canonical authorization closure through a
narrow S3 reader, loads one provider-bound session key ring from an external
Secrets Manager secret, and returns exact S3 ingress PUTs. Its role can
`GetObject` only under the canonical root/object prefix and query-presign
create-only `PutObject` only under this workspace's isolated ingress prefixes.
It cannot read, list, or delete ingress; write canonical objects; or CAS root.

The key-ring secret and both buckets are external inputs and survive compute
removal. Create a provider-bound initial key ring without putting secret bytes
in argv, stdout, a template, or stack state:

```sh
python3 -m deploy.aws_upload_broker.manage keyring-create \
  --name poc16/upload-west-2/session-keyring \
  --deployment-id upload-west-2 \
  --issuer aws-upload-production \
  --ingress-bucket ISOLATED_INGRESS_BUCKET \
  --expected-owner AWS_ACCOUNT_ID \
  --region us-west-2
```

The command returns only the secret ARN and exact version ID needed below.
Two-phase control-plane rotation remains tracked work. Local tests and a SAM
build are:

```sh
python3 -m deploy.aws_upload_broker.manage test
python3 -m deploy.aws_upload_broker.manage build
```

Deploy or update the separately owned broker stack with:

```sh
python3 -m deploy.aws_upload_broker.manage deploy --create \
  --stack poc16-upload --deployment-id upload-west-2 \
  --workspace WORKSPACE_ID \
  --canonical-bucket CANONICAL_BUCKET \
  --prefix workspaces/WORKSPACE_ID \
  --ingress-bucket ISOLATED_INGRESS_BUCKET \
  --issuer aws-upload-production \
  --keyring-secret-arn SESSION_KEYRING_SECRET_ARN \
  --keyring-version-id SESSION_KEYRING_VERSION_ID \
  --expected-owner AWS_ACCOUNT_ID \
  --region us-west-2
```

Use `--update` instead of `--create` only for that exactly tagged stack. Safe
removal targets the observed stack ID and leaves both buckets and the external
key-ring secret intact:

```sh
python3 -m deploy.aws_upload_broker.manage remove \
  --stack poc16-upload --deployment-id upload-west-2 \
  --region us-west-2
```

This makes the authorization endpoint deployable, but not the full writable
cloud path: there is no store-only publisher, event/scheduled drain, or live
attachment smoke yet.

### Prepared Cloudflare upload boundary

`deploy/cloudflare_upload/` now renders the provider boundary for the
isolated-ingress choice, but it is not yet a working upload service. The
broker config has no native R2 binding. It expects one S3-compatible
credential created from an exact-bucket `Object Read only` policy for
canonical DAG reads, plus one separate parent credential created from an exact
ingress-bucket `Object Read & Write` policy. The segregated stdlib signer uses
only that ingress parent to derive one short-lived URL for one exact
session-scoped `PutObject`; no temporary credential or S3 client is returned
to the uploader. The publisher config is the only role with native `INGRESS`
and `CANONICAL` bindings.

Both providers use one logical staging grammar:

```text
ingress/v1/workspaces/<ws64>/objects/<nonce32>/<sha256>
ingress/v1/workspaces/<ws64>/piles/<nonce32>/<member16>/<sha256>
```

The broker chooses the lowercase-hex session nonce and derives every path
from validated descriptor authority; the client does not supply a free-form
key. Objects are uploaded first. The closed pile/intention is uploaded last
and is the sole durable ready marker. Loose objects do not cause publication,
and an event for the final pile only reduces wake latency. Object class comes
before session deliberately: provider lifecycle can collect abandoned
`objects/` without ever matching an F10-governed `piles/` marker, while a
scheduled publisher can scan only the marker prefix.

These staging paths never become canonical pile paths. After validation, the
publisher performs a trusted create-only copy to an independently random
internal generation. Replaying the same session marker—including a PUT that
started before credential expiry but completed later—therefore produces, at
worst, another fresh no-op publication attempt. It cannot recreate a retired
internal key or make an old receipt destructive. Cleanup of client-writable
staging is tracked separately; the current lifecycle input still excludes
`piles/`.

The provider-neutral broker core now implements `OPEN`, `ISSUE`, and
`FINALIZE`. `OPEN` commits a finite, sorted `(digest, size)` vector under a
domain-separated Merkle root. A constant-size authenticated cursor then proves
and issues contiguous batches of at most `PAGE_BATCH`; finalization is
possible only after the whole committed vector and can issue only the one pile
digest fixed when the session opened. Replayed or forked cursors may reissue
already committed exact keys, but cannot enlarge or replace the finite
authority set. This keeps the broker database-free. A client that loses its
opaque cursor starts a new session, and lifecycle collection removes the
abandoned ingress. The client, transport-neutral broker HTTP membrane, and AWS
Function URL adapter are built; the Cloudflare adapter, deployed live routes,
and database-free publisher remain unbuilt.

This is a provider boundary, not a Python convention: compromising the
write-capable ingress parent still cannot address the canonical bucket. It is
also deliberately honest about two limits. Cloudflare's bucket-item write
parent can overwrite or delete acknowledged staging, and its bucket-item
read policy includes LIST over the selected bucket. Therefore a deployment
must use a canonical bucket dedicated to that workspace until a
provider-enforced workspace-prefix read path exists; setting
`CANONICAL_PREFIX` alone is not tenant isolation.

Render the two Worker configs, the two exact R2 token-policy inputs, and the
loose-object-only seven-day lifecycle input with:

```sh
export CLOUDFLARE_ACCOUNT_ID=32_LOWERCASE_HEX_CHARACTERS
export CF_UPLOAD_WORKSPACE=64_LOWERCASE_HEX_CHARACTERS
export CF_UPLOAD_CANONICAL_BUCKET=poc16-one-workspace-canonical
export CF_UPLOAD_CANONICAL_BUCKET_PROFILE=dedicated-workspace
export CF_UPLOAD_INGRESS_BUCKET=poc16-untrusted-ingress
export CF_UPLOAD_DEPLOYMENT_OWNER=my-stable-deployment-id
export CF_R2_BUCKET_ITEM_READ_PERMISSION_ID=READ_GROUP_ID
export CF_R2_BUCKET_ITEM_WRITE_PERMISSION_ID=WRITE_GROUP_ID
# Canonical JSON produced by deploy.upload_keyring; keep the old key through
# every issued cursor's expiry plus clock skew during rotation.
export UPLOAD_SESSION_KEYRING='...'

python3 -m deploy.cloudflare_upload.manage render
python3 -m deploy.cloudflare_upload.manage test
```

The checked-in broker and publisher entries return 503 and have no public
route. An explicit `CF_UPLOAD_ENABLE_STUB_DEPLOY=1` can deploy that fail-closed
binding skeleton for infrastructure testing; `remove` preflights both exact
owner/role markers, removes broker then publisher, and never deletes or
reconfigures either bucket. The real authorization endpoint, store-only
publisher, queue/schedule wakes, lifecycle installation/conformance check,
and live R2 proof remain tracked work. Cloudflare documents that action-level
presigned URLs are generated locally and grant one operation on one object;
the optional direct-provider test checks the exact signed PUT, header
substitution, key substitution, create-only replay, and privileged readback.

## Cloudflare read-only gateway

The Cloudflare Python Worker is isolated under `deploy/cloudflare_worker`. It
uses a direct R2 binding for one workspace prefix, imports the canonical
Python authorization code, and advertises `{"cap":"sync-v1/read"}`. It never
writes R2, opens SQLite, or exposes pile/poke/control mutations.

Install `uv`, then run its complete host, clean-bundle, and local-workerd
checks:

```sh
python3 deploy/cloudflare_worker/manage.py test
```

Local development uses the placeholder workspace and local R2 bucket in the
checked-in config. Supply a stable 32-byte base64 grant secret:

```sh
export GRANT_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
python3 deploy/cloudflare_worker/manage.py dev
```

Production commands generate an ignored Wrangler config and require every
deployment identity explicitly:

```sh
export CF_WORKSPACE=64_LOWERCASE_HEX_CHARACTERS
export CF_STORE_PREFIX=workspaces/$CF_WORKSPACE
export CF_R2_BUCKET=poc16-production
export CF_R2_PREVIEW_BUCKET=poc16-preview
export CF_WORKER_NAME=poc-16-readonly-gateway
export CF_DEPLOYMENT_OWNER=my-stable-deployment-id
export CF_ROUTE='gateway.example.com/*'
export CF_ZONE_NAME=example.com
export CLOUDFLARE_ACCOUNT_ID=32_LOWERCASE_HEX_CHARACTERS
export CLOUDFLARE_API_TOKEN=WORKERS_SCRIPTS_READ_AND_WRITE_TOKEN
export GRANT_SECRET=BASE64_OF_ONE_STABLE_32_BYTE_SECRET

python3 deploy/cloudflare_worker/manage.py build
CF_CREATE=1 python3 deploy/cloudflare_worker/manage.py deploy
python3 deploy/cloudflare_worker/manage.py deploy
python3 deploy/cloudflare_worker/manage.py remove
```

`deploy` passes the secret through Wrangler's encrypted secret upload and
never writes it to the generated config. First creation additionally requires
`CF_CREATE=1`; later deploys and every removal read the Worker settings through
Cloudflare's direct API and require the exact non-secret
`CF_DEPLOYMENT_OWNER` marker. Missing, malformed, and mismatched settings fail
closed before Wrangler can overwrite or delete the named script, and every
Wrangler mutation has a 120-second deadline. Cloudflare does not make the
settings read and later script mutation one conditional operation: deploy and
remove therefore assume one trusted deployment administrator and must be
externally serialized. The ownership marker prevents accidental targeting; it
is not a control-plane CAS against a concurrent administrator. The checked-in
config has no public route and cannot accidentally target a real bucket.
A deadline is a client-side bound, not proof that Cloudflare made no change;
after a timeout, inspect the exact owned script state before deciding whether
to retry.

`smoke` is an explicit live test: set `CF_LIVE_SMOKE=1` and
`CF_SMOKE_MINT_FILE` to a Python-generated mint request whose snapshot already
exists at the configured prefix. It establishes that its random workers.dev
name is absent before deployment, verifies authorization, and then removes
that exact name even if Wrangler applied the deployment before reporting a
failure. Primary and cleanup failures are both reported; neither path changes
or deletes R2 data.

## AWS Lambda read-only gateway

The AWS package is isolated under `deploy/aws_lambda/`. It requires the AWS
and SAM CLIs plus Docker. Build and execute the exact SAM artifact under the
Lambda Python 3.13 x86_64 runtime with:

```sh
python3 deploy/aws_lambda/manage.py package-smoke
```

Before publishing, merge a storage-law guard into the existing bucket policy.
The default profile applies authoritative-key denies to every principal and
freezes lifecycle-policy mutation for the whole bucket:

```sh
python3 deploy/aws_lambda/manage.py bucket-policy \
  --bucket BUCKET --prefix PREFIX
```

Audit existing lifecycle rules, object tags, ACLs, annotations, and replication
first; existing tags can already influence lifecycle behavior, and annotations
are mutable sidecars whose changes do not alter the parent ETag. The guard
denies direct annotation puts/deletes, both versioned and unversioned ACL
changes, and ETag-preserving encryption-key changes. Prefer S3 Object
Ownership's `BucketOwnerEnforced` setting so ACLs are disabled.

The guard does not administer S3 replication. Principals allowed
`s3:ReplicateObject`, `s3:ReplicateDelete`, `s3:ReplicateTags`,
`s3:ReplicateObjectAnnotation`, or `s3:ObjectOwnerOverrideToBucketOwner` remain
trusted. So do administrators able to replace the bucket policy or revoke the
gateway's KMS-key access. The narrower
`--profile single-publisher --publisher-principal ARN` form is safe only when
that ARN is the complete writer set and every other bucket writer, replication
principal, and administrator is explicitly trusted.

Deploy validates the bucket and prefix locally, builds in SAM's target
container, installs the hash-locked dependency closure, and requires the
Function URL to pass a root-backed readiness check:

```sh
python3 deploy/aws_lambda/manage.py deploy \
  --create --stack poc16-edge --deployment-id edge-west-2 \
  --workspace WORKSPACE_ID \
  --bucket BUCKET --prefix PREFIX --region us-west-2
```

For a customer-managed SSE-KMS bucket, add the exact `--kms-key-arn`; to
notify on handled Function URL 5xx responses and invocation-budget alarms,
add `--alarm-action-arn`. Later deployments use `--update` and refuse to
target a stack without the original ownership markers. Removal retains the
external bucket and its objects,
and refuses to act unless the named stack has the expected account, region,
deployment tag, and template marker:

```sh
python3 deploy/aws_lambda/manage.py remove \
  --stack poc16-edge --deployment-id edge-west-2 --region us-west-2
```

The deployment ID is a stable, non-secret operator identity stored in both
stack tags and outputs; another valid POC-16 stack does not match it. Create
mode proves the name absent immediately before SAM, but that check and SAM's
create are not one CloudFormation transaction. Operators must serialize
creation of a chosen friendly name; automated callers should use high-entropy
names.

## Test and measure

Run the full suite:

```sh
python3 -m pytest -q
```

The latency benchmark measures real hot-post and idle-sync paths:

```sh
python3 bench/bench_latency.py
```

The larger reconciliation benchmark is:

```sh
python3 bench/bench_sync.py 5000 10000
```

The repository tracks work with `bd`:

```sh
bd prime
bd ready
bd show ISSUE_ID
```
