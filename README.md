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

Today, a writable host daemon is the publication boundary. Remote peers upload
hash-addressed file objects to its `page` route and then send a closed fact
pile to its `pile` route. The host writes those values to its configured
filesystem, S3, or R2 store, validates the pile, builds the authenticated
indexes, and conditionally advances `root`. The Lambda and Cloudflare
deployments below do not accept uploads and cannot publish a workspace by
themselves.

The intended cloud path is direct-to-object-store and is not implemented yet.
After proving workspace upload authority, a client will receive short-lived
capabilities for exact broker-chosen upload keys, upload file objects first,
and finally upload one exact closed-pile publication intent. A provider that
can prove the complete request may target canonical `obj/<sha256>` and
`pile/<member>/<sha256>` keys directly. An isolated-ingress deployment uses
session-scoped staging keys and lets the publisher promote only verified
SHA-256 objects. In either case a conforming request binds a
collision-resistant body digest, an exact length or hard byte ceiling, expiry,
and create-only semantics; clients receive no LIST, DELETE, or `root`
permission. An S3/R2 object-created event, authenticated poke, or scheduled
scan wakes a database-free publisher. That publisher validates the pile and
objects, updates the authenticated trees, CASes `root`, and retires ingress
only after the committed root proves publication. A lost event or poke affects
latency, not durability.

That target also requires every valid candidate that may later regain standing
to remain durably reachable. The current client keeps losing/inactive receipts
only in its local catalog and may retire their original pile after publishing
the eligible subset. The generic authenticated index bounds discovery for
rooted/eligible candidates, but it does not manufacture missing dormant
bytes. A serverless publisher is not complete until ingress retirement or a
root-reachable candidate archive closes that retention boundary.

There is no correctness reason to proxy immutable bytes through the publisher
when the provider can enforce the complete request. The narrower boundary is
intentional: uploaders may create only the objects named by their grants,
while publishers alone may list ingress, read workspace state, create derived
index pages, retire proven piles, and CAS `root`. If a deployment cannot
enforce the exact key, create-only condition, body digest, byte bound, and
expiry, it must use isolated staging, keep the host daemon, or put a narrow
streaming upload verifier in front of the object store rather than grant a
broader bucket credential.

That fallback is concrete on Cloudflare. As checked on 2026-07-29, R2's
[S3-compatible `PutObject` table][r2-s3-api] advertises conditional writes and
`Content-MD5`, but not the flexible SHA-256 checksum needed to protect a
canonical `obj/<sha256>` name. The [native R2 Worker `put` API][r2-worker-api]
does accept a SHA-256 checksum and a conditional, so a write-only streaming
Worker can verify a canonical upload without owning `root`; alternatively the
client uploads directly into an isolated ingress bucket and the publisher
verifies and promotes it. Raw presigned canonical R2 PUTs remain unproven.

Cloudflare also requires provider-level separation. A child R2 credential can
be limited to `PutObject`, but the broker's current parent read/write token can
read, list, and delete within its bucket. It must never target the canonical
workspace bucket. A separate ingress bucket preserves canonical integrity,
but parent compromise could still erase unpublished staging; whether that
availability loss is accepted as a retryable pre-publication boundary or
requires a put-only verifier/parent remains an explicit deployment decision.

[r2-s3-api]: https://developers.cloudflare.com/r2/api/s3/api/
[r2-worker-api]: https://developers.cloudflare.com/r2/api/workers/workers-api-reference/

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
