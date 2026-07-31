# tiny p2p, POC-16

POC-16 is a fact-DAG repository with one storage format and one receiving
algorithm across a full peer, AWS Lambda, and a Cloudflare Worker. A hosted
recipient needs an object store but no database. SQLite exists only as a
disposable full-client query and authorship accelerator.

The implementation is deliberately strict about authority and direction:

- `RepositoryApplier` is the only fact-pile-to-root capability. It is
  database-free and owns immutable establishment, the root CAS, rejection
  evidence, and retirement of its own internal pile generations.
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
9. `full_peer/sql_store.py`: the sole SQL boundary.
10. `deploy/` and `adapters/`: provider adaptation and packaging only.

[DESIGN.md](DESIGN.md) gives the data model, invariants, and failure
semantics. [AGENTS.md](AGENTS.md) contains repository ratchets.

## Local use

Run the tests:

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

## Repository flow

An authored unit follows one path:

```text
facts command
    -> PileSender closes dependencies and encodes one fact-only {ws,facts} pile
    -> RepositoryApplier stages a fresh internal generation
    -> kernel judges the exact closed pile
    -> pure compiler derives FactTree, SuppTree, AuthorityTree, FactOrder
    -> immutable objects are conditionally established
    -> one CAS advances root
    -> only that exact internal generation may be retired
    -> RepositoryReader pins the resulting root
```

Root-CAS losers keep their exact work and retry from the newer root. A lost
CAS response is reconciled by reading the root. A crash after CAS but before
retirement replays as a token-checked no-op and then retires. One bad pile
cannot wedge later pile generations.

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
dependency path is retained afterward. Commands and remote minting consult
the pinned root's current suppression and authority maps.

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

Peers do not proxy file bytes through Lambda or a Worker. A broker reads a
pinned repository root to authorize an upload and returns exact, short-lived,
create-only PUT capabilities. The client uploads:

1. detached objects to an isolated ingress bucket;
2. one exact fact pile marker last.

The marker is the durable work item. Notifications and LIST results are
discovery hints; scheduled bounded rescans are the progress path, and only an
exact bounded marker read can establish work.

`RepositoryApplier` then:

1. fetches and validates the exact marker;
2. checks the exact key/session/member/digest binding and that every ordinary
   fact names the configured workspace (the workspace-genesis fact is the
   sole ws-less exception);
3. copies it behind one Applier-minted internal generation;
4. commits facts through the ordinary pile path;
5. retires only the internal generation;
6. promotes referenced attachments in bounded round-robin pages.

The Applier never deletes the client marker. Marker lifecycle is an ingress
retention policy, separate from the repository's exact internal-retirement
rule. Missing attachments do not block valid fact admission; immutable page
receipts and a non-authoritative cursor let concurrent Workers duplicate
bounded work without skipping completion or corrupting the tree.

The marker's member component names the broker-authenticated upload session,
not the author of every fact in a relayed closure. Per-fact signatures and
family needs remain the authority proof.

The broker is a `RepositoryReader` plus a provider signer. It has read-only
canonical credentials and exposes only exact create-only ingress PUT grants;
it has no repository mutation route. The Applier alone can mutate the
canonical bucket.

## Object-store contract

The algorithm depends on properties available from current S3 and R2
adapters:

- bounded strong reads of an exact key, rejecting one-over before full
  materialization;
- create-only immutable writes with collision verification;
- one linearizable conditional replace of `root`;
- an opaque version token returned with the exact root bytes;
- bounded, paginated LIST for discovery only.

`get_bounded` and `list_page` are mandatory store operations, not compatibility
wrappers around whole-object GET or whole-result LIST.

The opaque provider version token is not the root content hash. Readers use
the content hash as snapshot identity; Appliers use the opaque token only as
the compare capability for CAS. Correctness never depends on ETag being
MD5-like, on LIST ordering beyond the adapter contract, or on a database.

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
create-only PUTs. R2 currently gives that parent credential broader object
mutation authority than the grants the broker exposes; eliminating or
externally fencing that credential-level gap is tracked as a P0 provider
hardening bead. The Applier has native bindings to both buckets and a
one-minute cron.

Set the non-secret deployment inputs:

```sh
export CLOUDFLARE_ACCOUNT_ID=ACCOUNT32
export CF_UPLOAD_WORKSPACE=WS64
export CF_UPLOAD_CANONICAL_BUCKET=CANONICAL_BUCKET
export CF_UPLOAD_INGRESS_BUCKET=INGRESS_BUCKET
export CF_UPLOAD_DEPLOYMENT_OWNER=OWNER
export CF_UPLOAD_CANONICAL_BUCKET_PROFILE=dedicated-workspace
export CF_R2_BUCKET_ITEM_READ_PERMISSION_ID=READ_PERMISSION_ID32
export CF_R2_BUCKET_ITEM_WRITE_PERMISSION_ID=WRITE_PERMISSION_ID32
export CF_UPLOAD_ISSUER=ISSUER
```

Set `CLOUDFLARE_API_TOKEN`, the two canonical/ingress S3 credential pairs,
and `UPLOAD_SESSION_KEYRING`. For first creation set:

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

Deployment order is Applier then broker. Removal reverses that order and
preserves both R2 buckets:

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
