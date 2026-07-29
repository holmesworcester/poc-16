# POC-16

POC-16 is a small peer-to-peer workspace engine built around immutable,
content-addressed facts. Peers reconcile through a passive object-store
interface; a daemon or edge worker only authenticates requests and serves
bytes. The implementation includes users and devices, delegated admins,
messages, Bao-backed attachments, logical deletion, member eviction, rebuild,
and one-sided synchronization.

The current format is intentionally not backward compatible. `DESIGN.md`
describes the running format and its remaining limits.

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

The single `ctl/command` endpoint is a trusted node-local control plane.
Remote peers use the authenticated `root`, `page`, `pile`, `poke`, and `mint`
protocol routes.
Consequently `content.file.send` and `content.file.save` paths are resolved by
the daemon process, just like the POC-17 local command model.

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
export CF_ROUTE='gateway.example.com/*'
export CF_ZONE_NAME=example.com
export GRANT_SECRET=BASE64_OF_ONE_STABLE_32_BYTE_SECRET

python3 deploy/cloudflare_worker/manage.py build
python3 deploy/cloudflare_worker/manage.py deploy
python3 deploy/cloudflare_worker/manage.py remove
```

`deploy` passes the secret through Wrangler's encrypted secret upload and
never writes it to the generated config. The checked-in config has no public
route and cannot accidentally target a real bucket. `smoke` is an explicit
live test: set `CF_LIVE_SMOKE=1` and `CF_SMOKE_MINT_FILE` to a Python-generated
mint request whose snapshot already exists at the configured prefix. It
deploys a unique workers.dev Worker, verifies authorization, and removes that
Worker in a `finally` path without changing or deleting R2 data.

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
