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
python3 -m core create alice
python3 -m core status
```

`create` prints the workspace id. Commands accept a unique workspace-id
prefix:

```sh
python3 -m core post --ws WORKSPACE "hello"
python3 -m core msgs --ws WORKSPACE
python3 -m core send --ws WORKSPACE ./photo.jpg
python3 -m core files --ws WORKSPACE
python3 -m core get --ws WORKSPACE FILE_FID --out ./photo.jpg
python3 -m core remove --ws WORKSPACE FACT_FID
python3 -m core evict --ws WORKSPACE MEMBER_NAME
```

To add a peer, create an invite on the existing node and redeem it against a
second daemon:

```sh
python3 -m core invite --ws WORKSPACE
python3 -m core --node http://127.0.0.1:7200 join INVITE_LINK bob
```

Nodes synchronize on their daemon cadence. `sync --ws WORKSPACE` requests an
immediate dial, and `rebuild --ws WORKSPACE` reconstructs eligibility,
authenticated indexes, and application views around the stable local
admission catalog and published root.

The `ctl/*` endpoints are a trusted node-local control plane. Remote peers use
the authenticated `root`, `page`, `pile`, `poke`, and `mint` protocol routes.

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
