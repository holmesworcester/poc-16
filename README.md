# tiny p2p, POC-16

POC-16 is a fact-DAG replicated as independently advancing, device-signed
writer trees. Full peers, AWS Lambda, and Cloudflare Workers share the same
database-free authority, object, head, and HTTP core. A hosted owner target
needs an object store but no database. SQLite exists only as a disposable
full-client query and authorship accelerator.

The writer forest and the two-phase self-confined removal-path gate described
here are the running protocol. There is no predecessor authority repository or
compatibility route behind them.

The implementation is deliberately strict about authority and direction:

- `WriterLog` signs independently closed pile leaves and appends them to one
  device tree; `OpaqueHeadGate` advances only that device's slot.
- `RepositoryMirror` authenticates heads, Merkle extensions, and complete
  piles; `FactConsumer` admits their durable facts to an optional local
  projection.
- `PileSender` is the full peer's SQL-permitted close/sign boundary. Its normal
  send path publishes through `WriterLog`.
- `AccessGate` first accepts a device-signed historical-member proof to
  return only that member/device pair's current removal path, then accepts a
  second device-signed current-member proof carrying that path. Both judgments
  are discarded; neither synchronizes or mutates recipient authority state.
- Removal roots and proof nodes are private authenticated point-read state,
  never generic `obj/` or pack objects. A slot may record a root hash for audit,
  but only the self-confined path endpoint can read the private tree, and its
  witness does not contain neighboring members.
- `FullPeer` composes the complete core with identity, scheduling, Bao I/O,
  and disposable SQL; it owns no parallel admission or sync implementation.

There is no workspace-global mutable content root, ingress queue, upload
broker, or hosted pile-to-root compiler. Hosted devices upload immutable
objects directly and may CAS only their own writer slot.

## Read the code in this order

1. `core/fact.py`, then `facts/`: wire facts and family-owned policy.
2. `core/kernel.py`: the bounded, database-free closed-pile judgment.
3. `core/writer_tree.py`, `core/writer_head.py`, and
   `core/writer_repository.py`: per-device logs, owner publication, mirroring,
   and optional consumption.
4. `core/access.py`, `core/removal_path.py`, `core/removal_state.py`, and
   `core/suppression_tree.py`: discarded access judgments and the recipient's
   private authenticated removal state.
5. `core/http.py`, `core/http_stdlib.py`: the shared peer gate, then its
   standard-library HTTP server/byte adapter.
6. `full_peer/pile_sender.py`: stateful-client authorship and closure.
7. `full_peer/node.py`: `FullPeer`, the composition root, not a policy owner.
8. `full_peer/sql_store.py`: the sole SQL boundary.
9. `full_peer/daemon.py`, `full_peer/iroh_process.py`, `full_peer/iroh/`:
    process composition, child lifecycle, then the connection-only Iroh byte
    wrapper.
10. `adapters/` and `deploy/`: provider adaptation and isolated packaging.
11. `facts/auth/push_endpoint.py` and
    `facts/content/notification_preference.py`, then `notifications/`:
    authenticated notification state, durable post-publication discovery,
    current-authority derivation, and provider delivery.

[DESIGN.md](DESIGN.md) gives the data model, invariants, and failure semantics.
[AGENTS.md](AGENTS.md) contains repository ratchets.

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
`HttpGate`, whose bearer grant checks and normal GET/PUT/removal-path/mint/head
operations reach the same object-store, removal-tree, and writer-slot
interfaces as plain HTTP.
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
mode rejects plain-HTTP peer records, so an Iroh-enabled daemon cannot
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

`--url` remains rejected in Iroh mode. Direct HTTP remains an isolated local
diagnostic and test seam for the same gate; peer deployments use Iroh and one
daemon configuration cannot mix plain remote URLs with Iroh peer records.

## Repository flow

An ordinary FullPeer-authored unit follows this running content path:

```text
facts command
    -> PileSender closes dependencies and signs one canonical pile
    -> WriterLog verifies the exact closure and appends one Merkle leaf
    -> immutable pile, tree pages, and signed head are established
    -> a discarded device-signed current-member proof authorizes one device-slot CAS
    -> RepositoryMirror and FactConsumer repeat validation
    -> disposable SQL projects the accepted durable facts
```

Each writer has one CAS slot, so different writers commute. Same-writer losers
rebase on the newer signed head, and lost responses are reconciled by rereading
that slot. P2P sync lists slots, runs RBSR only for changed roots, and transfers
complete closed leaves. The section 7 hosted cut establishes the same immutable
objects directly, then advances only the local device's slot with the same
closed proof against the recipient's current removal root.

## Mobile notifications

Mobile notification delivery is durable operational work outside repository
publication. A successful writer-slot CAS never invokes a notification
callback and never waits for a queue or provider:

```text
mobile installation -> sealed push_endpoint fact
user setting         -> notification_preference fact
new message          -> family-owned notification trigger
scheduled scanner    -> validated writer-head diff -> durable pending cursor
disposable wake      -> pinned event bytes + current writer-forest join -> FCM
typed completion     -> pending-cursor CAS -> next writer-head page
```

An endpoint belongs to one workspace user and mobile installation. It carries
the selected push-node key and provider mapping, with the FCM target sealed to
that push node. The plaintext target never enters repository state. Rotation
publishes the replacement and an ordinary exact deletion of the prior endpoint
in one pile. Member and device removal make the endpoint unusable through the
same liveness rules as other facts.

Preferences are shared user state: `none`, `mentions`, or `all` globally, with
an optional per-channel override or `inherit`. An enrolled device replaces all
observed values using ordinary exact deletion. Concurrent active values meet
restrictively, so a concurrent mute wins. With no global preference the default
is `none`.

`NotificationDiscovery` has a separate operational object store and CAS
cursor. It lists the per-device head directory, pins one exact signed head,
and uses the shared `RepositoryMirror` and `FactConsumer` to validate its new
closed piles from that writer's acknowledged head. It then selects facts whose
family declares a `notification_trigger` hook. The cursor keeps authenticated
maps of acknowledged head OID by writer, already-emitted trigger FID, and exact
rejected head OID by writer. Repeated closure dependencies therefore do not
repeat notifications, and one malformed writer head is quarantined without
being acknowledged or blocking other writers. Discovery does not consult
SQLite, ingress, or a workspace-wide content root.

Bootstrap is explicit: normal launch validates all current writer heads and
marks their existing triggers seen, while a deliberate backfill starts with
empty acknowledged/seen maps. Scanning with an absent cursor fails loudly.
Each successful bootstrap creates a fresh random generation so an old paused
worker cannot complete identical work after state loss and rebootstrap.

One canonical body contains only workspace, immutable deployment owner,
bootstrap generation, writer device, acknowledged/base head, pinned target
head, and sorted `(fid, fact-object OID)` trigger references. Before
publishing, the scanner copies those exact event bytes and the hint into
notification state, then CASes one pending body OID with its exact seen-map
successor. Writer validation itself is discarded until that cursor CAS, so a
crash after validation cannot make a retry skip unacknowledged work. There is
at most one pending page per workspace. Queue, SQS, and local deliveries are
disposable wakes: every fair scheduled turn republishes the byte-identical
pending body until the worker records completion. A lost wake, finite queue
retention, ambiguous publish response, process crash, or scanner race can
duplicate work but cannot make discovery forget it. A zero-trigger validated
head advances directly.

The worker advances the pending cursor only after typed FCM acceptance or an
explicit current-authority or terminal outcome. A concurrent or stale delivery
is acknowledged only after notification state proves it is no longer the exact
pending item. Carrier acknowledgement by itself is never progress.

Scheduled scanning also fails loudly when state belongs to a different
immutable deployment or was deleted after bootstrap. It never guesses whether
to skip history or flood it again. Preserve notification state across updates
and rollback; state loss is an explicit recovery event, never implicit
reinitialization.

`NotificationWorker` hash-checks the scanner-preserved event bytes from
notification state, then reconstructs a discarded current query snapshot by
mirroring every current writer head through the same `FactConsumer`. Its
bounded authenticated join follows:

1. route key to candidate user preferences;
2. user and cell key to current preference values;
3. user key to all current endpoint facts.

It validates every posting and current suppression, membership/device
liveness, endpoint cell, and push-node binding through a small in-memory index
built directly from that validated forest. No aggregate repository root is
compiled even temporarily.
Message facts carry canonical mention IDs; display text is never parsed. A
delayed retry therefore honors a later mute, removal, endpoint rotation, or
event suppression instead of replaying historical authority.

The handler invokes the worker only when the delivered body's SHA-256 equals
the cursor's sole pending OID. Noncurrent wakes are acknowledged; the scanner
will republish any work that later becomes current. For current work, missing
or corrupt pending event data retries instead of clearing the cursor. Only after
FCM accepts every selected request, current authority selects no delivery, or
an explicit unregistered FID or locally malformed sealed endpoint is terminal
does the handler CAS to the stored successor. CAS ambiguity is resolved by
rereading the exact pending OID. Configuration errors, provider failures, and
unknown outcomes remain pending. A crash after acceptance or partial success
can resubmit the same request. Each installation cell has a stable delivery ID
and platform collapse ID; the mobile client must deduplicate it. FCM acceptance
is not proof that APNs or Android presented the notification.

AWS composes the scanner and worker as separate Lambdas around S3 notification
state and SQS. Cloudflare composes separate Workers around R2 state and a
Cloudflare Queue. A full peer can run the same shared scanner and worker with
filesystem notification state and an in-process wake. Provider receipts and
queue metadata carry no repository, endpoint, or completion authority. Queue
and DLQ retention provide retry latency and operational headroom only; fair
scans recreate wakes from the durable pending cursor. The cursor and immutable
notification-state objects remain deployment continuity and must not expire or
be silently discarded.

The Cloudflare artifact under `deploy/cloudflare_notifications` divides that
composition into four private Workers: a mutation-free canonical R2 reader, a
writer-head scanner with notification-state R2 plus Queue-producer authority, a
Queue consumer with canonical reads, the scanner's narrow
`get_bounded/pending/complete` service, and the selected push-node secret, and a
small FCM HTTP v1 bridge which alone holds the Firebase service account. The
consumer has no R2 binding, raw cursor CAS, or Firebase credential. Only the
scanner service can advance the exact current pending OID. The FCM bridge has
no repository binding or public route and targets Firebase installation IDs
through `fid`. Generic `INVALID_ARGUMENT`, project/auth failures, quotas,
timeouts, and malformed provider responses retry; only an exact typed FCM
`UNREGISTERED` detail makes that FID terminal.

The 1 KiB ceiling applies only to the small derived FCM data map (stable IDs,
channel, and event kind), not to workspace message facts, message text, files,
or closed piles. Exact/one-over tests include Base64 expansion, the stable
delivery ID, and JSON keys, keeping every locally accepted FCM data map below
the provider's 4,096-byte limit.

Notification-state root bytes do not contain pinned writer trees or their
closed piles; only pending event bytes are copied there. Cloudflare `deploy`
and `verify` therefore read both R2 lifecycle
configurations and reject an enabled deletion rule overlapping either the
notification-state prefix or its canonical workspace prefix. R2 Standard and
Infrequent Access storage remain synchronously readable, so that lifecycle
transition is safe; an unknown future class that requires asynchronous restore
fails closed. The tool never changes lifecycle configuration or deletes either
bucket or Queue.
Provisioning uses the free-plan-compatible one-day Queue retention. Paid
retention can provide more operational headroom, but is not a correctness
requirement because every fair scan recreates the pending wake from R2.

All four Workers carry one SHA-256 semantic delivery identity over the
Cloudflare account, workspace and canonical repository, notification-state
namespace, push-node public key, exact Firebase
application/environment/project, and completion domain. Queue, DLQ, schedule,
wake, and Worker names are deliberately excluded: they are replaceable
infrastructure, not authority to declare delivery complete. The Workers also
carry the exact staged software digest, one shared high-entropy release ID,
their exact role, and enablement state. The scanner checks the reader's
complete release marker before discovery. The consumer checks the reader,
scanner, and FCM markers before each batch, then passes its expected marker
into the same FCM RPC that
may issue the irreversible provider request. The FCM boundary rejects release
skew inside that call. A partial or competing four-Worker rollout can therefore
delay work but cannot send through a mismatched release. The deploy tool checks
these markers and the human owner before any update. It also compares each
immutable provider version's complete binding inventory, default and named
handlers, runtime flags, and exports with the generated least-authority role;
unknown, missing, duplicated, or redirected authority fails closed without
reading secret values. Before effects or a successful verification it checks
the account-level Worker inventory, Workers.dev and preview subdomain state,
and complete custom-domain result page, so a public or additional invocation
surface cannot hide behind otherwise correct release markers.

Changing a semantic identity binding is a drain/migration, not an in-place
update; the owner marker alone cannot authorize it. The writer-head cursor uses
that same identity as its owner. Equivalent scanners may therefore race or
fail over through replacement Queues while sharing the durable pending cursor,
but a different repository, state namespace, push node, Firebase route, or
completion domain cannot advance it.

The Firebase service-account key is deliberately not part of that immutable
identity or the mobile launch record. Rotating it still creates a new immutable
Worker version and shared release ID and repeats the exact-version mobile test.
The tool never uses `wrangler secret put`, because that command creates and
immediately deploys an untested version; secrets enter only during an inert
`versions upload --secrets-file`. Authentication or configuration failure
returns `RETRY` and leaves the durable pending cursor unchanged. A different
project is an identity change and cannot be substituted in place.

The preference commands are available now:

```sh
python3 -m full_peer content.notification.set_global WORKSPACE all
python3 -m full_peer content.notification.set_channel WORKSPACE general none
python3 -m full_peer content.notification.list WORKSPACE
python3 -m full_peer auth.push_endpoint.list WORKSPACE
```

An experimental FullPeer notification process must initialize every workspace
explicitly after the daemon starts. `current` is the normal first launch and
does not notify for existing history; `backfill` deliberately begins at the
empty tree:

```sh
python3 -m full_peer --node http://127.0.0.1:7101 \
  peer.notifications.bootstrap WORKSPACE current
# Or, only when historical delivery is intentional:
python3 -m full_peer --node http://127.0.0.1:7101 \
  peer.notifications.bootstrap WORKSPACE backfill
```

Repeating the same mode is harmless. A conflicting mode, absent state during
scanning, or a cursor owned by another deployment fails closed. The periodic
scanner runs after bootstrap; `peer.notifications.wake` is only a latency hint.

Endpoint registration still needs the mobile integration to obtain permission
and a current Firebase Installation ID, seal that FID with
`notifications.seal_target`, and durably publish the newest endpoint fact. Do
not pass an unsealed target to the fact command.

All notification deployments remain disabled by default. Fake-provider and
deployment tests establish crash/retry semantics, but production enablement is
blocked on real iOS and Android registration, foreground/background launch,
presentation deduplication, and deploy/smoke/remove records.

Run the deterministic fact, discovery, worker, provider, and deployment
coverage with:

```sh
python3 -m pytest -q tests/test_notification*.py tests/test_*notifications*.py
```

Cloudflare notification deployment requires Python 3.13 or newer, `uv`, and
Node.js with `npx`. Run `uv sync --group dev` in
`deploy/cloudflare_notifications` once; the lock selects
workers-py/pywrangler 1.16.0, while the control tool invokes the pinned
`wrangler@4.118.0` through `npx --yes` (which therefore needs that package in
its cache or registry access).

For Cloudflare, set `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`,
`CF_WORKSPACE`, `CF_DEPLOYMENT_OWNER`, `CF_CANONICAL_BUCKET`,
`CF_NOTIFICATION_STATE_BUCKET`, `CF_FIREBASE_APPLICATION`,
`CF_FIREBASE_ENVIRONMENT`, `CF_FIREBASE_PROJECT_ID`,
`CF_PUSH_NODE_PUBLIC`, the matching `CF_PUSH_NODE_SECRET`, and
`FIREBASE_SERVICE_ACCOUNT_JSON`. Test-mode enablement additionally names the
same exact project in `CF_FIREBASE_TEST_PROJECT_ID`; the service-account JSON
must carry that bound project ID. The control token needs Worker and Queue
permissions plus Workers R2 Storage Write, which Cloudflare currently requires
even to read bucket lifecycle rules.

Every staging command holds one fail-fast lock for this worktree from config
generation through the last provider call. Wrangler and its `stage-locked`
build descendant inherit that ownership, so another process cannot mix fixed
config, bundle, secret, or manifest paths; an orphan provider child keeps the
lock until it exits, while a crashed process with no child releases it without
trusting or deleting the stale lock file. Use another worktree for a concurrent
release. First creation is explicit:

```sh
export CF_CREATE=1
python3 -m deploy.cloudflare_notifications.manage provision
python3 -m deploy.cloudflare_notifications.manage build
python3 -m deploy.cloudflare_notifications.manage deploy
python3 -m deploy.cloudflare_notifications.manage bootstrap-current
# Wait for one successful scheduled scanner invocation, then seal the mode.
python3 -m deploy.cloudflare_notifications.manage seal-bootstrap
python3 -m deploy.cloudflare_notifications.manage verify
```

This first deployment is disabled. On a genuinely empty account, `deploy`
checks the Queue only; it does not query or mutate Cron triggers until the
scanner Worker exists. Candidate versions are uploaded in dependency order
(FCM boundary, reader, scanner, consumer), then promoted as one disabled
release. No ordinary `wrangler deploy` or `wrangler secret put` is used.

`deploy` always installs the scanner in sealed mode; scanning an absent cursor
then fails instead of guessing whether to skip or replay history.
`bootstrap-current` temporarily schedules initialization even while delivery
is disabled and skips existing triggers. Use `bootstrap-backfill` instead only
when replaying existing triggers is deliberate. Both operations are idempotent
for the chosen mode. After the Cloudflare scheduled invocation succeeds,
`seal-bootstrap` restores `none`; `verify` rejects a Worker still carrying a
bootstrap mode. The control tool cannot read the private R2 binding, so the
successful scheduled invocation—not merely local config generation—is the
bootstrap evidence. A later missing cursor remains a loud runtime fault and
requires another explicit recovery decision.

Disabled `verify` reconstructs the release from the four exact active Worker
versions and does not require a production manifest or mobile launch records;
it requires Queue and Cron effects to remain detached. Production `verify`
instead requires the protected manifest, exact launch records, and attached
effects.

Production enablement additionally requires `CF_IOS_LAUNCH_RECORD` and
`CF_ANDROID_LAUNCH_RECORD`. A production candidate is an immutable release
manifest containing one shared release ID, one source digest, and the exact
Cloudflare version ID for each of the four Workers. Use a new protected
manifest path for each candidate; `prepare-launch` refuses to overwrite one.

`stage-launch-fcm` promotes only that exact FCM version while Queue and Cron
effects remain detached and the other three Workers remain on the disabled
incumbent. `deploy-launch-harness` then creates a temporary Workers.dev route
whose only capability is a service binding to the FCM boundary. Cloudflare RPC
bindings cannot pin a version, so the FCM boundary reads its immutable runtime
version-metadata ID before calling Firebase and returns that ID in the same
accepted RPC result. The harness accepts only the exact FCM version recorded in
the release manifest; an active-version switch during a device test therefore
fails closed even when both versions carry identical release markers. The
route requires a 32-byte bearer secret and a canonical, at-most-16-KiB
`Content-Length`; it has no R2 or Queue binding. Its name is derived only from
the Cloudflare account and workspace, not an operator override. Give the
output of `launch-binding` to the physical-device harness. It writes each
record with `deploy.notification_launch.launch_record()` only after that exact
candidate causes the corresponding real device to launch:

```sh
export CF_NOTIFICATIONS_ENABLED=1
export CF_NOTIFICATION_RELEASE_MANIFEST=/protected/cf-notify-release.json
python3 -m deploy.cloudflare_notifications.manage prepare-launch
python3 -m deploy.cloudflare_notifications.manage stage-launch-fcm
export CF_NOTIFICATION_HARNESS_SECRET="$(openssl rand -hex 32)"
export CF_WORKERS_SUBDOMAIN=your-workers-subdomain
python3 -m deploy.cloudflare_notifications.manage deploy-launch-harness
python3 -m deploy.cloudflare_notifications.manage launch-binding
export CF_IOS_LAUNCH_RECORD=/protected/ios.json
export CF_ANDROID_LAUNCH_RECORD=/protected/android.json
python3 -m deploy.cloudflare_notifications.manage remove-launch-harness
python3 -m deploy.cloudflare_notifications.manage deploy
python3 -m deploy.cloudflare_notifications.manage verify
```

Both records bind the Cloudflare account, deployment identity, workspace,
R2/Queue locations, push-node ID, Firebase app/environment/project, and exact
source digest, shared release ID, and four Worker version IDs. Production
`deploy` validates those records before provider access, revalidates every
candidate and active version around each promotion, promotes those same IDs,
requires the deterministic launch harness to be absent before and after
effect activation and after rollback, and only then leaves the Queue consumer
and Cron schedule attached. Harness removal likewise verifies exact absence.
A partial or concurrent four-Worker rollout fails closed. The old
`CF_MOBILE_LAUNCH_GATE=1` flag has no effect.

For an emergency traffic stop, `manage disable` performs only ownership checks
and detaches Cron followed by the Queue consumer; it does not need Firebase or
push secrets, inspect R2 lifecycle, build, upload, or promote code. An FCM call
already in progress may still finish. A durable code-level disable uses the
incumbent source and manifest with `CF_NOTIFICATIONS_ENABLED=0` and `deploy`;
that promotes the FCM boundary first. For an upgrade, establish that disabled
incumbent, select a fresh manifest path for the new source, then repeat
`prepare-launch` through physical testing and production `deploy`.

Cloudflare's version model and machine-readable upload evidence are documented
under [Workers Versions and Deployments](https://developers.cloudflare.com/workers/versions-and-deployments/),
[Version metadata bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/),
[Wrangler commands](https://developers.cloudflare.com/workers/wrangler/commands/workers/),
and [Wrangler system environment variables](https://developers.cloudflare.com/workers/wrangler/system-environment-variables/).

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
workspace facts. The pile supplies the one-time validation closure.
Authenticated residence after writer-slot acceptance is the durable admission
certificate; no selected dependency path is retained afterward. A remote
proof names its exact provider; the hosted consumer validates the signed
writer tree and closed pile, then applies current suppression scopes. Stateful
commands assemble interchangeable candidates from their disposable SQL
projection.

## Client persistence

`full_peer/sql_store.py` is the sole SQLite boundary, and its projection is
intentionally small:

```text
facts(fid, blob)                  current serialized form, keyed by source fid
fact_index(kind, k0, k1, src)    every lookup and derived projection row
projected_heads(device, head_oid) replay checkpoint per accepted writer
```

The combined index includes type, canonical fact key, every explicit ref,
every family offer, every declared suppression/current-liveness scope, and
current action bindings. It contains no validation verdict, proof, rank,
selected dependency edge, eligibility label, or dormant state. Family queries
assemble views from those rows. There are no family-specific application
tables and no SQL receiving authority.

The database can be deleted and rebuilt from locally accepted writer slots
without network access or any change to protocol state. `facts.APP_VERSION`
is the one projection version. A mismatch discards SQL and replays exact source
facts through the running family re-extraction/index code. Current-shape facts
keep their ordinary canonical encoding. An explicitly retained legacy shape is
stored as one canonical current-form envelope keyed by its immutable source
fid; that envelope also carries the exact source value needed to reproduce a
signed closure. Queries and the generic index see only the current vocabulary.
There are no table migrations, version graphs, or generic old-protocol codecs.

## Hosted owner publication

Peers do not proxy large immutable bodies through Lambda or a Worker. Under
the section 7 cut, a stateful writer prepares the same objects it uses locally,
then publishes:

```text
mint one current sync grant from a device-signed proof carrying the current removal path
  -> POST /obj/open or /pack/open for an exact create-only PUT
  -> PUT missing pile/tree/head objects directly to S3 or R2
  -> ordinary head: POST /head/<proposed-head-oid> with an exact closed proof
  -> control head: issue an exact base/head/control-pile permit while current
  -> control head: commit the permit, joining removal before the head CAS
  -> CAS heads/<workspace>/<device>
```

`OwnerPublisher` compares the local and hosted signed writer trees, transfers
only the missing suffix, establishes the signed head last, and submits a proof
that binds the observed base and proposed head. A retry rereads the one slot;
an exact repeat is a no-op, and a same-writer race requires rebase. Different
writers never share a mutable content key.

The section 7 hosted gate will validate membership, member-signed device ownership,
non-removal, expiry, and the exact proposed head against its pinned removal
root. It checks that
the proposed head object exists, but deliberately does not parse or validate
the writer's content tree. A consuming peer does that later through
`RepositoryMirror` and `FactConsumer`.

There is no ingress namespace, upload session, journal, broker, finalize call,
bucket event, content queue, or hosted pile compiler. File descriptors and Bao
slices remain ordinary independently verifiable facts. Optional concat packs
are transfer layouts only: their small index locates exact pile bytes, whose
content address, signed pile, and Bao proof remain authoritative.

## Object-store contract

The algorithm depends on properties available from current S3 and R2
adapters:

- bounded strong reads of an exact key, rejecting one-over before full
  materialization;
- create-only immutable writes with collision verification;
- linearizable conditional replacement of one exact small key;
- an opaque version token returned with the exact bytes read; and
- bounded paginated LIST for writer-slot candidate discovery.

`get_bounded` is mandatory and cannot be a compatibility wrapper around an
unbounded whole-object GET. LIST is never an authority source: every returned
slot, head, page, pile, and fact is independently authenticated.

The opaque provider version token is not a content hash. Code uses it only as
the compare capability for CAS; semantic identities are SHA-256 addresses of
canonical bytes. Correctness never depends on ETag being MD5-like or on a
database.

The mutable protocol keys are `removal` and one
`heads/<workspace>/<device>` slot per writer. Optional source-local layout
slots may be replaced independently. The separate notification-state store
uses `cursor`. There is no mutable key named `root` and no shared content CAS.

The filesystem adapter is a stronger local implementation of the same
contract. S3 uses conditional requests through `adapters/s3`; the Cloudflare
runtime uses the native R2 binding through `adapters/r2/worker.py`.

## AWS deployment

AWS uses one externally owned S3 bucket and one Lambda stack. The Lambda runs
the shared `HttpGate` with the `owner` capability: it can read the recipient's
removal tree and writer forest, create content-addressed objects/packs, and
conditionally advance writer slots. A public `/removal/bootstrap` accepts only
an original direct-member CLEAR closure. A control-bearing head first obtains
a stateless permit bound to its current proof, exact base/head, and immutable
control piles. Permit commit evaluates those control-only piles, joins their
private removal cells, and only then attempts the head CAS. Ordinary content
and malformed control piles are rejected, and exact retries are idempotent. A
closed head proof confines each slot update to its authenticated device. The
Function URL adapter applies named request and aggregate control-pile bounds so
base64 expansion and event metadata remain within Lambda's buffered invocation
envelope; other metadata requests remain capped at 512 KiB. The template creates
the grant secret, role, Function URL, logs, and alarm; it never creates or
deletes the bucket.

Prerequisites are Python 3.13, AWS CLI, SAM CLI, Docker for the reproducible
build, and credentials for the target account. Inspect the deny-guard policy
that belongs on the existing bucket, then deploy:

```sh
python3 -m deploy.aws_lambda.manage bucket-policy \
  --bucket BUCKET --prefix workspaces/WS64 \
  --profile single-gateway --gateway-principal GATEWAY_ROLE_ARN

python3 -m deploy.aws_lambda.manage deploy --create \
  --stack poc16-edge --deployment-id edge-west-2 \
  --workspace WS64 --bucket BUCKET --prefix workspaces/WS64 \
  --expected-owner ACCOUNT_ID --region REGION
```

Use `--update` only for the exact owned stack. `live-smoke` creates a unique
temporary stack, exercises authority minting, reads, direct owner publication,
and denials against a supplied full-peer state, then removes compute again:

```sh
python3 -m deploy.aws_lambda.manage live-smoke \
  --state ./state --workspace WS64 --bucket BUCKET \
  --prefix workspaces/WS64 --expected-owner ACCOUNT_ID --region REGION
```

Removal deletes the owned stack's compute, secret, logs, and alarms, never the
external bucket. There is no ingress bucket, upload broker, private applier,
S3 event, content SQS queue, or schedule.

## Cloudflare deployment

Cloudflare uses one R2 bucket and one Python Worker running the same `HttpGate`
with the same `owner` capability. Small metadata operations use the native R2
binding. Large GETs use scoped R2 S3/SigV4 URLs; large create-only PUTs use a
short-lived HMAC ticket at a minimal streaming Worker route backed by the
native R2 binding. Neither body enters the Python Worker heap. The owner
gateway uses the same exact control-head permit to join private `removal` state
before advancing its writer slot, but it has no generic authority publication
route and no delete path. Control-pile count and aggregate bytes are bounded by
named portable constants; ordinary metadata remains capped at 512 KiB.

Set the non-secret deployment inputs:

```sh
export CLOUDFLARE_ACCOUNT_ID=ACCOUNT32
export CF_WORKSPACE=WS64
export CF_R2_BUCKET=BUCKET
export CF_R2_PREVIEW_BUCKET=PREVIEW_BUCKET
export CF_STORE_PREFIX=workspaces/WS64
export CF_DEPLOYMENT_OWNER=OWNER
export CF_ROUTE='sync.example.com/*'
export CF_R2_ENDPOINT='https://ACCOUNT32.r2.cloudflarestorage.com'
export CF_PACK_PUT_ENDPOINT='https://sync.example.com'
```

Set a deploy-only `CLOUDFLARE_API_TOKEN`, then provide `GRANT_SECRET` and
`PACK_TICKET_SECRET` as base64-encoded 32-byte values plus bucket-confined
`R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`. The R2 credentials exist only
to issue exact short-lived direct requests; the control token is never a
Worker secret. For first creation set:

```sh
export CF_CREATE=1
```

Build and run the real local workerd boundary before deployment:

```sh
python3 -m deploy.cloudflare_worker.manage test
python3 -m deploy.cloudflare_worker.manage build
python3 -m deploy.cloudflare_worker.manage deploy
```

Removal verifies ownership and removes only the Worker, preserving R2:

```sh
python3 -m deploy.cloudflare_worker.manage remove
```

Generated provider claims intentionally say `live_verified: false` until the
live S3/R2 conformance suite has been run for the selected account and
credential profile. Building the adapters and deploy artifacts is not a claim
that this checkout has deployed them.

### AWS notifications

Notifications are a separate operational stack. It reads the writer forest
and removal-tree objects, writes only a separate notification-state prefix, and
owns its SQS source and DLQ. It has no canonical mutation authority. The
Secrets Manager value has this exact shape; each `credential` is one Firebase
service-account document and `push_node_seed` is 32 random bytes encoded as 64
lowercase hex characters:

```json
{
  "firebase_apps": [
    {
      "application": "APP",
      "environment": "production",
      "credential": {"type": "service_account"}
    }
  ],
  "push_node_seed": "64_HEX_CHARACTERS"
}
```

Create that secret from a protected file. Record its exact Secrets Manager
`VersionId`; deployments never follow `AWSCURRENT`. Every Firebase credential
must name its `project_id`. The deploy tool derives a stable delivery domain
from the push-node public key and the sorted `(application, environment,
project_id)` routes. Credential bytes and secret versions are deliberately not
part of that identity.

Both the canonical repository and dedicated notification-state bucket must
keep their removal-root, writer-head, cursor, and reachable `obj/` objects
synchronously readable.
The deploy preflight reads both lifecycle configurations. For rules whose S3
prefix overlaps those objects it rejects expiration and any transition except
`STANDARD_IA`, `ONEZONE_IA`, or `GLACIER_IR`; Glacier Flexible Retrieval, Deep
Archive, Intelligent-Tiering, and unknown classes fail closed. Rules with a
provably disjoint prefix do not block deployment. Then create the stack
disabled:

```sh
python3 -m deploy.aws_notifications.manage deploy --create \
  --stack-name poc16-notifications \
  --deployment-id DEPLOYMENT \
  --workspace WS64 \
  --canonical-bucket CANONICAL_BUCKET \
  --canonical-prefix workspaces/WS64 \
  --state-bucket NOTIFICATION_STATE_BUCKET \
  --state-prefix workspaces/WS64/notifications \
  --expected-owner ACCOUNT_ID \
  --notification-secret-arn SECRET_ARN \
  --notification-secret-version-id SECRET_VERSION_ID \
  --region REGION
```

The disabled stack still contains both Lambdas, the source queue, the DLQ, and
their IAM roles. Its schedule and SQS event source are disabled, so no
production delivery runs. Initialize the durable cursor explicitly; `current`
is the normal first deployment and `backfill` is an intentional historical
replay:

```sh
python3 -m deploy.aws_notifications.manage bootstrap --current \
  --stack-name poc16-notifications \
  --deployment-id DEPLOYMENT --region REGION
```

Direct smoke is an explicit operator path and is permitted only while
production is disabled. The Lambda has no public route; AWS IAM is invocation
authority, and the command requires an explicit acknowledgement that it will
contact live FCM. It bypasses SQS and does not complete notification cursor
state. A pass proves current authority and at least one FCM acceptance; it does
not prove that iOS or Android launched:

```sh
python3 -m deploy.aws_notifications.manage direct-smoke \
  --stack-name poc16-notifications --deployment-id DEPLOYMENT \
  --hint-file notification-hint.json --confirm-live-fcm --region REGION
```

Production remains fail-closed until a real-device harness has observed both
an iOS and an Android launch and written one canonical record per platform.
Obtain the binding directly from the owned, disabled stack; this command
refuses an enabled deployment and validates both numeric Version ARNs against
the stack's partition, region, and account:

```sh
python3 -m deploy.aws_notifications.manage launch-binding \
  --stack-name poc16-notifications --deployment-id DEPLOYMENT \
  --region REGION > launch-binding.json
```

Records have the exact shape below. The harness must use that binding unchanged
and call `deploy.notification_launch.launch_record()` only after the
corresponding device test passes:

```json
{"binding":{"aws_partition":"aws","canonical_bucket":"CANONICAL_BUCKET","canonical_prefix":"workspaces/WS64","delivery_domain_id":"DELIVERY_DOMAIN_ID","delivery_version_arn":"DELIVERY_VERSION_ARN","deployment_id":"DEPLOYMENT","expected_bucket_owner":"ACCOUNT_ID","notification_secret_arn":"SECRET_ARN","notification_secret_version_id":"SECRET_VERSION_ID","notification_state_bucket":"NOTIFICATION_STATE_BUCKET","notification_state_prefix":"workspaces/WS64/notifications","provider":"aws","push_node_id":"PUSH_NODE_ID","scanner_version_arn":"SCANNER_VERSION_ARN","software_digest":"SOFTWARE_DIGEST","stack_account_id":"ACCOUNT_ID","stack_id":"FULL_STACK_ARN","workspace":"WS64"},"platform":"ios","result":"passed","schema":"poc16-mobile-notification-launch-v1"}
```

Repeat `deploy` with `--update --enable`, the same immutable arguments, and
`--ios-launch-record IOS.json --android-launch-record ANDROID.json`. An enabled
deployment rejects a changed software digest. Enable is a traffic-only
operation: it does not stage or build source and does not run SAM. The tool
creates a previous-template CloudFormation change set, requires its resolved
traffic parameter to match the requested state and every other parameter to
reuse its existing value, requires its only resource changes to be the
EventBridge schedule and SQS event-source switch, rechecks the exact disabled
stack, and only then executes it. The disabled stack must also match the
requested secret version, schedule, concurrency, retry, logging, and alarm
settings; a same-domain request for a not-yet-deployed credential version does
not silently enable the incumbent. It also reads the live numeric Lambda
versions, SQS mapping, EventBridge rule, and target. Exact code hash,
role-specific environment, role ARN, handler, runtime, memory, timeout,
architecture, function-level reserved concurrency, schedule, unfiltered SQS
wakes, and an input-free schedule target must match. Unknown Lambda or
EventBridge behavior fields, including durable or per-tenant execution, fail
closed. A concurrent stack update or out-of-band provider drift fails closed.
The same checks run after every traffic transition and release.

Upgrade in three distinct steps: disable using the incumbent code, deploy the
new code after the stack is already disabled, then repeat both launch tests
against that digest and enable it. A release update builds and packages first,
downloads the exact SAM-uploaded ZIPs, and passes each provider Base64 SHA-256
to `AWS::Lambda::Version.CodeSha256` before creating the inspected
CloudFormation change set. A mismatched or raced artifact therefore cannot be
published as the named Version. The update keeps `Enabled=false`, rechecks the
exact disabled predecessor, and requires a changed software release to publish
new scanner and delivery Versions.

A same-project credential rotation is narrower: create a new secret version
with the same push key and Firebase route projects, disable, and deploy it. The
delivery domain and cursor owner remain stable; only the delivery function and
numeric Version may change. The scanner has no Firebase secret ARN, version, or
push key in its environment. Changing a route project or push key fails closed
as a different delivery authority. Either kind of release invalidates the old
mobile launch evidence, so rerun both real-device tests before enabling. SQS,
EventBridge, bootstrap, and direct smoke all invoke immutable numeric Version
ARNs; no unqualified function ARN is an output. Function and Version resources
use `FunctionUpdate` runtime management, and live preflight verifies the exact
published configuration before activation.

The source queue retains wakes for four days and the DLQ for fourteen. Queue
identity is not authoritative: a lost wake is rediscovered by the fair scanner.
The durable record is the partition- and namespace-bound notification cursor,
whose owner also binds the stable delivery domain and FCM-acceptance completion
protocol.
Redrive is allowed only while production delivery is disabled:

```sh
python3 -m deploy.aws_notifications.manage redrive \
  --stack-name poc16-notifications --deployment-id DEPLOYMENT \
  --max-per-second 10 --region REGION
```

Removal never trusts approximate SQS depth. First use the traffic-only
`deploy --update --disable` operation, allow or redrive work as appropriate,
then explicitly accept carrier destruction. Emergency disable needs only the
stack name, deployment ID, and optional AWS region/profile; it does not stage,
build, or compare a local source checkout. Removal preserves both external
buckets and the secret but can discard any wakes still in SQS:

```sh
python3 -m deploy.aws_notifications.manage deploy --update --disable \
  --stack-name poc16-notifications --deployment-id DEPLOYMENT --region REGION
```

```sh
python3 -m deploy.aws_notifications.manage remove \
  --stack-name poc16-notifications --deployment-id DEPLOYMENT \
  --destroy-carrier --region REGION
```

## Current performance status

The current P2P benchmark measures `WriterLog -> RepositoryMirror ->
FactConsumer`: listed heads, changed-tree RBSR, exact pile transfer, and full
receiver validation. Hosted owner publication uses the same writer-tree diff
without receiver validation.

No 50k/200k fact-rate or file-throughput number is asserted here until the
benchmark is rerun. The corresponding bead requires facts/s at both sizes and
MiB/s for file transfer.
