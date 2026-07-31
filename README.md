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
13. `facts/auth/push_endpoint.py` and
    `facts/content/notification_preference.py`, then `notifications/`:
    authenticated notification state, durable post-publication discovery,
    current-authority derivation, and provider delivery.

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

## Mobile notifications

Mobile notification delivery is durable operational work outside repository
publication. A successful root CAS never invokes a notification callback and
never waits for a queue or provider:

```text
mobile installation -> sealed push_endpoint fact
user setting         -> notification_preference fact
new message          -> family-owned notification trigger
scheduled scanner    -> authenticated FactTree diff -> durable pending cursor
disposable wake      -> historical event proof + current authority join -> FCM
typed completion     -> pending-cursor CAS -> next FactTree page
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
cursor. On each bounded turn it pins one repository target root, diffs only
the authenticated `fact.type` postings in `FactTree` from its acknowledged
base, and selects families with a `notification_trigger` hook. It does not
read fact blobs, `FactOrder`, SQLite, ingress, or `RepositoryApplier`.

Bootstrap is explicit: normal launch initializes at the current repository
root, while a deliberate backfill starts at the empty tree. Scanning with an
absent cursor fails loudly. Each successful bootstrap creates a fresh random
generation so an old paused worker cannot complete identical work after state
loss and rebootstrap.

One canonical body contains only workspace, immutable deployment owner,
bootstrap generation, target-root object ID, and sorted trigger FIDs. Before
publishing, the scanner preserves the exact target root and body in
notification state and CASes one pending body OID with its exact successor.
There is at most one pending page per workspace. Queue, SQS, and local
deliveries are disposable wakes: every fair scheduled turn republishes the
byte-identical pending body until the worker records completion. A lost wake,
finite queue retention, ambiguous publish response, process crash, or scanner
race can duplicate work but cannot make discovery forget it. A zero-trigger
page advances directly.

The worker advances the pending cursor only after typed FCM acceptance or an
explicit current-authority or terminal outcome. A concurrent or stale delivery
is acknowledged only after notification state proves it is no longer the exact
pending item. Carrier acknowledgement by itself is never progress.

Scheduled scanning also fails loudly when state belongs to a different
immutable deployment or was deleted after bootstrap. It never guesses whether
to skip history or flood it again. Preserve notification state across updates
and rollback; state loss is an explicit recovery event, never implicit
reinitialization.

`NotificationWorker` resolves and hash-checks the historical event root from
notification state, authenticates every named event there, then separately
pins the current repository root. Its bounded authenticated join follows:

1. route key to candidate user preferences;
2. user and cell key to current preference values;
3. user key to all current endpoint facts.

It validates every posting and current suppression, membership/device
liveness, endpoint cell, and push-node binding through `RepositoryReader`.
Message facts carry canonical mention IDs; display text is never parsed. A
delayed retry therefore honors a later mute, removal, endpoint rotation, or
event suppression instead of replaying historical authority.

The handler invokes the worker only when the delivered body's SHA-256 equals
the cursor's sole pending OID. Noncurrent wakes are acknowledged; the scanner
will republish any work that later becomes current. For current work, missing
or corrupt historical data retries instead of clearing the cursor. Only after
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
FactTree scanner with notification-state R2 plus Queue-producer authority, a
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

Notification-state root bytes do not contain historical FactTree pages or
facts. Cloudflare `deploy` and `verify` therefore read both R2 lifecycle
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
update; the owner marker alone cannot authorize it. The FactTree cursor uses
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

For Cloudflare, set `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`,
`CF_WORKSPACE`, `CF_DEPLOYMENT_OWNER`, `CF_CANONICAL_BUCKET`,
`CF_NOTIFICATION_STATE_BUCKET`, `CF_FIREBASE_APPLICATION`,
`CF_FIREBASE_ENVIRONMENT`, `CF_FIREBASE_PROJECT_ID`,
`CF_PUSH_NODE_PUBLIC`, the matching `CF_PUSH_NODE_SECRET`, and
`FIREBASE_SERVICE_ACCOUNT_JSON`. Test-mode enablement additionally names the
same exact project in `CF_FIREBASE_TEST_PROJECT_ID`; the service-account JSON
must carry that bound project ID. The control token needs Worker and Queue
permissions plus Workers R2 Storage Write, which Cloudflare currently requires
even to read bucket lifecycle rules. First creation is explicit:

Every staging command holds one fail-fast lock for this worktree from config
generation through the last provider call. Wrangler and its `stage-locked`
build descendant inherit that ownership, so another process cannot mix fixed
config, bundle, secret, or manifest paths; an orphan provider child keeps the
lock until it exits, while a crashed process with no child releases it without
trusting or deleting the stale lock file. Use another worktree for a concurrent
release.

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
Authenticated residence after root CAS is the durable admission certificate;
no selected dependency path is retained afterward. A remote proof names its exact provider;
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

Family commands collect an `applied` or `noop` source immediately. File upload
runs descriptor and slice piles strictly in order, collecting each success
before creating the next source; `rejected`, retryable, and exceptional turns
stop the loop and retain the current source for inspection or retry. Thus even
a maximum-size file consumes at most one live journal slot. This is not yet a
durable whole-file workflow cursor: a crash between successful piles may
require rerunning the file command.

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

- canonical: the CAS register `root` and immutable authenticated `obj/`;
- ingress: create-only exact closed piles under
  `ingress/v1/workspaces/<ws64>/piles/<session32>/<uploader64>/<digest64>`.

The upload broker and repository Applier are separate Lambda stacks so their
mutation authorities remain segregated. The Applier has no public URL. The
broker can
read canonical authorization objects, sign one exact ingress PUT, and invoke
that private Applier; only the Applier can read ingress and CAS `root`.

Prerequisites:

- Python 3.13, AWS CLI, SAM CLI, and credentials for the target account;
- two distinct buckets;
- a Secrets Manager upload-session key ring;
- bucket policies that allow clients only their broker-issued create-only
  PUTs and allow the Applier role the exact canonical/ingress operations in
  its template.

Deploy the database-free Applier first:

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

Read its private `FunctionArn` stack output, then create the broker key ring:

```sh
python3 -m deploy.aws_upload_broker.manage keyring-create \
  --name poc16/upload-keyring \
  --deployment-id DEPLOYMENT \
  --issuer ISSUER \
  --ingress-bucket INGRESS_BUCKET \
  --region REGION \
  --expected-owner ACCOUNT_ID
```

The command prints the secret ARN and version ID. Deploy the public broker
with those values and the Applier ARN:

```sh
python3 -m deploy.aws_upload_broker.manage deploy --create \
  --stack poc16-upload-broker \
  --deployment-id DEPLOYMENT \
  --workspace WS64 \
  --canonical-bucket CANONICAL_BUCKET \
  --prefix workspaces/WS64 \
  --ingress-bucket INGRESS_BUCKET \
  --applier-function-arn APPLIER_FUNCTION_ARN \
  --issuer ISSUER \
  --keyring-secret-arn SECRET_ARN \
  --keyring-version-id VERSION_ID \
  --expected-owner ACCOUNT_ID \
  --region REGION
```

The client performs `OPEN`, PUTs the returned exact URL directly to S3, and
calls `FINALIZE`; the broker synchronously invokes the Applier. Neither stack
uses LIST, S3 notifications, SQS, or a schedule. A time-based ingress
lifecycle is safe because ingress is non-authoritative retry input; choose a
retention window long enough for the client retry policy. The deploy tools do
not create or mutate either bucket or its lifecycle. Stack removal deletes
compute and logs only, never either bucket or the external secret. Remove the
broker before the Applier when retiring both roles.

## Cloudflare deployment

Cloudflare likewise uses distinct canonical and ingress R2 buckets. The
broker has no native R2 binding: it receives a read-only canonical S3 token
and an ingress S3 signing token, while its code mints only exact create-only
PUTs. The separate ingress bucket is non-authoritative: misuse of its broader
parent credential can deny service, but cannot publish facts. The private,
route-less Applier Worker has native bindings to both buckets and alone owns
validation and the canonical root CAS. The public broker reaches it through a
Worker service binding. There is no bucket lock, queue, cron, or LIST drain.

Set the non-secret deployment inputs:

```sh
export CLOUDFLARE_ACCOUNT_ID=ACCOUNT32
export CF_UPLOAD_WORKSPACE=WS64
export CF_UPLOAD_CANONICAL_BUCKET=CANONICAL_BUCKET
export CF_UPLOAD_INGRESS_BUCKET=INGRESS_BUCKET
export CF_UPLOAD_DEPLOYMENT_OWNER=OWNER
export CF_UPLOAD_CANONICAL_BUCKET_PROFILE=dedicated-workspace
export CF_UPLOAD_INGRESS_BUCKET_PROFILE=dedicated-workspace
export CF_R2_BUCKET_ITEM_READ_PERMISSION_ID=READ_PERMISSION_ID32
export CF_R2_BUCKET_ITEM_WRITE_PERMISSION_ID=WRITE_PERMISSION_ID32
export CF_UPLOAD_ISSUER=ISSUER
export CF_UPLOAD_BROKER_DOMAIN=uploads.example.com
```

Set a deploy-only `CLOUDFLARE_API_TOKEN` with account-scoped Workers Scripts
Edit. `render` emits the two bucket-scoped access-policy documents; provision
their S3-compatible credentials and set
`CANONICAL_READ_ACCESS_KEY_ID`, `CANONICAL_READ_SECRET_ACCESS_KEY`,
`INGRESS_PARENT_ACCESS_KEY_ID`, `INGRESS_PARENT_SECRET_ACCESS_KEY`, and
`UPLOAD_SESSION_KEYRING`. The control token is used only by deployment and is
never a Worker secret. For first creation set:

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

Deployment installs and verifies the private Applier before exposing the
broker. Removal deletes the broker first and then the Applier, preserving both
R2 buckets and their independently managed lifecycle configuration:

```sh
python3 -m deploy.cloudflare_upload.manage remove
```

Generated provider claims intentionally say `live_verified: false` until the
live S3/R2 conformance suite has been run for the selected account and
credential profile. Building the adapters and deploy artifacts is not a claim
that this checkout has deployed them.

### AWS notifications

Notifications are a third, independent stack. It reads the canonical bucket,
writes only a separate notification-state prefix, and owns its SQS source and
DLQ. It does not receive the ingress bucket or canonical write authority. The
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
keep their authoritative `root` and `obj/` objects synchronously readable.
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

The honest `PileSender -> RepositoryApplier -> RepositoryReader` benchmark
path uses incremental snapshot extension. Each exact pile updates affected
Fact, Order, and Suppression routes and establishes immutable pages
immediately; it does not rebuild a client database or replay the full fact
corpus on every commit.

No 50k/200k fact-rate or file-throughput number is asserted here until the
benchmark is rerun. The corresponding bead requires facts/s at both sizes and
MiB/s for file transfer.
