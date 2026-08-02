# POC-16 engineer guide

Read `README.md` for current operation and `DESIGN.md` for the accepted target
protocol and trust boundaries. `poc-16-iq2` tracks the transition from the
running workspace-wide content root to per-device writer logs and a shared
head directory; `poc-16-iq2.9` is the one-way cutover gate. Do not deepen the
predecessor's global-root assumptions or claim that target behavior is already
deployed. Those files and this guide are the repository's only Markdown
authorities. Track unfinished work in beads, never in a Markdown TODO ledger.

The target `AuthorityGate` is actor-neutral: hosted and full peers run the same
implementation. Every semantic evaluation starts from exactly one canonical
closed pile. Pull evaluates a complete writer-tree leaf and may retain its
durable facts; push evaluates the same wire value only to check conditions in
fresh in-memory or temporary SQLite, then discards the pile judgment and every
derived row. A pushed pile never enters recipient fact space. Local persistent
SQL, Python fact objects, provider identity, and Iroh identity may not shortcut
this boundary. Provider storage bindings, process scheduling, and optional
content consumption are the only hosted/full-peer composition differences;
pile bytes, evaluator, gate, temporary schema, family queries, and typed result
must remain identical.

Target writer trees reuse the canonical bounded persistent Merkle-map style.
Each logical leaf names exactly one independently closed pile; range or diff
pagination stops only between leaves. Every pile is signed directly by its
publishing writer device. The pile signature authenticates the portable pile;
the device-signed writer head and Merkle inclusion path authenticate its place
in that device's tree. A cold receiver must validate the pile signature, head,
inclusion, and complete pile without an adjacent leaf or prior cache state.

Cloud publication is owner-confined: a device may populate and advance only
its own registered writer log, and hosted storage does not validate those
content bytes. Full-peer replication is validate-first peer sync: a peer may
serve all writers' piles it has consumed successfully, preserves every original
pile signature, signed head, and writer identity, and never treats its prior
judgment as a receiver's admission certificate. Do not add a combined P2P
content log or allow one device to upload relayed content into another device's
cloud writer log.
P2P exchanges the per-device head directory and runs the common RBSR algorithm
only for changed device roots. Add a combined peer inventory tree only after
measurements show that this forest is inadequate.

Start a work session with:

```sh
bd prime
bd ready
git status --short
```

## Current transition capabilities

The predecessor below still pushes ordinary piles into recipient storage. That
behavior is not target push semantics and must disappear at `poc-16-iq2.9`:
writers publish closed-pile leaves to their own trees, consumers pull them, and
only discarded condition evaluations are pushed. Do not preserve the current
PileSender-to-Applier route as a second target publication algorithm.

Authority flows from the database-free core into an optional stateful peer
composition:

- `RepositoryApplier` is database-free. It validates one closed pile, unions
  every durable fact into the validated set, establishes immutable objects,
  compiles and compare-and-swaps `root`, and returns one bounded exact result.
  It never deletes ingress.
- `RepositoryReader` is database-free and side-effect free. It answers from
  one pinned root through `WorkerView` and `ValidatedView`.
- `HttpGate` is database-free and owns the one peer route and authorization
  table over Applier and Reader.
- `PileSender` may use SQLite. It closes local intent, encodes ordinary piles,
  uploads each exact pile, and directly asks the recipient to apply that key.
  It cannot publish a root or delete ingress.

A hosted peer uses Applier, Reader, and HttpGate. `FullPeer` adds PileSender,
local identities, scheduling, local control, attachment I/O, and the
disposable SQL projection. Its receiving side still invokes Applier. A
metadata broker is a Reader plus a provider signer, not another validation
door. Never add a second pile-to-root path, provider-specific compiler, SQL
publication path, or authority membrane.

Read implementation authority in this order:

1. `core/fact.py` and `facts/` for fact bytes and family policy.
2. `core/kernel.py` for closed-pile judgment.
3. `core/repository_snapshot.py`, `core/repository_applier.py`, and
   `core/repository_reader.py` for the database-free repository engine.
4. `core/http.py` for peer routes and authorization.
5. `full_peer/` for the stateful local composition; `sql_store.py` is its sole
   SQL boundary and `upload_journal.py`, `upload_client.py`, and
   `upload_client_http.py` own resumable outbound upload state and effects.
6. `full_peer/daemon.py`, `full_peer/iroh_forwarders.py`,
   `full_peer/iroh_process.py`, and `full_peer/iroh/` for process composition,
   bounded outbound children, and the connection-only Iroh byte wrapper.
7. `adapters/` and `deploy/` for provider adaptation and packaging.
   `deploy/upload_session.py` and `deploy/upload_wire.py` are the shared
   client/broker protocol values; no client journal or outbound runtime lives
   under `deploy/`.
8. `notifications/hints.py`, `notifications/discovery.py`,
   `notifications/carrier.py`, `notifications/delivery.py`, and
   `notifications/worker.py` for post-publication work. Notification state is
   durable operational state outside core. It holds at most one pending diff
   page per workspace before any disposable wake is emitted; only typed worker
   completion advances it. It never grants fact authority or enters
   `RepositoryApplier`.

## The central theorem

The wire and stored values are deliberately different:

```text
wire:    one bounded, topologically ordered closed pile
stored:  fid -> canonical fact-object oid
```

The pile supplies the one-time validation closure at the ingress door. If any
member fails, the whole pile fails and no valid prefix is published. After a
successful root CAS, authenticated residence is the durable admission
certificate: every durable fact is an equal resident and ephemeral facts are
discarded. Do not store the selected dependency edges, proof DAGs, ranks,
winners, eligibility labels,
dormant candidates, or a second settlement state.

Validated storage is monotone:

```text
if f validates against S, f remains valid in every validated superset S'
```

If one provider is semantically significant, the fact must name that provider
or its complete offer address in immutable bytes. Otherwise providers at the
same complete address are interchangeable. Current suppression and authority
maps may change visibility or authorization, never fact residence.

## Authority flow

Read and change the receiving path in this order:

```text
closed pile
  -> RepositoryApplier
  -> kernel plus family policy
  -> monotone validated-fact union
  -> repository_snapshot's pure three-map compiler
  -> immutable object establishment
  -> the sole root CAS
  -> applied, noop, rejected, or retryable result
  -> RepositoryReader
```

`FactTree` binds `fact:<fid>` directly to the canonical fact object's oid and
also contains mechanical postings. `FactOrder` and `SuppTree` are deterministic
projections. A proof names its provider, so a hosted Reader authenticates that
FactTree residence and its SuppTree scopes directly. SQLite mirrors canonical
fact bytes plus generic index rows for local authorship and presentation only;
it must be deletable and rebuildable from a pinned Reader.

Direct-upload clients write one exact closed pile to isolated ingress and then
call broker `FINALIZE`; the broker invokes the recipient with that exact key.
The sender retries retryable or lost results. There is no server-side ingress
queue, LIST drain, detached-object completion pass, or internal pile copy. The
Applier invokes the same transition for a hosted recipient and a full peer and
leaves ingress immutable for a separate retention lifecycle.

## Fact families

Use one module per family under `facts/auth/` or `facts/content/`. Families own
construction, exact shape checks, named Needs, immutable refs/offers,
suppression selectors/actions, authority scopes, ownership, commands, query
assembly, and any inline authenticated payload format. `facts/__init__.py` is
the checked registry. Keep core family-neutral; it may dispatch through
`facts`, but it must not import concrete family modules or switch on their
tags. Bao descriptors and slices are ordinary facts; each slice carries the
payload and range proof needed for independent admission.

Needs use complete offer addresses. A fact may also name an exact provider in
its envelope when identity matters. Do not infer durable ownership from a
current winning provider. Suppression selectors are explicit: SELF, named
parent or ancestor paths, several selectors, or none. PARENT pins one direct
dependency; every ANCESTOR hop must be an immutable named ref. A family with
none cannot be directly suppressed, although its declared current authority
scopes may still make it unusable as a provider.

## Object-store and concurrency rules

The running predecessor uses immutable content-addressed objects plus one
linearizable opaque-token CAS register named `root`. The accepted target keeps
immutable objects but replaces ordinary content publication with one stable
CAS head per device and bounded strong LIST of the workspace head prefix; only
the small authority/removal projection remains shared. In both designs, exact
untrusted reads are bounded and provider ETags are opaque. LIST discovers
candidate heads in the target but never grants membership, authorship,
liveness, or fact validity. Every peer mirrors only missing content-addressed
head/tree objects. The target `AuthorityGate` evaluates one pushed closed pile
to prove requester and recipient membership, device join, and non-removal; it
discards that state and does not validate the advertised content tree.

One exact create-only ingress key and its digest identify one delivery attempt.
It is staging, not a server-side queue or repository authority. Provider
retention may eventually collect it, but `RepositoryApplier` has no ingress
DELETE capability and publication correctness never depends on collection.
Lost requests and responses are recovered by sender retry; an already-applied
pile returns an idempotent result from the authenticated repository.

Stale workers may duplicate bounded immutable work or delay convergence. They
must not overwrite different bytes at an object key, clobber a newer root,
delete ingress, mint from unobserved state, or corrupt a Merkle tree.

## Change rules

- Inbound piles enter through `RepositoryApplier`.
- Outbound piles enter through `PileSender`.
- Sync compares `fid -> object_oid`, assembles fresh closures from immutable
  refs and Needs, and receives them through the ordinary Applier.
- Provider adapters translate storage, events, budgets, and deployment
  configuration only.
- Iroh carries opaque HTTP bytes only. Endpoint identity, tickets, ALPN,
  and connection success never grant repository authority; local control
  never traverses Iroh.
- A receipt, cursor, notification, ETag, SQL row, or local lock carries no
  authority beyond its exact documented binding.
- Every behavior change needs a realistic test. Prefer actual daemon/socket,
  provider-fake, restart, crash-point, concurrent, and hostile-input coverage.
- Keep structural authority ratchets in `tests/test_repository_layout.py`.

When working in a worktree, edit only that worktree and commit completed work
on its branch before handoff or review. Preserve unrelated changes.

Run the authoritative repository preflight before handoff:

```sh
python3 tools/preflight.py
```

The installed beads v1.1.0 `bd preflight --check` is hardcoded for the beads
Go repository and cannot be configured here. The repository-owned command
runs these underlying gates:

```sh
python3 -m compileall -q core full_peer facts notifications adapters deploy bench tests tools
python3 -m pytest -q
python3 -m pytest -q tests/test_repository_layout.py
git diff --check
bd lint
bd dep cycles
```
