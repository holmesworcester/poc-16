# POC-16 engineer guide

Read `README.md` for operation and `DESIGN.md` for protocol and trust
boundaries. Those files and this guide are the repository's only Markdown
authorities. Track unfinished work in beads, never in a Markdown TODO ledger.

Start a work session with:

```sh
bd prime
bd ready
git status --short
```

## Capabilities

Authority flows from the database-free core into an optional stateful peer
composition:

- `RepositoryApplier` is database-free. It validates one closed pile, unions
  every durable fact into the validated set, establishes immutable objects,
  compiles and compare-and-swaps `root`, records rejection evidence, and
  retires only its exact internal generation.
- `RepositoryReader` is database-free and side-effect free. It answers from
  one pinned root through `WorkerView` and `ValidatedView`.
- `HttpGate` is database-free and owns the one peer route and authorization
  table over Applier and Reader.
- `PileSender` may use SQLite. It closes local intent, encodes ordinary piles,
  and delivers them. It cannot publish a root or retire ingress.

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

## The central theorem

The wire and stored values are deliberately different:

```text
wire:    one bounded, topologically ordered closed pile
stored:  fid -> canonical fact-object oid
```

The pile is the validation certificate. If any member fails, the whole pile
fails and no valid prefix is published. After a successful root CAS, every
durable fact is an equal resident; ephemeral facts are discarded. Do not store
the selected dependency edges, proof DAGs, ranks, winners, eligibility labels,
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
  -> repository_snapshot's pure four-map compiler
  -> immutable object establishment
  -> the sole root CAS
  -> exact outcome spend
  -> the sole internal-generation retirement attempt
  -> RepositoryReader
```

`FactTree` binds `fact:<fid>` directly to the canonical fact object's oid and
also contains mechanical postings. `FactOrder`, `SuppTree`, and
`AuthorityTree` are deterministic projections. SQLite mirrors canonical fact
bytes plus generic index rows for local authorship and presentation only; it
must be deletable and rebuildable from a pinned Reader.

Direct-upload clients write detached immutable objects first and one exact
closed pile marker last into isolated ingress. Notifications and LIST results
are liveness hints only. The Applier uses an exact marker as the stable identity
of one durably reserved internal generation and invokes the same transition
used by a full peer.

## Fact families

Use one module per family under `facts/auth/` or `facts/content/`. Families own
construction, exact shape checks, named Needs, immutable refs/offers,
suppression selectors/actions, authority scopes, ownership, commands, query
assembly, and detached blob references. `facts/__init__.py` is the checked
registry. Keep core family-neutral; it may dispatch through `facts`, but it
must not import concrete family modules or switch on their tags.

Needs use complete offer addresses. A fact may also name an exact provider in
its envelope when identity matters. Do not infer durable ownership from a
current winning provider. Suppression selectors are explicit: SELF, named
parent or ancestor paths, several selectors, or none. PARENT pins one direct
dependency; every ANCESTOR hop must be an immutable named ref. A family with
none cannot be directly suppressed, although its declared current authority
scopes may still make it unusable as a provider.

## Object-store and concurrency rules

The storage contract is immutable content-addressed objects plus one
linearizable opaque-token CAS register named `root`. Exact untrusted reads use
bounded APIs. Discovery uses bounded pagination. Never rely on ETags being
content hashes, unconditional replacement, whole-GET/whole-LIST fallbacks, or
LIST for safety.

Internal generation identity comes from a never-deleted create-only reservation,
not from a path segment, random nonce, or provider ETag. Identical workspace,
member, payload, and marker bindings are one logical delivery. After exact
publication or bounded, content-addressed rejection evidence exists, a
create-only outcome-bound spend grants at most one DELETE. Rejection evidence
binds the exact workspace, source, generation, payload, and permanent verdict;
its definite fresh spend and exact read-backs are required before deletion.
`EXISTS` and outcome-unknown deny deletion; a safe orphan is preferable to
retiring recreated work.

Stale workers may duplicate bounded immutable work or delay convergence. They
must not overwrite different bytes at an object key, clobber a newer root,
retire another generation, skip required detached-object completion, mint
from unobserved state, or corrupt a Merkle tree.

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
python3 -m compileall -q core full_peer facts adapters deploy bench tests tools
python3 -m pytest -q
python3 -m pytest -q tests/test_repository_layout.py
git diff --check
bd lint
bd dep cycles
```
