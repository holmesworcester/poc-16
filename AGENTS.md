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

There are three capabilities and two actors:

- `PileSender` may use SQLite. It closes local intent, encodes ordinary piles,
  and delivers them. It cannot publish a root or retire ingress.
- `RepositoryApplier` is database-free. It validates one closed pile, unions
  every durable fact into the validated set, establishes immutable objects,
  compiles and compare-and-swaps `root`, records rejection evidence, and
  retires only its exact internal generation.
- `RepositoryReader` is database-free and side-effect free. It answers from
  one pinned root through `WorkerView` and `ValidatedView`.

A full peer combines all three capabilities. A hosted recipient combines
Applier and Reader; its metadata broker is a Reader plus a provider signer,
not another actor or validation door. Never add a second pile-to-root path,
provider-specific compiler, SQL publication path, or authority membrane.

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
  -> exact internal-generation retirement
  -> RepositoryReader
```

`FactTree` binds `fact:<fid>` directly to the canonical fact object's oid and
also contains mechanical postings. `FactOrder`, `SuppTree`, and
`AuthorityTree` are deterministic projections. SQLite mirrors canonical fact
bytes plus generic index rows for local authorship and presentation only; it
must be deletable and rebuildable from a pinned Reader.

Direct-upload clients write detached immutable objects first and one exact
closed pile marker last into isolated ingress. Notifications and LIST results
are liveness hints only. The Applier copies an exact marker behind its own
internal generation and invokes the same transition used by a full peer.

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
parent or ancestor paths, several selectors, or none. A family with none
cannot be directly suppressed, although its declared current authority scopes
may still make it unusable as a provider.

## Object-store and concurrency rules

The storage contract is immutable content-addressed objects plus one
linearizable opaque-token CAS register named `root`. Exact untrusted reads use
bounded APIs. Discovery uses bounded pagination. Never rely on ETags being
content hashes, unconditional replacement, whole-GET/whole-LIST fallbacks, or
LIST for safety.

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
- A receipt, cursor, notification, ETag, SQL row, or local lock carries no
  authority beyond its exact documented binding.
- Every behavior change needs a realistic test. Prefer actual daemon/socket,
  provider-fake, restart, crash-point, concurrent, and hostile-input coverage.
- Keep structural authority ratchets in `tests/test_repository_layout.py`.

When working in a worktree, edit only that worktree and commit completed work
on its branch before handoff or review. Preserve unrelated changes.

Useful gates:

```sh
python3 -m pytest -q
python3 -m pytest -q tests/test_repository_layout.py
git diff --check
```
