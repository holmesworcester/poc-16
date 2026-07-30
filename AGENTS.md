# POC-16 engineer guide

Read `README.md` for operation and `DESIGN.md` for the protocol and trust
model. Those files and this guide are the repository’s only Markdown
authorities. Track unfinished work in beads, never in a Markdown TODO ledger.

Start a work session with:

```sh
bd prime
bd ready
git status --short
```

## Roles and actors

The repository has exactly three capabilities:

- `PileSender` may use SQLite. It closes local intent, encodes one ordinary
  pile, and delivers it. It has no root-CAS or retirement authority.
- `RepositoryApplier` is database-free. It is the sole exact-pile receiving
  engine, immutable-object establisher, root compiler/CAS owner, rejection
  recorder, and F10 internal-generation retiree.
- `RepositoryReader` is database-free, pinned to one root, and side-effect
  free. `WorkerView` and `CandidateView` are subordinate implementations
  constructed through it.

Those capabilities compose into two actor types:

- A full P2P node combines Sender + Applier + Reader. SQLite accelerates local
  authorship and presentation only.
- A hosted recipient combines Applier + Reader. Its metadata broker is a
  Reader plus a provider signer; it grants confined direct-upload
  capabilities but does not apply facts. Provider stacks may isolate that
  front door from the Applier process; the split is a least-privilege
  compartment boundary inside the hosted actor, not a third actor type.

Do not add a fourth publication role, a pre-Applier authority membrane, an
ambient per-workspace state machine, SQL settlement, a provider-specific
receiver, or any second pile-to-root path.

## Authority flow

Read and change the system in this order:

```text
facts family command
  → PileSender closes and encodes
  → internal generation or isolated direct-upload marker
  → RepositoryApplier validates with kernel/family policy
  → repository_snapshot compiles authenticated maps
  → immutable objects are established
  → RepositoryApplier performs the sole root CAS
  → exact internal generation is retired under its ApplyReceipt
  → RepositoryReader answers from one pinned root
  → client_projection optionally rebuilds disposable SQLite
```

Direct-upload clients write detached objects first and the exact pile marker
last into an isolated ingress namespace. Notifications are hints. The Applier
fetches the marker itself, copies it behind an Applier-minted internal
generation, uses the same transition as P2P receipt, commits facts before
detached-object completion, and never deletes client-writable ingress.

The object-store model is an immutable content-addressed map plus one
linearizable, opaque-token CAS register named `root`. Exact untrusted reads
use mandatory `get_bounded`; discovery uses mandatory bounded `list_page` and
cursors only as liveness hints. Whole-GET and whole-LIST compatibility
fallbacks are forbidden. LIST never authorizes a fact, mutation, or deletion.

## Fact families and indexes

Use one module per fact family under `facts/auth/` or `facts/content/`.
Families own construction, needs, validation, commands, query assembly, blob
references, suppression selectors/actions, authority scopes, and `POLICY`.
`facts/__init__.py` is the checked command, ephemeral-proof, and behavior
dispatch inventory. Keep `core/` family-neutral; it must not import concrete
`facts.auth` or `facts.content` modules.

Durable facts exist once as canonical encoded blobs. The mechanical generic
index covers type, reconciliation key, every explicit reference, and every
offer. SQLite contains one fact table and that one combined index; structural
standing/rank, exact resolved edges, and active suppression actions are typed
rows in the same index. Current liveness is distinct from structural standing.
Deleting SQLite must not alter repository answers.

If a client and a hosted Reader ask the same published-state question, both
must derive the answer from authenticated maps. SQLite may serve client-only
query assembly, never auth, suppression, admission, or root construction.

## Change rules

- Inbound facts and objects enter through `RepositoryApplier`.
- Outbound peer objects/piles are encoded and delivered through `PileSender`.
- A sync batch may share facts only when the combined kernel judgment
  preserves every selected witness's exact named edges. Valid-but-rewired or
  jointly invalid closures remain separate ordinary piles.
- Production code constructs `WorkerView`/`CandidateView` through
  `RepositoryReader`.
- Provider adapters translate storage, events, budgets, and deployment
  configuration. They do not contain protocol policy or a compiler.
- A proposal, receipt, cursor, notification, ETag, or SQL row is not authority
  beyond the exact binding documented by its type.
- Preserve concurrent safety: stale workers may delay convergence but cannot
  clobber a root, corrupt a tree, delete another generation, or mint from
  unobserved state.

Every behavior change needs a realistic test. Prefer real daemon/socket,
provider-fake, cold-restart, crash-point, and hostile-input coverage over
placeholder assertions. Keep structural authority ratchets in
`tests/test_repository_layout.py`.

When working in a worktree, edit only that worktree and commit completed work
on its branch before handoff or review. Preserve unrelated changes and never
use destructive checkout/reset commands against a shared workspace.

Useful gates:

```sh
python3 -m pytest -q
python3 -m pytest -q tests/test_repository_layout.py
git diff --check
```
