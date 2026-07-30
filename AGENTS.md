# POC-16 agent guide

Read `README.md` for operation and `DESIGN.md` for the running model. Those
files and this guide are the only Markdown authorities in the repository.
Track unfinished work in beads, never in a Markdown TODO ledger.

Start each session with:

```sh
bd prime
bd ready
git status --short
```

Use one module per fact family under `facts/auth/` or `facts/content/`.
Families own construction, needs, validation, commands, query assembly, and
the family’s `POLICY`. `facts/__init__.py` is the one checked dispatch
inventory; `facts/_policy.py` defines policy vocabulary but contains no
parallel tag registry. Keep `core/` family-neutral. Durable facts live once as
canonical blobs; the generic index mechanically covers reconciliation key,
type, every explicit reference, and every offer.

Read and change the write path in authority order:

```text
runtime turn → kernel/family → catalog settlement → publisher root CAS
```

Client queries select through the generic catalog index and let the family
assemble its view. The read-only CF path is separate:

```text
root + immutable objects → WorkerView → family authorize hook
```

It must remain database-free. `Node` composes local resources and exposes the
workspace-bound runtime; do not add another admission route in daemon or sync.
Preserve read isomorphism: if both client and CF paths ask the same published
state question, both must use the authenticated-tree answer. SQLite is for
client-only durable intent, query assembly, and full repair—not a parallel
answer or range directory. FactOrder is a direct bounded map from eligible
fact keys to stable fact objects; candidate/proof sync is the sole replicated
join.

Every behavior change needs a realistic test. Prefer real daemon/socket
coverage at product boundaries and direct hostile-input tests at codec and
admission boundaries. A prose assertion is not proof of runtime behavior.

When working in a worktree, edit only that worktree and commit completed work
on its branch before handoff. Preserve unrelated changes and never use
destructive checkout/reset commands against a shared workspace.

Useful gates:

```sh
python3 -m pytest -q
python3 bench/bench_latency.py 1000 5000 10000
git diff --check
```
