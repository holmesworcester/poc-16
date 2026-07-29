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
Families own construction, needs, validation, materialization, commands, and
queries. Cross-family selector and authorization policy belongs in the
exhaustive `facts/_policy.py` registry. Keep `core/` family-neutral.

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
