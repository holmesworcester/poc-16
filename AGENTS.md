# poc-16 — agent guide

This project tracks work with **bd (beads)**, a dependency-aware issue graph.
**Do not** use markdown TODO lists for task tracking — use bd.

## Start here
- **Temporary design and execution authority:** `docs/TODO.md`. The existing
  README/DESIGN/docs corpus contains useful history but is known stale; S10 owns
  consolidation after the recovery implementation lands.
- **Current epic** (claimed through S10; use `bd ready --exclude-type=epic`
  for the claimable implementation frontier):
  - **`poc-16-kb6`** — post-cutover recovery: explicit type-owned suppression
    selectors plus separate authorization guards, immutable removal admissions,
    hard-capped fact/suppression/authority trees, service-exclusive
    capacity-checked composite-root publication, and bounded Cloudflare Worker
    reads with precomputed freshness witnesses rather than per-request rebuilds.
    Temporary plan and bankruptcy ledger: `docs/TODO.md`.

Bead bankruptcy was declared on 2026-07-27. Every bead that was active before
`poc-16-kb6` is closed as superseded; closed history is evidence, not an
implementation mandate. Do not reopen or copy dependencies from the old
`808`/`jbg`/`yez`/`x1o`/`9fc`/`t9f` graphs. A requirement exists only when
`docs/TODO.md` states it and a `poc-16-kb6.*` child owns it.

## bd workflow
- `bd prime` — load full workflow context (run first).
- `bd ready --exclude-type=epic` — claimable implementation work (no active
  blockers). The recovery epic stays claimed until S10 closes it.
- `bd show <id>` — read a bead, e.g. `bd show poc-16-kb6.4`.
- `bd update <id> --claim` — take a bead before starting it.
- `bd close <id>` — mark done; releases its blocked dependents.
- `bd dep tree poc-16-kb6` — the dependency graph.

Each implementation bead names its `docs/TODO.md` section and dependencies.
Do not revive bankrupt work because an older design document still describes
it; S10 owns the final documentation consolidation.

## Style
Keep poc-13 code idioms: one file per family under `facts/auth/`, the
`SHAPE → NEEDS → VALIDATE → MODE → MATERIALIZE → COMMANDS → QUERIES` skeleton, "COMMANDS: build
a fact, admit it, stop." See the fidelity rubric in `docs/CHAINED_AUTH_PLAN.md` §2. The port uses
**poc-13 naming** (`workspace`/`user`/`user_invite`/`device`/…), applied as a
mechanical first step (contract bead `poc-16-kb6.4`).
