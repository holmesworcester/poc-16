# poc-16 — agent guide

This project tracks work with **bd (beads)**, a dependency-aware issue graph.
**Do not** use markdown TODO lists for task tracking — use bd.

## Start here
- **Design of record:** `docs/WORKSPACES.md` (multi-workspace / identity / infra model) and
  `docs/MODEL.md` + `DESIGN.md` (the passive-store RBSR + hoisting core). `docs/MULTILEVEL_PILE.md`
  has the hoisting math + measurements.
- **Current epics** (`bd ready` for the claimable frontier):
  - **`poc-16-808`** — simplification. The one tree engine, one kernel judge,
    pure mint, cursored pump, source-keyed projectors, and confluence laws are
    landed (`.1`–`.8`). Production settle-node placement is `.9`. Plan:
    `docs/SIMPLIFY.md`.
  - **`poc-16-jbg`** — FaaS concurrency + Cloudflare Workers, coordination-free. Notes
    in `DESIGN.md` §Concurrency & FaaS and `docs/WORKSPACES.md` §9. Fat nodes and
    two-root fold are landed; current entries are `.2`, `.3`, `.7`, and the
    stateless canonical-mint fix `.10`.
  - **`poc-16-yez`** — global 1:N deletion closure (suppression-key treap). Plan:
    `docs/DELETION_CLOSURE.md`. Death-key extraction is landed; P1 entries are `.2`,
    `.9`, and the publication-isolation regression `.13`; optional P2 `.5` is
    also claimable.
  - **`poc-16-zgj`** — poc-13 auth port + chained-seed hoisting measurement.
    Closed; plan and hand-back: `docs/CHAINED_AUTH_PLAN.md` / `docs/MULTILEVEL_PILE.md`.

## bd workflow
- `bd prime` — load full workflow context (run first).
- `bd ready` — claimable work (no active blockers).
- `bd show <id>` — read a bead, e.g. `bd show poc-16-808.9`.
- `bd update <id> --claim` — take a bead before starting it.
- `bd close <id>` — mark done; releases its blocked dependents.
- `bd dep tree poc-16-808` — the dependency graph.

Each implementation bead names its plan section and dependencies. The closed
`poc-16-zgj` graph remains the section-by-section record for
`docs/CHAINED_AUTH_PLAN.md`; do not reopen or replay its phase ordering when
starting current work.

## Style
Keep poc-13 code idioms: one file per family under `facts/auth/`, the
`SHAPE → NEEDS → VALIDATE → MODE → MATERIALIZE → COMMANDS → QUERIES` skeleton, "COMMANDS: build
a fact, admit it, stop." See the fidelity rubric in `docs/CHAINED_AUTH_PLAN.md` §2. The port uses
**poc-13 naming** (`workspace`/`user`/`user_invite`/`device`/…), applied as a mechanical first
step (bead `poc-16-zgj.1`).
