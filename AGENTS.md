# poc-16 — agent guide

This project tracks work with **bd (beads)**, a dependency-aware issue graph.
**Do not** use markdown TODO lists for task tracking — use bd.

## Start here
- **Design of record:** `WORKSPACES.md` (multi-workspace / identity / infra model) and
  `MODEL.md` + `DESIGN.md` (the passive-store RBSR + hoisting core). `MULTILEVEL_PILE.md`
  has the hoisting math + measurements.
- **Current work:** the epic **`poc-16-zgj`** — "Port poc-13 auth into poc-16 + test hoisting
  on chained seeds". Its full plan is `CHAINED_AUTH_PLAN.md`.

## bd workflow
- `bd prime` — load full workflow context (run first).
- `bd ready` — claimable work (no active blockers).
- `bd show <id>` — read a bead, e.g. `bd show poc-16-zgj.1`.
- `bd update <id> --claim` — take a bead before starting it.
- `bd close <id>` — mark done; releases its blocked dependents.
- `bd dep tree poc-16-zgj` — the whole graph.

The beads mirror `CHAINED_AUTH_PLAN.md` section-by-section; each bead names its plan section.

- **`poc-16-zgj.1` (the rename) is phase 0 and blocks everything** — do it first, keep it green.
- `.2`–`.6` are **phase 1**, the must-have hoisting measurement (member-can-invite → chained
  seed → `bench_order` by depth → green guard).
- `.7`–`.10` are **optional** phases 2–3 (keychain, device split, admin).
- `.11`–`.12` are the **writeup + hand-back** (update `MULTILEVEL_PILE.md` §A.5, deliver the
  verdict).

## Style
Keep poc-13 code idioms: one file per family under `tinyp2p/facts/auth/`, the
`SHAPE → NEEDS → VALIDATE → MODE → MATERIALIZE → COMMANDS → QUERIES` skeleton, "COMMANDS: build
a fact, admit it, stop." See the fidelity rubric in `CHAINED_AUTH_PLAN.md` §2. The port uses
**poc-13 naming** (`workspace`/`user`/`user_invite`/`device`/…), applied as a mechanical first
step (bead `poc-16-zgj.1`).
