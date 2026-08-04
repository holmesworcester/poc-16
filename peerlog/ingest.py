"""File verified runs into local writer-log copies.

Every accepted fact lands in its writer's island set and the treap;
abandonment is free because runs are final canonical bytes — there is
no dirty intermediate state. Heads observed during sync are compared
for equivocation: two signed heads whose trees disagree below the
shared seq are fork evidence, a detectable offense in the forest
model. Backdated ts beyond the quarantine band syncs late instead of
churning stable ranges.
"""
from dataclasses import dataclass

from .log import Head
from .proof import Run

TS_QUARANTINE = None  # dial: max backdate gossiped into stable ranges


@dataclass(frozen=True)
class ForkEvidence:
    writer: bytes
    heads: tuple[Head, Head]


def ingest(state, run: Run) -> None:
    """verify_run, then file facts into the writer's log copy and the
    treap; rejects the whole run on any failure."""
    raise NotImplementedError


def observe_head(state, head: Head) -> ForkEvidence | None:
    raise NotImplementedError
