"""Recipient-owned projection from accepted control piles to removal state.

This module is deliberately only composition.  Fact families classify one
ordinary closed-pile judgment and derive bounded CLEAR/ACTIVE groups;
``SuppressionTree`` owns the private authenticated map and its root CAS.
Neither bootstrap nor an accepted-leaf poke retains fact bytes, accepts a
caller root, scans the writer forest, or constructs another validation path.
"""

from dataclasses import dataclass

import facts

from .close import ClosedPileEvaluator
from .limits import MAX_CONTROL_PILE_BYTES
from .shape import valid_fid
from .suppression_tree import SuppressionTree
from .writer_repository import open_accepted_pile


@dataclass(frozen=True, slots=True)
class RemovalStateResult:
    """One complete recipient transition and the root observed afterward."""

    status: str
    root_oid: str | None

    def __post_init__(self):
        if self.status not in {
                "applied", "noop", "retryable", "rejected"} \
                or self.root_oid is not None and not valid_fid(self.root_oid):
            raise ValueError("recipient removal-state result")


class RecipientRemovalState:
    """Advance one recipient's private state from exact signed control piles."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("recipient removal-state workspace")
        self.workspace = workspace
        self.store = store
        self.tree = SuppressionTree(workspace, store)
        self.evaluator = ClosedPileEvaluator(
            workspace, max_bytes=MAX_CONTROL_PILE_BYTES)

    async def pin(self):
        """Pin the current private root for subsequent point proofs."""
        return await self.tree.pin()

    async def _result(self, status):
        pin = await self.pin()
        return RemovalStateResult(
            status, None if pin is None else pin.root_oid)

    def _groups(self, raw, *, writer=None):
        evaluated = self.evaluator.evaluate(raw, writer=writer)
        groups = facts.removal_state_groups(
            evaluated.judgment, evaluated.pile.facts)
        return evaluated, groups

    async def _apply(self, groups):
        changed = False
        for group in groups:
            outcome = await self.tree.apply(group)
            if outcome.status == "retryable":
                return await self._result("retryable")
            if outcome.status == "applied":
                changed = True
            elif outcome.status != "noop":
                raise TypeError("private suppression apply result")
        return await self._result("applied" if changed else "noop")

    async def bootstrap(self, raw_signed_pile):
        """Introduce one direct member from an original CLEAR-only closure."""
        try:
            evaluated, groups = self._groups(raw_signed_pile)
            facts.bootstrap_member(
                evaluated.judgment,
                evaluated.pile.facts,
                evaluated.pile.writer,
            )
            if any(
                    value.get("state") == "active"
                    for group in groups
                    for _sid, value in group):
                raise ValueError("bootstrap cannot activate removal state")
        except ValueError:
            return RemovalStateResult("rejected", None)
        return await self._apply(groups)

    async def advance_leaf(self, device, sequence):
        """Join one exact already-accepted writer leaf, then discard it."""
        try:
            raw = await open_accepted_pile(
                self.store,
                self.workspace,
                device,
                sequence,
                max_bytes=MAX_CONTROL_PILE_BYTES,
            )
            _evaluated, groups = self._groups(raw, writer=device)
        except ValueError:
            return RemovalStateResult("rejected", None)
        return await self._apply(groups)


__all__ = (
    "RecipientRemovalState",
    "RemovalStateResult",
)
