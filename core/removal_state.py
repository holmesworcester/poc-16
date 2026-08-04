"""Recipient-owned projection from accepted control piles to removal state.

This module is deliberately only composition.  Fact families classify one
ordinary closed-pile judgment and derive bounded CLEAR/ACTIVE groups;
``SuppressionTree`` owns the private authenticated map and its root CAS.
Neither bootstrap nor control application retains fact bytes, accepts a
caller root, scans the writer forest, or constructs another validation path.
"""

from dataclasses import dataclass
from itertools import islice

import facts

from .close import ClosedPileEvaluator, signed_pile_oid
from .crypto import h
from .fact import canon
from .limits import (
    MAX_CONTROL_PILE_BYTES,
    MAX_HEAD_CONTROL_BYTES,
    MAX_HEAD_CONTROL_PILES,
    MAX_REMOVAL_UPDATES,
    MAX_SUPPRESSION_ID_BYTES,
    valid_bounded_text,
)
from .shape import valid_fid
from .suppression import checked_suppression_slot
from .suppression_tree import SuppressionTree


CONTROL_EFFECTS_DOMAIN = "poc16-control-head-effects-v1"


@dataclass(frozen=True, slots=True)
class ControlPilePlan:
    """The exact deterministic removal effects of one evaluated pile."""

    oid: str
    groups: tuple[tuple[tuple[str, dict], ...], ...]

    def __post_init__(self):
        if not valid_fid(self.oid) or not isinstance(self.groups, tuple):
            raise ValueError("control pile plan")
        for group in self.groups:
            if not isinstance(group, tuple) \
                    or not 0 < len(group) <= MAX_REMOVAL_UPDATES:
                raise ValueError("control pile effect group")
            previous = None
            for row in group:
                if not isinstance(row, tuple) or len(row) != 2:
                    raise ValueError("control pile effect row")
                sid, value = row
                if not valid_bounded_text(
                        sid, MAX_SUPPRESSION_ID_BYTES) \
                        or previous is not None and sid <= previous:
                    raise ValueError("control pile effect sid")
                checked_suppression_slot(value)
                previous = sid


@dataclass(frozen=True, slots=True)
class ControlHeadPlan:
    """Bounded exact control piles and their canonical ACI effects."""

    workspace: str
    writer: str
    piles: tuple[ControlPilePlan, ...]
    byte_count: int

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.writer) \
                or not isinstance(self.piles, tuple) \
                or not 0 < len(self.piles) <= MAX_HEAD_CONTROL_PILES \
                or not all(isinstance(pile, ControlPilePlan)
                           for pile in self.piles) \
                or len({pile.oid for pile in self.piles}) != len(self.piles) \
                or not any(pile.groups for pile in self.piles) \
                or type(self.byte_count) is not int \
                or not 0 < self.byte_count <= MAX_HEAD_CONTROL_BYTES:
            raise ValueError("control head plan")

    @property
    def oids(self):
        return tuple(pile.oid for pile in self.piles)

    @property
    def effects_oid(self):
        return h(canon([
            CONTROL_EFFECTS_DOMAIN,
            self.workspace,
            self.writer,
            [
                [
                    [[sid, value] for sid, value in group]
                    for group in pile.groups
                ]
                for pile in self.piles
            ],
        ]))

    @property
    def active_sids(self):
        return tuple(sorted({
            sid
            for pile in self.piles
            for group in pile.groups
            for sid, value in group
            if value.get("state") == "active"
        }))

    @property
    def groups(self):
        return tuple(
            group
            for pile in self.piles
            for group in pile.groups
        )


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

    def plan_control(self, raw_signed_piles, writer):
        """Evaluate a bounded exact control tuple without changing state."""
        if not valid_fid(writer):
            raise ValueError("control head writer")
        try:
            raws = tuple(islice(
                iter(raw_signed_piles), MAX_HEAD_CONTROL_PILES + 1))
        except TypeError as error:
            raise ValueError("control head piles") from error
        if not raws or len(raws) > MAX_HEAD_CONTROL_PILES \
                or any(not isinstance(raw, bytes) or not raw for raw in raws):
            raise ValueError("control head piles")
        byte_count = sum(map(len, raws))
        if byte_count > MAX_HEAD_CONTROL_BYTES:
            raise ValueError("control head piles too large")
        piles = []
        for raw in raws:
            _evaluated, groups = self._groups(raw, writer=writer)
            piles.append(ControlPilePlan(
                signed_pile_oid(raw), tuple(groups)))
        return ControlHeadPlan(
            self.workspace, writer, tuple(piles), byte_count)

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

    async def apply_plan(self, plan):
        """Join one already checked exact plan; retries may replay it whole."""
        if not isinstance(plan, ControlHeadPlan) \
                or plan.workspace != self.workspace:
            return await self._result("rejected")
        return await self._apply(plan.groups)

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

    async def apply_control(self, raw_signed_pile, writer):
        """Join one exact writer-signed control closure, then discard it."""
        try:
            plan = self.plan_control((raw_signed_pile,), writer)
        except ValueError:
            return await self._result("rejected")
        return await self.apply_plan(plan)


__all__ = (
    "ControlHeadPlan",
    "ControlPilePlan",
    "RecipientRemovalState",
    "RemovalStateResult",
)
