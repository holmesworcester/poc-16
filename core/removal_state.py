"""Recipient-owned projection from accepted control piles to removal state.

Fact families select one semantic sink from each ordinary closed-pile
judgment. The recipient ACI-joins those sink rows into one bounded
``RemovalTree`` CAS turn. Pile bytes and validation receipts disappear as
soon as a self-contained permit has authenticated the canonical rows.
"""

from dataclasses import dataclass
from itertools import islice

import facts

from .close import ClosedPileEvaluator
from .limits import (
    MAX_CONTROL_PILE_BYTES,
    MAX_HEAD_CONTROL_BYTES,
    MAX_HEAD_CONTROL_FACTS,
    MAX_HEAD_CONTROL_PILES,
    MAX_HEAD_REMOVAL_UPDATES,
    MAX_REMOVAL_PATH_SCOPES,
    MAX_REMOVAL_UPDATES,
    MAX_SUPPRESSION_ID_BYTES,
    PayloadTooLarge,
    valid_bounded_text,
)
from .shape import valid_fid
from .suppression import checked_suppression_slot, suppression_slot
from .removal_tree import RemovalTree, join_slots


def checked_updates(rows, maximum=MAX_HEAD_REMOVAL_UPDATES):
    """Canonicalize one bounded ACI row set without touching storage."""
    if type(maximum) is not int or not 0 <= maximum \
            <= MAX_HEAD_REMOVAL_UPDATES:
        raise ValueError("removal update bound")
    try:
        rows = tuple(islice(iter(rows), maximum + 1))
    except TypeError as error:
        raise ValueError("removal updates") from error
    if len(rows) > maximum:
        raise PayloadTooLarge("too many head removal updates")
    joined = {}
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            raise ValueError("removal update row")
        sid, value = row
        if not valid_bounded_text(sid, MAX_SUPPRESSION_ID_BYTES):
            raise ValueError("removal update sid")
        joined[sid] = join_slots(joined.get(sid), value)
    updates = tuple(sorted(joined.items()))
    for sid, value in updates:
        checked_suppression_slot(value)
    return updates


@dataclass(frozen=True, slots=True)
class ControlHeadPlan:
    """The complete bounded result of issue-time control evaluation."""

    workspace: str
    writer: str
    updates: tuple[tuple[str, dict], ...]
    pile_count: int
    fact_count: int
    byte_count: int

    def __post_init__(self):
        if not valid_fid(self.workspace) or not valid_fid(self.writer) \
                or type(self.pile_count) is not int \
                or not 0 < self.pile_count <= MAX_HEAD_CONTROL_PILES \
                or type(self.fact_count) is not int \
                or not 0 < self.fact_count <= MAX_HEAD_CONTROL_FACTS \
                or type(self.byte_count) is not int \
                or not 0 < self.byte_count <= MAX_HEAD_CONTROL_BYTES \
                or checked_updates(self.updates) != self.updates \
                or not self.updates:
            raise ValueError("control head plan")

    @property
    def active_sids(self):
        return tuple(
            sid for sid, value in self.updates
            if value.get("state") == "active"
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
        self.tree = RemovalTree(workspace, store)
        self.evaluator = ClosedPileEvaluator(
            workspace, max_bytes=MAX_CONTROL_PILE_BYTES)

    async def pin(self, previous=None):
        """Pin the current private root for subsequent point proofs."""
        return await self.tree.pin(previous)

    async def _result(self, status):
        pin = await self.pin()
        return RemovalStateResult(
            status, None if pin is None else pin.root_oid)

    def _updates(self, raw, *, writer=None):
        evaluated = self.evaluator.evaluate(raw, writer=writer)
        updates = facts.removal_state_updates(
            evaluated.judgment, evaluated.pile.facts)
        return evaluated, checked_updates(updates, MAX_REMOVAL_UPDATES)

    def plan_control(self, raw_signed_piles, writer):
        """Evaluate exact piles once and return their bounded canonical join."""
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
            raise PayloadTooLarge("control head piles too large")

        fact_count = 0
        joined = {}
        for raw in raws:
            evaluated, updates = self._updates(raw, writer=writer)
            if not updates:
                raise ValueError("control pile has no removal effect")
            fact_count += len(evaluated.pile.facts)
            if fact_count > MAX_HEAD_CONTROL_FACTS:
                raise PayloadTooLarge("too many head control facts")
            for sid, value in updates:
                joined[sid] = join_slots(joined.get(sid), value)
            if len(joined) > MAX_HEAD_REMOVAL_UPDATES:
                raise PayloadTooLarge("too many head removal updates")

        return ControlHeadPlan(
            self.workspace,
            writer,
            checked_updates(joined.items()),
            len(raws),
            fact_count,
            byte_count,
        )

    async def plan_control_missing(self, pin, raw_signed_piles, writer):
        """Plan only rows not already subsumed by the issue-time live pin.

        A hosted recipient can know most of a writer's cumulative control
        suffix already through other writers. Each source pile remains
        independently bounded and evaluated once; only the still-effective
        rows consume the six-row atomic permit budget.
        """
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
            raise PayloadTooLarge("control head piles too large")
        joined, fact_count = {}, 0
        for raw in raws:
            plan = self.plan_control((raw,), writer)
            fact_count += plan.fact_count
            if fact_count > MAX_HEAD_CONTROL_FACTS:
                raise PayloadTooLarge("too many head control facts")
            for sid, value in plan.updates:
                joined[sid] = join_slots(joined.get(sid), value)

        ordered = tuple(sorted(joined.items()))
        currents = await pin.lookup_many(sid for sid, _expected in ordered)
        missing = []
        for (sid, expected), current in zip(ordered, currents):
            if join_slots(current, expected) != current:
                missing.append((sid, expected))
        # An exact all-known control suffix still needs a nonempty permit to
        # bind its head transition. Reapplying one canonical incumbent is an
        # authenticated no-op and preserves the permit codec's fail-closed
        # nonempty-plan invariant.
        updates = checked_updates(
            missing or (ordered[0],))
        return ControlHeadPlan(
            self.workspace,
            writer,
            updates,
            len(raws),
            fact_count,
            byte_count,
        )

    async def _apply(self, updates, maximum):
        outcome = await self.tree.apply(updates, maximum=maximum)
        if outcome.status not in {"applied", "noop", "retryable"}:
            raise TypeError("private removal apply result")
        return await self._result(outcome.status)

    async def apply_plan(self, plan):
        """Join one issue-time plan in exactly one private-root CAS turn."""
        if not isinstance(plan, ControlHeadPlan) \
                or plan.workspace != self.workspace:
            return await self._result("rejected")
        return await self._apply(
            plan.updates, MAX_HEAD_REMOVAL_UPDATES)

    async def apply_updates(self, updates):
        """Apply canonical rows authenticated by a self-contained permit."""
        updates = checked_updates(updates)
        if not updates:
            return await self._result("rejected")
        return await self._apply(updates, MAX_HEAD_REMOVAL_UPDATES)

    async def includes(self, pin, updates):
        """Return whether one pin already contains every permitted ACI row."""
        if pin is None or getattr(pin, "workspace", None) != self.workspace:
            return False
        updates = checked_updates(updates)
        for sid, expected in updates:
            proof = await pin.proof(sid)
            if proof is None:
                return False
            current = pin.verify(sid, proof)
            if join_slots(current, expected) != current:
                return False
        return True

    async def bootstrap(self, raw_signed_pile):
        """Introduce one direct member from an original CLEAR-only closure."""
        try:
            evaluated, updates = self._updates(raw_signed_pile)
            facts.bootstrap_member(
                evaluated.judgment,
                evaluated.pile.facts,
                evaluated.pile.writer,
            )
            if not updates or any(
                    value.get("state") == "active"
                    for _sid, value in updates):
                raise ValueError("bootstrap cannot activate removal state")
        except ValueError:
            return RemovalStateResult("rejected", None)
        return await self._apply(updates, MAX_REMOVAL_UPDATES)

    async def admit(self, identity):
        """Persist one fully evaluated positive subject chain exactly once."""
        device = getattr(identity, "device", None)
        owner = getattr(identity, "owner", None)
        scopes = getattr(identity, "scopes", None)
        if not valid_fid(device) or not valid_fid(owner):
            return await self._result("rejected")
        try:
            updates = checked_updates(
                ((sid, suppression_slot()) for sid in scopes),
                MAX_REMOVAL_PATH_SCOPES,
            )
        except (TypeError, ValueError):
            return await self._result("rejected")
        if not updates:
            return await self._result("rejected")
        return await self._apply(updates, MAX_REMOVAL_PATH_SCOPES)

    async def apply_control(self, raw_signed_pile, writer):
        """Join one exact writer-signed control sink, then discard it."""
        try:
            plan = self.plan_control((raw_signed_pile,), writer)
        except ValueError:
            return await self._result("rejected")
        return await self.apply_plan(plan)


__all__ = (
    "ControlHeadPlan",
    "RecipientRemovalState",
    "RemovalStateResult",
    "checked_updates",
)
