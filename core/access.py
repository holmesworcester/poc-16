"""One database-free subject lookup gate shared by every recipient."""

from dataclasses import dataclass

import facts

from .close import (
    ClosedPileEvaluator,
    decode_signed_pile,
    signed_pile_oid,
)
from .crypto import h
from .head_permit import (
    ControlHeadPermit,
    decode as decode_permit,
    encode as encode_permit,
)
from .limits import MAX_CONTROL_APPLY_ATTEMPTS, MAX_MINT_REQUEST_BYTES
from .removal_path import RemovalPath, encode as encode_path
from .removal_state import RecipientRemovalState
from .shape import valid_fid
from .writer_head import WriterBinding, writer_store_binding
from .writer_repository import HeadGrant, control_extension


class ControlHeadRetry(ValueError):
    """One exact permitted control-head turn lost a removal-root CAS."""


class LookupRefresh(ValueError):
    """The caller names a stale judgment tip and must retry at ``tip``."""

    def __init__(self, tip):
        super().__init__("proof_refresh_required")
        self.tip = tip


class LookupActive(ValueError):
    """The subject is removed; only its own authenticated story is carried."""

    def __init__(self, tip, path):
        super().__init__("removal denied")
        self.tip = tip
        self.path = path


@dataclass(frozen=True, slots=True)
class LookupJudgment:
    status: str
    tip: str | None
    path: bytes | None
    pin: object = None

    def __post_init__(self):
        if self.status not in {"unknown", "clear", "active"} \
                or self.status == "unknown" and (
                    self.tip is not None or self.path is not None) \
                or self.status != "unknown" and not valid_fid(self.tip) \
                or self.status == "clear" and self.path is not None \
                or self.status == "active" and not isinstance(
                    self.path, bytes):
            raise ValueError("lookup judgment")


class AccessGate:
    """Evaluate discarded closed piles; retain only recipient removal state."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("access workspace")
        self.workspace = workspace
        self.store = store
        self.state = RecipientRemovalState(workspace, store)
        self.evaluator = ClosedPileEvaluator(
            workspace, max_bytes=MAX_MINT_REQUEST_BYTES)
        self._pin_cache = None
        self._lookup_cache = {}

    def _evaluate(self, raw):
        return self.evaluator.evaluate(raw)

    async def _pin(self):
        previous = self._pin_cache
        pin = await self.state.pin(previous)
        if previous is not None and (
                pin is None or pin.root_oid != previous.root_oid):
            self._lookup_cache.clear()
        self._pin_cache = pin
        return pin

    async def _lookup(self, identity):
        """Judge one admitted device/owner tuple at the recipient's live pin."""
        pin = await self._pin()
        if pin is None:
            return LookupJudgment("unknown", None, None)
        key = pin.root_oid, identity.device, identity.owner, identity.scopes
        cached = self._lookup_cache.get(key)
        if cached is not None:
            status, path = cached
            if status == "unknown":
                return LookupJudgment("unknown", None, None)
            return LookupJudgment(status, pin.root_oid, path, pin)

        states = await pin.lookup_many(identity.scopes)
        active = any(
            value is not None and value.get("state") == "active"
            for value in states)
        if not active and any(value is None for value in states):
            self._lookup_cache[key] = ("unknown", None)
            return LookupJudgment("unknown", None, None)
        status = "active" if active else "clear"
        path = None
        if status == "active":
            present = tuple(
                sid for sid, value in zip(identity.scopes, states)
                if value is not None)
            proofs = await pin.proofs(present)
            path = encode_path(RemovalPath(
                self.workspace, pin.root_oid, proofs))
        self._lookup_cache[key] = status, path
        return LookupJudgment(status, pin.root_oid, path, pin)

    @staticmethod
    def _finish_lookup(judgment, basis, *, admitted=False):
        if judgment.status == "unknown":
            return None
        if judgment.status == "active":
            raise LookupActive(judgment.tip, judgment.path)
        if not admitted and basis and basis != judgment.tip:
            raise LookupRefresh(judgment.tip)
        return judgment

    async def authorize_access(self, proof, trusted_now, *, purpose="sync"):
        """Lookup current standing; evaluate a positive chain only if UNKNOWN."""
        pile = decode_signed_pile(proof, workspace=self.workspace)
        looked = facts.lookup_request(
            pile, trusted_now, purpose=purpose)
        if looked is None:
            return None
        identity, basis, verb = looked
        judgment = await self._lookup(identity)
        admitted = False
        if judgment.status == "unknown":
            try:
                evaluated = self._evaluate(proof)
            except ValueError:
                return None
            admission = facts.authorize_admission(
                evaluated.judgment,
                evaluated.pile.facts,
                trusted_now,
                purpose=purpose,
                writer=evaluated.pile.writer,
            )
            if admission is None:
                return None
            evaluated_identity, evaluated_verb = admission
            if (evaluated_identity.device, evaluated_identity.owner,
                    evaluated_verb) != (identity.device, identity.owner, verb):
                return None
            result = await self.state.admit(evaluated_identity)
            if result.status not in {"applied", "noop"}:
                return None
            judgment = await self._lookup(identity)
            admitted = True
        judgment = self._finish_lookup(
            judgment, basis, admitted=admitted)
        return identity.device, verb, judgment.tip

    async def authorize_head(self, proof, proposed_head, trusted_now):
        """Bind a current path to one exact writer-head CAS request."""
        decision = await self._head_decision(
            proof, proposed_head, trusted_now)
        if decision is None:
            return None
        pin, device, owner, base_head, _scopes = decision
        _head, controls = await control_extension(
            self.store,
            WriterBinding(
                self.workspace,
                device,
                owner,
                writer_store_binding(self.workspace, device),
            ),
            base_head,
            proposed_head,
        )
        if controls:
            return None
        return HeadGrant(
            self.workspace,
            device,
            base_head,
            proposed_head,
            pin.root_oid,
        )

    async def _head_decision(self, proof, proposed_head, trusted_now):
        """Return the live lookup pin and exact outer-signed head claim."""
        if not valid_fid(proposed_head):
            return None
        pile = decode_signed_pile(proof, workspace=self.workspace)
        looked = facts.lookup_request(
            pile, trusted_now, proposed_head=proposed_head)
        if looked is None:
            return None
        identity, basis, base_head = looked
        judgment = self._finish_lookup(
            await self._lookup(identity), basis)
        if judgment is None:
            return None
        return (
            judgment.pin,
            identity.device,
            identity.owner,
            base_head,
            identity.scopes,
        )

    async def issue_head_permit(
            self, proof, proposed_head, control_piles, trusted_now, secret):
        """Authorize exact control piles while the writer is still current."""
        decision = await self._head_decision(
            proof, proposed_head, trusted_now)
        if decision is None:
            return None
        pin, device, owner, base_head, _scopes = decision
        try:
            control_piles = tuple(control_piles)
        except TypeError:
            return None
        _head, declared = await control_extension(
            self.store,
            WriterBinding(
                self.workspace,
                device,
                owner,
                writer_store_binding(self.workspace, device),
            ),
            base_head,
            proposed_head,
        )
        supplied = tuple(signed_pile_oid(raw) for raw in control_piles)
        if supplied != declared:
            return None
        plan = await self.state.plan_control_missing(
            pin, control_piles, device)
        return encode_permit(ControlHeadPermit(
            self.workspace,
            device,
            base_head,
            proposed_head,
            pin.root_oid,
            plan.updates,
        ), secret)

    async def commit_head_permit(
            self, head_gate, permit_raw, proposed_head, secret):
        """Apply authenticated rows, then perform one exact writer-slot CAS."""
        if not callable(getattr(head_gate, "control_replay", None)) \
                or not callable(getattr(head_gate, "advance_control", None)):
            raise TypeError("control head gate")
        permit = decode_permit(permit_raw, secret)
        if permit.workspace != self.workspace or permit.head != proposed_head:
            return None
        grant = HeadGrant(
            permit.workspace,
            permit.device,
            permit.base_head,
            permit.head,
            permit.removal_root,
        )
        permit_oid = h(permit_raw)
        replay = await head_gate.control_replay(grant, permit_oid)
        if replay is not None:
            return replay
        pin = await self.state.pin()
        if pin is None:
            return None
        recovering = pin.root_oid != permit.removal_root
        if recovering and not await self.state.includes(
                pin, permit.updates):
            raise ControlHeadRetry("control head removal root is stale")

        result = None
        attempts = 1 if recovering else MAX_CONTROL_APPLY_ATTEMPTS
        for _attempt in range(attempts):
            result = await self.state.apply_updates(permit.updates)
            if result.status != "retryable":
                break
        if result is None or result.status == "retryable":
            raise ControlHeadRetry("control head removal CAS")
        if result.status not in {"applied", "noop"} \
                or not valid_fid(result.root_oid):
            return None
        return await head_gate.advance_control(
            grant, permit_oid, result.root_oid)


__all__ = (
    "AccessGate",
    "ControlHeadRetry",
    "LookupActive",
    "LookupJudgment",
    "LookupRefresh",
)
