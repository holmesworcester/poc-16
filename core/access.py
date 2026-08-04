"""Database-free two-phase access decisions over one private removal pin."""

import facts

from .close import ClosedPileEvaluator, signed_pile_oid
from .crypto import h
from .head_permit import (
    ControlHeadPermit,
    decode as decode_permit,
    encode as encode_permit,
)
from .limits import MAX_CONTROL_APPLY_ATTEMPTS, MAX_MINT_REQUEST_BYTES
from .removal_path import build as build_path, encode as encode_path
from .removal_state import RecipientRemovalState
from .shape import valid_fid
from .writer_head import WriterBinding, writer_store_binding
from .writer_repository import HeadGrant, control_extension


class ControlHeadRetry(ValueError):
    """One exact permitted control-head turn lost a removal-root CAS."""


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

    def _evaluate(self, raw):
        return self.evaluator.evaluate(raw)

    async def removal_path(self, proof, trusted_now):
        """Answer historical membership with only caller-derived points."""
        evaluated = self._evaluate(proof)
        identity = facts.authorize_removal_path(
            evaluated.judgment,
            evaluated.pile.facts,
            evaluated.pile.writer,
            trusted_now,
        )
        if identity is None:
            return None
        pin = await self.state.pin()
        if pin is None:
            return None
        return encode_path(await build_path(pin, identity.scopes))

    async def authorize_access(self, proof, trusted_now, *, purpose="sync"):
        """Require one current self-confined path at the exact pinned root."""
        pin = await self.state.pin()
        if pin is None:
            return None
        evaluated = self._evaluate(proof)
        return facts.authorize_access(
            evaluated.judgment,
            evaluated.pile.facts,
            pin,
            trusted_now,
            purpose=purpose,
            writer=evaluated.pile.writer,
        )

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
        """Return the exact pin and family-owned caller identity decision."""
        if not valid_fid(proposed_head):
            return None
        pin = await self.state.pin()
        if pin is None:
            return None
        evaluated = self._evaluate(proof)
        decision = facts.authorize_writer_head(
            evaluated.judgment,
            evaluated.pile.facts,
            pin,
            evaluated.pile.writer,
            proposed_head,
            trusted_now,
        )
        if decision is None:
            return None
        try:
            device, owner, base_head, scopes = decision
            scopes = tuple(scopes)
        except (TypeError, ValueError):
            return None
        if not valid_fid(device) or not valid_fid(owner) \
                or base_head is not None and not valid_fid(base_head) \
                or not scopes:
            return None
        return pin, device, owner, base_head, scopes

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
        plan = self.state.plan_control(control_piles, device)
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


__all__ = ("AccessGate", "ControlHeadRetry")
