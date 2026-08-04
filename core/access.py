"""Database-free two-phase access decisions over one private removal pin."""

import facts

from .close import ClosedPileEvaluator
from .limits import MAX_MINT_REQUEST_BYTES
from .removal_path import build as build_path, encode as encode_path
from .removal_state import RecipientRemovalState
from .shape import valid_fid
from .writer_repository import HeadGrant


class AccessGate:
    """Evaluate discarded closed piles; retain only recipient removal state."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("access workspace")
        self.workspace = workspace
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
        device, _owner, base_head = decision
        return HeadGrant(
            self.workspace,
            device,
            base_head,
            proposed_head,
            pin.root_oid,
        )


__all__ = ("AccessGate",)
