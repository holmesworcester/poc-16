"""Mutable authority publication and pinned, database-free access checks.

Authority facts use the ordinary closed-pile kernel and repository compiler,
but advance the distinct ``authority`` CAS register.  Family policy decides
which validated facts may reside there; core owns no auth tag inventory.
Access proofs are discarded evaluations against one exact pinned authority
root.  A proof can select only a provider whose exact bytes reside in that
root and whose current suppression scopes are all CLEAR.
"""
from dataclasses import dataclass, field

import facts

from .close import ClosedPileEvaluator
from .crypto import h
from .limits import (
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from .object_store import (
    ABSENT,
    AUTHORITY_ROOT_KEY,
    StoreError,
    Versioned,
    VersionToken,
    async_store,
)
from .repository_applier import RepositoryApplier
from .repository_reader import RepositoryReader
from .shape import valid_fid
from .worker import MAX_PROOF_FACTS
from .writer_head import WriterBinding, writer_store_binding
from .writer_repository import HeadGrant


def authority_resident(fact):
    """Return the fact family's explicit authority-repository declaration."""
    family = facts.family_for(getattr(fact, "t", None))
    return family is not None and family.DURABLE \
        and family.POLICY.authority_resident


def _access_decision(view, evaluated, trusted_now, purpose):
    """Dispatch exactly one ephemeral family request against ``view``."""
    decision = facts.authorize_access(
        evaluated.judgment,
        evaluated.pile.facts,
        view,
        trusted_now,
        purpose=purpose,
    )
    return decision if decision == (
        evaluated.pile.writer, purpose) else None


def _head_decision(view, evaluated, proposed_head, trusted_now):
    """Dispatch one exact head request against the same pinned view."""
    return facts.authorize_writer_head(
        evaluated.judgment,
        evaluated.pile.facts,
        view,
        evaluated.pile.writer,
        proposed_head,
        trusted_now,
    )


def _active_offers(view, name, key, owner=None):
    """Return current exact authority offers from authenticated residence."""
    page = view.postings(name, key, owner)
    found = []
    while True:
        for row in page.rows:
            fact = view.fact_of(row.fid)
            for offer in fact.offers():
                if offer[0] == name and offer[1] == key \
                        and (owner is None or offer[2] == owner) \
                        and view.fact_active(fact.fid):
                    found.append(offer)
        if page.cursor is None:
            return tuple(found)
        page = view.postings(name, key, owner, after=page.cursor)


@dataclass(frozen=True, slots=True)
class AuthorityPin:
    """One exact authority root plus its separate opaque CAS capability."""

    workspace: str
    root_bytes: bytes
    root_oid: str
    version: VersionToken | None
    _store: object = field(repr=False, compare=False)

    def __post_init__(self):
        if not valid_fid(self.workspace) \
                or not isinstance(self.root_bytes, bytes) \
                or self.root_oid != h(self.root_bytes) \
                or self.version is not None \
                and not isinstance(self.version, VersionToken):
            raise ValueError("authority pin")
        object.__setattr__(self, "_store", async_store(self._store))
        # Decode and workspace-bind the root before exposing the pin. Object
        # pages remain cold until an answer asks for them.
        RepositoryReader(self.workspace, self.root_bytes, lambda _oid: None)

    async def _fetch(self, oid):
        return await self._store.get_bounded(
            "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)

    async def _answer(
            self, answer, *, max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        return await RepositoryReader.answer_awaited(
            self.workspace,
            self.root_bytes,
            self._fetch,
            answer,
            max_unique_fetches=max_unique_fetches,
            max_fetch_bytes=max_fetch_bytes,
        )

    async def authorize_access(
            self, proof, trusted_now, *, purpose="sync",
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Evaluate one signed proof against only this pinned authority root."""
        if not isinstance(proof, bytes) \
                or len(proof) > MAX_MINT_REQUEST_BYTES \
                or type(trusted_now) is not int \
                or not isinstance(purpose, str) or not purpose:
            return None
        try:
            evaluated = ClosedPileEvaluator(self.workspace).evaluate(proof)
            if len(evaluated.pile.facts) > MAX_PROOF_FACTS:
                return None

            def answer(reader):
                try:
                    return _access_decision(
                        reader.worker(), evaluated, trusted_now, purpose)
                except Exception:
                    return None

            return await self._answer(
                answer,
                max_unique_fetches=max_unique_fetches,
                max_fetch_bytes=max_fetch_bytes,
            )
        except (PayloadTooLarge, StoreError):
            raise
        except Exception:
            return None

    async def authorize_head(
            self, proof, proposed_head, trusted_now, *,
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Authorize one exact writer-head OID against this authority pin."""
        if not isinstance(proof, bytes) \
                or len(proof) > MAX_MINT_REQUEST_BYTES \
                or not valid_fid(proposed_head) \
                or type(trusted_now) is not int:
            return None
        try:
            evaluated = ClosedPileEvaluator(self.workspace).evaluate(proof)
            if len(evaluated.pile.facts) > MAX_PROOF_FACTS:
                return None

            def answer(reader):
                try:
                    return _head_decision(
                        reader.worker(), evaluated,
                        proposed_head, trusted_now)
                except Exception:
                    return None

            decision = await self._answer(
                answer,
                max_unique_fetches=max_unique_fetches,
                max_fetch_bytes=max_fetch_bytes,
            )
            if decision is None:
                return None
            device, _owner, base_head = decision
            return HeadGrant(
                self.workspace,
                device,
                base_head,
                proposed_head,
                self.root_oid,
            )
        except (PayloadTooLarge, StoreError):
            raise
        except Exception:
            return None

    async def writer_binding(
            self, device, owner=None, *,
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Resolve one head identity from authenticated current authority."""
        if not valid_fid(device) \
                or owner is not None and not valid_fid(owner):
            return None

        def answer(reader):
            try:
                view = reader.worker()
                members = _active_offers(
                    view, "member", device, owner)
                owners = {offer[2] for offer in members}
                if len(owners) != 1:
                    return None
                selected_owner = next(iter(owners))
                if device != selected_owner and not _active_offers(
                        view, "device_key", device, selected_owner):
                    return None
                return WriterBinding(
                    self.workspace,
                    device,
                    selected_owner,
                    writer_store_binding(self.workspace, device),
                )
            except Exception:
                return None

        try:
            return await self._answer(
                answer,
                max_unique_fetches=max_unique_fetches,
                max_fetch_bytes=max_fetch_bytes,
            )
        except (PayloadTooLarge, StoreError):
            raise
        except Exception:
            return None


class AuthorityRepository:
    """The sole signed-pile transition into one workspace's authority root."""

    def __init__(self, workspace, store):
        if not valid_fid(workspace):
            raise ValueError("authority workspace")
        self.workspace = workspace
        self.store = async_store(store)
        evaluator = ClosedPileEvaluator(workspace)
        self.applier = RepositoryApplier(
            workspace,
            self.store,
            root_key=AUTHORITY_ROOT_KEY,
            evaluate=lambda raw: evaluator.evaluate(raw).judgment,
            accept_fact=authority_resident,
        )

    async def publish(self, raw):
        """Validate and apply exact signed bytes without an ingress queue."""
        return await self.applier.apply_pile(raw)

    async def pin(self):
        """Atomically read and validate the current exact authority root."""
        opened = await self.store.read_versioned(AUTHORITY_ROOT_KEY)
        if opened is ABSENT:
            return None
        if not isinstance(opened, Versioned):
            raise TypeError("versioned authority-root read")
        return AuthorityPin(
            self.workspace,
            opened.value,
            h(opened.value),
            opened.token,
            self.store,
        )

    async def pin_root(self, root_oid):
        """Open one immutable historical authority root by content identity."""
        if not valid_fid(root_oid):
            return None
        raw = await self.store.get_bounded(
            "obj/" + root_oid, MAX_REPOSITORY_OBJECT_BYTES)
        if not isinstance(raw, bytes) or h(raw) != root_oid:
            return None
        try:
            return AuthorityPin(
                self.workspace, raw, root_oid, None, self.store)
        except ValueError:
            return None

    async def authorize_access(
            self, proof, trusted_now, *, purpose="sync",
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Pin once, then answer without SQL, LIST, mutation, or root drift."""
        pin = await self.pin()
        if pin is None:
            return None
        return await pin.authorize_access(
            proof,
            trusted_now,
            purpose=purpose,
            max_unique_fetches=max_unique_fetches,
            max_fetch_bytes=max_fetch_bytes,
        )

    async def authorize_head(
            self, proof, proposed_head, trusted_now, *,
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Pin once and authorize one exact per-device slot update."""
        pin = await self.pin()
        if pin is None:
            return None
        return await pin.authorize_head(
            proof,
            proposed_head,
            trusted_now,
            max_unique_fetches=max_unique_fetches,
            max_fetch_bytes=max_fetch_bytes,
        )

    async def writer_binding(
            self, device, owner=None, *,
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Resolve one candidate head against one freshly pinned root."""
        pin = await self.pin()
        if pin is None:
            return None
        return await pin.writer_binding(
            device,
            owner,
            max_unique_fetches=max_unique_fetches,
            max_fetch_bytes=max_fetch_bytes,
        )

    async def writer_binding_at(
            self, root_oid, device, owner=None, *,
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES):
        """Resolve a previously accepted slot at its recorded authority root."""
        pin = await self.pin_root(root_oid)
        if pin is None:
            return None
        return await pin.writer_binding(
            device,
            owner,
            max_unique_fetches=max_unique_fetches,
            max_fetch_bytes=max_fetch_bytes,
        )


__all__ = (
    "AUTHORITY_ROOT_KEY",
    "AuthorityPin",
    "AuthorityRepository",
    "authority_resident",
)
