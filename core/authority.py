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
)
from .object_store import (
    ABSENT,
    AUTHORITY_ROOT_KEY,
    Versioned,
    VersionToken,
    async_store,
)
from .repository_applier import RepositoryApplier
from .repository_reader import RepositoryReader
from .shape import valid_fid
from .worker import MAX_PROOF_FACTS


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


@dataclass(frozen=True, slots=True)
class AuthorityPin:
    """One exact authority root plus its separate opaque CAS capability."""

    workspace: str
    root_bytes: bytes
    root_oid: str
    version: VersionToken
    _store: object = field(repr=False, compare=False)

    def __post_init__(self):
        if not valid_fid(self.workspace) \
                or not isinstance(self.root_bytes, bytes) \
                or self.root_oid != h(self.root_bytes) \
                or not isinstance(self.version, VersionToken):
            raise ValueError("authority pin")
        object.__setattr__(self, "_store", async_store(self._store))
        # Decode and workspace-bind the root before exposing the pin. Object
        # pages remain cold until an answer asks for them.
        RepositoryReader(self.workspace, self.root_bytes, lambda _oid: None)

    async def _fetch(self, oid):
        return await self._store.get_bounded(
            "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)

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

            return await RepositoryReader.answer_awaited(
                self.workspace,
                self.root_bytes,
                self._fetch,
                answer,
                max_unique_fetches=max_unique_fetches,
                max_fetch_bytes=max_fetch_bytes,
            )
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

    async def receive_pile(self, uploader, raw):
        """Retain and apply one exact signed authority closure."""
        return await self.applier.receive_pile(uploader, raw)

    async def apply_exact(self, source_store, source, payload):
        """Apply a caller-named retained authority closure."""
        return await self.applier.apply_exact(source_store, source, payload)

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


__all__ = (
    "AUTHORITY_ROOT_KEY",
    "AuthorityPin",
    "AuthorityRepository",
    "authority_resident",
)
