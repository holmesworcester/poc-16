"""Validated, ephemeral notification views over the writer-head forest.

Notification progress is per writer.  Delivery occasionally needs one joined
query view for preferences, endpoints, and suppression; build that view in
memory through the ordinary RepositoryMirror/FactConsumer path and discard it
after the decision.  It is never a published workspace root.
"""
from dataclasses import dataclass, field
from types import MappingProxyType

import facts

from core import merkle_map
from core.crypto import h
from core.fact import bound_to, decode
from core.fact_index import IndexPosting, PostingPage, index_rows
from core.limits import MAX_DIRECT_OBJECT_BYTES, PayloadTooLarge
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    STALE,
    Applied,
    ListPage,
    Versioned,
    VersionToken,
)
from core.shape import valid_fid
from core.writer_head import WriterBinding
from core.writer_repository import FactConsumer, RepositoryMirror


class MemoryStore:
    """One invocation's non-authoritative ObjectStore implementation."""

    def __init__(self):
        self.values = {}

    async def get_bounded(self, key, maximum):
        value = self.values.get(key)
        if value is not None and len(value) > maximum:
            raise PayloadTooLarge("notification memory read")
        return value

    async def copy_pile_object(self, oid, maximum, write):
        if not valid_fid(oid) or not callable(write) \
                or type(maximum) is not int \
                or not 0 < maximum <= MAX_DIRECT_OBJECT_BYTES:
            raise ValueError("notification memory pile read")
        value = self.values.get("obj/" + oid)
        if value is None:
            return None
        if len(value) > maximum:
            raise PayloadTooLarge("notification memory pile read")
        write(value)
        return len(value)

    async def read_versioned(self, key):
        value = self.values.get(key)
        return ABSENT if value is None else Versioned(
            value, VersionToken(h(value)))

    async def put_if_absent(self, key, value):
        if key not in self.values:
            self.values[key] = value
            return CREATED
        if self.values[key] != value:
            raise ValueError("notification memory object conflict")
        return EXISTS

    async def cas(self, key, token, value):
        current = await self.read_versioned(key)
        current_token = current.token \
            if isinstance(current, Versioned) else ABSENT
        if current_token != token:
            return STALE
        self.values[key] = value
        return Applied(VersionToken(h(value)))

    async def list_page(self, prefix, cursor=None, limit=256):
        keys = sorted(
            key for key in self.values
            if key.startswith(prefix) and (cursor is None or key > cursor))
        selected = tuple(keys[:limit])
        return ListPage(
            selected,
            selected[-1] if len(keys) > limit else None,
        )


def claimed_writer_binding(workspace, device, _removal_root, candidate):
    """Bind a signed head to its claim; its piles must prove that claim.

    RepositoryMirror verifies the head signature and FactConsumer additionally
    requires each received closure to contain the exact member/device offer.
    Current liveness is deliberately a separate delivery-time decision.
    """
    if getattr(candidate, "workspace", None) != workspace \
            or getattr(candidate, "device", None) != device:
        raise ValueError("notification writer binding")
    return WriterBinding(
        workspace, device, candidate.owner, candidate.store)


@dataclass(frozen=True, slots=True)
class CurrentView:
    """Small Worker-shaped index over one validated in-memory fact join."""

    workspace: str
    facts_by_fid: dict
    _postings: tuple = field(init=False, repr=False, compare=False)
    _actions: dict = field(init=False, repr=False, compare=False)
    _known_sids: set = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not valid_fid(self.workspace) \
                or not isinstance(self.facts_by_fid, dict):
            raise ValueError("notification current view")
        checked = {}
        for fid, raw in sorted(self.facts_by_fid.items()):
            fact = decode(raw)
            family = facts.family_for(fact.t)
            if fact.fid != fid or not bound_to(fact, self.workspace) \
                    or family is None or not family.DURABLE:
                raise ValueError("notification current fact")
            checked[fid] = fact
        postings = {
            IndexPosting(kind, k0, k1, fid)
            for fid, fact in checked.items()
            for kind, k0, k1, _source in index_rows(fact)
        }
        actions = {}
        for fact in sorted(
                checked.values(), key=lambda item: (item.key, item.fid)):
            for sid in sorted(facts.action_sids(fact)):
                actions.setdefault(sid, fact.fid)
        known = {
            sid for fact in checked.values()
            for sid in facts.current_scopes(fact)
        } | set(actions)
        object.__setattr__(
            self, "facts_by_fid", MappingProxyType(checked))
        object.__setattr__(self, "_postings", tuple(sorted(postings)))
        object.__setattr__(self, "_actions", actions)
        object.__setattr__(self, "_known_sids", known)

    def fact_known(self, fid):
        return fid in self.facts_by_fid

    def fact_of(self, fid):
        try:
            return self.facts_by_fid[fid]
        except KeyError as error:
            raise ValueError("unknown notification fact") from error

    def postings(
            self, kind, k0=None, k1=None, *, after=None,
            limit=merkle_map.MAX_RANGE_ROWS):
        if not isinstance(kind, str) or not kind \
                or k1 is not None and k0 is None \
                or type(limit) is not int \
                or not 0 < limit <= merkle_map.MAX_RANGE_ROWS \
                or after is not None and (
                    not isinstance(after, str) or not after.isdigit()):
            raise ValueError("notification posting page")
        rows = tuple(
            row for row in self._postings
            if row.kind == kind
            and (k0 is None or row.k0 == k0)
            and (k1 is None or row.k1 == k1)
        )
        start = 0 if after is None else int(after)
        if start > len(rows):
            raise ValueError("notification posting cursor")
        selected = rows[start:start + limit]
        end = start + len(selected)
        return PostingPage(
            selected,
            str(end) if end < len(rows) else None,
            0,
        )

    def suppression_known(self, sid):
        return sid in self._known_sids

    def scopes_active(self, scopes):
        return all(sid not in self._actions for sid in scopes)

    def fact_active(self, fid):
        return self.scopes_active(facts.current_scopes(self.fact_of(fid)))

    def principal_active(self, namespace, public_key):
        return facts.principal_sid(namespace, public_key) not in self._actions


@dataclass(frozen=True, slots=True)
class CurrentRepository:
    """One discarded validated writer-forest view for a delivery turn."""

    workspace: str
    view: CurrentView

    def __post_init__(self):
        if not valid_fid(self.workspace) \
                or not isinstance(self.view, CurrentView) \
                or self.view.workspace != self.workspace:
            raise ValueError("notification current repository")


async def current_repository(source, workspace):
    """Validate all current writer heads into one discarded query snapshot."""
    local = MemoryStore()
    consumer = FactConsumer(workspace)
    result = await RepositoryMirror(
        workspace, local, claimed_writer_binding, consumer,
    ).sync_from(source)
    if result.errors:
        raise ValueError("notification current writer forest")
    raw_facts = {
        fid: consumer.fact_bytes(fid)
        for fid in consumer.fact_ids()
    }
    if not raw_facts:
        raise ValueError("notification current writer forest is empty")
    return CurrentRepository(workspace, CurrentView(workspace, raw_facts))


__all__ = (
    "CurrentRepository",
    "CurrentView",
    "MemoryStore",
    "claimed_writer_binding",
    "current_repository",
)
