"""Bounded, SQLite-free authorization reads over one composite root."""
from dataclasses import dataclass

import facts

from . import merkle_map, indexes, manifest
from .close import decode_pile
from .crypto import h
from .kernel import drain

MAX_PROOF_FACTS = 64


@dataclass
class WorkerView:
    etag: str
    anchor: str
    seed: str
    trees: dict
    fetch: object

    @classmethod
    def from_root(cls, root_bytes, fetch):
        root = manifest.decode_root(root_bytes)
        if not all(root.trees[name]["root"] for name in indexes.TREE_NAMES):
            raise ValueError("composite root is not Worker-readable")
        return cls(
            h(root_bytes), root.anchor, root.layout_seed, root.trees, fetch)

    def _reader(self, name):
        descriptor = self.trees[name]
        return merkle_map.Reader(
            descriptor["root"], self.seed, self.fetch,
            max_page_depth=descriptor["depth"])

    def fact_record(self, fid):
        row = self._reader(indexes.FACT).get(indexes.fact_key(fid))
        if row is None:
            raise ValueError("missing FactRecord")
        return indexes.checked_fact_record(row, fid)

    def postings(
            self, kind, k0=None, k1=None, *, after=None,
            limit=merkle_map.MAX_RANGE_ROWS):
        """One bounded generic-index page for a cold publisher/query."""
        return indexes.posting_page(
            self._reader(indexes.FACT), kind, k0, k1,
            after=after, limit=limit)

    def fact_location(self, fid):
        """Canonical reconciliation key locating this fact's home range."""
        return self.fact_record(fid)["key"]

    def suppression(self, sid):
        row = self._reader(indexes.SUPP).get(sid)
        if not isinstance(row, dict) or row.get("state") not in {
                "clear", "active"}:
            raise ValueError("missing SuppSlot")
        if row["state"] == "clear" and set(row) != {"state"}:
            raise ValueError("SuppSlot shape")
        if row["state"] == "active" and (
                set(row) != {"state", "action"}
                or not isinstance(row["action"], str)):
            raise ValueError("SuppSlot shape")
        return row

    def scopes_active(self, scopes):
        return all(self.suppression(sid)["state"] == "clear" for sid in scopes)

    def fact_active(self, fid):
        record = self.fact_record(fid)
        return self.scopes_active(record["selectors"]) \
            and self.scopes_active(record["liveness"])

    def principal_active(self, kind, public_key):
        return self.suppression(
            indexes.principal_sid(kind, public_key))["state"] == "clear"

    def suppression_known(self, sid):
        """Whether the published snapshot reserves this exact typed id."""
        return self._reader(indexes.SUPP).get(sid) is not None

    def authority_known(self, name, a0, a1=None):
        """Whether this exact base offer address exists in the snapshot."""
        return self._reader(indexes.AUTHORITY).get(
            indexes.need_key(name, a0, a1)) is not None

    def authority_provider(self, name, a0, a1=None, requires=()):
        row = self._reader(indexes.AUTHORITY).get(
            indexes.need_key(name, a0, a1, requires))
        if row is None:
            return None
        if not isinstance(row, dict) or row.get("state") not in {
                "none", "provider"}:
            raise ValueError("missing AuthoritySlot")
        if row["state"] == "none":
            return None
        if set(row) != {"state", "fid", "rank"} \
                or not isinstance(row["fid"], str) \
                or type(row["rank"]) is not int:
            raise ValueError("AuthoritySlot shape")
        return row["fid"] if self.fact_active(row["fid"]) else None

    def _committed_needs_match(self, stream):
        """Mirror the kernel's committed-authority omission check.

        A submitted equivalent provider is allowed: peers with different
        current winners must still be able to authenticate the sync that
        converges them.  But once a base offer address is committed, its
        canonical provider must be live and must carry every family-declared
        co-offer.  This is the bounded-tree form of
        kernel._matches_committed_authority; an absent base address alone is
        the legitimate bootstrap case.
        """
        authority = self._reader(indexes.AUTHORITY)
        for fact in stream:
            handler = facts.family_for(fact.t)
            for need in handler.needs(fact):
                address = indexes.need_key(
                    need.name, need.a0, need.a1)
                row = authority.get(address)
                if row is None:
                    continue
                provider = self.authority_provider(
                    need.name, need.a0, need.a1)
                if provider is None:
                    return False
                offered = {
                    tuple(offer) for offer in self.fact_record(provider)["offers"]
                    if isinstance(offer, list) and len(offer) == 3
                }
                if any(
                        (required_name, required_a0, required_a1 or "")
                        not in offered
                        for required_name, required_a0, required_a1
                        in need.requires):
                    return False
        return True

    def mint(self, pile_bytes, trusted_now, *, purpose="sync"):
        """Validate one bounded closure for the caller's exact purpose.

        ``purpose`` is supplied by the trusted endpoint, never decoded from a
        bearer token or caller-owned JSON.  A family still has to accept that
        purpose and the submitted request fact must name the same value.
        """
        try:
            stream, blobs = decode_pile(pile_bytes, self.anchor)
            if blobs or len(stream) > MAX_PROOF_FACTS:
                return None
            result = drain(stream, self.anchor)
            if not result.ok or not self._committed_needs_match(stream):
                return None
            ephemeral = [
                valid for valid in result.valids
                if not facts.family_for(valid.fact.t).DURABLE
            ]
            if len(ephemeral) != 1:
                return None
            request = ephemeral[0]
            family = facts.family_for(request.fact.t)
            authorize = getattr(family, "authorize", None)
            return authorize(
                self, request, stream, trusted_now, purpose=purpose) \
                if authorize is not None else None
        except Exception:
            return None
