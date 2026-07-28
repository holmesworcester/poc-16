"""Bounded, SQLite-free authorization reads over one composite root."""
from dataclasses import dataclass

import facts

from . import btreap, indexes, manifest
from .close import decode_pile
from .crypto import h
from .kernel import drain
from .shape import valid_fid

MAX_PROOF_FACTS = 64


@dataclass
class WorkerView:
    etag: str
    anchor: str
    globals_: frozenset
    seed: str
    trees: dict
    fetch: object

    @classmethod
    def from_root(cls, root_bytes, fetch):
        anchor, globals_, _ = manifest.decode_root(root_bytes)
        seed, trees = manifest.decode_composite(root_bytes)
        if not all(trees[name]["root"] for name in indexes.TREE_NAMES):
            raise ValueError("composite root is not Worker-readable")
        return cls(h(root_bytes), anchor, globals_, seed, trees, fetch)

    def _reader(self, name):
        descriptor = self.trees[name]
        return btreap.Reader(
            descriptor["root"], self.seed, self.fetch,
            max_page_depth=descriptor["depth"])

    def fact_record(self, fid):
        row = self._reader(indexes.FACT).get(indexes.fact_key(fid))
        if not isinstance(row, dict) or set(row) != {
                "edges", "evidence", "key", "liveness", "offers", "raw",
                "selectors", "tag"}:
            raise ValueError("missing FactRecord")
        if not isinstance(row["selectors"], list) \
                or len(row["selectors"]) > indexes.MAX_SELECTORS \
                or not all(isinstance(sid, str) for sid in row["selectors"]) \
                or not isinstance(row["liveness"], list) \
                or len(row["liveness"]) > indexes.MAX_SELECTORS \
                or not all(isinstance(sid, str) for sid in row["liveness"]) \
                or not isinstance(row["edges"], dict) \
                or not isinstance(row["offers"], list) \
                or not isinstance(row["evidence"], str) \
                or row["evidence"] and not valid_fid(row["evidence"]):
            raise ValueError("FactRecord shape")
        return row

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
            handler = facts.handler_for(fact.t)
            for need in handler.needs(fact):
                if len(need) == 3:
                    name, a0, a1 = need
                    requires = ()
                elif len(need) == 4:
                    name, a0, a1, requires = need
                else:
                    return False
                address = indexes.need_key(name, a0, a1)
                row = authority.get(address)
                if row is None:
                    continue
                provider = self.authority_provider(name, a0, a1)
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
                        in requires):
                    return False
        return True

    def mint(self, pile_bytes, trusted_now):
        """Validate only the submitted bounded closure, then exact-read state."""
        try:
            stream, blobs = decode_pile(pile_bytes)
            if blobs or len(stream) > MAX_PROOF_FACTS:
                return None
            result = drain(stream, self.anchor)
            if not result.ok or not self._committed_needs_match(stream):
                return None
            ephemeral = [
                valid for valid in result.valids
                if not facts.handler_for(valid.fact.t).DURABLE
            ]
            if len(ephemeral) != 1:
                return None
            request = ephemeral[0]
            body = request.fact.body
            from facts.auth import request as request_family
            if request.fact.t != request_family.TAG \
                    or body["verb"] not in request_family.VERBS \
                    or body["exp"] < trusted_now:
                return None
            edges = {edge.role: edge.fid for edge in request.edges}
            presented = edges.get("member")
            by_fid = {fact.fid: fact for fact in stream}
            provider = by_fid.get(presented)
            if provider is None or (
                    "member", body["pk"], "") not in provider.offers():
                return None
            authority_row = self._reader(indexes.AUTHORITY).get(
                indexes.need_key("member", body["pk"]))
            if authority_row is None:
                # A never-seen address may bootstrap from its validated
                # self-contained closure. A terminal pre-tombstone, or a
                # known address whose slot was omitted, must fail closed.
                principal_row = self._reader(indexes.SUPP).get(
                    indexes.principal_sid("member", body["pk"]))
                if principal_row is not None:
                    return None
            else:
                canonical = self.authority_provider("member", body["pk"])
                if canonical is None \
                        or not self.principal_active("member", body["pk"]):
                    return None
            return body["pk"], body["verb"]
        except Exception:
            return None
