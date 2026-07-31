"""Bounded, SQLite-free authorization reads over one composite root."""
import facts

from . import indexes, merkle_map
from .close import decode_pile
from .crypto import h
from .kernel import drain
from .validated_set import ValidatedView

MAX_PROOF_FACTS = 64


class WorkerView:
    """Authorization-only facade over shared authenticated read mechanics."""

    def __init__(self, root_bytes, fetch):
        # The awaited HTTP driver owns authorization-read memoization and its
        # fetch budget; synchronous Worker reads must expose every cold fetch.
        self._validated = ValidatedView(
            root_bytes, fetch, cache_objects=False)
        self.etag = h(root_bytes)
        self.anchor = self._validated.root.anchor

    @classmethod
    def from_root(cls, root_bytes, fetch):
        return cls(root_bytes, fetch)

    def _reader(self, name):
        return self._validated._reader(name)

    def fact_oid(self, fid):
        return self._validated.fact_oid(fid)

    def fact(self, fid):
        return self._validated.fact(fid)

    def postings(
            self, kind, k0=None, k1=None, *, after=None,
            limit=merkle_map.MAX_RANGE_ROWS):
        """One bounded generic-index page for a cold applier/query."""
        return indexes.posting_page(
            self._reader(indexes.FACT), kind, k0, k1,
            after=after, limit=limit)

    def fact_location(self, fid):
        """Canonical reconciliation key locating this fact's home range."""
        return self.fact(fid).key

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
        fact = self.fact(fid)
        return self.scopes_active(facts.current_scopes(fact))

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

    def authority_provider(self, name, a0, a1=None):
        """Return the current provider for one complete authority address."""
        row = self._reader(indexes.AUTHORITY).get(
            indexes.need_key(name, a0, a1))
        if row is None:
            return None
        if not isinstance(row, dict) or row.get("state") not in {
                "none", "provider"}:
            raise ValueError("missing AuthoritySlot")
        if row["state"] == "none":
            return None
        if set(row) != {"state", "fid"} \
                or not isinstance(row["fid"], str):
            raise ValueError("AuthoritySlot shape")
        fid = row["fid"]
        return fid if fid is not None and self.fact_active(fid) else None

    def mint(self, pile_bytes, trusted_now, *, purpose="sync"):
        """Validate one bounded closure for the caller's exact purpose.

        ``purpose`` is supplied by the trusted endpoint, never decoded from a
        bearer token or caller-owned JSON.  A family still has to accept that
        purpose and the submitted request fact must name the same value.
        """
        try:
            stream = decode_pile(pile_bytes, self.anchor)
            if len(stream) > MAX_PROOF_FACTS:
                return None
            result = drain(stream, self.anchor)
            if not result.ok:
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
