"""Bounded, SQLite-free authorization reads over one composite root."""
import facts

from . import indexes, merkle_map
from .close import ClosedPileEvaluator
from .crypto import h
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

    def fact_known(self, fid):
        """Whether this exact fact has an authenticated residence."""
        row = self._reader(indexes.FACT).get(indexes.fact_key(fid))
        return row is not None and bool(indexes.checked_fact_oid(row))

    def fact_of(self, fid):
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
        return self.fact_of(fid).key

    def suppression(self, sid):
        row = self._reader(indexes.SUPP).get(sid)
        return indexes.checked_suppression_slot(row)

    def scopes_active(self, scopes):
        return all(self.suppression(sid)["state"] == "clear" for sid in scopes)

    def fact_active(self, fid):
        fact = self.fact_of(fid)
        return self.scopes_active(facts.current_scopes(fact))

    def principal_active(self, kind, public_key):
        return self.suppression(
            indexes.principal_sid(kind, public_key))["state"] == "clear"

    def suppression_known(self, sid):
        """Whether the published snapshot reserves this exact typed id."""
        return self._reader(indexes.SUPP).get(sid) is not None

    def mint(self, pile_bytes, trusted_now, *, purpose="sync"):
        """Validate one signed closed pile for the caller's exact purpose.

        ``purpose`` is supplied by the trusted endpoint, never decoded from a
        bearer token or caller-owned JSON.  A family still has to accept that
        purpose and the submitted request fact must name the same value.
        """
        try:
            evaluated = ClosedPileEvaluator(self.anchor).evaluate(pile_bytes)
            stream = evaluated.pile.facts
            if len(stream) > MAX_PROOF_FACTS:
                return None
            decision = facts.authorize_access(
                evaluated.judgment,
                stream,
                self,
                trusted_now,
                purpose=purpose,
            )
            return decision if decision == (
                evaluated.pile.writer, purpose) else None
        except Exception:
            return None
