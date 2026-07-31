"""Authenticated reads and reconstruction of the validated fact set.

FactTree is the durable certificate: a ``fact:<fid> -> object oid`` residence
exists only after an entire closed pile passed the kernel and its compiled
root won CAS.  Reconstruction verifies those canonical bytes and recompiles
the mechanical maps; it never re-adjudicates already admitted facts.
"""

from dataclasses import dataclass

import facts

from . import indexes, merkle_map, repository_snapshot, snapshot
from .fact import bound_to, decode, encode
from .limits import MAX_CLOSURE_FACTS
from .object_store import verified_object
from .shape import valid_fid


@dataclass(frozen=True, slots=True)
class ValidatedSet:
    workspace: str
    root: object
    facts: dict


class ValidatedView:
    """Authenticated point/range reads over validated fact residences."""

    def __init__(self, root_bytes, fetch, *, cache_objects=True):
        self._root_bytes = root_bytes
        self.root = snapshot.decode_root(root_bytes)
        if self.root.layout_seed != indexes.layout_seed(self.root.anchor):
            raise ValueError("composite layout seed")
        if not all(
                self.root.maps[name]["root"]
                for name in snapshot.MAP_NAMES):
            raise ValueError("validated repository is incomplete")
        if type(cache_objects) is not bool:
            raise TypeError("validated object cache")
        self._source_fetch = fetch
        self._objects = {} if cache_objects else None
        self._facts = {}
        self._oids = {}

    def fetch(self, oid):
        if self._objects is None:
            return self._source_fetch(oid)
        if oid not in self._objects:
            self._objects[oid] = self._source_fetch(oid)
        return self._objects[oid]

    def _reader(self, name):
        descriptor = self.root.maps[name]
        return merkle_map.Reader(
            descriptor["root"], self.root.layout_seed, self.fetch,
            max_page_depth=descriptor["depth"],
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"])

    def fact_oid(self, fid):
        if not valid_fid(fid):
            raise ValueError("validated fid")
        if fid not in self._oids:
            row = self._reader(indexes.FACT).get(indexes.fact_key(fid))
            if row is None:
                raise ValueError("missing validated fact")
            self._oids[fid] = indexes.checked_fact_oid(row)
        return self._oids[fid]

    def fact(self, fid):
        if fid in self._facts:
            return self._facts[fid]
        raw = verified_object(self.fact_oid(fid), self.fetch)
        fact = decode(raw)
        if fact.fid != fid or not bound_to(fact, self.root.anchor):
            raise ValueError("validated fact identity")
        family = facts.family_for(fact.t)
        if family is None or not family.DURABLE:
            raise ValueError("validated fact durability")
        self._facts[fid] = fact
        return fact

    def fact_ids(self):
        """Enumerate exactly one residence row per validated fact."""
        reader = self._reader(indexes.FACT)
        start, stop = "fact:", "fact:\uffff"
        cursor, fids, seen = None, [], set()
        while True:
            page = reader.range_page(
                start, stop, after=cursor, limit=merkle_map.MAX_RANGE_ROWS)
            for key, value in page.rows:
                fid = key[len("fact:"):]
                if indexes.fact_key(fid) != key or fid in seen:
                    raise ValueError("validated fact key")
                self._oids[fid] = indexes.checked_fact_oid(value)
                fids.append(fid)
                seen.add(fid)
            if len(fids) > self.root.maps[indexes.FACT]["count"]:
                raise ValueError("validated fact count")
            cursor = page.cursor
            if cursor is None:
                break
        return tuple(fids)

    def _providers(self, name, a0, a1=None):
        reader = self._reader(indexes.FACT)
        cursor, fids = None, []
        while True:
            page = indexes.posting_page(
                reader, name, a0, a1, after=cursor)
            fids.extend(row.fid for row in page.rows)
            cursor = page.cursor
            if cursor is None:
                break
        return tuple(sorted(set(fids)))

    def provider(self, need, source=None):
        """Resolve an exact source or an interchangeable offer provider."""
        providers = self.providers(need, source)
        return providers[0] if providers else None

    def providers(self, need, source=None):
        """Return every canonical provider for one complete offer address."""
        fids = (source,) if source is not None else self._providers(
            need.name, need.a0, need.a1)
        accepted = []
        for fid in fids:
            try:
                fact = self.fact(fid)
            except ValueError:
                continue
            offered = set(fact.offers())
            if not any(
                    name == need.name and a0 == need.a0
                    and (need.a1 is None or a1 == need.a1)
                    for name, a0, a1 in offered):
                continue
            accepted.append(fid)
        return tuple(sorted(accepted))

    def closure(self, fids):
        """Assemble and verify a fresh closed wire unit for validated facts."""
        selected = tuple(sorted(
            (self.fact(fid) for fid in fids), key=lambda fact: fact.key))
        out, done, visiting = [], set(), set()

        def rollback(mark):
            removed = out[mark:]
            del out[mark:]
            done.difference_update(fact.fid for fact in removed)

        def visit(fid):
            if fid in done:
                return True
            if fid in visiting:
                return False
            mark = len(out)
            visiting.add(fid)
            try:
                fact = self.fact(fid)
                for _, parent in sorted(fact.refs()):
                    if not visit(parent):
                        rollback(mark)
                        return False
                family = facts.family_for(fact.t)
                for need in family.needs(fact):
                    source = facts.explicit_provider(fact, need.role)
                    candidates = self.providers(need, source)
                    chosen = False
                    for provider in candidates:
                        candidate_mark = len(out)
                        if visit(provider):
                            chosen = True
                            break
                        rollback(candidate_mark)
                    if not chosen:
                        rollback(mark)
                        return False
                if len(done) >= MAX_CLOSURE_FACTS:
                    rollback(mark)
                    return False
                done.add(fid)
                out.append(fact)
                return True
            finally:
                visiting.remove(fid)

        if not all(visit(fact.fid) for fact in selected):
            raise ValueError("validated fact has no finite closure")
        unit = tuple(out)
        from .kernel import drain

        judgment = drain(unit, self.root.anchor)
        if not judgment.ok or len(judgment.valids) != len(unit):
            raise ValueError("validated fact closure")
        return unit


def reconstruct(root_bytes, fetch):
    """Verify and return every fact reachable from one authenticated root."""
    view = ValidatedView(root_bytes, fetch)
    facts_by_fid = {
        fid: view.fact(fid)
        for fid in view.fact_ids()
    }
    if not facts_by_fid or view.root.anchor not in facts_by_fid:
        raise ValueError("validated set anchor")
    compiled = repository_snapshot.compile_snapshot(
        view.root.anchor, facts_by_fid)
    if compiled.root != root_bytes:
        raise ValueError("noncanonical repository projection")
    return ValidatedSet(
        view.root.anchor,
        view.root,
        facts_by_fid,
    )


__all__ = ("ValidatedSet", "ValidatedView", "reconstruct")
