"""SQL-permitted local authorship that emits one ordinary exact pile."""
import facts

from .close import close, encode_pile
from .crypto import h
from .kernel import drain, resolve_deps
from .limits import PayloadTooLarge


class AuthorityRejected(ValueError):
    """A valid authored fact lacks current canonical standing."""


class PileSender:
    """Close local intent and deliver it to a recipient's shared Applier."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def close(self, news, deps_new):
        """Close local intent using the disposable SQL projection."""
        node, workspace = self.node, self.workspace
        with node.lock:
            idx = node.idx(workspace)
            newmap = {fact.fid: fact for fact in news}

            def fact_of(fid):
                return newmap.get(fid) or node.fact_of(workspace, fid)

            def deps_of(fid):
                if fid in deps_new:
                    return deps_new[fid]
                return resolve_deps(fact_of(fid), idx) or ()

            return tuple(close(news, deps_of, fact_of))

    def pack(self, closed):
        """Encode one already-closed outbound unit in the ordinary wire codec."""
        return encode_pile(closed, workspace=self.workspace)

    def pack_batches(self, closed_units):
        """Coalesce witness-compatible units within the pile byte boundary.

        A proof closure binds every fact to exact named dependency edges.
        Adding another independently verified closure can change canonical
        offer selection even when the resulting stream remains valid. Such a
        union would manufacture a different historical witness, so it must be
        sent separately. Compatible closures can still share their common
        prefix and avoid one receiver settlement per changed fact.
        """
        def edge_map(unit, *, strict=True):
            judgment = drain(unit, self.workspace)
            if not judgment.ok or len(judgment.valids) != len(unit):
                if strict:
                    raise ValueError("outbound unit is not an exact closure")
                return None
            return {
                valid.fact.fid: tuple(valid.edges)
                for valid in judgment.valids
            }

        def checked_unit(unit):
            edges = edge_map(unit)
            # Fail before any delivery if one indivisible proof is too large.
            self.pack(unit)
            return unit, edges

        batches, current, current_edges = [], [], {}
        for raw_unit in closed_units:
            unit = tuple(raw_unit)
            if not unit:
                continue
            unit, isolated_edges = checked_unit(unit)
            if not current:
                current = list(unit)
                current_edges = isolated_edges
                continue

            shared = current_edges.keys() & isolated_edges.keys()
            compatible = all(
                current_edges[fid] == isolated_edges[fid]
                for fid in shared
            )
            additions = [
                fact for fact in unit
                if fact.fid not in current_edges
            ]
            if compatible and not additions:
                continue
            trial = (*current, *additions)
            try:
                self.pack(trial)
            except PayloadTooLarge:
                batches.append(self.pack(current))
                current = list(unit)
                current_edges = isolated_edges
                continue

            if compatible:
                combined_edges = edge_map(trial, strict=False)
                expected_edges = {
                    **current_edges,
                    **{
                        fact.fid: isolated_edges[fact.fid]
                        for fact in additions
                    },
                }
                compatible = combined_edges is not None \
                    and combined_edges == expected_edges
            if not compatible:
                batches.append(self.pack(current))
                current = list(unit)
                current_edges = isolated_edges
                continue

            current.extend(additions)
            current_edges = combined_edges
        if current:
            batches.append(self.pack(current))
        return tuple(batches)

    def deliver(self, peer, closed_units):
        """Deliver local verified closures through one outbound capability.

        Detached immutable objects go first.  Piles are encoded and bounded
        before the first network mutation, then delivered through the peer's
        narrow transport interface.
        """
        units = tuple(tuple(unit) for unit in closed_units)
        batches = self.pack_batches(units)
        store = self.node.store(self.workspace)
        object_ids = sorted({
            oid
            for unit in units
            for fact in unit
            for oid in facts.blob_refs(fact)
        })
        for oid in object_ids:
            raw = store.get("obj/" + oid)
            if raw is None:
                continue
            if h(raw) != oid:
                raise ValueError("local immutable object integrity")
            peer.put_obj(oid, raw)
        for raw in batches:
            peer.put_pile(raw)
        return len(batches)

    def pile(self, news, deps_new):
        """Close and encode local intent without receiving it."""
        return self.pack(self.close(news, deps_new))

    def send(self, news, deps_new):
        """Deliver local intent through the recipient RepositoryApplier."""
        node, workspace = self.node, self.workspace
        raw = self.pile(news, deps_new)
        fresh = node.receive_pile(
            workspace, node.member_for(workspace), raw)
        missing = [
            fact.fid for fact in news
            if facts.family_for(fact.t).DURABLE
            and node.fact_of(workspace, fact.fid) is None
        ]
        if missing:
            sample = ", ".join(sorted(missing)[:3])
            error = (
                f"authored facts are outside the canonical set: {sample}")
            if any(
                    node.candidate_of(workspace, fid) is not None
                    for fid in missing):
                raise AuthorityRejected(error)
            raise ValueError(error)
        return fresh
