"""SQL-permitted local authorship that emits one ordinary exact pile."""
import facts

from core.close import close, encode_pile
from core.crypto import h
from core.kernel import drain, resolve_deps
from core.limits import MAX_OBJECT_BYTES, PayloadTooLarge


class PileSender:
    """Close local intent and deliver it to a recipient's shared Applier."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def close(self, news, deps_new):
        """Close local intent using the disposable SQL projection."""
        node, workspace = self.node, self.workspace
        with node.lock:
            context = node.sql(workspace)
            newmap = {fact.fid: fact for fact in news}

            def fact_of(fid):
                return newmap.get(fid) or node.fact_of(workspace, fid)

            def deps_of(fid):
                if fid in deps_new:
                    return deps_new[fid]
                return resolve_deps(fact_of(fid), context) or ()

            return tuple(close(news, deps_of, fact_of))

    def pack(self, closed):
        """Encode one already-closed outbound unit in the ordinary wire codec."""
        return encode_pile(closed, workspace=self.workspace)

    def pack_batches(self, closed_units):
        """Coalesce closed units while preserving whole-pile validity."""
        def valid_unit(unit, *, strict=True):
            judgment = drain(unit, self.workspace)
            if not judgment.ok or len(judgment.valids) != len(unit):
                if strict:
                    raise ValueError("outbound unit is not an exact closure")
                return False
            return True

        def checked_unit(unit):
            valid_unit(unit)
            # Fail before delivery if one indivisible closure is too large.
            self.pack(unit)
            return unit

        batches, current, current_fids = [], [], set()
        for raw_unit in closed_units:
            unit = tuple(raw_unit)
            if not unit:
                continue
            unit = checked_unit(unit)
            if not current:
                current = list(unit)
                current_fids = {fact.fid for fact in unit}
                continue

            additions = [
                fact for fact in unit
                if fact.fid not in current_fids
            ]
            if not additions:
                continue
            trial = (*current, *additions)
            try:
                self.pack(trial)
            except PayloadTooLarge:
                batches.append(self.pack(current))
                current = list(unit)
                current_fids = {fact.fid for fact in unit}
                continue

            if not valid_unit(trial, strict=False):
                batches.append(self.pack(current))
                current = list(unit)
                current_fids = {fact.fid for fact in unit}
                continue

            current.extend(additions)
            current_fids.update(fact.fid for fact in additions)
        if current:
            batches.append(self.pack(current))
        return tuple(batches)

    def deliver(self, peer, closed_units):
        """Deliver local verified closures through one outbound capability.

        Detached immutable objects go first.  Piles are encoded and bounded
        before the first network mutation, then delivered through the peer's
        narrow byte interface.
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
            raw = store.get_bounded(
                "obj/" + oid, MAX_OBJECT_BYTES)
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
            raise ValueError(
                f"authored facts were not admitted: {sample}")
        return fresh
