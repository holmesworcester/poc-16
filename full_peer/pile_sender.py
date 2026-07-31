"""SQL-permitted local authorship that emits one ordinary exact pile."""
import facts

from core.close import close, encode_pile
from core.kernel import drain, resolve_deps


class PileSender:
    """Close local intent and deliver it to a recipient's shared Applier."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def close(self, news, deps_new):
        """Close local intent using the disposable SQL projection."""
        node, workspace = self.node, self.workspace
        with node.lock:
            node._sync_sql(workspace)
            context = node.sql(workspace)
            newmap = {fact.fid: fact for fact in news}

            def fact_of(fid):
                return newmap.get(fid) or context.fact(fid)

            def deps_of(fid):
                if fid in deps_new:
                    return deps_new[fid]
                return resolve_deps(fact_of(fid), context) or ()

            return tuple(close(news, deps_of, fact_of))

    def pack(self, closed):
        """Encode one already-closed outbound unit in the ordinary wire codec."""
        return encode_pile(closed, workspace=self.workspace)

    def pack_batches(self, closed_units):
        """Encode each independent closure as its own ordinary pile."""
        batches = []
        for raw_unit in closed_units:
            unit = tuple(raw_unit)
            if not unit:
                continue
            judgment = drain(unit, self.workspace)
            if not judgment.ok or len(judgment.valids) != len(unit):
                raise ValueError("outbound unit is not an exact closure")
            batches.append(self.pack(unit))
        return tuple(batches)

    def deliver(self, peer, closed_units):
        """Deliver fact-only verified closures through one capability."""
        units = tuple(tuple(unit) for unit in closed_units)
        batches = self.pack_batches(units)
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
