"""SQL-permitted local authorship of canonical signed closed piles."""
import facts

from core.close import close, encode_signed_pile, make_signed_pile
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
            node._ensure_projection(workspace)
            context = node.sql(workspace)
            newmap = {fact.fid: fact for fact in news}

            def fact_of(fid):
                return newmap.get(fid) or context.fact_of(fid)

            def deps_of(fid):
                if fid in deps_new:
                    return deps_new[fid]
                return resolve_deps(fact_of(fid), context) or ()

            return tuple(close(news, deps_of, fact_of))

    def pack(self, closed):
        """Sign and encode one already-closed portable unit."""
        secret, writer = self.node.identity(self.workspace)
        return encode_signed_pile(make_signed_pile(
            secret, self.workspace, writer, tuple(closed)))

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

    def pile(self, news, deps_new):
        """Close and encode local intent without receiving it."""
        return self.pack(self.close(news, deps_new))

    def send(self, news, deps_new, *, owner=None):
        """Publish local intent through this device's one writer log."""
        node, workspace = self.node, self.workspace
        closed = self.close(news, deps_new)
        fresh = node.publish_closed(workspace, (closed,), owner=owner)
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
