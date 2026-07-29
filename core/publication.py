"""Compile one eligible client snapshot and advance its root by one CAS."""
from . import indexes, manifest, suppression_state
from .crypto import h
from .kernel import resolve_deps
from .store import verified_object


class Publisher:
    """The sole authority for immutable snapshot objects and mutable root."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def _previous_entries(self, raw, fetch):
        if not raw:
            return ()
        try:
            root = manifest.decode_root(raw)
        except ValueError:
            return ()
        if root.anchor != self.workspace:
            raise ValueError("root anchor")
        try:
            return manifest.decode(
                verified_object(root.manifest, fetch), fetch)
        except ValueError:
            return ()

    def publish(self, settlement, *, reuse=True):
        node, ws = self.node, self.workspace
        store, idx = node.store(ws), node.idx(ws)
        forced_rebuild = idx.execute(
            "SELECT 1 FROM meta WHERE k='tree-rebuild'").fetchone() is not None

        # A rootless store may retain locally admitted litter, but no reader
        # can accept a snapshot that does not contain its anchor.
        if idx.execute(
                "SELECT 1 FROM proofs WHERE fid=?", (ws,)).fetchone() is None:
            node._stamp(ws, settlement.received)
            return None

        changed = settlement.activated
        deactivated = set(settlement.deactivated)
        authority_changed = settlement.authority_changed
        cache = {}

        def deps_of(fid):
            if fid not in cache:
                cache[fid] = resolve_deps(node.fact_of(ws, fid), idx) or []
            return cache[fid]

        previous_root = store.get("root")
        etag = h(previous_root) if previous_root is not None else None

        def emit(raw):
            oid = h(raw)
            if not store.has("obj/" + oid):
                store.put("obj/" + oid, raw)
            return oid

        fetch = lambda oid: store.get("obj/" + oid)
        entries = self._previous_entries(previous_root, fetch)
        if not (reuse and not authority_changed and not deactivated):
            entries = ()
        incremental = reuse and not forced_rebuild \
            and not authority_changed and not deactivated
        changed_keys = {
            fact.key
            for fid in changed
            if (fact := node.fact_of(ws, fid)) is not None
        } if incremental else None
        _, manifest_oid = manifest.build(
            node.keys(ws), lambda fid: node.fact_of(ws, fid), deps_of, emit,
            entries, changed=changed_keys)

        previous_trees = {}
        if previous_root:
            try:
                previous_trees = manifest.decode_root(previous_root).trees
            except ValueError:
                pass
        seed, trees = indexes.build(
            ws, idx, lambda fid: node.fact_of(ws, fid), emit,
            previous=previous_trees, fetch=fetch,
            changed_fids=changed if incremental else None)
        root = manifest.encode_root(
            ws, manifest_oid,
            action_etag=suppression_state.etag(idx),
            layout_seed=seed, trees=trees)
        if store.cas("root", etag, root) is None:
            raise RuntimeError("root changed")
        node._stamp(ws, settlement.received)
        return root
