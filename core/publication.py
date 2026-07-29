"""Compile one eligible client snapshot and advance its root by one CAS."""
import json
from typing import NamedTuple

from . import indexes, manifest, suppression_state
from .crypto import h
from .kernel import resolve_deps
from .store import verified_object

INDEX_VERSION = "admission-catalog-v23"


class RootChanged(RuntimeError):
    """The mutable root no longer matches the snapshot this work read."""


class PublicationPlan(NamedTuple):
    """An eligibility delta pinned to the exact root it extends."""

    received: tuple
    activated: tuple
    deactivated: tuple
    authority_changed: bool
    changed_sids: tuple
    base_root: bytes | None
    base_etag: str | None


class Publisher:
    """The sole authority for immutable snapshot objects and mutable root."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def root_base(self):
        raw = self.node.store(self.workspace).get("root")
        return raw, h(raw) if raw is not None else None

    def base(self, *, pending=False):
        """Return the exact root represented by this local catalog."""
        idx = self.node.idx(self.workspace)
        row = idx.execute(
            "SELECT v FROM meta WHERE k='publish-base'").fetchone() \
            if pending else None
        label = "catalog mutation" if row is not None else "index"
        if row is None:
            row = idx.execute(
                "SELECT v FROM meta WHERE k='root'").fetchone()
        base = self.root_base()
        if row != (base[1],):
            raise RootChanged(f"{label} is not based on the current root")
        return base

    @staticmethod
    def plan(change, base):
        return PublicationPlan(*change, *base)

    def dirty(self, base):
        """Remember the publication base before catalog state moves ahead."""
        idx = self.node.idx(self.workspace)
        idx.execute(
            "INSERT OR REPLACE INTO meta VALUES('publish-base', ?)",
            (base[1],))
        idx.execute("DELETE FROM meta WHERE k='root'")

    def same_snapshot_envelope(self, raw):
        """Whether foreign root bytes retain every known snapshot binding."""
        previous = self.node.idx(self.workspace).execute(
            "SELECT v FROM meta WHERE k='root-bytes'").fetchone()
        try:
            old, foreign = json.loads(previous[0]), json.loads(raw)
            return all(
                old.get(key) == foreign.get(key)
                for key in (
                    "action_etag", "anchor", "layout_seed",
                    "manifest", "trees"))
        except (AttributeError, TypeError, ValueError):
            return False

    def stamp(self, root_bytes, admitted=()):
        """Commit the exact root version won by this publication/rebuild."""
        idx = self.node.idx(self.workspace)
        root_etag = h(root_bytes) if root_bytes is not None else None
        try:
            self.node.catalog(self.workspace).commit_stage(admitted)
            idx.execute(
                "DELETE FROM meta WHERE k IN ('tree-rebuild','publish-base')")
            idx.execute("INSERT OR REPLACE INTO meta VALUES('root', ?)",
                        (root_etag,))
            idx.execute("INSERT OR REPLACE INTO meta VALUES('root-bytes', ?)",
                        (root_bytes,))
            idx.execute("INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
                        (INDEX_VERSION,))
            idx.commit()
        except Exception:
            idx.rollback()
            raise

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
            if settlement.base_root is None:
                self.stamp(None, settlement.received)
            return None

        changed = settlement.activated
        deactivated = set(settlement.deactivated)
        authority_changed = settlement.authority_changed
        changed_sids = settlement.changed_sids
        cache = {}

        def deps_of(fid):
            if fid not in cache:
                cache[fid] = resolve_deps(node.fact_of(ws, fid), idx) or []
            return cache[fid]

        previous_root = settlement.base_root

        def emit(raw):
            oid = h(raw)
            store.put_if_absent("obj/" + oid, raw)
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

        previous_snapshot = None
        if previous_root:
            try:
                previous_snapshot = manifest.decode_root(previous_root)
            except ValueError:
                pass
        seed, trees = indexes.build(
            ws, idx, lambda fid: node.fact_of(ws, fid), emit,
            previous=previous_snapshot.trees if previous_snapshot else {},
            fetch=fetch,
            changed_fids=changed if incremental else None,
            changed_sids=changed_sids if incremental else ())
        action_etag = previous_snapshot.action_etag \
            if incremental and not changed_sids and previous_snapshot \
            else suppression_state.etag(idx)
        root = manifest.encode_root(
            ws, manifest_oid,
            action_etag=action_etag,
            layout_seed=seed, trees=trees)
        if root == settlement.base_root:
            if store.etag("root") != settlement.base_etag:
                raise RootChanged("root changed during publication")
            self.stamp(root, settlement.received)
            return root
        root_etag = store.cas("root", settlement.base_etag, root)
        if root_etag is None:
            raise RootChanged("root changed during publication")
        if root_etag != h(root):
            raise ValueError("root CAS returned the wrong version")
        self.stamp(root, settlement.received)
        return root
