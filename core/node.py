"""Node: local composition around the workspace runtime.

``WorkspaceRuntime`` owns the serial write turn:

    ingress -> kernel -> catalog -> publisher root CAS -> retirement

This class supplies its local resources: keychain/workspace configuration,
stores, the stable fact catalog, generic derived indexes, and diagnostics.
Every replicated effect still enters through a pile. Family queries select
ids through the generic index and decode the canonical fact blobs directly;
there is no second application database to synchronize.
"""
import json
import os
import sqlite3
import threading
import time

import facts

from . import (
    admission as admission_layer,
    catalog,
    legacy_v7,
    snapshot,
    suppression_state,
)
from .crypto import h
from .fact import Fact
from .keychain import Keychain
from .publication import INDEX_VERSION, Publisher, RootChanged
from .runtime import WorkspaceRuntime
from .object_store import ABSENT
from .store import FsStore

SUPP_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS supp(fid TEXT, k TEXT, PRIMARY KEY(fid, k));",
    "CREATE INDEX IF NOT EXISTS supp_by_k ON supp(k);")
IDX_SCHEMA = catalog.SCHEMA + """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
""" + suppression_state.SCHEMA + "\n".join(SUPP_SCHEMA)


def now_ms():
    return int(time.time() * 1000)


class Node:
    def __init__(self, dir, initial_secret=None, *, store_factory=None):
        self.dir = dir
        os.makedirs(dir, exist_ok=True)
        self.lock = threading.RLock()
        self._store_factory = store_factory
        self.url = None  # the daemon sets its advertised base URL
        self._kr_path = os.path.join(dir, "keyring.json")
        self.keychain = Keychain(self._kr_path, initial_secret)
        self.keyring = self.keychain.data
        self.sk, self.pk = self.keychain.default()
        # app.db was a disposable projection cache. The canonical blob catalog
        # plus generic index now answers family queries directly.
        try:
            os.remove(os.path.join(dir, "app.db"))
        except FileNotFoundError:
            pass
        self._stores, self._idx, self._admissions = {}, {}, {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        self._sync_errors = {}
        self._ingress_attempt_errors = {}
        for ws in self.workspaces():  # a stale/wiped index is rebuilt from the store
            self._sync_index(ws)

    # ---- node-local state ----------------------------------------------------

    def save_keyring(self):
        self.keychain.save()

    @property
    def member(self):
        return self.pk[:16]

    def identity(self, workspace=None):
        return self.keychain.default() if workspace is None \
            else self.keychain.for_workspace(workspace)

    def identity_id(self, workspace=None):
        return self.identity(workspace)[1]

    def member_for(self, workspace):
        return self.identity_id(workspace)[:16]

    def workspaces(self):
        return list(self.keyring["workspaces"])

    def workspace(self, workspace):
        """Bind the socket-free coordinator for one workspace turn."""
        return WorkspaceRuntime(self, workspace)

    def admission(self, workspace):
        """Bind the workspace's sole durable-fact admission membrane."""
        if workspace not in self._admissions:
            self._admissions[workspace] = \
                admission_layer.AdmissionMembrane(self, workspace)
        return self._admissions[workspace]

    def add_workspace(self, workspace, name, peers, identity=None):
        """Record the locally trusted anchor before its first pile is opened."""
        with self.lock:
            identity = identity or self.keychain.default_id()
            self.keychain.identity(identity)
            self.keyring["workspaces"][workspace] = {
                "peers": list(peers), "name": name,
                "identity": identity}
            self.save_keyring()

    def bind_identity(self, workspace, identity):
        with self.lock:
            self.keychain.bind(workspace, identity)
            self._invalidate_sync_cache(workspace)

    def _invalidate_sync_cache(self, workspace):
        """Make every peer recompare this workspace on its next walk."""
        for key in [
                key for key in self.sync_cache if key[0] == workspace]:
            self.sync_cache.pop(key).clear()

    def record_ingress_attempt_failure(self, ws, source, error):
        """Expose a retained retryable/program failure without deleting it."""
        self._ingress_attempt_errors[(ws, source)] = (
            error,
            {
                "error": f"{type(error).__name__}: {error}",
                "source": source,
                "ts": now_ms(),
            },
        )

    def clear_ingress_attempt_failure(self, ws, source):
        self._ingress_attempt_errors.pop((ws, source), None)

    def reconcile_ingress_attempt_failures(self, ws, live_sources):
        """Drop local diagnostics whose shared durable intent is retired."""
        live_sources = set(live_sources)
        for workspace, source in tuple(self._ingress_attempt_errors):
            if workspace == ws and source not in live_sources:
                self.clear_ingress_attempt_failure(ws, source)

    def ingress_attempt_failures(self, ws):
        return [
            dict(value)
            for (workspace, _), (_, value)
            in sorted(self._ingress_attempt_errors.items())
            if workspace == ws
        ]

    def ingress_attempt_error(self, ws, source):
        row = self._ingress_attempt_errors.get((ws, source))
        return row[0] if row is not None else None

    def ingress_failures(self, ws):
        """Shared immutable rejection evidence, projected as status rows."""
        out = []
        for name in self.store(ws).list("failed/meta"):
            try:
                value = json.loads(self.store(ws).get(name))
                if isinstance(value, dict):
                    out.append(value)
            except (TypeError, ValueError):
                out.append({
                    "error": "ValueError: unreadable failure record",
                    "id": name.rsplit("/", 1)[-1],
                    "source": name,
                    "ts": 0,
                })
        return sorted(out, key=lambda row: (row.get("ts", 0), row.get("id", "")))

    def record_sync_failure(self, ws, url, error):
        with self.lock:
            self._sync_errors[(ws, url)] = {
                "error": f"{type(error).__name__}: {error}",
                "peer": url,
                "ts": now_ms(),
            }

    def record_sync_success(self, ws, url):
        with self.lock:
            self._sync_errors.pop((ws, url), None)

    def sync_failures(self, ws):
        with self.lock:
            return [
                dict(value)
                for (workspace, _), value in sorted(self._sync_errors.items())
                if workspace == ws
            ]

    def store(self, ws):
        if ws not in self._stores:
            self._stores[ws] = self._store_factory(ws) \
                if self._store_factory is not None \
                else FsStore(os.path.join(self.dir, "ws", ws))
        return self._stores[ws]

    def idx(self, ws):
        if ws not in self._idx:
            os.makedirs(os.path.join(self.dir, "ws"), exist_ok=True)
            con = sqlite3.connect(os.path.join(self.dir, "ws", ws + ".idx.db"),
                                  check_same_thread=False)
            con.executescript(IDX_SCHEMA)
            catalog.upgrade_schema(con, ws)
            suppression_state.upgrade_schema(con)
            self._idx[ws] = con
        return self._idx[ws]

    def _sync_index(self, ws):
        """Rebuild derived standing when the catalog's root stamp is stale."""
        for _ in range(8):
            versioned = self.store(ws).read_versioned("root")
            root_digest = None if versioned is ABSENT \
                else h(versioned.value)
            idx = self.idx(ws)
            row = idx.execute("SELECT v FROM meta WHERE k='root'").fetchone()
            version = idx.execute(
                "SELECT v FROM meta WHERE k='index-version'").fetchone()
            semantic_upgrade = version is None or version[0] != INDEX_VERSION
            if row == (root_digest,) and not semantic_upgrade:
                return
            try:
                self.rebuild(ws, republish=semantic_upgrade)
            except RootChanged:
                continue
        raise RootChanged("root kept changing during index synchronization")

    def fact_of(self, ws, fid) -> Fact:
        return self.catalog(ws).eligible(fid)

    def candidate_of(self, ws, fid) -> Fact:
        """A retained candidate, whether currently eligible or not.

        New rows have an exact local kernel receipt. Proof-less legacy rows
        remain distinguishable until the explicit catalog-cut migration.
        """
        return self.catalog(ws).candidate(fid)

    def catalog(self, ws):
        return catalog.Catalog(self.idx(ws), ws)

    def select_ranked(
            self, ws, kind, k0=None, k1=None, *,
            include_suppressed=False):
        """Select current facts through the one generic type/offer index."""
        with self.lock:
            self._sync_index(ws)
            rows = self.catalog(ws).indexed(kind, k0, k1)
            if include_suppressed:
                return rows
            return tuple(
                (rank, fact) for rank, fact in rows
                if not self.suppressed(ws, fact)
            )

    def select(self, ws, kind, k0=None, k1=None, **options):
        return tuple(
            fact for _, fact in self.select_ranked(
                ws, kind, k0, k1, **options)
        )

    def by_type(self, ws, tag, **options):
        return self.select(ws, catalog.TYPE_INDEX, tag, **options)

    def keys(self, ws):
        """Canonical eligible keys for client-only repair/full publication."""
        return [
            fact_key for (fact_key,) in self.idx(ws).execute(
                "SELECT i.k0 FROM fact_index i "
                "JOIN proofs p ON p.fid=i.src "
                "WHERE i.kind='fact.key' ORDER BY i.k0")
        ]

    # ---- the turn ------------------------------------------------------------

    def turn(self, ws):
        return self.workspace(ws).turn()

    # ---- authoring tail: close -> own pile -> turn ("kick") ------------------

    def ingest_new(self, ws, news, deps_new, blobs=None):
        return self.workspace(ws).ingest(news, deps_new, blobs)

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws, *, republish=False):
        with self.lock:
            st, idx = self.store(ws), self.idx(ws)
            publisher = Publisher(self, ws)
            base = publisher.root_base()
            raw, root = base.root, None
            archive, legacy_stream = None, ()
            fetch = lambda oid: st.get("obj/" + oid)
            if raw is not None:
                try:
                    root = snapshot.decode_root(raw)
                except ValueError:
                    try:
                        previous = legacy_v7.decode_root(raw)
                    except ValueError:
                        # Tests and operator repair may rewrite only a format
                        # stamp. Republish such an exact known envelope from a
                        # current catalog; never interpret unknown bytes.
                        if not publisher.same_snapshot_envelope(raw):
                            raise ValueError(
                                "unreadable root does not match indexed "
                                "snapshot")
                        self.admission(ws).publish(
                            reuse=False, _base=base)
                        base = publisher.root_base()
                        raw = base.root
                        root = snapshot.decode_root(raw)
                    else:
                        if previous.anchor != ws \
                                or previous.layout_seed \
                                != snapshot.layout_seed(ws):
                            raise ValueError("root anchor")
                        # The one explicit v7→v8 cut: only raw facts already
                        # authenticated by the old RangeTree are rejudged.
                        # Proof-less local-only rows are not inferred admitted.
                        legacy_stream = tuple(
                            legacy_v7.recover(previous, fetch))
            if root is not None:
                if root.anchor != ws:
                    raise ValueError("root anchor")
                try:
                    from .candidate_archive import reconstruct

                    archive = reconstruct(raw, fetch)
                except ValueError as exc:
                    if not republish:
                        raise ValueError(
                            f"invalid candidate archive: {exc}") from exc
                    raise
            idx.execute("BEGIN")
            try:
                # Facts and generic rows are the retained catalog (legacy
                # proof-less rows remain distinguishable). Re-derive generic
                # rows from canonical blobs, then rebuild root-derived
                # eligibility, edges, actions, and selector reverse routes.
                self.catalog(ws).reindex()
                for table in ("proofs", "edges", "actions"):
                    idx.execute(f"DELETE FROM {table}")
                # DROP, not DELETE: CREATE IF NOT EXISTS keeps a pre-v14
                # file's single-group supp DDL, whose UNIQUE(k) would
                # silently swallow all but one victim per group on re-merge.
                idx.execute("DROP TABLE IF EXISTS supp")
                for statement in SUPP_SCHEMA:
                    idx.execute(statement)
                for fid in self.catalog(ws).admitted_ids():
                    fact = self.catalog(ws).admitted(fid)
                    if fact is None:
                        continue
                    idx.executemany(
                        "INSERT OR IGNORE INTO supp VALUES(?,?)",
                        ((fid, sid)
                         for sid in sorted(facts.fact_scopes(fact))),
                    )
                idx.execute(
                    "DELETE FROM meta "
                    "WHERE k IN ('root','publish-base')")
                idx.commit()
            except Exception:
                idx.rollback()
                raise
            if archive is not None:
                admission = self.admission(ws)._settle_verified(
                    archive.receipt_proofs,
                    tuple(
                        receipt
                        for receipt, _ in archive.receipt_proofs),
                    base,
                    force=True,
                    allowed_staged=set(archive.records),
                )
            else:
                admission = self.admission(ws).admit(
                    legacy_stream, base=base, force=True,
                    allowed_staged={
                        fact.fid for fact in legacy_stream})
            settlement = admission.settlement
            # A semantic index upgrade can select different canonical
            # providers for the same fact ids. A retained local receipt can
            # also regain standing under an external (or absent) root. Compile
            # the exact derived answer: Publisher skips CAS only when those
            # bytes equal the base, otherwise it publishes the local union.
            try:
                self.admission(ws).publish(settlement, reuse=False)
            except Exception:
                idx.rollback()
                raise

    # ---- exact suppression consult -------------------------------------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        return suppression_state.suppresses(self.idx(ws), fact)
