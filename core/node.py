"""Full P2P composition: PileSender + RepositoryApplier + RepositoryReader.

SQLite is a disposable local query/authorship projection.  It is rebuilt from
the committed authenticated repository and is never an input to receiving,
settlement, immutable-object creation, root CAS, or retirement.
"""
import asyncio
import json
import os
import sqlite3
import threading
import time

from . import (
    catalog,
    client_projection,
    suppression_state,
)
from .fact import Fact
from .keychain import Keychain
from .limits import MAX_OBJECT_BYTES, MAX_ROOT_BYTES, PAGE_BATCH
from .pile_sender import PileSender
from .repository_applier import RepositoryApplier
from .repository_reader import RepositoryReader
from .store import FsStore

IDX_SCHEMA = catalog.SCHEMA + """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


def now_ms():
    return int(time.time() * 1000)


def _run_applier(awaitable):
    """Run the async provider-neutral engine from the synchronous full node."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    outcome = {}

    def run():
        try:
            outcome["value"] = asyncio.run(awaitable)
        except BaseException as error:
            outcome["error"] = error

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


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
        self._stores, self._idx = {}, {}
        self._appliers, self._senders = {}, {}
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

    def applier(self, workspace):
        """Return the exact receiving engine shared with hosted recipients."""
        if workspace not in self._appliers:
            self._appliers[workspace] = RepositoryApplier(
                workspace, self.store(workspace))
        return self._appliers[workspace]

    def sender(self, workspace):
        """Return the SQL-permitted local pile author."""
        if workspace not in self._senders:
            self._senders[workspace] = PileSender(self, workspace)
        return self._senders[workspace]

    def reader(self, workspace):
        """Pin the same DB-free read capability used by hosted recipients."""
        store = self.store(workspace)
        root = store.get_bounded("root", MAX_ROOT_BYTES)
        if root is None:
            return None
        return RepositoryReader(
            workspace,
            root,
            lambda oid: store.get_bounded(
                "obj/" + oid, MAX_OBJECT_BYTES),
        )

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

    def ingress_attempt_failures(self, ws):
        out = []
        for (workspace, source), (_, value) in sorted(
                self._ingress_attempt_errors.items()):
            if workspace != ws:
                continue
            if not self.store(ws).has(source):
                self.clear_ingress_attempt_failure(ws, source)
                continue
            out.append(dict(value))
        return out

    def ingress_attempt_error(self, ws, source):
        row = self._ingress_attempt_errors.get((ws, source))
        return row[0] if row is not None else None

    def ingress_failures(self, ws):
        """Shared immutable rejection evidence, projected as status rows."""
        store = self.store(ws)
        names, cursor, seen = [], None, set()
        for _ in range(PAGE_BATCH):
            page = store.list_page(
                "failed/meta/", cursor, PAGE_BATCH - len(names))
            names.extend(
                name for name in page.keys if name not in names)
            if page.cursor is None or len(names) >= PAGE_BATCH:
                break
            if page.cursor in seen:
                raise ValueError("failure record cursor did not advance")
            seen.add(page.cursor)
            cursor = page.cursor

        out = []
        for name in names:
            try:
                value = json.loads(store.get_bounded(
                    name, MAX_OBJECT_BYTES))
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
            self._idx[ws] = con
        return self._idx[ws]

    def _sync_index(self, ws):
        """Refresh the disposable client projection without repository writes."""
        reader = self.reader(ws)
        root_digest = None if reader is None else reader.etag
        idx = self.idx(ws)
        stamped = idx.execute(
            "SELECT v FROM meta WHERE k='root'").fetchone()
        version = idx.execute(
            "SELECT v FROM meta WHERE k='index-version'").fetchone()
        if stamped == (root_digest,) \
                and version == (catalog.INDEX_VERSION,):
            return
        client_projection.refresh(
            idx,
            reader,
            workspace=ws,
        )

    def fact_of(self, ws, fid) -> Fact:
        return self.catalog(ws).eligible(fid)

    def candidate_of(self, ws, fid) -> Fact:
        """A retained candidate, whether currently eligible or dormant."""
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
        """Canonical eligible keys for client-only query assembly."""
        return [
            fact_key for (fact_key,) in self.idx(ws).execute(
                "SELECT i.k0 FROM fact_index i "
                "JOIN fact_index s ON s.src=i.src "
                "AND s.kind=? AND s.k0='eligible' "
                "WHERE i.kind='fact.key' ORDER BY i.k0",
                (catalog.STATE_INDEX,),
            )
        ]

    # ---- the turn ------------------------------------------------------------

    def turn(self, ws):
        """Apply each discovered exact pile independently through one engine."""
        with self.lock:
            store = self.store(ws)
            before = store.get_bounded("root", MAX_ROOT_BYTES)
            fresh = []
            for item in _run_applier(self.applier(ws).turn()):
                if item.error is not None:
                    self.record_ingress_attempt_failure(
                        ws, item.source, item.error)
                    continue
                result = item.result
                if result.status == "stale":
                    self.record_ingress_attempt_failure(
                        ws, item.source,
                        RuntimeError("repository root changed"))
                    continue
                self.clear_ingress_attempt_failure(ws, item.source)
                fresh.extend(result.valids)
            if store.get_bounded("root", MAX_ROOT_BYTES) != before:
                self._invalidate_sync_cache(ws)
            self._sync_index(ws)
            return fresh

    # ---- authoring tail: close -> own pile -> turn ("kick") ------------------

    def ingest_new(self, ws, news, deps_new):
        return self.sender(ws).send(news, deps_new)

    def receive_pile(self, ws, member, raw):
        """Stage one fresh internal generation and invoke RepositoryApplier."""
        with self.lock:
            self.stage_received_pile(ws, member, raw)
            return self.turn(ws)

    def stage_received_pile(self, ws, member, raw):
        """Create an internal generation without duplicating apply semantics."""
        with self.lock:
            return _run_applier(self.applier(ws).stage(member, raw))

    def receive_object(self, ws, oid, raw):
        """Pass one inbound detached object through RepositoryApplier."""
        with self.lock:
            return _run_applier(
                self.applier(ws).admit_object(oid, raw))

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws, *, republish=False):
        """Rebuild only the disposable SQL projection from the pinned root."""
        if republish:
            raise ValueError(
                "repository repair requires an exact RepositoryApplier pile")
        with self.lock:
            client_projection.refresh(
                self.idx(ws),
                self.reader(ws),
                workspace=ws,
            )

    # ---- exact suppression consult -------------------------------------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        return suppression_state.suppresses(self.idx(ws), fact)
