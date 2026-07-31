"""Full P2P composition: PileSender + RepositoryApplier + RepositoryReader.

SQLite is a disposable local query/authorship projection.  It is rebuilt from
the committed authenticated repository and is never an input to receiving,
immutable-object creation, root CAS, or retirement.
"""
import asyncio
import json
import os
import threading
import time

from core import fact_index
from core.fact import Fact
from core.limits import (
    MAX_OBJECT_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PAGE_BATCH,
)
from core.repository_applier import RepositoryApplier
from core.repository_reader import RepositoryReader
from core.store import FsStore

from . import sql_store
from .keychain import (
    MAX_IROH_PEERS,
    Keychain,
    iroh_endpoint,
    iroh_peer,
    is_iroh_peer,
    normalize_peer,
    normalize_peers,
)
from .pile_sender import PileSender


def now_ms():
    return int(time.time() * 1000)


def _run_applier(awaitable):
    """Run the async provider-neutral engine from the synchronous full peer."""
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


class FullPeer:
    def __init__(self, dir, initial_secret=None, *, store_factory=None):
        self.dir = dir
        os.makedirs(dir, exist_ok=True)
        self.lock = threading.RLock()
        self._store_factory = store_factory
        self.peer_address = None  # daemon-owned URL or Iroh reachability
        self._forwarders = None
        self._kr_path = os.path.join(dir, "keyring.json")
        self.keychain = Keychain(self._kr_path, initial_secret)
        self.sk, self.pk = self.keychain.default()
        # app.db was a disposable projection cache. SqlStore now holds the
        # canonical blobs and generic index needed by family queries.
        try:
            os.remove(os.path.join(dir, "app.db"))
        except FileNotFoundError:
            pass
        self._stores, self._sql = {}, {}
        self._appliers, self._senders = {}, {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        self._iroh_peer_urls = {}  # (ws, endpoint) -> disposable loopback URL
        self._sync_errors = {}
        self._ingress_attempt_errors = {}
        for ws in self.workspaces():  # a stale/wiped index is rebuilt from the store
            self._sync_sql(ws)

    # ---- full-peer-local state -----------------------------------------------

    def save_keyring(self):
        self.keychain.save()

    @property
    def keyring(self):
        """The currently committed full-peer-local configuration value."""
        return self.keychain.data

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

    def has_workspace(self, workspace):
        return workspace in self.keyring["workspaces"]

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
                "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES),
        )

    def add_workspace(self, workspace, name, peers, identity=None):
        """Record the locally trusted anchor before its first pile is opened."""
        with self.lock:
            identity = identity or self.keychain.default_id()
            self.keychain.identity(identity)
            peers = normalize_peers(peers)
            if self._forwarders is not None and any(
                    not is_iroh_peer(peer) for peer in peers):
                raise ValueError("Iroh mode requires Iroh peer locators")
            current_iroh = sum(
                is_iroh_peer(peer)
                for candidate, entry in self.keyring["workspaces"].items()
                if candidate != workspace
                for peer in entry["peers"]
            )
            if current_iroh + sum(map(is_iroh_peer, peers)) \
                    > MAX_IROH_PEERS:
                raise ValueError("too many Iroh peers")
            entry = {
                "peers": peers, "name": name,
                "identity": identity}
            self._save_workspace(workspace, entry)
            self._evict_sync_cache(workspace)
            self._forget_iroh_workspace(workspace)
            self._peers_changed()

    def use_iroh(self, advertised, forwarders):
        """Attach daemon-owned Iroh reachability; never repository authority."""
        advertised = normalize_peer(advertised)
        if not is_iroh_peer(advertised):
            raise ValueError("Iroh advertisement must be an Iroh peer")
        with self.lock:
            if any(
                    not is_iroh_peer(peer)
                    for entry in self.keyring["workspaces"].values()
                    for peer in entry["peers"]):
                raise ValueError("Iroh mode requires Iroh peer locators")
            self.peer_address = advertised
            self._forwarders = forwarders
            self._peers_changed()

    def advertised_peer(self):
        if isinstance(self.peer_address, dict):
            return dict(self.peer_address)
        if isinstance(self.peer_address, str) and self.peer_address:
            return self.peer_address
        raise ValueError("peer has no advertised address")

    def resolve_peer(self, workspace, peer):
        """Resolve local reachability; callers still use the ordinary HTTP client."""
        peer = normalize_peer(peer)
        if isinstance(peer, str):
            if self._forwarders is not None:
                raise ValueError("Iroh mode rejects plain HTTP peers")
            return peer
        if self._forwarders is None:
            raise ValueError("Iroh peer requires an Iroh-enabled full peer")
        url = self._forwarders.resolve(workspace, peer)
        key = workspace, peer["endpoint"]
        with self.lock:
            previous = self._iroh_peer_urls.get(key)
            if previous is not None and previous != url:
                self._evict_sync_cache(workspace, previous)
            self._iroh_peer_urls[key] = url
        return url

    def release_peer(self, workspace, peer):
        peer = normalize_peer(peer)
        if is_iroh_peer(peer) and self._forwarders is not None:
            with self.lock:
                if self._forwarders.release(workspace, peer):
                    self._forget_iroh_peer(workspace, peer["endpoint"])

    def iroh_peers(self):
        return tuple(
            (workspace, dict(peer))
            for workspace, entry in self.keyring["workspaces"].items()
            for peer in entry["peers"]
            if is_iroh_peer(peer)
        )

    def set_iroh_peer(self, workspace, endpoint, ticket):
        """Durably add or refresh one reachability record by endpoint id."""
        peer = iroh_peer(endpoint, ticket)
        self._edit_iroh_peer(workspace, peer["endpoint"], peer)

    def remove_iroh_peer(self, workspace, endpoint):
        """Durably remove one reachability record and its local forwarder."""
        self._edit_iroh_peer(workspace, iroh_endpoint(endpoint), None)

    def _edit_iroh_peer(self, workspace, endpoint, replacement):
        with self.lock:
            if self._forwarders is None:
                raise ValueError("peer.iroh requires an Iroh-enabled daemon")
            entry = self.keyring["workspaces"][workspace]
            peers, found = [], False
            for peer in entry["peers"]:
                if is_iroh_peer(peer) and peer["endpoint"] == endpoint:
                    found = True
                    if replacement is not None:
                        peers.append(replacement)
                else:
                    peers.append(peer)
            if replacement is None and not found:
                raise KeyError(f"unknown Iroh peer {endpoint!r}")
            if replacement is not None and not found:
                if len(self.iroh_peers()) >= MAX_IROH_PEERS:
                    raise ValueError("too many Iroh peers")
                peers.append(replacement)
            peers = normalize_peers(peers)
            self._save_workspace(workspace, {**entry, "peers": peers})
            self._forget_iroh_peer(workspace, endpoint)
            self._peers_changed()

    def peer_connection_status(self, workspace):
        return [] if self._forwarders is None \
            else self._forwarders.status(workspace)

    def _peers_changed(self):
        if self._forwarders is not None:
            self._forwarders.refresh(self.iroh_peers())

    def _save_workspace(self, workspace, entry):
        workspaces = dict(self.keyring["workspaces"])
        workspaces[workspace] = entry
        self.keychain.commit({**self.keyring, "workspaces": workspaces})

    def bind_identity(self, workspace, identity):
        with self.lock:
            self.keychain.bind(workspace, identity)
            self._evict_sync_cache(workspace)

    def _evict_sync_cache(self, workspace, url=None):
        """Detach reachability state without mutating an in-flight walk."""
        with self.lock:
            for key in [
                key for key in self.sync_cache
                if key[0] == workspace
                and (url is None or key[1] == url)
            ]:
                self.sync_cache.pop(key)

    def sync_state(self, workspace, url):
        """Acquire one walk state at the same lock boundary used for eviction."""
        with self.lock:
            return self.sync_cache.setdefault((workspace, url), {})

    def _forget_iroh_peer(self, workspace, endpoint):
        with self.lock:
            previous = self._iroh_peer_urls.pop((workspace, endpoint), None)
            if previous is not None:
                self._evict_sync_cache(workspace, previous)

    def _forget_iroh_workspace(self, workspace):
        with self.lock:
            for key in [
                    key for key in self._iroh_peer_urls
                    if key[0] == workspace]:
                self._forget_iroh_peer(*key)

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
        """Expose the raw connection only to SQL-backed authoring helpers."""
        return self.sql(ws).db

    def sql(self, ws):
        if ws not in self._sql:
            self._sql[ws] = sql_store.SqlStore.open(
                os.path.join(self.dir, "ws", ws + ".idx.db"), ws)
        return self._sql[ws]

    def _sync_sql(self, ws):
        """Refresh the disposable client projection without repository writes."""
        reader = self.reader(ws)
        projection = self.sql(ws)
        if projection.current_for(reader):
            return
        projection.refresh(reader)

    def fact_of(self, ws, fid) -> Fact:
        return self.sql(ws).fact(fid)

    def select(
            self, ws, kind, k0=None, k1=None, *,
            include_suppressed=False, **_options):
        """Select current facts through the one generic type/offer index."""
        with self.lock:
            self._sync_sql(ws)
            rows = self.sql(ws).indexed(kind, k0, k1)
            if include_suppressed:
                return rows
            return tuple(
                fact for fact in rows
                if not self.suppressed(ws, fact)
            )

    def by_type(self, ws, tag, **options):
        return self.select(ws, fact_index.TYPE_INDEX, tag, **options)

    def keys(self, ws):
        """Canonical validated keys for client-only query assembly."""
        return [
            fact_key for (fact_key,) in self.idx(ws).execute(
                "SELECT i.k0 FROM fact_index i "
                "WHERE i.kind='fact.key' ORDER BY i.k0",
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
                self._evict_sync_cache(ws)
            self._sync_sql(ws)
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
            self.sql(ws).refresh(self.reader(ws))

    # ---- exact suppression consult -------------------------------------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        return self.sql(ws).suppresses(fact)

    def suppression_active(self, ws, sid):
        return self.sql(ws).active(sid)
