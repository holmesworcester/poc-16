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

from . import catalog, indexes, manifest, suppression_state
from .close import close, decode_pile, encode_pile
from .crypto import h
from .fact import Fact, canon
from .keychain import Keychain
from .kernel import (
    drain,
    resolve_deps,
    rebuild_proofs,
)
from .publication import INDEX_VERSION, Publisher, RootChanged
from .runtime import WorkspaceRuntime
from .store import FsStore, verified_object

SUPP_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS supp(fid TEXT, k TEXT, PRIMARY KEY(fid, k));",
    "CREATE INDEX IF NOT EXISTS supp_by_k ON supp(k);")
IDX_SCHEMA = catalog.SCHEMA + """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
""" + suppression_state.SCHEMA + "\n".join(SUPP_SCHEMA)


def now_ms():
    return int(time.time() * 1000)


def _edges(items, anchor=None):
    """Closure edges resolved against the whole resident set: the canonical
    providers any reader of the store derives, with no index of its own
    (was tree._canonical_graph)."""
    deps, db = {}, sqlite3.connect(":memory:")
    try:
        db.executescript(catalog.SCHEMA)
        admitted = catalog.Catalog(db, anchor)
        for fact in items.values():
            admitted.stage(fact)
        admitted.commit_stage(items)
        if rebuild_proofs(db, items.get, anchor):
            raise ValueError("store closure")
        for fid, f in items.items():
            resolved = resolve_deps(f, db)
            if resolved is None or any(d not in items for d in resolved):
                raise ValueError("store closure")
            deps[fid] = resolved
    finally:
        db.close()
    return deps


def resident(man, fetch, anchor=None):
    """Every committed fact, deps-first, from the manifest alone.

    Leaf piles decode with the ONE pile codec (close.decode_pile); the member
    set is then proved by rebuilding the manifest from the keys we read and
    comparing its root oid — placement, chunking, pile and sibling bytes in a
    single equality (replaces tree.validate_view).
    """
    items = {}
    entries = manifest.decode(verified_object(man, fetch), fetch) if man else ()
    for entry in entries:
        members, _ = decode_pile(verified_object(entry.leaf, fetch))
        items.update({f.fid: f for f in members})
    if any(
            (family := facts.family_for(fact.t)) is None
            or not family.DURABLE
            for fact in items.values()):
        raise ValueError("store contains an ephemeral fact")
    deps = _edges(items, anchor)
    if manifest.build(
            sorted(f.key for f in items.values()), items.__getitem__,
            deps.__getitem__, lambda raw: None)[1] != man:
        raise ValueError("store placement")
    return close(items.values(), deps.__getitem__, items.__getitem__)


class Node:
    def __init__(self, dir, initial_secret=None):
        self.dir = dir
        os.makedirs(dir, exist_ok=True)
        self.lock = threading.RLock()
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
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        self._sync_errors = {}
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

    def _quarantine_ingress(self, ws, source, raw, error):
        """Retire one permanently failing ingress unit without losing bytes.

        Piles are independent closed units.  Keeping a bad one under ``pile/``
        retries it forever and prevents unrelated work from draining; moving it
        to the node-local failure area makes the failure explicit and
        recoverable while removing it from the live ingress queue.
        """
        st = self.store(ws)
        payload = raw if isinstance(raw, bytes) else b""
        failure_id = h(payload or source.encode())
        if payload:
            st.put_if_absent("failed/pile/" + failure_id, payload)
        st.put(
            "failed/meta/" + failure_id,
            canon({
                "error": f"{type(error).__name__}: {error}",
                "id": failure_id,
                "source": source,
                "ts": now_ms(),
            }),
        )
        st.delete(source)

    def ingress_failures(self, ws):
        """Durable summaries for quarantined piles; payloads stay local."""
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

    def store(self, ws) -> FsStore:
        if ws not in self._stores:
            self._stores[ws] = FsStore(os.path.join(self.dir, "ws", ws))
        return self._stores[ws]

    def idx(self, ws):
        if ws not in self._idx:
            os.makedirs(os.path.join(self.dir, "ws"), exist_ok=True)
            con = sqlite3.connect(os.path.join(self.dir, "ws", ws + ".idx.db"),
                                  check_same_thread=False)
            con.executescript(IDX_SCHEMA)
            catalog.upgrade_schema(con)
            suppression_state.upgrade_schema(con)
            self._idx[ws] = con
        return self._idx[ws]

    def _sync_index(self, ws):
        """Rebuild derived standing when the catalog's root stamp is stale."""
        for _ in range(8):
            etag = self.store(ws).etag("root")
            idx = self.idx(ws)
            row = idx.execute("SELECT v FROM meta WHERE k='root'").fetchone()
            version = idx.execute(
                "SELECT v FROM meta WHERE k='index-version'").fetchone()
            semantic_upgrade = version is None or version[0] != INDEX_VERSION
            if row == (etag,) and not semantic_upgrade:
                return
            try:
                self.rebuild(ws, republish=semantic_upgrade)
            except RootChanged:
                continue
        raise RootChanged("root kept changing during index synchronization")

    def _restore_authoritative_state(self, ws):
        """Discard a failed turn's local state before releasing its lock."""
        self.idx(ws).rollback()
        self._sync_index(ws)

    def fact_of(self, ws, fid) -> Fact:
        return self.catalog(ws).eligible(fid)

    def candidate_of(self, ws, fid) -> Fact:
        """A kernel-valid durable receipt, whether currently eligible or not."""
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

    def _action_evidence(self, ws, fact):
        """Persist the action's current canonical proof closure."""
        idx = self.idx(ws)
        fact_of = lambda fid: self.fact_of(ws, fid)
        raw = encode_pile(close(
            [fact],
            lambda fid: resolve_deps(fact_of(fid), idx),
            fact_of,
        ))
        oid = h(raw)
        self.store(ws).put_if_absent("obj/" + oid, raw)
        return oid

    def _refresh_action_evidence(self, ws, sids=None):
        """Canonicalize proof bytes after eligibility and edges settle."""
        idx, changed = self.idx(ws), set()
        fids = {
            fid for (fid,) in idx.execute(
                "SELECT DISTINCT fid FROM actions ORDER BY fid")
        } if sids is None else {
            row[0]
            for sid in sorted(set(sids))
            if (row := idx.execute(
                "SELECT fid FROM actions WHERE sid=?", (sid,)).fetchone())
        }
        for fid in sorted(fids):
            fact = self.fact_of(ws, fid)
            if fact is None:
                raise ValueError("active action lacks standing")
            changed.update(suppression_state.bind_evidence(
                idx, fid, self._action_evidence(ws, fact)))
        return changed

    def _validate_root_actions(self, ws, root_bytes, fetch):
        """Validate action evidence entirely through authenticated slots."""
        from .worker import WorkerView

        view = WorkerView.from_root(root_bytes, fetch)
        fact_tree = view._reader(indexes.FACT)
        for sid, slot in view._reader(indexes.SUPP).items():
            if not isinstance(slot, dict) or slot.get("state") != "active":
                continue
            fid = slot.get("action")
            if fact_tree.get(indexes.action_key(sid)) != slot:
                raise ValueError("action slot mismatch")
            record = view.fact_record(fid)
            evidence_oid = record["evidence"]
            if not evidence_oid:
                raise ValueError("action evidence missing")
            action, _ = suppression_state.validate_evidence(
                ws, sid, fid, evidence_oid, fetch)
            if action.fid != fid:
                raise ValueError("action evidence fact")
    # ---- the turn ------------------------------------------------------------

    def turn(self, ws):
        return self.workspace(ws).turn()

    def merge(self, ws, candidates, *, base=None, force=False):
        publisher = Publisher(self, ws)
        base = publisher.base() if base is None else base
        idx, newfids = self.idx(ws), []
        admitted = self.catalog(ws)
        idx.execute("BEGIN")
        try:
            actions_dirty = False
            for f in candidates:
                if not facts.family_for(f.t).DURABLE:
                    continue  # judged, never persisted: litter drains away
                if admitted.stage(f):
                    newfids.append(f.fid)
                idx.executemany(
                    "INSERT OR IGNORE INTO supp VALUES(?,?)",
                    ((f.fid, sid)
                     for sid in sorted(
                         facts.fact_scopes(f))))
                if facts.action_sids(f):
                    actions_dirty = True
                    suppression_state.archive(idx, f)
            force = force or (
                not newfids and not admitted.has_eligible()
                and idx.execute(
                    "SELECT 1 FROM facts LIMIT 1").fetchone() is not None)
            change = admitted.settle(
                newfids, force=force, actions_dirty=actions_dirty) \
                if newfids or force or actions_dirty \
                else catalog.Eligibility((), (), (), False, ())
            changed_sids = set(change.changed_sids)
            if change.authority_changed:
                changed_sids.update(self._refresh_action_evidence(ws))
            elif changed_sids:
                changed_sids.update(
                    self._refresh_action_evidence(ws, changed_sids))
            change = change._replace(
                changed_sids=tuple(sorted(changed_sids)))
            restored = set(change.activated) - set(newfids)
            if restored:
                self._invalidate_sync_cache(ws)
            publisher.dirty(base)
            idx.commit()
            return publisher.plan(change, base)
        except Exception:
            idx.rollback()
            raise

    def commit(self, ws, settlement=None, *, reuse=True, _base=None):
        idx = self.idx(ws)
        publisher = Publisher(self, ws)
        if settlement is None:
            base = publisher.base(pending=True) if _base is None else _base
            try:
                staged = self.catalog(ws).staged_ids()
                publisher.dirty(base)
                admitted = self.catalog(ws)
                change = admitted.settle(
                    staged, force=True, actions_dirty=True)
                changed_sids = set(change.changed_sids)
                changed_sids.update(self._refresh_action_evidence(ws))
                change = change._replace(
                    received=tuple(staged),
                    authority_changed=True,
                    changed_sids=tuple(sorted(changed_sids)),
                )
                idx.commit()
                settlement = publisher.plan(change, base)
            except Exception:
                idx.rollback()
                raise
        return publisher.publish(settlement, reuse=reuse)

    # ---- authoring tail: close -> own pile -> turn ("kick") ------------------

    def ingest_new(self, ws, news, deps_new, blobs=None):
        return self.workspace(ws).ingest(news, deps_new, blobs)

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws, *, republish=False):
        with self.lock:
            st, idx = self.store(ws), self.idx(ws)
            publisher = Publisher(self, ws)
            base = publisher.root_base()
            raw, root, stream = base[0], None, []
            if raw:
                try:
                    root = manifest.decode_root(raw)
                except ValueError:
                    # A foreign envelope may be republished from this index
                    # only when all known snapshot bindings equal the exact
                    # root it stamped. Damaged or different bytes fail closed.
                    if not publisher.same_snapshot_envelope(raw):
                        raise ValueError(
                            "unreadable root does not match indexed snapshot")
                    staged = self.catalog(ws).discard_stage()
                    suppression_state.discard(idx, staged)
                    self.commit(ws, reuse=False, _base=base)
                    raw = st.get("root")
                    base = (raw, h(raw))
                    root = manifest.decode_root(raw)
            if root is not None:
                if root.anchor != ws:
                    raise ValueError("root anchor")
                fetch = lambda oid: st.get("obj/" + oid)
                try:
                    stream = list(resident(root.manifest, fetch, ws))
                except ValueError as exc:
                    if not republish:
                        raise ValueError(
                            f"invalid store facts: {exc}") from exc
                    # A semantic index upgrade can re-pick canonical
                    # providers for the same fact set; the old placement is
                    # then a layout this code has no reader for. Republish
                    # from the index under the current rule (same answer as
                    # the foreign-stamp branch above) and read back what we
                    # just wrote.
                    self.commit(ws, reuse=False)
                    raw = st.get("root")
                    base = (raw, h(raw))
                    root = manifest.decode_root(raw)
                    stream = list(resident(root.manifest, fetch, ws))
                if ws not in {fact.fid for fact in stream}:
                    raise ValueError("store fact set")
            idx.execute("BEGIN")
            try:
                staged = self.catalog(ws).discard_stage()
                suppression_state.discard(idx, staged)
                # Facts and their generic index rows are the stable admitted
                # catalog. Re-derive the generic rows exactly from canonical
                # blobs, then rebuild root-derived eligibility, edges,
                # actions, and the selector reverse map around them.
                self.catalog(ws).reindex()
                for table in ("proofs", "edges", "actions"):
                    idx.execute(f"DELETE FROM {table}")
                # DROP, not DELETE: CREATE IF NOT EXISTS keeps a pre-v14
                # file's single-group supp DDL, whose UNIQUE(k) would
                # silently swallow all but one victim per group on re-merge.
                idx.execute("DROP TABLE IF EXISTS supp")
                for statement in SUPP_SCHEMA:
                    idx.execute(statement)
                for (fid,) in idx.execute("SELECT fid FROM facts"):
                    fact = self.candidate_of(ws, fid)
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
            settlement = self.merge(
                ws, stream, base=base, force=True)
            if root is not None:
                try:
                    self._validate_root_actions(
                        ws, raw, lambda oid: st.get("obj/" + oid))
                except ValueError:
                    if not republish:
                        raise
            # A semantic index upgrade can select different canonical
            # providers for the same fact ids. A retained local receipt can
            # also regain standing under an external (or absent) root. Compile
            # the exact derived answer: Publisher skips CAS only when those
            # bytes equal the base, otherwise it publishes the local union.
            try:
                publisher.publish(settlement, reuse=False)
            except Exception:
                idx.rollback()
                raise

    # ---- exact suppression consult -------------------------------------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        return suppression_state.suppresses(self.idx(ws), fact)
