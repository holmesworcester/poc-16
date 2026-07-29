"""Node: local composition around the workspace runtime.

``WorkspaceRuntime`` owns the serial write turn:

    ingress -> kernel -> catalog -> publisher root CAS -> pump -> retirement

This class supplies its local resources: keychain/workspace configuration,
stores, the stable admitted catalog, the disposable client projection, and
diagnostics. Every replicated effect still enters through a pile. The
published set and client view can be rebuilt from the root; node-local
ineligible catalog receipts are intentionally not published and survive only
while this node's catalog does.
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
from .pump import (
    LOG_SCHEMA,
    append_admitted,
    append_received,
    append_retracted,
    open_projection,
)
from .publication import Publisher
from .runtime import WorkspaceRuntime
from .shape import key_parts
from .store import FsStore, verified_object

SUPP_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS supp(fid TEXT, k TEXT, PRIMARY KEY(fid, k));",
    "CREATE INDEX IF NOT EXISTS supp_by_k ON supp(k);")
IDX_SCHEMA = catalog.SCHEMA + """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
""" + suppression_state.SCHEMA + "\n".join(SUPP_SCHEMA) + LOG_SCHEMA
INDEX_VERSION = "admission-catalog-v21"


def now_ms():
    return int(time.time() * 1000)


def _edges(items, anchor=None):
    """Closure edges resolved against the whole resident set: the canonical
    providers any reader of the store derives, with no index of its own
    (was tree._canonical_graph)."""
    deps, db = {}, sqlite3.connect(":memory:")
    try:
        db.executescript(catalog.SCHEMA)
        db.executemany(
            "INSERT INTO facts VALUES(?,?,?,?,1)",
            ((f.fid, f.ts, f.t, json.dumps(f.to_json()))
             for f in items.values()))
        db.executemany(
            "INSERT INTO offers VALUES(?,?,?,?)",
            ((*offer, f.fid)
             for f in items.values() for offer in f.offers()))
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
    for entry in manifest.decode(verified_object(man, fetch), fetch):
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
        self.app = open_projection(os.path.join(dir, "app.db"))
        self._stores, self._idx = {}, {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        self._sync_errors = {}
        for ws in self.workspaces():  # a stale/wiped index is rebuilt from the store
            self._sync_index(ws)
            self.log_arrivals(ws, (
                fid for (fid,) in self.idx(ws).execute("SELECT fid FROM proofs")
            ))
            # Resume rows committed after the last root publication through
            # the same workspace boundary used by live turns.
            self.workspace(ws).project()

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
            columns = {
                row[1] for row in con.execute("PRAGMA table_info(facts)")
            }
            if "admitted" not in columns:
                con.execute(
                    "ALTER TABLE facts ADD COLUMN admitted INT "
                    "NOT NULL DEFAULT 1 CHECK(admitted IN (0,1))")
                con.commit()
            self._idx[ws] = con
        return self._idx[ws]

    def _sync_index(self, ws):
        """Rebuild derived standing when the catalog's root stamp is stale."""
        etag = self.store(ws).etag("root")
        idx = self.idx(ws)
        row = idx.execute("SELECT v FROM meta WHERE k='root'").fetchone()
        version = idx.execute(
            "SELECT v FROM meta WHERE k='index-version'").fetchone()
        semantic_upgrade = version is None or version[0] != INDEX_VERSION
        if row is None or row[0] != etag or semantic_upgrade:
            self.rebuild(ws, republish=semantic_upgrade)

    def _restore_authoritative_projections(self, ws):
        """Discard a failed turn's local state before releasing its lock."""
        self.idx(ws).rollback()
        self.app.rollback()
        self._sync_index(ws)
        self.workspace(ws).project()

    def _stamp(self, ws, admitted=()):
        idx = self.idx(ws)
        try:
            self.catalog(ws).commit_stage(admitted)
            idx.execute("DELETE FROM meta WHERE k='tree-rebuild'")
            idx.execute("INSERT OR REPLACE INTO meta VALUES('root', ?)",
                        (self.store(ws).etag("root"),))
            idx.execute("INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
                        (INDEX_VERSION,))
            idx.commit()
        except Exception:
            idx.rollback()
            raise

    def fact_of(self, ws, fid) -> Fact:
        return self.catalog(ws).eligible(fid)

    def candidate_of(self, ws, fid) -> Fact:
        """A kernel-valid durable receipt, whether currently eligible or not."""
        return self.catalog(ws).candidate(fid)

    def catalog(self, ws):
        return catalog.Catalog(self.idx(ws), ws)

    def keys(self, ws):
        return [
            key_parts(ts, fid) for ts, fid in
            self.idx(ws).execute(
                "SELECT f.ts, f.fid FROM facts f "
                "JOIN proofs p ON p.fid=f.fid ORDER BY f.ts, f.fid")
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

    def _refresh_action_evidence(self, ws):
        """Canonicalize proof bytes after eligibility and edges settle."""
        idx, changed = self.idx(ws), set()
        for (fid,) in idx.execute(
                "SELECT DISTINCT fid FROM actions ORDER BY fid"):
            fact = self.fact_of(ws, fid)
            if fact is None:
                raise ValueError("active action lacks standing")
            changed.update(suppression_state.bind_evidence(
                idx, fid, self._action_evidence(ws, fact)))
        return changed

    def _validate_root_actions(self, ws, root_bytes, fetch):
        """Cross-check derived action evidence against authenticated slots."""
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
            row = self.idx(ws).execute(
                "SELECT evidence FROM actions WHERE sid=? AND fid=?",
                (sid, fid),
            ).fetchone()
            if row != (evidence_oid,):
                raise ValueError("action evidence mismatch")

    # ---- the turn ------------------------------------------------------------

    def turn(self, ws):
        return self.workspace(ws).turn()

    def log_arrivals(self, ws, fids, *, repeat=False):
        """Append resident-object events, but only for published facts.

        ``repeat`` records an actual re-delivery, allowing a missing local
        object to be repaired after an earlier event. Ordinary probes stay
        idempotent, including startup repair of a CAS-to-log crash.
        """
        with self.lock:
            self._sync_index(ws)
            idx, st = self.idx(ws), self.store(ws)
            notified = set() if repeat else {
                fid for (fid,) in idx.execute(
                    "SELECT DISTINCT fid FROM log WHERE op='*'")
            }
            landed = []
            for fid in dict.fromkeys(fids):
                fact = self.fact_of(ws, fid)
                if fact is None or fid in notified:
                    continue
                refs = facts.blob_refs(fact)
                if refs and all(st.has("obj/" + oid) for oid in refs):
                    landed.append(fid)
            if landed:
                append_received(idx, landed)
                idx.commit()
            return landed

    def _log_projection(
            self, ws, admitted, retracted, reproject, action_sids=()):
        idx = self.idx(ws)
        admitted = tuple(admitted)
        retracted = set(retracted)
        retracted.update(  # forward mask: action known before the victim
            fid for fid in admitted
            if self.suppressed(ws, self.fact_of(ws, fid)))
        append_admitted(idx, admitted)
        append_retracted(idx, sorted(retracted))
        self.apply_actions(
            ws, set(action_sids) | {
                sid for sid, fid in idx.execute(
                    "SELECT sid, fid FROM actions")
                if fid in set(admitted)
            })
        if reproject:
            seq = idx.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM log").fetchone()[0]
            idx.execute(
                "INSERT OR REPLACE INTO meta VALUES('reproject', ?)",
                (seq,))

    def merge(self, ws, candidates):
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
            force = not newfids and not admitted.has_eligible() \
                and idx.execute(
                    "SELECT 1 FROM facts LIMIT 1").fetchone() is not None
            change = admitted.settle(
                newfids, force=force, actions_dirty=actions_dirty) \
                if newfids or force or actions_dirty \
                else catalog.Eligibility((), (), (), False)
            action_changes = set(admitted.action_changes)
            if action_changes or change.authority_changed or idx.execute(
                    "SELECT 1 FROM actions WHERE evidence='' LIMIT 1"
            ).fetchone() is not None:
                action_changes.update(self._refresh_action_evidence(ws))
            deactivated = set(change.deactivated)
            restored = set(change.activated) - set(newfids)
            if restored:
                self._invalidate_sync_cache(ws)
            reproject = change.authority_changed or bool(action_changes)
            self._log_projection(
                ws, change.activated, deactivated,
                reproject, action_changes)
            idx.execute("DELETE FROM meta WHERE k='root'")
            idx.commit()
            return catalog.Eligibility(
                change.received,
                change.activated,
                change.deactivated,
                reproject,
            )
        except Exception:
            idx.rollback()
            raise

    def commit(self, ws, settlement=None, *, reuse=True):
        idx = self.idx(ws)
        if settlement is None:
            try:
                staged = self.catalog(ws).staged_ids()
                idx.execute("DELETE FROM meta WHERE k='root'")
                admitted = self.catalog(ws)
                change = admitted.settle(
                    staged, force=True, actions_dirty=True)
                action_changes = set(admitted.action_changes)
                if action_changes or change.authority_changed or idx.execute(
                        "SELECT 1 FROM actions WHERE evidence='' LIMIT 1"
                ).fetchone() is not None:
                    action_changes.update(self._refresh_action_evidence(ws))
                settlement = catalog.Eligibility(
                    staged,
                    change.activated,
                    change.deactivated,
                    True,
                )
                if change.activated or change.deactivated or action_changes:
                    self._log_projection(
                        ws, settlement.activated,
                        settlement.deactivated, True, action_changes)
                idx.commit()
            except Exception:
                idx.rollback()
                raise
        return Publisher(self, ws).publish(settlement, reuse=reuse)

    # ---- authoring tail: close -> own pile -> turn ("kick") ------------------

    def ingest_new(self, ws, news, deps_new, blobs=None):
        return self.workspace(ws).ingest(news, deps_new, blobs)

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws, *, republish=False):
        with self.lock:
            st, idx = self.store(ws), self.idx(ws)
            raw, root = st.get("root"), None
            if raw:
                try:
                    root = manifest.decode_root(raw)
                except ValueError:
                    # A layout we have no reader for (foreign stamp, damaged
                    # bytes). The derived index is the store's only remaining
                    # reader, so republish FROM it under the current stamp and
                    # rebuild from what we just wrote — never over bytes we
                    # could not read (§1: rebuild wholesale, no compat path).
                    staged = self.catalog(ws).discard_stage()
                    suppression_state.discard(idx, staged)
                    self.commit(ws, reuse=False)
                    raw = st.get("root")
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
                    root = manifest.decode_root(raw)
                    stream = list(resident(root.manifest, fetch, ws))
                if ws not in {fact.fid for fact in stream}:
                    raise ValueError("store fact set")
            # Drop the cursor BEFORE the log DROP resets AUTOINCREMENT: a
            # crash anywhere after this point leaves no cursor row, so a
            # restarted pump takes the rebuild branch instead of skipping
            # new low seqs against a stale-high cursor.
            self.app.execute("DELETE FROM cursors WHERE ws=?", (ws,))
            self.app.commit()
            idx.execute("BEGIN")
            try:
                staged = self.catalog(ws).discard_stage()
                suppression_state.discard(idx, staged)
                # facts/offers are the stable admitted catalog. Rebuild only
                # the root-derived eligibility, edges, actions, and reverse
                # projections around it.
                for table in ("proofs", "edges", "actions"):
                    idx.execute(f"DELETE FROM {table}")
                # DROP, not DELETE: CREATE IF NOT EXISTS keeps a pre-v14
                # file's single-group supp DDL, whose UNIQUE(k) would
                # silently swallow all but one victim per group on re-merge.
                for table in ("supp", "log"):
                    idx.execute(f"DROP TABLE IF EXISTS {table}")
                for statement in SUPP_SCHEMA + (LOG_SCHEMA,):
                    idx.execute(statement)
                for (fid,) in idx.execute("SELECT fid FROM facts"):
                    fact = self.candidate_of(ws, fid)
                    idx.executemany(
                        "INSERT OR IGNORE INTO supp VALUES(?,?)",
                        ((fid, sid)
                         for sid in sorted(facts.fact_scopes(fact))),
                    )
                idx.execute(
                    "DELETE FROM meta WHERE k IN ('root','reproject')")
                idx.commit()
            except Exception:
                idx.rollback()
                raise
            if root is None:  # no root at all: an empty store is legal
                self.catalog(ws).settle(
                    (), force=True, actions_dirty=True)
                self._stamp(ws)
                self.workspace(ws).project()
                return
            settlement = self.merge(ws, stream)
            try:
                self._validate_root_actions(
                    ws, raw, lambda oid: st.get("obj/" + oid))
            except ValueError:
                if not republish:
                    raise
            self.apply_actions(
                ws, [sid for (sid,) in self.idx(ws).execute(
                    "SELECT sid FROM actions")])
            if republish:
                # A semantic index upgrade can select different canonical
                # providers for the same fact ids. Fingerprints cover ids, not
                # closure edges, so old fences are deliberately not memoized.
                self.commit(ws, settlement, reuse=False)
            else:
                self._stamp(ws, settlement.received)
            self.log_arrivals(
                ws, (fact.fid for fact in stream))
            self.workspace(ws).project()

    # ---- exact suppression consult + local reverse projection ----------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        return suppression_state.suppresses(self.idx(ws), fact)

    def apply_actions(self, ws, sids):
        """Retract resident victims through the rebuildable sid reverse map."""
        idx = self.idx(ws)
        dead = {
            fid
            for sid in set(sids)
            if suppression_state.active(idx, sid)
            for (fid,) in idx.execute(
                "SELECT fid FROM supp WHERE k=?", (sid,))
            if self.fact_of(ws, fid) is not None
        }
        last = dict(idx.execute(
            "SELECT fid, op FROM log WHERE op IN ('+','-') ORDER BY seq"))
        append_retracted(idx, sorted(
            fid for fid in dead if last.get(fid) == "+"))
        return dead
