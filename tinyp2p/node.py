"""Node: the turn-based runtime.

One serial loop — turn() — is the only mutator of a workspace:

    drain piles -> kernel each (parallel, own scratchpads) -> merge valid/globals
    -> spill blobs -> commit (pure layout -> put objects -> CAS root)
    -> materialize (projectors consume Valid only) -> retire piles

Everything enters through a pile: local commands, pulled units, pushed
piles. The index and app dbs are derived projections — delete either and
rebuild() replays the store's own units through the same kernel.
"""
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import facts
from .close import close, decode_pile, encode_pile
from .crypto import h
from .fact import Fact, from_json
from .keychain import Keychain
from .kernel import (
    Judgment,
    drain,
    extend_proofs,
    rebuild_proofs,
    resolve_deps,
)
from .layout import fingerprint, layout
from .store import FsStore

IDX_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT);
CREATE TABLE IF NOT EXISTS offers(name TEXT, a0 TEXT, a1 TEXT, src TEXT,
                                  PRIMARY KEY(name, a0, a1, src));
CREATE INDEX IF NOT EXISTS offers_by_src ON offers(src, name, a0, a1);
CREATE TABLE IF NOT EXISTS proofs(fid TEXT PRIMARY KEY, rank INT NOT NULL);
CREATE TABLE IF NOT EXISTS globals(name TEXT, value TEXT,
                                   PRIMARY KEY(name, value));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""
INDEX_VERSION = "family-contract-v3"


def now_ms():
    return int(time.time() * 1000)


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
        self.app = sqlite3.connect(os.path.join(dir, "app.db"), check_same_thread=False)
        self.app.executescript(facts.APP_SCHEMA)
        self._stores, self._idx = {}, {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
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
            for key in [
                    key for key in self.sync_cache if key[0] == workspace]:
                self.sync_cache.pop(key).clear()

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
            self._idx[ws] = con
        return self._idx[ws]

    def _sync_index(self, ws):
        """Every SQLite is a derived projection stamped with the manifest it
        reflects; a mismatched stamp means rebuild from the store."""
        etag = self.store(ws).etag("root")
        row = self.idx(ws).execute("SELECT v FROM meta WHERE k='root'").fetchone()
        version = self.idx(ws).execute(
            "SELECT v FROM meta WHERE k='index-version'").fetchone()
        if etag and (row is None or row[0] != etag
                     or version is None or version[0] != INDEX_VERSION):
            self.rebuild(ws)

    def _stamp(self, ws):
        idx = self.idx(ws)
        idx.execute("INSERT OR REPLACE INTO meta VALUES('root', ?)",
                    (self.store(ws).etag("root"),))
        idx.execute("INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
                    (INDEX_VERSION,))
        idx.commit()

    def fact_of(self, ws, fid) -> Fact:
        row = self.idx(ws).execute("SELECT j FROM facts WHERE fid=?", (fid,)).fetchone()
        return from_json(json.loads(row[0])) if row else None

    def keys(self, ws):
        return [f"{ts:015d}:{fid}" for ts, fid in
                self.idx(ws).execute("SELECT ts, fid FROM facts ORDER BY ts, fid")]

    def globals(self, ws):
        return frozenset(self.idx(ws).execute(
            "SELECT name, value FROM globals ORDER BY name, value").fetchall())

    # ---- the turn ------------------------------------------------------------

    def turn(self, ws):
        with self.lock:
            st = self.store(ws)
            piles = st.list("pile/")
            if not piles:
                return []  # nothing delivered; drain-on-read stays free
            units = []
            for k in piles:
                try:
                    units.append(decode_pile(st.get(k)))
                except Exception:
                    units.append(None)  # malformed: rejected on the spot
            if len(units) > 1:  # independent piles judge in parallel
                with ThreadPoolExecutor(max_workers=8) as ex:
                    results = list(ex.map(
                        lambda u: drain(u[0], ws) if u else Judgment(False, (), frozenset()),
                        units))
            else:
                results = [drain(u[0], ws) if u else Judgment(False, (), frozenset())
                           for u in units]
            valids, new_globals, blobs = [], set(), {}
            for u, (ok, vs, global_rows) in zip(units, results):
                if ok:
                    valids += vs
                    new_globals.update(global_rows)
                    blobs.update(u[1])
            fresh, newfids = self.merge(ws, valids, new_globals)
            for bh, b in blobs.items():
                st.put_if_absent("obj/" + bh, b)
            self.commit(ws, newfids)
            self.materialize(ws, fresh)
            for k in piles:
                st.delete(k)  # retire ingress after the CAS, rejects included
            return fresh

    def merge(self, ws, valids, global_rows=()):
        idx, out, newfids = self.idx(ws), [], []
        for v in valids:
            f = v.fact
            if not facts.handler_for(f.t).DURABLE:
                continue  # judged, never persisted: litter drains away
            if idx.execute("SELECT 1 FROM facts WHERE fid=?", (f.fid,)).fetchone() is None:
                newfids.append(f.fid)  # what changed this drain — drives incremental layout
            idx.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?,?)",
                        (f.fid, f.ts, f.t, json.dumps(f.to_json())))
            for name, a0, a1 in f.offers():
                idx.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                            (name, a0, a1, f.fid))
            out.append(v)
        idx.executemany("INSERT OR IGNORE INTO globals VALUES(?,?)", global_rows)
        idx.commit()
        if newfids:
            shadows = self._shadows(ws, newfids)
            self._update_proofs(ws, newfids, shadows)
        return out, newfids

    def _shadows(self, ws, newfids):
        """Could a fact added this drain shift an existing range's resolved
        deps? Any new offer for an address that now has more than one provider
        might change its shortest-proof winner under a frozen range, so the
        generic core drops the memo rather than knowing which offer names
        families consume."""
        idx = self.idx(ws)
        for fid in newfids:
            for name, a0, a1 in self.fact_of(ws, fid).offers():
                if idx.execute(
                        "SELECT COUNT(*) FROM offers WHERE name=? AND a0=? AND a1=?",
                        (name, a0, a1)).fetchone()[0] > 1:
                    return True
        return False

    def _rebuild_proofs(self, ws):
        """Give the accepted set its canonical, history-independent proof DAG."""
        unresolved = rebuild_proofs(
            self.idx(ws), lambda fid: self.fact_of(ws, fid))
        if unresolved:
            sample = ", ".join(sorted(unresolved)[:3])
            raise ValueError(
                f"authority facts have no finite canonical proof: {sample}")
        self.idx(ws).commit()

    def _update_proofs(self, ws, newfids, shadows):
        """Rank the ordinary append-only case without rescanning history."""
        idx = self.idx(ws)
        missing = {
            fid for (fid,) in idx.execute(
                "SELECT DISTINCT o.src FROM offers o "
                "LEFT JOIN proofs p ON p.fid=o.src "
                "WHERE p.fid IS NULL")
        }
        if not missing:
            return
        if shadows or not newfids or not missing <= set(newfids):
            self._rebuild_proofs(ws)
            return
        unresolved = extend_proofs(
            idx, missing, lambda fid: self.fact_of(ws, fid))
        if unresolved:
            sample = ", ".join(sorted(unresolved)[:3])
            raise ValueError(
                f"authority facts have no finite canonical proof: {sample}")
        idx.commit()

    def commit(self, ws, newfids=()):
        st, idx = self.store(ws), self.idx(ws)
        shadows = self._shadows(ws, newfids)
        # Bulk benchmark builders write the derived index directly, while the
        # live path can rank only its new offer sources in dependency order.
        self._update_proofs(ws, newfids, shadows)
        cache = {}

        def deps_of(fid):
            if fid not in cache:
                cache[fid] = resolve_deps(self.fact_of(ws, fid), idx) or []
            return cache[fid]

        memo = None
        prev = st.get("root")
        if prev and not shadows:
            memo = {f["hi"]: f for f in json.loads(prev)["fences"]}
        man, objects = layout(self.keys(ws), lambda fid: self.fact_of(ws, fid),
                              deps_of, ws, self.globals(ws), memo)
        for key, b in objects.items():
            if not st.has(key):
                st.put(key, b)
        st.cas("root", st.etag("root"), man)  # the single commit point
        self._stamp(ws)
        return man

    def materialize(self, ws, valids):
        valids = tuple(valids)
        db = self.app
        for v in valids:
            facts.materialize(db, ws, v)
        facts.reconcile(
            db, ws, self.idx(ws), lambda fid: self.fact_of(ws, fid), valids)
        db.commit()

    # ---- authoring tail: close -> own pile -> turn ("kick") ------------------

    def ingest_new(self, ws, news, deps_new, blobs=None):
        with self.lock:
            idx = self.idx(ws)
            newmap = {f.fid: f for f in news}

            def fact_of(fid):
                return newmap.get(fid) or self.fact_of(ws, fid)

            def deps_of(fid):
                if fid in deps_new:
                    return deps_new[fid]
                return resolve_deps(fact_of(fid), idx) or []

            b = encode_pile(close(news, deps_of, fact_of), blobs)
            self.store(ws).put(f"pile/{self.member_for(ws)}/{h(b)}", b)
            return self.turn(ws)

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws):
        with self.lock:
            st, idx = self.store(ws), self.idx(ws)
            idx.executescript(
                "DELETE FROM facts; DELETE FROM offers; DELETE FROM proofs; "
                "DELETE FROM globals;")
            idx.commit()
            man = st.get("root")
            if not man:
                return
            m = json.loads(man)
            stream = []
            for f in m["fences"] + [m["tail"]]:
                if f.get("pile"):
                    stream += decode_pile(st.get("obj/" + f["pile"]))[0]
            result = drain(stream, ws)
            assert result.ok, "own store failed its own kernel"
            fresh = self.merge(ws, result.valids, result.globals)[0]
            self.materialize(ws, fresh)
            self._stamp(ws)
