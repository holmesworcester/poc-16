"""Node: the turn-based runtime.

One serial loop — turn() — is the only mutator of a workspace:

    drain piles -> kernel each (parallel, own scratchpads) -> merge valid
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

from .close import close, decode_pile, encode_pile
from .crypto import h, keypair, load_sk
from .fact import Fact, from_json
from .kernel import EPHEMERAL, kernel, offer_src, resolve_deps
from .layout import fingerprint, layout
from .store import FsStore

IDX_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT);
CREATE TABLE IF NOT EXISTS offers(name TEXT, a0 TEXT, a1 TEXT, src TEXT,
                                  PRIMARY KEY(name, a0, a1, src));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""
APP_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                    pk TEXT, text TEXT, ts INT);
CREATE TABLE IF NOT EXISTS members(ws TEXT, pk TEXT, name TEXT, role TEXT,
                                   evicted INT DEFAULT 0, PRIMARY KEY(ws, pk));
CREATE TABLE IF NOT EXISTS files(fid TEXT PRIMARY KEY, ws TEXT, chan TEXT,
                                 name TEXT, size INT, blob TEXT, pk TEXT, ts INT);
"""


def now_ms():
    return int(time.time() * 1000)


class Node:
    def __init__(self, dir):
        self.dir = dir
        os.makedirs(dir, exist_ok=True)
        self.lock = threading.RLock()
        self.url = None  # the daemon sets its advertised base URL
        self._kr_path = os.path.join(dir, "keyring.json")
        if os.path.exists(self._kr_path):
            self.keyring = json.load(open(self._kr_path))
        else:
            sk, _ = keypair()
            self.keyring = {"sk": sk.encode().hex(), "workspaces": {}}
            self.save_keyring()
        self.sk = load_sk(self.keyring["sk"])
        self.pk = self.sk.verify_key.encode().hex()
        self.app = sqlite3.connect(os.path.join(dir, "app.db"), check_same_thread=False)
        self.app.executescript(APP_SCHEMA)
        self._stores, self._idx = {}, {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        for ws in self.workspaces():  # a stale/wiped index is rebuilt from the store
            self._sync_index(ws)

    # ---- node-local state ----------------------------------------------------

    def save_keyring(self):
        json.dump(self.keyring, open(self._kr_path, "w"))

    @property
    def member(self):
        return self.pk[:16]

    def workspaces(self):
        return list(self.keyring["workspaces"])

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
        if etag and (row is None or row[0] != etag):
            self.rebuild(ws)

    def _stamp(self, ws):
        idx = self.idx(ws)
        idx.execute("INSERT OR REPLACE INTO meta VALUES('root', ?)",
                    (self.store(ws).etag("root"),))
        idx.commit()

    def fact_of(self, ws, fid) -> Fact:
        row = self.idx(ws).execute("SELECT j FROM facts WHERE fid=?", (fid,)).fetchone()
        return from_json(json.loads(row[0])) if row else None

    def keys(self, ws):
        return [f"{ts:015d}:{fid}" for ts, fid in
                self.idx(ws).execute("SELECT ts, fid FROM facts ORDER BY ts, fid")]

    def member_src(self, ws, role="member"):
        return offer_src(self.idx(ws), role, self.pk)

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
                    results = list(ex.map(lambda u: kernel(u[0], ws) if u else (False, [], set()), units))
            else:
                results = [kernel(u[0], ws) if u else (False, [], set()) for u in units]
            valids, blobs = [], {}
            for u, (ok, vs, _) in zip(units, results):
                if ok:
                    valids += vs
                    blobs.update(u[1])
            fresh, newfids = self.merge(ws, valids)
            for bh, b in blobs.items():
                st.put_if_absent("obj/" + bh, b)
            self.commit(ws, newfids)
            self.materialize(ws, fresh)
            for k in piles:
                st.delete(k)  # retire ingress after the CAS, rejects included
            return fresh

    def merge(self, ws, valids):
        idx, out, newfids = self.idx(ws), [], []
        for v in valids:
            f = v.fact
            if f.t in EPHEMERAL:
                continue  # judged, never persisted: litter drains away
            if idx.execute("SELECT 1 FROM facts WHERE fid=?", (f.fid,)).fetchone() is None:
                newfids.append(f.fid)  # what changed this drain — drives incremental layout
            idx.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?,?)",
                        (f.fid, f.ts, f.t, json.dumps(f.to_json())))
            for name, a0, a1 in f.offers():
                idx.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                            (name, a0, a1, f.fid))
            out.append(v)
        idx.commit()
        return out, newfids

    def _shadows(self, ws, newfids):
        """Could a fact added this drain shift an existing range's resolved
        deps? Only a new member/admin/author offer for an address that now has
        more than one provider can — then min-src may move under a frozen
        range, so the incremental reuse is unsound and the memo is dropped."""
        idx = self.idx(ws)
        for fid in newfids:
            for name, a0, a1 in self.fact_of(ws, fid).offers():
                if name in ("member", "admin", "author") and idx.execute(
                        "SELECT COUNT(*) FROM offers WHERE name=? AND a0=? AND a1=?",
                        (name, a0, a1)).fetchone()[0] > 1:
                    return True
        return False

    def commit(self, ws, newfids=()):
        st, idx = self.store(ws), self.idx(ws)
        cache = {}

        def deps_of(fid):
            if fid not in cache:
                cache[fid] = resolve_deps(self.fact_of(ws, fid), idx) or []
            return cache[fid]

        memo = None
        prev = st.get("root")
        if prev and not self._shadows(ws, newfids):
            memo = {f["hi"]: f for f in json.loads(prev)["fences"]}
        removal = [r for (r,) in idx.execute("SELECT DISTINCT a0 FROM offers WHERE name='removed'")]
        man, objects = layout(self.keys(ws), lambda fid: self.fact_of(ws, fid),
                              deps_of, ws, removal, memo)
        for key, b in objects.items():
            if not st.has(key):
                st.put(key, b)
        st.cas("root", st.etag("root"), man)  # the single commit point
        self._stamp(ws)
        return man

    def materialize(self, ws, valids):
        db = self.app
        for v in valids:
            f, b = v.fact, v.fact.body
            if f.t == "msg":
                db.execute("INSERT OR IGNORE INTO messages VALUES(?,?,?,?,?,?)",
                           (f.fid, ws, b["chan"], b["pk"], b["text"], f.ts))
            elif f.t == "file":
                db.execute("INSERT OR IGNORE INTO files VALUES(?,?,?,?,?,?,?,?)",
                           (f.fid, ws, b["chan"], b["name"], b["size"], b["blob"], b["pk"], f.ts))
            elif f.t in ("genesis", "join"):
                db.execute("INSERT OR IGNORE INTO members VALUES(?,?,?,?,0)",
                           (ws, b["pk"], b["name"], "admin" if f.t == "genesis" else "member"))
            elif f.t == "evict":
                db.execute("UPDATE members SET evicted=1 WHERE ws=? AND pk=?",
                           (ws, f.atoms[0][2]))
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
            self.store(ws).put(f"pile/{self.member}/{h(b)}", b)
            return self.turn(ws)

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws):
        with self.lock:
            st, idx = self.store(ws), self.idx(ws)
            idx.executescript("DELETE FROM facts; DELETE FROM offers;")
            idx.commit()
            man = st.get("root")
            if not man:
                return
            m = json.loads(man)
            stream = []
            for f in m["fences"] + [m["tail"]]:
                for oh in (f.get("annex"), f.get("page")):
                    if oh:
                        stream += decode_pile(st.get("obj/" + oh))[0]
            ok, valids, _ = kernel(stream, ws)
            assert ok, "own store failed its own kernel"
            self.materialize(ws, self.merge(ws, valids)[0])
            self._stamp(ws)
