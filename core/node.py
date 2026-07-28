"""Node: the turn-based runtime.

One serial loop — turn() — is the only mutator of a workspace:

    drain piles -> kernel each (parallel, own scratchpads) -> merge valid/globals
    -> spill blobs -> commit (settle the manifest -> put objects -> CAS root)
    -> pump projection log -> retire piles

Everything enters through a pile: local commands, pulled units, pushed
piles. The index and app dbs are derived projections — delete either and
rebuild() replays the store's own units through the same kernel.
"""
import json
import os
import sqlite3
import threading
import time

import facts

from . import actions, indexes, manifest
from .close import close, decode_pile, encode_pile
from .crypto import h
from .fact import Fact, canon, from_json
from .keychain import Keychain
from .kernel import (
    SCHEMA as KERNEL_SCHEMA,
    ResolvedEdge,
    drain,
    drain_committed,
    extend_proofs,
    proof_sources,
    resolve_edges,
    resolve_deps,
    unresolved_facts,
)
from .pump import (
    CURSOR_SCHEMA,
    LOG_SCHEMA,
    append_admitted,
    append_received,
    append_retracted,
    pump,
)
from .shape import key_parts
from .store import FsStore

SUPP_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS supp(fid TEXT, k TEXT, PRIMARY KEY(fid, k));",
    "CREATE INDEX IF NOT EXISTS supp_by_k ON supp(k);")
IDX_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts(fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT);
CREATE TABLE IF NOT EXISTS offers(name TEXT, a0 TEXT, a1 TEXT, src TEXT,
                                  PRIMARY KEY(name, a0, a1, src));
CREATE INDEX IF NOT EXISTS offers_by_src ON offers(src, name, a0, a1);
CREATE TABLE IF NOT EXISTS proofs(fid TEXT PRIMARY KEY, rank INT NOT NULL);
CREATE TABLE IF NOT EXISTS edges(
    src TEXT NOT NULL, role TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY(src, role));
CREATE TABLE IF NOT EXISTS globals(name TEXT, value TEXT,
                                   PRIMARY KEY(name, value));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
""" + actions.SCHEMA + "\n".join(SUPP_SCHEMA) + LOG_SCHEMA
INDEX_VERSION = "family-contract-v17-action-slots"
APP_VERSION = 3


def now_ms():
    return int(time.time() * 1000)


def _object(oid, fetch):
    """One immutable object, hash-verified at the door; "" names nothing."""
    raw = fetch(oid) if oid else None
    if raw is None or h(raw) != oid:
        raise ValueError("object integrity")
    return raw


def _edges(items):
    """Closure edges resolved against the whole resident set: the canonical
    providers any reader of the store derives, with no index of its own
    (was tree._canonical_graph)."""
    deps, db = {}, sqlite3.connect(":memory:")
    try:
        db.executescript(KERNEL_SCHEMA)
        db.executemany(
            "INSERT INTO facts VALUES(?,?,?)",
            ((f.fid, f.ts, f.t) for f in items.values()))
        db.executemany(
            "INSERT INTO offers VALUES(?,?,?,?)",
            ((*offer, f.fid)
             for f in items.values() for offer in f.offers()))
        if unresolved_facts(db, items.get):
            raise ValueError("store closure")
        for fid, f in items.items():
            resolved = resolve_deps(f, db)
            if resolved is None or any(d not in items for d in resolved):
                raise ValueError("store closure")
            deps[fid] = resolved
    finally:
        db.close()
    return deps


def resident(man, fetch):
    """Every committed fact, deps-first, from the manifest alone.

    Leaf piles decode with the ONE pile codec (close.decode_pile); the member
    set is then proved by rebuilding the manifest from the keys we read and
    comparing its root oid — placement, chunking, pile and sibling bytes in a
    single equality (replaces tree.validate_view).
    """
    items = {}
    for entry in manifest.decode(_object(man, fetch), fetch):
        members, _ = decode_pile(_object(entry.leaf, fetch))
        items.update({f.fid: f for f in members})
    deps = _edges(items)
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
        app_path = os.path.join(dir, "app.db")
        self.app = sqlite3.connect(app_path, check_same_thread=False)
        if self.app.execute("PRAGMA user_version").fetchone()[0] \
                != APP_VERSION:
            self.app.close()  # app.db is derived; rebuild beats migration
            os.remove(app_path)
            self.app = sqlite3.connect(app_path, check_same_thread=False)
        self.app.executescript(
            facts.APP_SCHEMA + CURSOR_SCHEMA
            + f"PRAGMA user_version={APP_VERSION};")
        self._stores, self._idx = {}, {}
        self._reproject = set()
        self._quarantine_offer_cache = {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        self._sync_errors = {}
        self._state_errors = {}
        for ws in self.workspaces():  # a stale/wiped index is rebuilt from the store
            self._sync_index(ws)
            self.log_arrivals(ws, (
                fid for (fid,) in self.idx(ws).execute("SELECT fid FROM facts")
            ))
            pump(self, ws)  # resume rows committed after the last root publish

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

    def state_failures(self, ws):
        with self.lock:
            return [
                {"component": component, **value}
                for (workspace, component), value
                in sorted(self._state_errors.items())
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
            self._idx[ws] = con
        return self._idx[ws]

    def _sync_index(self, ws):
        """Every SQLite is a derived projection stamped with the root it
        reflects; a mismatched stamp means rebuild from the store."""
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
        pump(self, ws)

    def _stamp(self, ws):
        idx = self.idx(ws)
        try:
            idx.execute("INSERT OR REPLACE INTO meta VALUES('root', ?)",
                        (self.store(ws).etag("root"),))
            idx.execute("INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
                        (INDEX_VERSION,))
            idx.commit()
        except Exception:
            idx.rollback()
            raise

    def commit_index(self, ws):
        """Commit direct derived-index writes as ahead of the manifest.

        The live merge path and bulk benchmark builders share this boundary so
        a process death before ``commit()`` cannot leave unpublished rows under
        an apparently current root stamp.
        """
        idx = self.idx(ws)
        try:
            idx.execute("DELETE FROM meta WHERE k='root'")
            idx.commit()
        except Exception:
            idx.rollback()
            raise

    def fact_of(self, ws, fid) -> Fact:
        row = self.idx(ws).execute("SELECT j FROM facts WHERE fid=?", (fid,)).fetchone()
        return from_json(json.loads(row[0])) if row else None

    def keys(self, ws):
        return [
            key_parts(ts, fid) for ts, fid in
            self.idx(ws).execute(
                "SELECT ts, fid FROM facts ORDER BY ts, fid")
        ]

    def globals(self, ws):
        return frozenset(self.idx(ws).execute(
            "SELECT name, value FROM globals ORDER BY name, value").fetchall())

    def _provider_scopes(self, ws, provider, incoming=None):
        """Scopes whose activation withdraws this authority candidate."""
        incoming = incoming or {}
        scopes = set(actions.provider_scopes(provider))
        policy = facts.policy_for(provider.t)
        if policy is None:
            return frozenset(scopes)
        edges = dict(self.idx(ws).execute(
            "SELECT role, dst FROM edges WHERE src=?", (provider.fid,)))
        for role in policy.authority_liveness_guards:
            fid = edges.get(role)
            guarded = incoming.get(fid) or self.fact_of(ws, fid)
            if guarded is None:
                raise ValueError("authority liveness edge")
            scopes.update(actions.provider_scopes(guarded))
        return frozenset(scopes)

    def _screen_guards(self, ws, fact, edges, incoming=None):
        """Reject a new effect whose declared authority is already masked."""
        policy = facts.policy_for(fact.t)
        if policy is None or not policy.authorization_guards:
            return
        by_role = {edge.role: edge.fid for edge in edges}
        incoming = incoming or {}
        idx = self.idx(ws)
        for role in policy.authorization_guards:
            fid = by_role.get(role)
            provider = incoming.get(fid) or self.fact_of(ws, fid)
            if provider is None:
                raise ValueError("authorization guard edge")
            if any(
                    actions.blocks(idx, sid, fact.key)
                    for sid in self._provider_scopes(
                        ws, provider, incoming)):
                raise actions.ScreenRejected("suppressed authority")

    def _action_evidence(self, ws, fact, incoming, incoming_deps):
        """Persist the action's already-validated immutable proof closure."""
        idx = self.idx(ws)
        fact_of = lambda fid: incoming.get(fid) or self.fact_of(ws, fid)

        def deps_of(fid):
            if fid in incoming_deps:
                return incoming_deps[fid]
            item = fact_of(fid)
            return resolve_deps(item, idx) if item is not None else None

        raw = encode_pile(close([fact], deps_of, fact_of))
        oid = h(raw)
        self.store(ws).put_if_absent("obj/" + oid, raw)
        return oid

    def _backfill_current_actions(self, ws):
        """One-format-cut helper: turn resident action facts into evidence."""
        idx = self.idx(ws)
        for (fid,) in idx.execute("SELECT fid FROM facts ORDER BY fid"):
            fact = self.fact_of(ws, fid)
            if not actions.action_sids(fact):
                continue
            evidence = self._action_evidence(ws, fact, {}, {})
            actions.archive(idx, fact, evidence)

    def _restore_root_actions(self, ws, root_bytes, fetch):
        """Rebuild the local action projection from authenticated tree slots."""
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
            raw = _object(evidence_oid, fetch)
            stream, blobs = decode_pile(raw)
            result = drain(stream, ws)
            candidates = [
                valid.fact for valid in result.valids
                if valid.fact.fid == fid and sid in actions.action_sids(
                    valid.fact)
            ]
            if blobs or not result.ok or len(candidates) != 1:
                raise ValueError("action evidence")
            actions.archive(
                self.idx(ws), candidates[0], evidence_oid)

    # ---- the turn ------------------------------------------------------------

    def turn(self, ws):
        with self.lock:
            st = self.store(ws)
            piles = st.list("pile/")
            if not piles:
                return []  # nothing delivered; drain-on-read stays free
            fresh_all = []
            for source in piles:
                raw = st.get(source)
                try:
                    unit = decode_pile(raw)
                except Exception as error:
                    self._quarantine_ingress(ws, source, raw, error)
                    continue

                result = drain(unit[0], ws)
                if not result.ok:
                    self._quarantine_ingress(
                        ws, source, raw, ValueError("ingress rejected"))
                    continue

                try:
                    self._sync_index(ws)
                    fresh, newfids = self.merge(
                        ws, result.valids, result.globals)
                    arrived = set()
                    for bh, blob in unit[1].items():
                        if not st.has("obj/" + bh):
                            st.put("obj/" + bh, blob)
                            arrived.add(bh)
                    self.commit(ws, newfids)
                    spilled = {}
                    for valid in fresh:
                        refs = facts.blob_refs(valid.fact)
                        if refs:
                            spilled[valid.fact.fid] = refs
                    received = {
                        fid for fid, refs in spilled.items()
                        if set(refs) & arrived
                    }
                    if received:
                        self.log_arrivals(ws, received, repeat=True)
                    resident = set(spilled) - received
                    if resident:
                        self.log_arrivals(ws, resident)
                    pump(self, ws)
                except actions.ScreenRejected as error:
                    self._restore_authoritative_projections(ws)
                    self._quarantine_ingress(
                        ws, source, raw, error)
                    raise
                except Exception:
                    self._restore_authoritative_projections(ws)
                    raise
                st.delete(source)
                fresh_all.extend(fresh)
            return fresh_all

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

    def merge(self, ws, valids, global_rows=()):
        idx, out, newfids, new_action_sids = self.idx(ws), [], [], set()
        valids = tuple(valids)
        by_fid = {valid.fact.fid: valid for valid in valids}
        incoming = {valid.fact.fid: valid.fact for valid in valids}
        incoming_deps = {
            valid.fact.fid: valid.deps for valid in valids
        }
        valids = tuple(
            by_fid[fact.fid]
            for fact in close(
                [valid.fact for valid in valids],
                lambda fid: [
                    dep for dep in by_fid[fid].deps if dep in by_fid],
                lambda fid: by_fid[fid].fact,
            )
        )
        idx.execute("BEGIN")
        try:
            for v in valids:
                f = v.fact
                if not facts.handler_for(f.t).DURABLE:
                    continue  # judged, never persisted: litter drains away
                if idx.execute(
                        "SELECT 1 FROM facts WHERE fid=?",
                        (f.fid,)).fetchone() is None:
                    # What changed this drain — drives incremental layout.
                    newfids.append(f.fid)
                idx.execute("INSERT OR IGNORE INTO facts VALUES(?,?,?,?)",
                            (f.fid, f.ts, f.t, json.dumps(f.to_json())))
                idx.executemany(
                    "INSERT OR IGNORE INTO supp VALUES(?,?)",
                    ((f.fid, sid)
                     for sid in sorted(actions.fact_scopes(f))))
                for name, a0, a1 in f.offers():
                    idx.execute("INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                                (name, a0, a1, f.fid))
                edges = v.edges
                if not edges:
                    policy = facts.policy_for(f.t)
                    if policy is None:
                        ref_count = len(f.refs())
                        roles = tuple(
                            f"ref:{name}:{ordinal}"
                            for ordinal, (name, _) in enumerate(f.refs())
                        ) + tuple(
                            f"dep:{ordinal}"
                            for ordinal in range(
                                ref_count, len(v.deps))
                        )
                    else:
                        ref_count = len(policy.ref_roles)
                        roles = policy.ref_roles + policy.need_roles
                    if len(roles) == len(v.deps):
                        edges = tuple(
                            ResolvedEdge(
                                role, dep,
                                "ref" if ordinal < ref_count
                                else "need",
                            )
                            for ordinal, (role, dep)
                            in enumerate(zip(roles, v.deps))
                        )
                    else:
                        edges = resolve_edges(f, idx)
                if edges is None:
                    raise ValueError("fact has no named dependency edges")
                idx.executemany(
                    "INSERT OR REPLACE INTO edges VALUES(?,?,?,?)",
                    ((f.fid, edge.role, edge.fid, edge.kind)
                     for edge in edges),
                )
                self._screen_guards(ws, f, edges, incoming)
                for sid in actions.action_sids(f):
                    before = idx.execute(
                        "SELECT fid FROM actions WHERE sid=?",
                        (sid,)).fetchone()
                    evidence = self._action_evidence(
                        ws, f, incoming, incoming_deps)
                    actions.archive(idx, f, evidence)
                    after = idx.execute(
                        "SELECT fid FROM actions WHERE sid=?",
                        (sid,)).fetchone()
                    if after == (f.fid,) and before != after:
                        new_action_sids.add(sid)
                out.append(v)
            idx.executemany(
                "INSERT OR IGNORE INTO globals VALUES(?,?)", global_rows)
            pruned, restored, shadows = set(), set(), False
            admitted = set(newfids)
            if newfids:
                shadows = self._shadows(ws, newfids)
                pruned, restored = self._update_proofs(
                    ws, newfids, shadows)
                if pruned or restored:
                    self._rebuild_globals(ws)
            if pruned or restored:
                if restored:
                    self._invalidate_sync_cache(ws)
                out = [valid for valid in out
                       if valid.fact.fid not in pruned]
                newfids = sorted(
                    (set(newfids) | restored) - pruned)
            reproject = shadows or bool(pruned or restored)
            if reproject:
                self._reproject.add(ws)
            self._log_projection(
                ws, newfids, set(pruned) - admitted - restored,
                reproject, new_action_sids)
            idx.execute("DELETE FROM meta WHERE k='root'")
            idx.commit()
            return out, newfids
        except Exception:
            idx.rollback()
            raise

    def _quarantined_offers(self, ws):
        """Return a process-local index of offers retained outside the DAG."""
        if ws not in self._quarantine_offer_cache:
            retained_offers = set()
            for key in self.store(ws).list("quarantine/"):
                try:
                    retained = from_json(json.loads(
                        self.store(ws).get(key)))
                except Exception:
                    continue
                if key == "quarantine/" + retained.fid:
                    retained_offers.update(retained.offers())
            self._quarantine_offer_cache[ws] = retained_offers
        return self._quarantine_offer_cache[ws]

    def _shadows(self, ws, newfids):
        """Could a fact added this drain shift an existing range's resolved
        deps? Any new offer for an address that now has more than one provider
        might change its shortest-proof winner under a frozen range. A match
        against a quarantined provider can also repair an absent proof. In
        either case the generic core drops the memo rather than knowing which
        offer names families consume."""
        idx = self.idx(ws)
        quarantined = None
        for fid in newfids:
            fact = self.fact_of(ws, fid)
            if fact is None:
                continue
            for name, a0, a1 in fact.offers():
                if idx.execute(
                        "SELECT COUNT(*) FROM offers WHERE name=? AND a0=? AND a1=?",
                        (name, a0, a1)).fetchone()[0] > 1:
                    return True
                if quarantined is None:
                    quarantined = self._quarantined_offers(ws)
                if (name, a0, a1) in quarantined:
                    return True
        return False

    def _restore_quarantine(self, ws):
        """Reinsert previously valid facts before recomputing authority.

        A canonical winner can change twice: a conflict can first orphan a
        downstream fact, then a later shorter proof can restore its original
        authority source. Keep pruned facts outside the published set so they
        cannot poison a leaf, but retain them locally so that second change is
        history-independent and survives an index rebuild.
        """
        idx, restored = self.idx(ws), set()
        for key in self.store(ws).list("quarantine/"):
            try:
                fact = from_json(json.loads(self.store(ws).get(key)))
            except Exception:
                continue
            handler = facts.handler_for(fact.t)
            if key != "quarantine/" + fact.fid \
                    or handler is None or not handler.DURABLE:
                continue
            if idx.execute(
                    "SELECT 1 FROM facts WHERE fid=?",
                    (fact.fid,)).fetchone() is not None:
                continue
            idx.execute(
                "INSERT INTO facts VALUES(?,?,?,?)",
                (fact.fid, fact.ts, fact.t, json.dumps(fact.to_json())))
            idx.executemany(
                "INSERT OR IGNORE INTO supp VALUES(?,?)",
                ((fact.fid, sid)
                 for sid in sorted(actions.fact_scopes(fact))))
            for name, a0, a1 in fact.offers():
                idx.execute(
                    "INSERT OR IGNORE INTO offers VALUES(?,?,?,?)",
                    (name, a0, a1, fact.fid))
            restored.add(fact.fid)
        return restored

    def _quarantine(self, ws, fids):
        """Retain kernel-valid facts that are outside the current proof DAG."""
        st = self.store(ws)
        retained_offers = self._quarantined_offers(ws)
        for fid in sorted(fids):
            fact = self.fact_of(ws, fid)
            if fact is not None:
                st.put_if_absent(
                    "quarantine/" + fid, canon(fact.to_json()))
                retained_offers.update(fact.offers())

    def _prune_unresolved(self, ws):
        """Derive the same finite-proof subset from any arrival order."""
        idx, pruned = self.idx(ws), set()
        while True:
            unresolved = set(unresolved_facts(
                idx, lambda fid: self.fact_of(ws, fid)))
            if not unresolved:
                return pruned
            pruned.update(unresolved)
            self._quarantine(ws, unresolved)
            idx.executemany(
                "DELETE FROM offers WHERE src=?",
                ((fid,) for fid in unresolved))
            idx.executemany(
                "DELETE FROM proofs WHERE fid=?",
                ((fid,) for fid in unresolved))
            idx.executemany(
                "DELETE FROM edges WHERE src=?",
                ((fid,) for fid in unresolved))
            idx.executemany(
                "DELETE FROM supp WHERE fid=?",
                ((fid,) for fid in unresolved))
            idx.executemany(
                "DELETE FROM facts WHERE fid=?",
                ((fid,) for fid in unresolved))

    def _rebuild_globals(self, ws):
        """Reproject monotone rows after canonical pruning removes a source."""
        idx = self.idx(ws)
        idx.execute("DELETE FROM globals")
        rows = set()
        for (fid,) in idx.execute("SELECT fid FROM facts ORDER BY fid"):
            fact = self.fact_of(ws, fid)
            rows.update(facts.handler_for(fact.t).global_rows(fact))
        idx.executemany(
            "INSERT OR IGNORE INTO globals VALUES(?,?)", sorted(rows))

    def _update_proofs(self, ws, newfids, shadows):
        """Rank an append or prune to the union's canonical finite subset."""
        idx = self.idx(ws)

        def refresh_edges():
            idx.execute("DELETE FROM edges")
            for (fid,) in idx.execute("SELECT fid FROM facts ORDER BY fid"):
                fact = self.fact_of(ws, fid)
                edges = resolve_edges(fact, idx)
                if edges is None:
                    raise ValueError("ranked fact has no named edges")
                idx.executemany(
                    "INSERT INTO edges VALUES(?,?,?,?)",
                    ((fid, edge.role, edge.fid, edge.kind)
                     for edge in edges),
                )

        restored = self._restore_quarantine(ws) \
            if shadows or not newfids else set()
        if shadows or restored or not newfids:
            pruned = self._prune_unresolved(ws)
            refresh_edges()
            return pruned, restored
        # A healthy index ranks every offer source and explicit-ref target.
        # Only new facts can introduce either, so ordinary appends stay O(new).
        missing = {
            fid for fid in proof_sources(
                newfids, lambda source: self.fact_of(ws, source))
            if idx.execute(
                "SELECT 1 FROM proofs WHERE fid=?", (fid,)).fetchone() is None
        }
        if not missing:
            return set(), set()
        unresolved = extend_proofs(
            idx, missing, lambda fid: self.fact_of(ws, fid))
        if unresolved:
            pruned = self._prune_unresolved(ws)
            refresh_edges()
            return pruned, restored
        return set(), restored

    def commit(self, ws, newfids=(), *, reuse=True):
        st, idx = self.store(ws), self.idx(ws)
        # A root names its anchor — rebuild() and mint.Authority.from_root
        # both reject one that doesn't, so never publish one. An index
        # without it is not a store yet (an arrival order can land bare
        # signatures first): it stays ahead of the manifest, unpublished,
        # until a turn brings the anchor in. A rootless store is legal.
        if idx.execute(
                "SELECT 1 FROM facts WHERE fid=?", (ws,)).fetchone() is None:
            return None
        self._backfill_current_actions(ws)
        shadows = self._shadows(ws, newfids)
        # Bulk benchmark builders write the derived index directly, while the
        # live path can rank only its new offer sources in dependency order.
        try:
            idx.execute("DELETE FROM meta WHERE k='root'")
            pruned, restored = self._update_proofs(
                ws, newfids, shadows)
            if pruned or restored:
                self._rebuild_globals(ws)
                self._reproject.add(ws)
                self._log_projection(
                    ws, sorted(set(restored) - pruned),
                    set(pruned) - restored, True)
                newfids = tuple(sorted(
                    (set(newfids) | restored) - pruned))
            # merge() and the direct/bulk boundary have already indexed keys.
            self.commit_index(ws)
            if restored:
                self._invalidate_sync_cache(ws)
        except Exception:
            idx.rollback()
            raise
        cache = {}

        def deps_of(fid):
            if fid not in cache:
                cache[fid] = resolve_deps(self.fact_of(ws, fid), idx) or []
            return cache[fid]

        prev = st.get("root")
        etag = h(prev) if prev is not None else None

        def emit(raw):
            oid = h(raw)
            if not st.has("obj/" + oid):
                st.put("obj/" + oid, raw)
            return oid

        fetch = lambda oid: st.get("obj/" + oid)
        entries = self._previous(ws, prev, fetch)
        # A settle is a pure function of the key set; ``entries`` only memoizes
        # unchanged leaves. Shadows/prunes/republish can re-pick canonical
        # providers for an unchanged member set, so they drop the memo.
        if not (reuse and not shadows and not pruned and not restored):
            entries = ()
        _, man = manifest.build(
            self.keys(ws), lambda fid: self.fact_of(ws, fid), deps_of, emit,
            entries)
        previous_trees = {}
        if prev:
            try:
                _, previous_trees = manifest.decode_composite(prev)
            except ValueError:
                pass
        seed, trees = indexes.build(
            ws, idx, lambda fid: self.fact_of(ws, fid), emit,
            previous=previous_trees, fetch=fetch)
        root = manifest.encode_root(
            ws, self.globals(ws), man,
            action_summary=actions.summary(idx),
            layout_seed=seed, trees=trees)
        if st.cas("root", etag, root) is None:  # the single commit point
            raise RuntimeError("root changed")
        self._stamp(ws)
        return root

    def _previous(self, ws, raw, fetch):
        """The previous root's manifest entries: a memo for the next settle.
        Bytes we cannot read — a foreign layout stamp, a missing shard —
        settle from scratch; there is no read-compat path (docs/CUTOVER.md
        §1)."""
        if not raw:
            return ()
        try:
            anchor, _, man = manifest.decode_root(raw)
        except ValueError:
            return ()
        if anchor != ws:
            raise ValueError("root anchor")
        try:
            return manifest.decode(_object(man, fetch), fetch)
        except ValueError:
            return ()

    def materialize(self, ws, _valids=()):
        """Transitional benchmark API; the delivery log is authoritative."""
        return pump(self, ws)

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
            fresh = self.turn(ws)
            missing = [
                fact.fid for fact in news
                if facts.handler_for(fact.t).DURABLE
                and self.fact_of(ws, fact.fid) is None
            ]
            if missing:
                sample = ", ".join(sorted(missing)[:3])
                raise ValueError(
                    f"authored facts are outside the canonical set: {sample}")
            return fresh

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
                    self.commit(ws, reuse=False)
                    raw = st.get("root")
                    root = manifest.decode_root(raw)
            if root is not None:
                anchor, globals_, man = root
                if anchor != ws:
                    raise ValueError("root anchor")
                fetch = lambda oid: st.get("obj/" + oid)
                try:
                    stream = list(resident(man, fetch))
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
                    anchor, globals_, man = manifest.decode_root(raw)
                    stream = list(resident(man, fetch))
                if ws not in {fact.fid for fact in stream}:
                    raise ValueError("store fact set")
                result = drain_committed(stream, ws, globals_)
                if not result.ok:
                    raise ValueError("invalid store facts")
            # Drop the cursor BEFORE the log DROP resets AUTOINCREMENT: a
            # crash anywhere after this point leaves no cursor row, so a
            # restarted pump takes the rebuild branch instead of skipping
            # new low seqs against the stale-high cursor (the process-local
            # _reproject flag does not survive a restart).
            self.app.execute("DELETE FROM cursors WHERE ws=?", (ws,))
            self.app.commit()
            idx.execute("BEGIN")
            try:
                for table in (
                        "facts", "offers", "proofs", "globals", "actions"):
                    idx.execute(f"DELETE FROM {table}")
                # DROP, not DELETE: CREATE IF NOT EXISTS keeps a pre-v14
                # file's single-group supp DDL, whose UNIQUE(k) would
                # silently swallow all but one victim per group on re-merge.
                for table in ("supp", "log"):
                    idx.execute(f"DROP TABLE IF EXISTS {table}")
                for statement in SUPP_SCHEMA + (LOG_SCHEMA,):
                    idx.execute(statement)
                idx.execute(
                    "DELETE FROM meta WHERE k IN ('root','reproject')")
                idx.commit()
            except Exception:
                idx.rollback()
                raise
            self._reproject.add(ws)
            if root is None:  # no root at all: an empty store is legal
                self._stamp(ws)
                pump(self, ws)
                return
            self.merge(ws, result.valids, result.globals)
            try:
                self._restore_root_actions(
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
                self.commit(ws, reuse=False)
            else:
                self._stamp(ws)
            self.log_arrivals(
                ws, (valid.fact.fid for valid in result.valids))
            pump(self, ws)

    # ---- exact suppression consult + local reverse projection ----------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        return actions.suppresses(self.idx(ws), fact)

    def apply_actions(self, ws, sids):
        """Retract resident victims through the rebuildable sid reverse map."""
        idx = self.idx(ws)
        dead = {
            fid
            for sid in set(sids)
            for (fid,) in idx.execute(
                "SELECT fid FROM supp WHERE k=?", (sid,))
            if self.fact_of(ws, fid) is not None
        }
        last = dict(idx.execute(
            "SELECT fid, op FROM log WHERE op IN ('+','-') ORDER BY seq"))
        append_retracted(idx, sorted(
            fid for fid in dead if last.get(fid) == "+"))
        return dead
