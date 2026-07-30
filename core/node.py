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
from dataclasses import dataclass, field
from typing import NamedTuple

import facts

from . import admission_proof, catalog, manifest, shape, suppression_state
from .close import close, decode_pile, encode_pile
from .crypto import h
from .fact import Fact, canon
from .ingress import (
    KernelRejected,
    _retire_published,
    preserve_rejection,
    retire_rejected,
)
from .keychain import Keychain
from .kernel import (
    drain,
    resolve_deps,
    rebuild_proofs,
)
from .publication import INDEX_VERSION, Publisher, RootChanged
from .runtime import WorkspaceRuntime
from .object_store import ABSENT, ensure_object, verified_object
from .store import FsStore

SUPP_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS supp(fid TEXT, k TEXT, PRIMARY KEY(fid, k));",
    "CREATE INDEX IF NOT EXISTS supp_by_k ON supp(k);")
IDX_SCHEMA = catalog.SCHEMA + """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
""" + suppression_state.SCHEMA + "\n".join(SUPP_SCHEMA)


class Admission(NamedTuple):
    """One successful kernel judgment and its unpublished settlement."""

    settlement: object
    valids: tuple


@dataclass(frozen=True, slots=True)
class _BoundAdmission:
    """One exact hash-bound pile judgment allowed to request retirement."""

    settlement: object
    valids: tuple
    workspace: str
    source: str
    raw: bytes
    payload: str
    generation: str
    blobs: tuple
    issuer: object = field(repr=False, compare=False)


def now_ms():
    return int(time.time() * 1000)


def _edges(items, anchor=None):
    """Closure edges resolved against the whole resident set: the canonical
    providers any reader of the store derives, with no index of its own
    (was tree._canonical_graph)."""
    deps, db = {}, sqlite3.connect(":memory:")
    try:
        db.executescript(catalog.SCHEMA)
        admitted = catalog.ScratchCatalog(db, anchor)
        for fact in items.values():
            admitted.load(fact)
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


def resident(man, fetch, anchor):
    """Every committed fact, deps-first, from the manifest alone.

    Reference leaves resolve each fact through its sole content-addressed
    residence. The member set is then proved by rebuilding the manifest from
    the keys we read and comparing its root oid — placement, chunking,
    reference and sibling bytes in a single equality.
    """
    items = {}
    entries = manifest.decode(verified_object(man, fetch), fetch) if man else ()
    for entry in entries:
        members = manifest.range_members(entry, fetch, anchor)
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


def _legacy_resident(man, fetch, anchor):
    """Decode the sole v7 pile-leaf layout during the explicit v8 cutover."""
    items, leaf_raw = {}, {}
    entries = manifest.decode(verified_object(man, fetch), fetch) if man else ()
    for entry in entries:
        raw = verified_object(entry.leaf, fetch)
        members, blobs = decode_pile(raw, anchor)
        if blobs:
            raise ValueError("legacy store placement")
        for fact in members:
            if fact.fid in items:
                raise ValueError("legacy store placement")
            items[fact.fid] = fact
        leaf_raw[entry.leaf] = raw
    if any(
            (family := facts.family_for(fact.t)) is None
            or not family.DURABLE
            for fact in items.values()):
        raise ValueError("store contains an ephemeral fact")
    deps = _edges(items, anchor)
    keys = sorted(fact.key for fact in items.values())
    cuts = shape.stable_cut_positions(
        [shape.fid_of(address) for address in keys])
    chunks = [
        keys[start:stop]
        for start, stop in zip([0] + cuts, cuts + [len(keys)])
        if stop > start
    ]
    expected = []
    for addresses in chunks:
        members = [items[shape.fid_of(address)] for address in addresses]
        raw = encode_pile(members, workspace=anchor)
        outside = manifest.closure_keys(
            members, deps.__getitem__,
            lambda fid: items[fid].key)
        closure_raw = canon({"keys": outside}) if outside else None
        entry = manifest.Entry(
            addresses[0],
            h(raw),
            h(closure_raw) if closure_raw is not None else "",
        )
        if leaf_raw.get(entry.leaf) != raw:
            raise ValueError("legacy store placement")
        if closure_raw is not None and verified_object(
                entry.closure, fetch) != closure_raw:
            raise ValueError("legacy store placement")
        expected.append(entry)
    if expected != entries or manifest.encode(
            expected, lambda _raw: None) != man:
        raise ValueError("legacy store placement")
    return close(items.values(), deps.__getitem__, items.__getitem__)


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
        self.sync_cache = {}  # (ws, peer_url) -> walk state
        self._sync_errors = {}
        self._ingress_attempt_errors = {}
        self._admission_issuer = object()
        # One live retirement capability per exact ingress generation. Direct
        # uploads can remain present until their signed PUT authority expires;
        # replacing by key prevents every pre-deadline poll from accumulating
        # another otherwise equivalent no-op receipt.
        self._publication_receipts = {}
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
        receipt = preserve_rejection(
            self.store(ws), source, raw, error)
        return self._retire_rejected_ingress(
            ws, source, raw, receipt)

    def _retire_published_ingress(
            self, ws, source, raw, receipt):
        """Retire one accepted pile under its exact publication result.

        The result is minted only after Applied, byte-identical ambiguous-CAS
        readback, or a token-verified no-op. Once minted, a later root cannot
        undo that historical event because candidate retention is monotone.
        """
        key = (ws, source, h(raw))
        registered = self._publication_receipts.get(key)
        if registered is None or registered is not receipt:
            raise ValueError("published ingress capability")
        retired = _retire_published(
            self.store(ws), ws, source, raw, receipt,
            self._admission_issuer)
        self._publication_receipts.pop(key)
        return retired

    def _published_ingress_receipt(self, ws, source, raw):
        """Return this process's exact pending retirement capability."""
        return self._publication_receipts.get((ws, source, h(raw)))

    def _reconcile_publication_receipts(self, ws, live_sources):
        """Forget capabilities whose shared ingress generation is absent."""
        live_sources = set(live_sources)
        for key in tuple(self._publication_receipts):
            if key[0] == ws and key[1] not in live_sources:
                self._publication_receipts.pop(key)

    def _retire_rejected_ingress(
            self, ws, source, raw, receipt):
        """Retire one rejected pile under exact durable quarantine evidence.

        Every accepted pile writer binds the final path segment to ``h(raw)``;
        direct upload additionally makes creation conditional. That stable
        same-address value is the precondition required by ``retire_exact``.
        """
        return retire_rejected(
            self.store(ws), source, raw, receipt)

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

    def _restore_authoritative_state(self, ws):
        """Discard a failed turn's local state before releasing its lock."""
        self.idx(ws).rollback()
        self._sync_index(ws)

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

    def admit(
            self, ws, stream, *, base=None, force=False,
            allowed_staged=None):
        """Run the kernel, then durably settle only its exact Valid receipts.

        This method is the catalog's sole durable fact entrance. Callers pass
        a closed fact stream, never a caller-constructed receipt.
        """
        judgment = drain(tuple(stream), ws)
        if not judgment.ok:
            if judgment.failure is not None:
                raise judgment.failure
            raise KernelRejected("ingress rejected")
        return self._admit_judgment(
            ws, judgment, base=base, force=force,
            allowed_staged=allowed_staged)

    def _admit_judgment(
            self, ws, judgment, *, base=None, force=False,
            allowed_staged=None):
        """Persist one judgment minted by this node's immediate kernel run."""
        publisher = Publisher(self, ws)
        base = publisher.base() if base is None else base
        store = self.store(ws)

        def emit(raw):
            oid = h(raw)
            ensure_object(store, oid, raw)
            return oid

        admission_proofs = admission_proof.build(
            ws, judgment.valids, emit)
        receipt_proofs = tuple(
            (receipt, admission_proofs[receipt.fact.fid])
            for receipt in judgment.valids
            if facts.family_for(receipt.fact.t).DURABLE
        )
        return self._settle_receipts(
            ws, receipt_proofs, judgment.valids, base,
            force=force, allowed_staged=allowed_staged)

    def admit_ingress(
            self, ws, source, raw, *, base=None, force=False):
        """Decode/judge one exact source value and mint retirement authority."""
        from .ingress import check_source

        binding = check_source(source, raw)
        stream, blobs = decode_pile(raw, ws)
        judgment = drain(tuple(stream), ws)
        if not judgment.ok:
            if judgment.failure is not None:
                raise judgment.failure
            raise KernelRejected("ingress rejected")
        admitted = self._admit_judgment(
            ws, judgment, base=base, force=force,
            allowed_staged={fact.fid for fact in stream})
        return _BoundAdmission(
            admitted.settlement,
            admitted.valids,
            ws,
            source,
            raw,
            h(raw),
            binding.generation,
            tuple(sorted(blobs.items())),
            self._admission_issuer,
        )

    def _settle_receipts(
            self, ws, receipt_proofs, valids, base, *, force=False,
            allowed_staged=None):
        """Enter already-kernel-minted receipts and derive one publication.

        ``Node.admit`` supplies receipts from its immediate ``drain`` call.
        Cold archive repair supplies receipts from the same verifier after it
        has rerun ``drain`` over a root-authenticated proof closure. There is
        no raw-fact durable entrance beneath this method.
        """
        publisher = Publisher(self, ws)
        idx, newfids = self.idx(ws), []
        witness_changes = set()
        admitted = self.catalog(ws)
        idx.execute("BEGIN")
        try:
            actions_dirty = False
            for receipt, proof_oid in receipt_proofs:
                f = receipt.fact
                family = facts.family_for(f.t)
                if family is None or not family.DURABLE:
                    raise ValueError("non-durable admission receipt")
                stored = admitted._admit_valid(receipt, proof_oid)
                if stored.staged:
                    newfids.append(f.fid)
                if stored.witness_changed:
                    witness_changes.add(f.fid)
                idx.executemany(
                    "INSERT OR IGNORE INTO supp VALUES(?,?)",
                    ((f.fid, sid)
                     for sid in sorted(
                         facts.fact_scopes(f))))
                if facts.action_sids(f):
                    actions_dirty = actions_dirty or stored.staged
                    suppression_state.archive(idx, f)
            witness_changes.difference_update(newfids)
            force = force or (
                not newfids and not admitted.has_eligible()
                and idx.execute(
                    "SELECT 1 FROM facts LIMIT 1").fetchone() is not None)
            change = admitted.settle(
                newfids, force=force, actions_dirty=actions_dirty,
                allowed_staged=allowed_staged) \
                if newfids or force or actions_dirty \
                else catalog.Eligibility((), (), (), (), (), False, ())
            if force:
                staged = self.catalog(ws).staged_ids()
                change = change._replace(
                    received=staged if allowed_staged is None else tuple(
                        fid for fid in staged if fid in allowed_staged))
            if witness_changes:
                changed_sids = set(change.changed_sids)
                changed_sids.update(
                    sid for sid, in idx.execute(
                        "SELECT sid FROM actions WHERE fid IN "
                        f"({','.join('?' for _ in witness_changes)})",
                        tuple(sorted(witness_changes)),
                    )
                )
                change = change._replace(
                    witnesses=tuple(sorted(witness_changes)),
                    changed_sids=tuple(sorted(changed_sids)),
                )
            restored = set(change.activated) - set(newfids)
            if restored:
                self._invalidate_sync_cache(ws)
            publisher.dirty(base)
            idx.commit()
            admitted_fids = tuple(
                receipt.fact.fid for receipt, _ in receipt_proofs)
            return Admission(
                publisher.plan(change, base, admitted_fids), tuple(valids))
        except Exception:
            idx.rollback()
            raise

    def commit(
            self, ws, settlement=None, *, reuse=True, _base=None):
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
                change = change._replace(
                    received=tuple(staged),
                    authority_changed=True,
                )
                idx.commit()
                settlement = publisher.plan(change, base)
            except Exception:
                idx.rollback()
                raise
        return publisher.publish(settlement, reuse=reuse).root

    def commit_ingress(self, admission, *, reuse=True):
        """Publish one exact kernel judgment and return its retirement token."""
        if not isinstance(admission, _BoundAdmission):
            raise TypeError("bound ingress admission")
        from .ingress import check_source

        if admission.issuer is not self._admission_issuer:
            raise ValueError("bound ingress issuer")
        binding = check_source(admission.source, admission.raw)
        if admission.payload != h(admission.raw):
            raise ValueError("bound ingress payload")
        if admission.generation != binding.generation:
            raise ValueError("bound ingress generation")
        durable = tuple(sorted(
            valid.fact.fid
            for valid in admission.valids
            if (family := facts.family_for(valid.fact.t)) is not None
            and family.DURABLE
        ))
        if admission.settlement.admitted != durable:
            raise ValueError("publication admission binding")
        receipt = Publisher(
            self, admission.workspace
        )._publish_ingress(admission, reuse=reuse)
        if receipt.issuer is not self._admission_issuer:
            raise ValueError("publication receipt issuer")
        self._publication_receipts[(
            admission.workspace,
            admission.source,
            admission.payload,
        )] = receipt
        return receipt

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
            if raw:
                try:
                    root = manifest.decode_root(raw)
                except ValueError:
                    try:
                        previous = manifest.decode_previous_root(raw)
                    except ValueError:
                        # Tests and operator repair may rewrite only a format
                        # stamp. Republish such an exact known envelope from a
                        # current catalog; never interpret unknown bytes.
                        if not publisher.same_snapshot_envelope(raw):
                            raise ValueError(
                                "unreadable root does not match indexed "
                                "snapshot")
                        self.commit(ws, reuse=False, _base=base)
                        base = publisher.root_base()
                        raw = base.root
                        root = manifest.decode_root(raw)
                    else:
                        if previous.anchor != ws:
                            raise ValueError("root anchor")
                        # The one explicit v7→v8 cut: only raw facts already
                        # authenticated by the old RangeTree are rejudged.
                        # Proof-less local-only rows are not inferred admitted.
                        legacy_stream = tuple(_legacy_resident(
                            previous.manifest, fetch, ws))
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
            elif legacy_stream and ws not in {
                    fact.fid for fact in legacy_stream}:
                raise ValueError("store fact set")
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
                admission = self._settle_receipts(
                    ws,
                    archive.receipt_proofs,
                    tuple(
                        receipt
                        for receipt, _ in archive.receipt_proofs),
                    base,
                    force=True,
                    allowed_staged=set(archive.records),
                )
            else:
                admission = self.admit(
                    ws, legacy_stream, base=base, force=True,
                    allowed_staged={
                        fact.fid for fact in legacy_stream})
            settlement = admission.settlement
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
