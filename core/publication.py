"""Compile one eligible client snapshot and advance its root by one CAS."""
import json
from dataclasses import dataclass, field
from typing import NamedTuple

from . import catalog, indexes, snapshot
from .crypto import h
from .fact import encode as encode_fact
from .shape import fid_of
from .object_store import (
    ABSENT,
    STALE,
    Applied,
    Absent,
    OutcomeUnknown,
    VersionToken,
    Versioned,
    ensure_object,
)

INDEX_VERSION = catalog.INDEX_VERSION


class RootChanged(RuntimeError):
    """The mutable root no longer matches the snapshot this work read."""


class RootBase(NamedTuple):
    """One root read: logical bytes/digest plus its opaque CAS token."""

    root: bytes | None
    digest: str | None
    token: VersionToken | Absent


class PublicationPlan(NamedTuple):
    """An eligibility delta pinned to the exact root it extends."""

    received: tuple
    activated: tuple
    deactivated: tuple
    updated: tuple
    witnesses: tuple
    authority_changed: bool
    changed_sids: tuple
    admitted: tuple
    base_root: bytes | None
    base_token: VersionToken | Absent


class PublicationResult(NamedTuple):
    """Exact authorized-root outcome without ingress-retirement authority."""

    workspace: str
    root: bytes | None
    admitted: tuple
    outcome: str


@dataclass(frozen=True, slots=True, eq=False)
class PublicationReceipt:
    """Node-minted authority to retire one exact published ingress value.

    Value fields explain the durable publication event.  ``issuer`` binds the
    receipt to the node that admitted it, while identity equality lets that
    node reject caller-constructed copies even when every visible field was
    copied from a genuine receipt.
    """

    workspace: str
    root: bytes | None
    admitted: tuple
    outcome: str
    source: str | None
    payload: str | None
    generation: str
    issuer: object = field(repr=False, compare=False)


class Publisher:
    """The sole authority for immutable snapshot objects and mutable root."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def root_base(self):
        versioned = self.node.store(self.workspace).read_versioned("root")
        if versioned is ABSENT:
            return RootBase(None, None, ABSENT)
        return RootBase(versioned.value, h(versioned.value), versioned.token)

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
        if row != (base.digest,):
            raise RootChanged(f"{label} is not based on the current root")
        return base

    @staticmethod
    def plan(change, base, admitted=()):
        return PublicationPlan(
            *change, tuple(sorted(set(admitted))), base.root, base.token)

    def _result(self, root, admitted, outcome):
        return PublicationResult(
            self.workspace,
            root,
            tuple(sorted(set(admitted))),
            outcome,
        )

    def dirty(self, base):
        """Remember the publication base before catalog state moves ahead."""
        idx = self.node.idx(self.workspace)
        idx.execute(
            "INSERT OR REPLACE INTO meta VALUES('publish-base', ?)",
            (base.digest,))
        idx.execute("DELETE FROM meta WHERE k='root'")

    def same_snapshot_envelope(self, raw):
        """Whether foreign root bytes retain every known snapshot binding."""
        previous = self.node.idx(self.workspace).execute(
            "SELECT v FROM meta WHERE k='root-bytes'").fetchone()
        try:
            old, foreign = json.loads(previous[0]), json.loads(raw)
            return all(
                old.get(key) == foreign.get(key)
                for key in ("anchor", "layout_seed", "maps"))
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

    def publish(self, settlement, *, reuse=True):
        """Publish ordinary local/repair state without retirement authority."""
        return self._publish(settlement, reuse=reuse)

    def _publish_ingress(self, admission, *, reuse=True):
        """Publish one already-bound admission and bind the exact result."""
        from .ingress import check_source

        if admission.workspace != self.workspace:
            raise ValueError("publication ingress workspace")
        binding = check_source(admission.source, admission.raw)
        if admission.payload != h(admission.raw):
            raise ValueError("publication ingress payload")
        if admission.generation != binding.generation:
            raise ValueError("publication ingress generation")
        result = self._publish(admission.settlement, reuse=reuse)
        return PublicationReceipt(
            result.workspace,
            result.root,
            result.admitted,
            result.outcome,
            admission.source,
            admission.payload,
            admission.generation,
            admission.issuer,
        )

    def _publish(self, settlement, *, reuse=True):
        node, ws = self.node, self.workspace
        store, idx = node.store(ws), node.idx(ws)
        forced_rebuild = idx.execute(
            "SELECT 1 FROM meta WHERE k='tree-rebuild'").fetchone() is not None

        # A rootless store may retain locally admitted litter, but no reader
        # can accept a snapshot that does not contain its anchor.
        if idx.execute(
                "SELECT 1 FROM proofs WHERE fid=?", (ws,)).fetchone() is None:
            if settlement.base_root is None:
                if store.read_versioned("root") is not ABSENT:
                    raise RootChanged(
                        "root changed during rootless publication")
                self.stamp(None, settlement.received)
            return self._result(
                None, settlement.admitted, "rootless")

        changed = settlement.activated
        deactivated = set(settlement.deactivated)
        changed_sids = settlement.changed_sids
        previous_root = settlement.base_root

        def emit(raw):
            oid = h(raw)
            ensure_object(store, oid, raw)
            return oid

        objects = {}

        def fetch(oid):
            if oid not in objects:
                objects[oid] = store.get("obj/" + oid)
            return objects[oid]

        previous = None
        if previous_root:
            try:
                previous = snapshot.decode_root(previous_root)
            except ValueError:
                pass
            if previous is not None and previous.anchor != ws:
                raise ValueError("root anchor")
        tree_incremental = reuse and not forced_rebuild \
            and previous is not None and previous_root is not None
        candidate_changes = tuple(sorted(set(
            settlement.received
            + settlement.activated
            + settlement.deactivated
            + settlement.updated
            + settlement.witnesses
        )))
        candidate_fids = candidate_changes if tree_incremental else \
            node.catalog(ws).publication_ids(settlement.received)
        built_indexes = indexes.build(
            ws, idx, emit,
            previous={
                name: previous.maps[name]
                for name in indexes.TREE_NAMES
            } if previous else {},
            fetch=fetch,
            changed_fids=candidate_changes if tree_incremental else None,
            changed_sids=changed_sids if tree_incremental else (),
            candidate_fids=candidate_fids)
        seed, trees = built_indexes.seed, built_indexes.trees
        must_compile = set(
            settlement.received + settlement.witnesses)
        represented = set(built_indexes.represented)
        if tree_incremental:
            # Exact duplicate/higher-witness Valids already reside in the
            # pinned authorized base. New candidates and winning witness joins
            # may never claim that induction step: this build must emit them.
            represented.update(set(settlement.admitted) - must_compile)
        if not set(settlement.admitted) <= represented \
                or not must_compile <= set(built_indexes.represented):
            raise ValueError("publication omitted admitted candidate")

        if tree_incremental:
            order_changes = []
            for fid in sorted(set(changed)):
                fact = node.fact_of(ws, fid)
                if fact is None:
                    raise ValueError("missing activated fact")
                order_changes.append((fact.key, h(encode_fact(fact))))
            for fid in sorted(deactivated):
                fact = node.candidate_of(ws, fid)
                if fact is None:
                    raise ValueError("missing deactivated fact")
                order_changes.append((fact.key, None))
            fact_order = snapshot.update_fact_order(
                previous.maps[snapshot.FACT_ORDER],
                tuple(order_changes),
                seed,
                fetch,
                emit,
            ) if order_changes else previous.maps[snapshot.FACT_ORDER]
        else:
            rows = []
            for address in node.keys(ws):
                fact = node.fact_of(ws, fid_of(address))
                if fact is None or fact.key != address:
                    raise ValueError("missing eligible fact")
                rows.append((address, h(encode_fact(fact))))
            fact_order = snapshot.build_fact_order(rows, seed, emit)

        root = snapshot.encode_root(
            ws,
            {
                snapshot.FACT_ORDER: fact_order,
                **trees,
            },
            seed=seed,
        )
        if root == settlement.base_root:
            current = store.read_versioned("root")
            if current is ABSENT \
                    or current.token != settlement.base_token \
                    or current.value != settlement.base_root:
                raise RootChanged("root changed during publication")
            self.stamp(root, settlement.received)
            return self._result(
                root, settlement.admitted, "noop")
        unknown = None
        outcome = None
        for _ in range(2):
            try:
                result = store.cas(
                    "root", settlement.base_token, root)
            except OutcomeUnknown as error:
                unknown = error
            else:
                if isinstance(result, Applied):
                    outcome = "applied"
                    break
                if result is not STALE:
                    raise TypeError("conditional-replace result")
            current = store.read_versioned("root")
            if isinstance(current, Versioned) and current.value == root:
                outcome = "confirmed"
                break
            if current is ABSENT:
                current_root, current_token = None, ABSENT
            else:
                current_root, current_token = current.value, current.token
            if current_root != settlement.base_root \
                    or current_token != settlement.base_token:
                raise RootChanged("root changed during publication")
        else:
            raise unknown or RootChanged("root changed during publication")
        self.stamp(root, settlement.received)
        return self._result(
            root, settlement.admitted, outcome)
