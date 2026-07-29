"""One socket-free client workspace turn.

Authority flows in one direction:

    ingress bytes -> kernel judgment -> catalog settlement -> root CAS
                  -> ingress retirement

The daemon and local commands both enter here. Transport never gains a second
admission path, and the database-free Worker remains entirely separate.
"""
import facts

from .close import close, decode_pile, encode_pile
from .crypto import h
from .ingress import KernelRejected, PermanentIngressRejection
from .kernel import drain, resolve_deps
from .object_store import ensure_object


class AuthorityRejected(ValueError):
    """A valid immutable fact lacks current canonical authority."""


class WorkspaceRuntime:
    """A workspace-bound coordinator; it owns ordering, not policy."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def turn(self):
        node, ws = self.node, self.workspace
        with node.lock:
            store = node.store(ws)
            piles = store.list("pile/")
            # LIST is part of the conforming authoritative-store contract.
            # Absence here does not retire anything; it only proves that a
            # shared winner already discharged this node's local diagnostic.
            node.reconcile_ingress_attempt_failures(ws, piles)
            if not piles:
                if node.catalog(ws).staged_ids():
                    node.commit(ws)
                return []
            fresh_all = []
            for source in piles:
                raw = None
                try:
                    raw = store.get(source)
                    stream, blobs = decode_pile(raw)
                    judgment = drain(stream, ws)
                    if not judgment.ok:
                        if judgment.failure is not None:
                            raise judgment.failure
                        raise KernelRejected("ingress rejected")
                except PermanentIngressRejection as error:
                    try:
                        node._quarantine_ingress(
                            ws, source, raw, error)
                    except Exception as quarantine_error:
                        node.record_ingress_attempt_failure(
                            ws, source, quarantine_error)
                    else:
                        node.clear_ingress_attempt_failure(ws, source)
                    continue
                except Exception as error:
                    node.record_ingress_attempt_failure(
                        ws, source, error)
                    continue
                try:
                    node._sync_index(ws)
                    settlement = node.merge(
                        ws, (valid.fact for valid in judgment.valids),
                        allowed_staged={
                            valid.fact.fid for valid in judgment.valids})
                    valids = tuple(
                        valid for valid in judgment.valids
                        if node.fact_of(ws, valid.fact.fid) is not None)
                    for oid, blob in blobs.items():
                        ensure_object(store, oid, blob)
                    node.commit(ws, settlement)
                except Exception as error:
                    try:
                        node._restore_authoritative_state(ws)
                    except Exception as restore_error:
                        node.record_ingress_attempt_failure(
                            ws, source,
                            RuntimeError(
                                f"{type(error).__name__}: {error}; "
                                "authoritative restore failed: "
                                f"{type(restore_error).__name__}: "
                                f"{restore_error}"))
                        raise restore_error from error
                    node.record_ingress_attempt_failure(
                        ws, source, error)
                    continue
                try:
                    node._retire_ingress_exact(ws, source, raw)
                except Exception as error:
                    node.record_ingress_attempt_failure(
                        ws, source, error)
                    continue
                node.clear_ingress_attempt_failure(ws, source)
                fresh_all.extend(valids)
            return fresh_all

    def ingest(self, news, deps_new, blobs=None):
        """Close locally authored facts, enqueue them, and run one turn."""
        node, ws = self.node, self.workspace
        with node.lock:
            idx = node.idx(ws)
            newmap = {fact.fid: fact for fact in news}

            def fact_of(fid):
                return newmap.get(fid) or node.fact_of(ws, fid)

            def deps_of(fid):
                if fid in deps_new:
                    return deps_new[fid]
                return resolve_deps(fact_of(fid), idx) or []

            raw = encode_pile(close(news, deps_of, fact_of), blobs)
            source = f"pile/{node.member_for(ws)}/{h(raw)}"
            node.store(ws).put_if_absent(source, raw)
            fresh = self.turn()
            missing = [
                fact.fid for fact in news
                if facts.family_for(fact.t).DURABLE
                and node.fact_of(ws, fact.fid) is None
            ]
            if missing:
                attempt_error = node.ingress_attempt_error(ws, source)
                if attempt_error is not None:
                    raise attempt_error
                sample = ", ".join(sorted(missing)[:3])
                error = (
                    f"authored facts are outside the canonical set: {sample}")
                # A retained candidate passed the immutable kernel but lost
                # current authority/eligibility. Surface that as a permission
                # failure to the local control plane; malformed facts never
                # enter the catalog and remain ordinary bad requests.
                if any(node.candidate_of(ws, fid) is not None
                       for fid in missing):
                    raise AuthorityRejected(error)
                raise ValueError(error)
            return fresh
