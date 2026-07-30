"""One socket-free client workspace turn.

Authority flows in one direction:

    ingress bytes -> kernel judgment -> catalog settlement -> root CAS
                  -> ingress retirement

The daemon and local commands both enter here. Transport never gains a second
admission path, and the database-free Worker remains entirely separate.
"""
import facts

from .close import close, encode_pile
from .ingress import PermanentIngressRejection, stage_pile
from .kernel import resolve_deps


class AuthorityRejected(ValueError):
    """A valid immutable fact lacks current canonical authority."""


class WorkspaceRuntime:
    """A workspace-bound coordinator; it owns ordering, not policy."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace

    def _reject(self, source, raw, error):
        """Quarantine one exact, permanently invalid ingress object."""
        node, ws = self.node, self.workspace
        try:
            node.admission(ws).reject(source, raw, error)
        except Exception as quarantine_error:
            node.record_ingress_attempt_failure(
                ws, source, quarantine_error)
        else:
            node.clear_ingress_attempt_failure(ws, source)

    def turn(self):
        node, ws = self.node, self.workspace
        with node.lock:
            store = node.store(ws)
            membrane = node.admission(ws)
            piles = store.list("pile/")
            # LIST is part of the conforming authoritative-store contract.
            # Absence here does not retire anything; it only proves that a
            # shared winner already discharged this node's local diagnostic.
            node.reconcile_ingress_attempt_failures(ws, piles)
            membrane.reconcile(piles)
            if not piles:
                if node.catalog(ws).staged_ids():
                    membrane.publish()
                return []
            fresh_all = []
            for source in piles:
                raw = None
                try:
                    raw = store.get(source)
                except PermanentIngressRejection as error:
                    self._reject(source, raw, error)
                    continue
                except Exception as error:
                    node.record_ingress_attempt_failure(
                        ws, source, error)
                    continue
                if raw is None:
                    continue
                pending = membrane.pending(source, raw)
                if pending is not None:
                    try:
                        membrane.retire(source, raw, pending)
                    except Exception as error:
                        node.record_ingress_attempt_failure(
                            ws, source, error)
                    else:
                        node.clear_ingress_attempt_failure(ws, source)
                    continue
                try:
                    processed = membrane.process(source, raw)
                except PermanentIngressRejection as error:
                    self._reject(source, raw, error)
                    continue
                except Exception as error:
                    try:
                        membrane.restore()
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
                if processed.receipt is None:
                    node.clear_ingress_attempt_failure(ws, source)
                    continue
                try:
                    membrane.retire(
                        source, raw, processed.receipt)
                except Exception as error:
                    node.record_ingress_attempt_failure(
                        ws, source, error)
                    continue
                node.clear_ingress_attempt_failure(ws, source)
                fresh_all.extend(processed.valids)
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

            raw = encode_pile(
                close(news, deps_of, fact_of), blobs, workspace=ws)
            source = stage_pile(
                node.store(ws), node.member_for(ws), raw)
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
