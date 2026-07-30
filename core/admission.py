"""Workspace-bound admission and ingress-retirement authority.

Authority flows through one membrane:

    exact pile -> kernel -> historical proof -> catalog settlement
               -> root CAS result -> exact retirement capability

``Node`` supplies workspace resources.  ``WorkspaceRuntime`` owns turn
ordering and calls :meth:`AdmissionMembrane.process` once per live pile.
Neither transport nor cold synchronization gets a second durable entrance.
"""
from dataclasses import dataclass
from typing import NamedTuple

import facts

from . import admission_proof, catalog, ingress, suppression_state
from .close import decode_pile
from .crypto import h
from .ingress import (
    KernelRejected,
    check_source,
    preserve_rejection,
)
from .kernel import drain
from .object_store import ensure_object
from .publication import PublicationReceipt, Publisher


class Admission(NamedTuple):
    """One successful kernel judgment and its unpublished settlement."""

    settlement: object
    valids: tuple


class ProcessedIngress(NamedTuple):
    """One published pile, ready for exact retirement."""

    valids: tuple
    receipt: PublicationReceipt | None


@dataclass(frozen=True, slots=True)
class _BoundAdmission:
    """One exact pile judgment allowed to request a publication receipt."""

    settlement: object
    valids: tuple
    source: str
    raw: bytes
    blobs: tuple


class AdmissionMembrane:
    """The sole durable fact entrance for one workspace."""

    def __init__(self, node, workspace):
        self.node = node
        self.workspace = workspace
        self._issuer = object()
        # One live capability per exact ingress generation.  Replacing by key
        # prevents repeated polls from accumulating equivalent no-op receipts.
        self._bounds = {}
        self._receipts = {}

    def reject(self, source, raw, error):
        """Preserve a permanent rejection, then retire its exact source."""
        receipt = preserve_rejection(
            self.node.store(self.workspace), source, raw, error)
        return self._retire_rejected(source, raw, receipt)

    def _retire_rejected(self, source, raw, receipt):
        return ingress.retire_rejected(
            self.node.store(self.workspace), source, raw, receipt)

    def pending(self, source, raw):
        """Return this process's exact pending publication capability."""
        return self._receipts.get((source, h(raw)))

    def reconcile(self, live_sources):
        """Forget capabilities whose shared ingress generation is absent."""
        live_sources = set(live_sources)
        for key in tuple(self._bounds):
            if key[0] not in live_sources:
                self._bounds.pop(key)
        for key in tuple(self._receipts):
            if key[0] not in live_sources:
                self._receipts.pop(key)

    def retire(self, source, raw, receipt):
        """Retire an accepted pile under its exact root-CAS result."""
        # Malformed/free-form names fail at the exact-value door before the
        # process-local capability registry is consulted.
        check_source(source, raw)
        key = (source, h(raw))
        registered = self._receipts.get(key)
        if registered is None or registered is not receipt:
            raise ValueError("published ingress capability")
        retired = ingress._retire_published(
            self.node.store(self.workspace),
            self.workspace,
            source,
            raw,
            receipt,
            self._issuer,
        )
        self._receipts.pop(key)
        return retired

    def restore(self):
        """Discard a failed turn's local projection before releasing its lock."""
        self.node.idx(self.workspace).rollback()
        self.node._sync_index(self.workspace)

    def process(self, source, raw):
        """Judge, settle, publish, and register one exact live pile."""
        self.node._sync_index(self.workspace)
        admission = self.admit_ingress(source, raw)
        try:
            valids = tuple(
                valid for valid in admission.valids
                if self.node.fact_of(
                    self.workspace, valid.fact.fid) is not None)
            for oid, blob in admission.blobs:
                ensure_object(self.node.store(self.workspace), oid, blob)
            return ProcessedIngress(
                valids,
                self.commit_ingress(admission),
            )
        finally:
            self._bounds.pop((source, h(raw)), None)

    def admit(
            self, stream, *, base=None, force=False,
            allowed_staged=None):
        """Run the kernel and settle only its exact durable receipts."""
        return self._admit_judgment(
            self._judge(stream),
            base=base,
            force=force,
            allowed_staged=allowed_staged,
        )

    def _judge(self, stream):
        judgment = drain(tuple(stream), self.workspace)
        if judgment.ok:
            return judgment
        if judgment.failure is not None:
            raise judgment.failure
        raise KernelRejected("ingress rejected")

    def admit_ingress(
            self, source, raw, *, base=None, force=False):
        """Decode/judge one exact source value and bind its publication."""
        check_source(source, raw)
        stream, blobs = decode_pile(raw, self.workspace)
        admitted = self._admit_judgment(
            self._judge(stream),
            base=base,
            force=force,
            allowed_staged={fact.fid for fact in stream},
        )
        admission = _BoundAdmission(
            admitted.settlement,
            admitted.valids,
            source,
            raw,
            tuple(sorted(blobs.items())),
        )
        self._bounds[(source, h(raw))] = admission
        return admission

    def _admit_judgment(
            self, judgment, *, base=None, force=False,
            allowed_staged=None):
        """Build retained proofs for one immediate kernel judgment."""
        publisher = Publisher(self.node, self.workspace)
        base = publisher.base() if base is None else base
        store = self.node.store(self.workspace)

        def emit(raw):
            oid = h(raw)
            ensure_object(store, oid, raw)
            return oid

        proofs = admission_proof.build(
            self.workspace, judgment.valids, emit)
        receipt_proofs = tuple(
            (receipt, proofs[receipt.fact.fid])
            for receipt in judgment.valids
            if facts.family_for(receipt.fact.t).DURABLE
        )
        return self._settle_verified(
            receipt_proofs,
            judgment.valids,
            base,
            force=force,
            allowed_staged=allowed_staged,
        )

    def _settle_verified(
            self, receipt_proofs, valids, base, *, force=False,
            allowed_staged=None):
        """Settle already-kernel-verified receipts and their proof oids."""
        node, ws = self.node, self.workspace
        publisher = Publisher(node, ws)
        idx, newfids = node.idx(ws), []
        witness_changes = set()
        admitted = node.catalog(ws)
        idx.execute("BEGIN")
        try:
            actions_dirty = False
            for receipt, proof_oid in receipt_proofs:
                fact = receipt.fact
                family = facts.family_for(fact.t)
                if family is None or not family.DURABLE:
                    raise ValueError("non-durable admission receipt")
                stored = admitted._admit_valid(receipt, proof_oid)
                if stored.staged:
                    newfids.append(fact.fid)
                if stored.witness_changed:
                    witness_changes.add(fact.fid)
                idx.executemany(
                    "INSERT OR IGNORE INTO supp VALUES(?,?)",
                    (
                        (fact.fid, sid)
                        for sid in sorted(facts.fact_scopes(fact))
                    ),
                )
                if facts.action_sids(fact):
                    actions_dirty = actions_dirty or stored.staged
                    suppression_state.archive(idx, fact)
            witness_changes.difference_update(newfids)
            force = force or (
                not newfids
                and not admitted.has_eligible()
                and idx.execute(
                    "SELECT 1 FROM facts LIMIT 1").fetchone() is not None
            )
            change = admitted.settle(
                newfids,
                force=force,
                actions_dirty=actions_dirty,
                allowed_staged=allowed_staged,
            ) if newfids or force or actions_dirty else \
                catalog.Eligibility((), (), (), (), (), ())
            if force:
                staged = node.catalog(ws).staged_ids()
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
                node._invalidate_sync_cache(ws)
            publisher.dirty(base)
            idx.commit()
            admitted_fids = tuple(
                receipt.fact.fid for receipt, _ in receipt_proofs)
            return Admission(
                publisher.plan(change, base, admitted_fids),
                tuple(valids),
            )
        except Exception:
            idx.rollback()
            raise

    def publish(
            self, settlement=None, *, reuse=True, _base=None):
        """Compile/publish staged state without ingress-retirement authority."""
        node, ws = self.node, self.workspace
        idx = node.idx(ws)
        publisher = Publisher(node, ws)
        if settlement is None:
            base = publisher.base(pending=True) if _base is None else _base
            try:
                staged = node.catalog(ws).staged_ids()
                publisher.dirty(base)
                change = node.catalog(ws).settle(
                    staged, force=True, actions_dirty=True)
                change = change._replace(
                    received=tuple(staged),
                )
                idx.commit()
                settlement = publisher.plan(change, base)
            except Exception:
                idx.rollback()
                raise
        return publisher.publish(settlement, reuse=reuse).root

    def commit_ingress(self, admission, *, reuse=True):
        """Publish one bound judgment and mint exact retirement authority."""
        if not isinstance(admission, _BoundAdmission):
            raise TypeError("bound ingress admission")
        key = (admission.source, h(admission.raw))
        if self._bounds.get(key) is not admission:
            raise ValueError("bound ingress capability")
        binding = check_source(admission.source, admission.raw)
        self._bounds.pop(key)
        durable = tuple(sorted(
            valid.fact.fid
            for valid in admission.valids
            if (family := facts.family_for(valid.fact.t)) is not None
            and family.DURABLE
        ))
        if admission.settlement.admitted != durable:
            raise ValueError("publication admission binding")
        result = Publisher(
            self.node, self.workspace
        ).publish(admission.settlement, reuse=reuse)
        if result.root is None or result.outcome == "rootless":
            # A rootless settlement is retained local state, not publication
            # evidence.  Leave the pile live and retry it after an anchor
            # arrives; never wedge it behind an unusable pending receipt.
            return None
        receipt = PublicationReceipt(
            self.workspace,
            result.root,
            result.admitted,
            result.outcome,
            admission.source,
            key[1],
            binding.generation,
            self._issuer,
        )
        self._receipts[key] = receipt
        return receipt
