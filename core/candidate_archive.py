"""Database-free reads and full verification of the admitted candidate set.

``CandidateView`` is the authenticated point/range surface used by action and
candidate-witness sync and cold Workers. ``reconstruct`` is the maintenance
path: it walks only
objects reachable from one authenticated root, proves residence and generic
posting completeness, reruns the current kernel over the eligible set, and
reruns each selected historical admission witness.
"""
from dataclasses import dataclass

import facts

from . import admission_proof, btreap, indexes, manifest, settlement
from .crypto import h
from .fact import canon, decode, encode
from .object_store import verified_object
from .shape import valid_fid


@dataclass(frozen=True)
class Archive:
    workspace: str
    root: object
    records: dict
    facts: dict
    receipt_proofs: tuple


class CandidateView:
    """Authenticated point reads over canonical candidate residences."""

    def __init__(self, root_bytes, fetch):
        self._root_bytes = root_bytes
        self.root = manifest.decode_root(root_bytes)
        if self.root.layout_seed != indexes.layout_seed(self.root.anchor):
            raise ValueError("composite layout seed")
        if not self.root.manifest or not all(
                self.root.trees[name]["root"] for name in indexes.TREE_NAMES):
            raise ValueError("candidate archive is incomplete")
        self._source_fetch = fetch
        self._objects = {}
        self._object_fetches = 0
        self._object_bytes = 0
        self._facts = {}
        self._records = {}

    def fetch(self, oid):
        """Cache immutable reads so one proof DAG never refetches a page."""
        if oid not in self._objects:
            raw = self._source_fetch(oid)
            self._objects[oid] = raw
            self._object_fetches += 1
            if isinstance(raw, bytes):
                self._object_bytes += len(raw)
        return self._objects[oid]

    def _reader(self, name):
        descriptor = self.root.trees[name]
        return btreap.Reader(
            descriptor["root"], self.root.layout_seed, self.fetch,
            max_page_depth=descriptor["depth"])

    def fact_record(self, fid):
        if not valid_fid(fid):
            raise ValueError("candidate fid")
        if fid not in self._records:
            row = self._reader(indexes.FACT).get(indexes.fact_key(fid))
            if row is None:
                raise ValueError("missing FactRecord")
            self._records[fid] = indexes.checked_fact_record(row, fid)
        return self._records[fid]

    def fact(self, fid):
        if fid in self._facts:
            return self._facts[fid]
        record = self.fact_record(fid)
        raw = verified_object(record["fact_oid"], self.fetch)
        fact = decode(raw)
        if encode(fact) != raw:
            raise ValueError("candidate residence encoding")
        if fact.fid != fid or fact.key != record["key"]:
            raise ValueError("candidate residence identity")
        self._facts[fid] = fact
        return fact

    def verify(self, fid, proof_oid=None, *, budget=None):
        """Verify one witness with a genuinely cold per-proof read budget."""
        cold = CandidateView(self._root_bytes, self._source_fetch)
        return cold._verify(fid, proof_oid, budget=budget)

    def _verify(self, fid, proof_oid=None, *, budget=None):
        budget = admission_proof.VerificationBudget() \
            if budget is None else budget
        if not isinstance(budget, admission_proof.VerificationBudget):
            raise TypeError("admission proof budget")
        before_fetches = self._object_fetches
        before_bytes = self._object_bytes
        record = self.fact_record(fid)
        budget.charge_io(
            self._object_fetches - before_fetches,
            self._object_bytes - before_bytes,
        )
        proof_oid = record["admission"] if proof_oid is None else proof_oid
        def metered_fact(source):
            before_fetches = self._object_fetches
            before_bytes = self._object_bytes
            fact = self.fact(source)
            budget.charge_io(
                self._object_fetches - before_fetches,
                self._object_bytes - before_bytes,
            )
            return fact

        return admission_proof.verify(
            self.root.anchor, fid, proof_oid, metered_fact, self.fetch,
            budget=budget, fact_reads_metered=True)

    def candidate_ids(self):
        """Enumerate the one authenticated FactRecord row per candidate.

        This correctness-first maintenance range lets reconciliation join
        selected witnesses for eligible and dormant candidates. It neither
        walks object-store LIST nor amplifies one candidate into every generic
        posting it contributes.
        """
        reader = self._reader(indexes.FACT)
        start, stop = "fact:", "fact:\uffff"
        cursor, fids, seen = None, [], set()
        while True:
            page = reader.range_page(
                start, stop, after=cursor, limit=btreap.MAX_RANGE_ROWS)
            for key, value in page.rows:
                fid = key[len("fact:"):]
                if indexes.fact_key(fid) != key or fid in seen:
                    raise ValueError("candidate FactRecord key")
                indexes.checked_fact_record(value, fid)
                fids.append(fid)
                seen.add(fid)
            if len(fids) > self.root.trees[indexes.FACT]["count"]:
                raise ValueError("candidate FactRecord count")
            cursor = page.cursor
            if cursor is None:
                break
        return tuple(fids)

    def dormant_ids(self):
        """Compatibility maintenance view over the canonical record range."""
        return tuple(
            fid for fid in self.candidate_ids()
            if self.fact_record(fid)["state"] == "dormant"
        )


def _tree_rows(view, name):
    descriptor = view.root.trees[name]
    if btreap.root_metadata(
            descriptor["root"], view.root.layout_seed, view.fetch) != (
                descriptor["count"], descriptor["depth"]):
        raise ValueError(f"{name} descriptor metadata")
    reader = view._reader(name)
    rows = reader.items(max_pages=descriptor["count"])
    if len(rows) != descriptor["count"] \
            or reader.pages_read != descriptor["count"]:
        raise ValueError(f"{name} descriptor count")
    return rows


def _candidate_records(rows):
    records = {}
    for key, value in rows:
        if not key.startswith("fact:"):
            continue
        fid = key[len("fact:"):]
        if indexes.fact_key(fid) != key or fid in records:
            raise ValueError("FactRecord key")
        records[fid] = indexes.checked_fact_record(value, fid)
    return records


def _canonical_projection(workspace, records, facts_by_fid):
    projected = settlement.project(workspace, facts_by_fid)
    for fid, record in records.items():
        standing = projected.standing.get(fid)
        expected_state = "eligible" if standing is not None else "dormant"
        if record["state"] != expected_state:
            raise ValueError("noncanonical candidate eligibility")
        if standing is None:
            if record["rank"] is not None:
                raise ValueError("dormant FactRecord state")
            continue
        rank, edges = standing
        if record["rank"] != rank or record["dependencies"] != [
                [edge.role, edge.fid, edge.kind] for edge in edges]:
            raise ValueError("eligible FactRecord judgment")
    return projected


def _check_record_projection(records, facts_by_fid):
    def edges_of(fid):
        return {
            role: parent
            for role, parent, _ in records[fid]["dependencies"]
        }

    for fid, record in records.items():
        fact = facts_by_fid[fid]
        selectors = sorted(facts.fact_scopes(fact))
        liveness = sorted(
            set(facts.authority_scopes(
                fact, edges_of, facts_by_fid.get))
            - set(selectors)
        )
        if record["key"] != fact.key \
                or record["offers"] != [
                    list(offer) for offer in fact.offers()
                ] \
                or record["selectors"] != selectors \
                or record["liveness"] != liveness:
            raise ValueError("FactRecord projection")


def _derived_rows(projected, records, facts_by_fid):
    def slot(sid):
        action = projected.actions.get(sid)
        return {"state": "clear"} if action is None else {
            "state": "active", "action": action}

    fact_actions, supp = {}, {}
    for fid in projected.standing:
        fact, record = facts_by_fid[fid], records[fid]
        for sid in record["selectors"]:
            supp[sid] = slot(sid)
        family = facts.family_for(fact.t)
        policy = family.POLICY if family is not None else None
        if policy is not None and policy.direct_targets:
            sid = indexes.fact_key(fid)
            fact_actions[indexes.action_key(sid)] = slot(sid)
        for sid in facts.principal_sids(fact):
            fact_actions[indexes.action_key(sid)] = slot(sid)
            supp[sid] = slot(sid)

    action_rows = []
    for sid, fid in sorted(projected.actions.items()):
        record = records[fid]
        if record["state"] != "eligible" \
                or sid not in facts.action_sids(facts_by_fid[fid]):
            raise ValueError("action evidence binding")
        active = {"state": "active", "action": fid}
        supp[sid] = active
        fact_actions[indexes.action_key(sid)] = active
        action_rows.append((sid, fid, record["admission"]))

    choices = {}
    for fid, (rank, _) in projected.standing.items():
        for name, a0, a1 in facts_by_fid[fid].offers():
            if name in indexes.INTERNAL_INDEXES:
                raise ValueError("reserved authority offer")
            for address in ((name, a0, a1), (name, a0, None)):
                choices.setdefault(address, []).append((rank, fid))
    authority = {}
    for address, candidates in choices.items():
        rank, fid = min(candidates)
        authority[indexes.need_key(*address)] = {
            "state": "provider", "fid": fid, "rank": rank}
    action_etag = h(canon(["active-actions-v1", action_rows]))
    return fact_actions, supp, authority, action_etag


def reconstruct(root_bytes, fetch):
    """Verify and return the complete root-reachable candidate archive."""
    view = CandidateView(root_bytes, fetch)
    fact_rows = _tree_rows(view, indexes.FACT)
    # The other descriptors are part of the same root CAS. Full traversal is
    # maintenance-only, but proves their advertised count/depth metadata before
    # this snapshot is allowed to seed a new publisher.
    supp_rows = _tree_rows(view, indexes.SUPP)
    authority_rows = _tree_rows(view, indexes.AUTHORITY)
    records = _candidate_records(fact_rows)
    if not records or view.root.anchor not in records:
        raise ValueError("candidate archive anchor")

    entries = manifest.decode(
        verified_object(view.root.manifest, fetch), fetch)
    ranged = {}
    for entry in entries:
        for fact in manifest.range_members(
                entry, fetch, view.root.anchor):
            if fact.fid in ranged:
                raise ValueError("duplicate eligible residence")
            ranged[fact.fid] = fact
    expected_eligible = {
        fid for fid, record in records.items()
        if record["state"] == "eligible"
    }
    if set(ranged) != expected_eligible:
        raise ValueError("candidate residence partition")

    facts_by_fid = dict(ranged)
    view._facts.update(ranged)
    for fid in records:
        facts_by_fid[fid] = view.fact(fid)
    if any(
            (family := facts.family_for(fact.t)) is None
            or not family.DURABLE
            for fact in facts_by_fid.values()):
        raise ValueError("store contains an ephemeral fact")
    _check_record_projection(records, facts_by_fid)
    projected = _canonical_projection(
        view.root.anchor, records, facts_by_fid)
    current_edges = {
        fid: tuple(edge.fid for edge in edges)
        for fid, (_, edges) in projected.standing.items()
    }
    rebuilt_manifest = manifest.build(
        sorted(fact.key for fact in ranged.values()),
        ranged.__getitem__,
        current_edges.__getitem__,
        lambda raw: None,
    )[1]
    if rebuilt_manifest != view.root.manifest:
        raise ValueError("eligible RangeTree placement")

    expected_postings = {}
    for fid, record in records.items():
        value = {
            "state": indexes.POSTING_VALUE,
            "fid": fid,
            "eligibility": record["state"],
        }
        expected_postings.update({
            key: value
            for key in indexes.record_postings(
                facts_by_fid[fid], record)
        })
    fact_actions, expected_supp, expected_authority, action_etag = \
        _derived_rows(projected, records, facts_by_fid)
    expected_fact = {
        indexes.fact_key(fid): record for fid, record in records.items()}
    expected_fact.update(expected_postings)
    expected_fact.update(fact_actions)
    if dict(fact_rows) != expected_fact:
        raise ValueError("FactTree projection")
    if dict(supp_rows) != expected_supp:
        raise ValueError("SuppTree projection")
    if dict(authority_rows) != expected_authority:
        raise ValueError("AuthorityTree projection")
    if view.root.action_etag != action_etag:
        raise ValueError("action etag projection")

    receipt_proofs = {}
    for fid, record in records.items():
        # Each selected proof must fit its own genuinely cold read budget;
        # warm pages from an earlier candidate cannot bless a later one.
        verified = CandidateView(root_bytes, fetch).verify(fid)
        receipts = {
            receipt.fact.fid: receipt
            for receipt in verified.valids
        }
        root_receipt = receipts.get(fid)
        if root_receipt is None:
            raise ValueError("admission proof root receipt")
        if record["state"] == "dormant" \
                and record["dependencies"] != [
                    [edge.role, edge.fid, edge.kind]
                    for edge in root_receipt.edges]:
            raise ValueError("FactRecord admission edges")
        receipt_proofs[fid] = (root_receipt, record["admission"])

    return Archive(
        view.root.anchor,
        view.root,
        records,
        facts_by_fid,
        tuple(receipt_proofs[fid] for fid in sorted(receipt_proofs)),
    )
