"""Pure admitted-candidate join to one canonical repository snapshot.

There is no storage or actor state in this module.  Given the same workspace,
facts, and selected historical admission witnesses it emits the same immutable
objects and four-map root regardless of whether the caller is a full P2P node,
an AWS Lambda, or a Cloudflare Worker.
"""
from collections import defaultdict
from dataclasses import dataclass

import facts

from . import indexes, merkle_map, settlement, snapshot
from .crypto import h
from .fact import bound_to, encode
from .fact_index import INTERNAL_INDEXES
from .kernel import ResolvedEdge, valid_resolved_edges
from .shape import valid_fid


@dataclass(frozen=True, slots=True)
class Candidate:
    """One admitted fact and its selected complete historical witness."""

    fact: object
    admission: str
    admission_edges: tuple


@dataclass(frozen=True, slots=True)
class CompiledSnapshot:
    """Canonical root proposal and every immutable object it emits."""

    root: bytes | None
    outbox: tuple
    records: dict
    projection: settlement.Projection


def _checked_candidate(anchor, fid, candidate):
    if not isinstance(candidate, Candidate) \
            or candidate.fact.fid != fid \
            or not bound_to(candidate.fact, anchor) \
            or not valid_fid(candidate.admission) \
            or not valid_resolved_edges(
                tuple(edge.fid for edge in candidate.admission_edges),
                candidate.admission_edges):
        raise ValueError("repository candidate")
    family = facts.family_for(candidate.fact.t)
    if family is None or not family.DURABLE:
        raise ValueError("repository candidate durability")
    return candidate


def candidate_records(anchor, candidates, projection=None):
    """Derive the one canonical FactRecord for every admitted candidate."""
    if not valid_fid(anchor) or not isinstance(candidates, dict):
        raise ValueError("repository candidates")
    checked = {
        fid: _checked_candidate(anchor, fid, candidate)
        for fid, candidate in sorted(candidates.items())
    }
    by_fid = {fid: candidate.fact for fid, candidate in checked.items()}
    projection = settlement.project(anchor, by_fid) \
        if projection is None else projection

    dependencies = {}
    for fid, candidate in checked.items():
        standing = projection.standing.get(fid)
        edges = candidate.admission_edges if standing is None else standing[1]
        dependencies[fid] = tuple(edges)

    def edges_of(fid):
        return {
            edge.role: edge.fid
            for edge in dependencies.get(fid, ())
        }

    records = {}
    for fid, candidate in checked.items():
        fact = candidate.fact
        standing = projection.standing.get(fid)
        state = "eligible" if standing is not None else "dormant"
        rank = standing[0] if standing is not None else None
        selectors = sorted(facts.fact_scopes(fact))
        liveness = sorted(
            set(facts.authority_scopes(fact, edges_of, by_fid.get))
            - set(selectors)
        )
        raw = encode(fact)
        records[fid] = indexes.checked_fact_record({
            "admission": candidate.admission,
            "dependencies": [
                [edge.role, edge.fid, edge.kind]
                for edge in dependencies[fid]
            ],
            "fact_oid": h(raw),
            "key": fact.key,
            "liveness": liveness,
            "offers": [list(offer) for offer in fact.offers()],
            "rank": rank,
            "selectors": selectors,
            "state": state,
        }, fid)
    return records, projection


def derived_rows(projection, records, facts_by_fid):
    """Derive FactTree action slots plus SuppTree and AuthorityTree rows."""
    def slot(sid):
        action = projection.actions.get(sid)
        return {"state": "clear"} if action is None else {
            "state": "active", "action": action}

    fact_actions, supp = {}, {}
    # Retention reserves the key universe.  A candidate may be dormant today
    # and regain standing later, so every family-declared selector/principal
    # remains an authenticated CLEAR/ACTIVE slot even while that candidate is
    # absent from FactOrder and AuthorityTree.
    for fid in records:
        fact, record = facts_by_fid[fid], records[fid]
        for sid in record["selectors"]:
            supp[sid] = slot(sid)
        policy = facts.family_for(fact.t).POLICY
        if policy.direct_targets:
            sid = indexes.fact_key(fid)
            fact_actions[indexes.action_key(sid)] = slot(sid)
        for sid in facts.principal_sids(fact):
            fact_actions[indexes.action_key(sid)] = slot(sid)
            supp[sid] = slot(sid)

    for sid, fid in sorted(projection.actions.items()):
        record = records.get(fid)
        fact = facts_by_fid.get(fid)
        if record is None or fact is None \
                or record["state"] != "eligible" \
                or sid not in facts.action_sids(fact):
            raise ValueError("action evidence binding")
        active = {"state": "active", "action": fid}
        supp[sid] = active
        fact_actions[indexes.action_key(sid)] = active

    choices = defaultdict(list)
    for fid, (rank, _) in projection.standing.items():
        for name, a0, a1 in facts_by_fid[fid].offers():
            if name in INTERNAL_INDEXES:
                raise ValueError("reserved authority offer")
            choices[(name, a0, a1)].append((rank, fid))
            choices[(name, a0, None)].append((rank, fid))
    authority = {}
    for address, candidates in choices.items():
        rank, fid = min(candidates)
        authority[indexes.need_key(*address)] = {
            "state": "provider",
            "fid": fid,
            "rank": rank,
        }
    return fact_actions, supp, authority


def logical_rows(anchor, candidates):
    """Return the complete logical rows from which all four maps are built."""
    records, projection = candidate_records(anchor, candidates)
    facts_by_fid = {
        fid: candidate.fact for fid, candidate in candidates.items()
    }
    fact_rows = {
        indexes.fact_key(fid): record
        for fid, record in records.items()
    }
    for fid, record in records.items():
        value = {
            "state": indexes.POSTING_VALUE,
            "fid": fid,
            "eligibility": record["state"],
        }
        for key in indexes.record_postings(facts_by_fid[fid], record):
            if key in fact_rows:
                raise ValueError("duplicate FactTree row")
            fact_rows[key] = value
    fact_actions, supp_rows, authority_rows = derived_rows(
        projection, records, facts_by_fid)
    for key, value in fact_actions.items():
        incumbent = fact_rows.setdefault(key, value)
        if incumbent != value:
            raise ValueError("conflicting FactTree action slot")
    order_rows = {
        facts_by_fid[fid].key: records[fid]["fact_oid"]
        for fid in projection.standing
    }
    return {
        snapshot.FACT_ORDER: order_rows,
        indexes.FACT: fact_rows,
        indexes.SUPP: supp_rows,
        indexes.AUTHORITY: authority_rows,
    }, records, projection


def compile_snapshot(anchor, candidates):
    """Build one history-independent root and an in-memory immutable outbox."""
    if not candidates:
        return CompiledSnapshot(
            None, (), {}, settlement.Projection({}, {}))
    if anchor not in candidates:
        raise ValueError("repository anchor candidate")
    rows, records, projection = logical_rows(anchor, candidates)
    pending = {}

    def emit(raw):
        oid = h(raw)
        incumbent = pending.setdefault(oid, raw)
        if incumbent != raw:
            raise ValueError("repository object hash collision")
        return oid

    for candidate in candidates.values():
        emit(encode(candidate.fact))
    seed = snapshot.layout_seed(anchor)
    maps = {}
    order = merkle_map.build(
        tuple(rows[snapshot.FACT_ORDER].items()), seed, emit)
    maps[snapshot.FACT_ORDER] = snapshot.descriptor(order)
    for name in indexes.TREE_NAMES:
        built = merkle_map.build(
            tuple(rows[name].items()), seed, emit)
        maps[name] = snapshot.descriptor(built)
    root = snapshot.encode_root(anchor, maps, seed=seed)
    return CompiledSnapshot(
        root,
        tuple(sorted(pending.items())),
        records,
        projection,
    )
