"""Three logical authenticated indexes over the one B-treap codec."""
from collections import defaultdict
import json

import facts

from . import actions, btreap
from .crypto import h
from .fact import canon, from_json

FACT = "fact"
SUPP = "supp"
AUTHORITY = "authority"
TREE_NAMES = (FACT, SUPP, AUTHORITY)
MAX_SELECTORS = 8
MAX_RAW_FACT_BYTES = 64 * 1024


def layout_seed(anchor):
    return h(canon(["composite-layout-seed-v1", anchor]))


def fact_key(fid):
    return "fact:" + fid


def action_key(sid):
    return "action:" + sid


principal_sid = actions.principal_sid


def need_key(name, a0, a1=None, requires=()):
    return canon([
        "need", name, a0, a1,
        sorted([list(row) for row in requires]),
    ]).decode()


def _previous(name, roots, seed, fetch):
    root = roots.get(name, {}).get("root", "") if roots else ""
    return dict(btreap.Reader(root, seed, fetch).items()) if root else {}


def _activate(rows, key, action_fid):
    current = rows.get(key)
    winner = action_fid
    if isinstance(current, dict) and current.get("state") == "active":
        winner = min(winner, current["action"])
    rows[key] = {"state": "active", "action": winner}


def build(anchor, idx, fact_of, emit, *, previous=None, fetch=None):
    """Build Fact/Supp/Authority roots for the same logical commit."""
    seed = layout_seed(anchor)
    previous = previous or {}
    fetch = fetch or (lambda oid: None)
    # Each root is a pure function of its current logical set.  Historical
    # retention belongs to immutable evidence objects, never to a hidden
    # "whatever this replica once saw" row set.
    fact_rows = {}
    supp_rows = {}

    current = [
        fact_of(fid)
        for (fid,) in idx.execute("SELECT fid FROM facts ORDER BY fid")
    ]

    archived_actions, action_rows = {}, []
    for sid, fid, raw, evidence in idx.execute(
            "SELECT sid, fid, j, evidence FROM actions ORDER BY sid"):
        fact = from_json(json.loads(raw))
        if fact.fid != fid or sid not in actions.action_sids(fact):
            raise ValueError("action archive integrity")
        archived_actions[fid] = fact
        action_rows.append((sid, fid))
    action_evidence = dict(idx.execute(
        "SELECT fid, evidence FROM actions ORDER BY fid"))

    def add_fact_record(fact):
        raw = canon(fact.to_json())
        if len(raw) > MAX_RAW_FACT_BYTES:
            raise ValueError("raw fact exceeds authenticated record budget")
        selectors = sorted(actions.fact_scopes(fact))
        if len(selectors) > MAX_SELECTORS:
            raise ValueError("fact selector budget")
        raw_oid = h(raw)
        emitted = emit(raw)
        if emitted is not None and emitted != raw_oid:
            raise ValueError("fact emitter changed object identity")
        edges = dict(idx.execute(
            "SELECT role, dst FROM edges WHERE src=? ORDER BY role",
            (fact.fid,)).fetchall())
        policy = facts.policy_for(fact.t)
        liveness = set(actions.provider_scopes(fact)) - set(selectors)
        if policy is not None:
            for role in policy.authority_liveness_guards:
                provider_fid = edges.get(role)
                provider = fact_of(provider_fid) if provider_fid else None
                if provider is None:
                    raise ValueError("authority liveness edge")
                liveness.update(actions.provider_scopes(provider))
        fact_rows[fact_key(fact.fid)] = {
            "edges": edges,
            "evidence": action_evidence.get(fact.fid, ""),
            "key": fact.key,
            "liveness": sorted(liveness),
            "offers": [list(row) for row in fact.offers()],
            "raw": raw_oid,
            "selectors": selectors,
            "tag": fact.t,
        }
        for sid in selectors:
            supp_rows.setdefault(sid, {"state": "clear"})
        if policy is not None and policy.direct_targets:
            sid = fact_key(fact.fid)
            fact_rows.setdefault(action_key(sid), {"state": "clear"})
        for name, public_key, _ in fact.offers():
            if name == "member":
                sid = principal_sid("member", public_key)
            elif name == "device_key":
                sid = principal_sid("device", public_key)
            else:
                continue
            fact_rows.setdefault(action_key(sid), {"state": "clear"})

    for fact in current:
        add_fact_record(fact)
    for fid, fact in archived_actions.items():
        if fact_key(fid) not in fact_rows:
            add_fact_record(fact)

    for fid, sid in idx.execute("SELECT fid, k FROM supp ORDER BY fid, k"):
        supp_rows.setdefault(sid, {"state": "clear"})

    # Terminal principal slots are independent of provider arrival.  An
    # eviction remains active for future providers with the same public key.
    for name, public_key in idx.execute(
            "SELECT DISTINCT name, a0 FROM offers "
            "WHERE name IN ('member','device_key') ORDER BY name, a0"):
        kind = "member" if name == "member" else "device"
        supp_rows.setdefault(principal_sid(kind, public_key),
                             {"state": "clear"})

    for sid, fid in action_rows:
        _activate(supp_rows, sid, fid)
        _activate(fact_rows, action_key(sid), fid)

    # Authority is current-state, not a grow-only archive.  Previously known
    # NeedKeys remain explicit NO_PROVIDER rows so absence is authenticated.
    authority_rows = {}
    candidates = defaultdict(list)
    for name, a0, a1, src, rank in idx.execute(
            "SELECT o.name, o.a0, o.a1, o.src, p.rank "
            "FROM offers o JOIN proofs p ON p.fid=o.src "
            "ORDER BY p.rank, o.src"):
        candidates[(name, a0, a1)].append((rank, src))
        candidates[(name, a0, None)].append((rank, src))
    for address, choices in candidates.items():
        rank, source = min(choices)
        authority_rows[need_key(*address)] = {
            "state": "provider",
            "fid": source,
            "rank": rank,
        }

    built = {}
    for name, rows in (
            (FACT, fact_rows),
            (SUPP, supp_rows),
            (AUTHORITY, authority_rows)):
        result = btreap.build(tuple(rows.items()), seed, emit)
        built[name] = {
            "root": result.root,
            "count": result.count,
            "depth": result.page_depth,
        }
    return seed, built
