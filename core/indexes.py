"""Exact authenticated read views over the committed fact set.

The range manifest is shaped for reconciliation, not point authorization. A
Worker should not download it, enumerate facts, or reconstruct SQLite merely
to decide whether one principal or fact is live. This module projects the
same admitted snapshot into three maps over the history-independent B-treap:

``FactTree``
    ``fact:<fid>`` maps to the bounded data needed for an exact read: the raw
    object id, resolved named edges, offers, explicit suppression selectors,
    continuing liveness ids, and optional action evidence. ``action:<sid>``
    maps to the same CLEAR/ACTIVE value as SuppTree for known direct and
    principal targets. That second binding is deliberate: sync may enumerate
    active SuppTree entries, but accepts one only when FactTree independently
    binds the same sid-to-action witness.

``SuppTree``
    A typed suppression id maps to ``{"state": "clear"}`` or
    ``{"state": "active", "action": <fid>}``. CLEAR is a positive,
    authenticated reservation saying that this known id has no admitted
    action. It is not a missing row: a missing required slot makes Worker
    authorization fail closed. ACTIVE is monotone and names the canonical
    action fact whose evidence can be reached through FactTree.

``AuthorityTree``
    A canonical base NeedKey maps to the kernel's selected provider and proof
    rank. It lets a Worker check committed authority with one exact path
    instead of trusting whichever provider a request happened to submit.
    Family-required co-offers are then checked against that provider's
    FactRecord; they are not inferred from the request.

All three descriptors are returned together for the composite root's single
CAS. They use an anchor-derived seed, so a logical map has one root independent
of insertion order. The incremental path may only path-copy an additions-only
commit; prune, restore, winner changes, format changes, and direct bulk writes
take the full canonical path. Both paths must produce the same roots for the
same logical maps.
"""
from collections import defaultdict
import json

import facts

from . import btreap, suppression_state
from .crypto import h
from .fact import canon, from_json

FACT = "fact"
SUPP = "supp"
AUTHORITY = "authority"
TREE_NAMES = (FACT, SUPP, AUTHORITY)
MAX_SELECTORS = 8
MAX_RAW_FACT_BYTES = 64 * 1024


def layout_seed(anchor):
    """Pin all three canonical treaps to this workspace, not local history."""
    return h(canon(["composite-layout-seed-v1", anchor]))


def fact_key(fid):
    """FactTree address for a fact's bounded authenticated record."""
    return "fact:" + fid


def action_key(sid):
    """FactTree corroboration slot for one SuppTree action state."""
    return "action:" + sid


principal_sid = suppression_state.principal_sid


def need_key(name, a0, a1=None, requires=()):
    """Canonical authority address; full keys may bind required co-offers."""
    return canon([
        "need", name, a0, a1,
        sorted([list(row) for row in requires]),
    ]).decode()


def _activate(rows, key, action_fid):
    """Monotonically activate a slot with a replica-independent witness."""
    current = rows.get(key)
    winner = action_fid
    if isinstance(current, dict) and current.get("state") == "active":
        winner = min(winner, current["action"])
    rows[key] = {"state": "active", "action": winner}


def build(
        anchor, idx, fact_of, emit, *, previous=None, fetch=None,
        changed_fids=None):
    """Build or path-update Fact/Supp/Authority for one logical commit.

    ``changed_fids`` is an additions-only ordinary commit. Prune, restore,
    proof-winner changes, and format upgrades pass ``None`` and take the
    canonical bulk path. ``previous`` is only a path-copy optimization: it
    cannot affect the logical rows or resulting roots.

    The caller supplies one derived-index snapshot and publishes the returned
    descriptors together with the range manifest. This function emits
    immutable objects but never advances the mutable root itself.
    """
    seed = layout_seed(anchor)
    previous = previous or {}
    fetch = fetch or (lambda oid: None)
    incremental = changed_fids is not None and all(
        previous.get(name, {}).get("root") for name in TREE_NAMES)

    archived_actions, action_rows, action_evidence = {}, [], {}
    for sid, fid, raw, evidence in idx.execute(
            "SELECT sid, fid, j, evidence FROM actions ORDER BY sid"):
        fact = from_json(json.loads(raw))
        if fact.fid != fid \
                or sid not in suppression_state.action_sids(fact):
            raise ValueError("action archive integrity")
        archived_actions[fid] = fact
        action_rows.append((sid, fid))
        action_evidence[fid] = min(
            evidence, action_evidence.get(fid, evidence))

    def fact_record(fact):
        raw = canon(fact.to_json())
        if len(raw) > MAX_RAW_FACT_BYTES:
            raise ValueError("raw fact exceeds authenticated record budget")
        selectors = sorted(suppression_state.fact_scopes(fact))
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
        # Selectors answer whether this fact is suppressed. Liveness ids
        # answer whether authority it depends on remains usable. Keeping both
        # in the record makes Worker reads explicit and bounded.
        liveness = set(
            suppression_state.provider_scopes(fact)) - set(selectors)
        if policy is not None:
            for role in policy.authority_liveness_guards:
                provider_fid = edges.get(role)
                provider = fact_of(provider_fid) if provider_fid else None
                if provider is None:
                    raise ValueError("authority liveness edge")
                liveness.update(
                    suppression_state.provider_scopes(provider))
        return {
            "edges": edges,
            "evidence": action_evidence.get(fact.fid, ""),
            "key": fact.key,
            "liveness": sorted(liveness),
            "offers": [list(row) for row in fact.offers()],
            "raw": raw_oid,
            "selectors": selectors,
            "tag": fact.t,
        }

    def active_slot(sid):
        # CLEAR is authenticated state for a reserved id, never shorthand for
        # an absent tree row. ACTIVE carries the deterministic archive winner.
        row = idx.execute(
            "SELECT fid FROM actions WHERE sid=?", (sid,)).fetchone()
        return {"state": "active", "action": row[0]} \
            if row is not None else {"state": "clear"}

    def reservations(fact):
        """Precreate every slot whose absence must not mean permission.

        Explicit selectors reserve SuppTree ids. Directly deletable facts and
        principal providers also reserve FactTree corroboration slots so
        action sync can cross-check an enumerated ACTIVE entry.
        """
        fact_slots, supp_slots = {}, {}
        selectors = suppression_state.fact_scopes(fact)
        for sid in selectors:
            supp_slots[sid] = active_slot(sid)
        policy = facts.policy_for(fact.t)
        if policy is not None and policy.direct_targets:
            sid = fact_key(fact.fid)
            fact_slots[action_key(sid)] = active_slot(sid)
        for name, public_key, _ in fact.offers():
            if name == "member":
                sid = principal_sid("member", public_key)
            elif name == "device_key":
                sid = principal_sid("device", public_key)
            else:
                continue
            fact_slots[action_key(sid)] = active_slot(sid)
            supp_slots[sid] = active_slot(sid)
        return fact_slots, supp_slots

    def authority_value(address):
        name, a0, a1 = address
        if a1 is None:
            row = idx.execute(
                "SELECT p.rank, o.src FROM offers o "
                "JOIN proofs p ON p.fid=o.src "
                "WHERE o.name=? AND o.a0=? "
                "ORDER BY p.rank, o.src LIMIT 1",
                (name, a0),
            ).fetchone()
        else:
            row = idx.execute(
                "SELECT p.rank, o.src FROM offers o "
                "JOIN proofs p ON p.fid=o.src "
                "WHERE o.name=? AND o.a0=? AND o.a1=? "
                "ORDER BY p.rank, o.src LIMIT 1",
                (name, a0, a1),
            ).fetchone()
        if row is None:
            return None
        rank, source = row
        return {
            "state": "provider",
            "fid": source,
            "rank": rank,
        }

    if incremental:
        fact_changes, supp_changes, addresses = {}, {}, set()
        for fid in sorted(set(changed_fids)):
            fact = fact_of(fid)
            if fact is None:
                continue
            fact_changes[fact_key(fid)] = fact_record(fact)
            fact_slots, supp_slots = reservations(fact)
            fact_changes.update(fact_slots)
            supp_changes.update(supp_slots)
            for name, a0, a1 in fact.offers():
                addresses.add((name, a0, a1))
                addresses.add((name, a0, None))

        # Action state is a small monotone set. Include it on every update so
        # action-first sync can publish a witness not yet in the ordinary set.
        for sid, fid in action_rows:
            fact = archived_actions[fid]
            fact_changes[fact_key(fid)] = fact_record(fact)
            active = {"state": "active", "action": fid}
            fact_changes[action_key(sid)] = active
            supp_changes[sid] = active

        authority_changes = {
            need_key(*address): authority_value(address)
            for address in sorted(
                addresses,
                key=lambda row: (
                    row[0], row[1], row[2] is not None, row[2] or ""))
        }
        change_sets = {
            FACT: tuple(sorted(fact_changes.items())),
            SUPP: tuple(sorted(supp_changes.items())),
            AUTHORITY: tuple(sorted(authority_changes.items())),
        }
        built = {}
        for name in TREE_NAMES:
            result = btreap.update(
                previous[name]["root"], seed, change_sets[name], fetch, emit)
            built[name] = {
                "root": result.root,
                "count": result.count,
                "depth": result.page_depth,
            }
        return seed, built

    # Full rebuild is the reference definition of all three logical maps.
    # Historical action evidence remains explicit; no replica-local arrival
    # order or observation leaks into the result.
    fact_rows, supp_rows = {}, {}
    current = [
        fact_of(fid)
        for (fid,) in idx.execute("SELECT fid FROM facts ORDER BY fid")
    ]
    for fact in current:
        fact_rows[fact_key(fact.fid)] = fact_record(fact)
        fact_slots, supp_slots = reservations(fact)
        for key, value in fact_slots.items():
            fact_rows.setdefault(key, value)
        for key, value in supp_slots.items():
            supp_rows.setdefault(key, value)
    for fid, fact in archived_actions.items():
        if fact_key(fid) not in fact_rows:
            fact_rows[fact_key(fid)] = fact_record(fact)

    for _, sid in idx.execute("SELECT fid, k FROM supp ORDER BY fid, k"):
        supp_rows.setdefault(sid, active_slot(sid))

    for sid, fid in action_rows:
        _activate(supp_rows, sid, fid)
        _activate(fact_rows, action_key(sid), fid)

    authority_rows, candidates = {}, defaultdict(list)
    for name, a0, a1, src, rank in idx.execute(
            "SELECT o.name, o.a0, o.a1, o.src, p.rank "
            "FROM offers o JOIN proofs p ON p.fid=o.src "
            "ORDER BY p.rank, o.src"):
        candidates[(name, a0, a1)].append((rank, src))
        candidates[(name, a0, None)].append((rank, src))
    for address, choices in candidates.items():
        rank, source = min(choices)
        authority_rows[need_key(*address)] = {
            "state": "provider", "fid": source, "rank": rank}

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
