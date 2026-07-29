"""Exact authenticated read views over the committed fact set.

The range manifest is shaped for reconciliation, not point authorization. A
Worker should not download it, enumerate facts, or reconstruct SQLite merely
to decide whether one principal or fact is live. This module projects the
same admitted snapshot into three maps over the history-independent B-treap:

``FactTree``
    ``fact:<fid>`` maps only to the bounded data needed for an exact Worker
    read: offers, explicit suppression selectors, continuing liveness ids,
    and optional action evidence. Raw facts remain in manifest piles.
    ``action:<sid>`` maps to the same CLEAR/ACTIVE value as SuppTree for known
    direct and principal targets. That second binding is deliberate: sync may
    enumerate active SuppTree entries, but accepts one only when FactTree
    independently binds the same sid-to-action witness.

``SuppTree``
    A typed suppression id maps to ``{"state": "clear"}`` or
    ``{"state": "active", "action": <fid>}``. CLEAR is a positive,
    authenticated reservation saying that this known id has no admitted
    action. It is not a missing row: a missing required slot makes Worker
    authorization fail closed. ACTIVE names the effective action in this
    snapshot; a later root may return to CLEAR if canonical settlement makes
    that proposal ineligible. Its evidence can be reached through FactTree.

``AuthorityTree``
    A canonical base NeedKey maps to the kernel's selected provider and proof
    rank. It lets a Worker check committed authority with one exact path
    instead of trusting whichever provider a request happened to submit.
    Family-required co-offers are then checked against that provider's
    FactRecord; they are not inferred from the request.

All three descriptors are returned together for the composite root's single
CAS. They use an anchor-derived seed, so a logical map has one root independent
of insertion order. The incremental path receives new fact ids and exact
changed suppression ids; prune, restore, authority-winner changes, format
changes, and direct bulk writes take the full canonical path. Both paths must
produce the same roots for the same logical maps.
"""
from collections import defaultdict

import facts

from . import btreap
from .catalog import INTERNAL_INDEXES
from .crypto import h
from .fact import canon

FACT = "fact"
SUPP = "supp"
AUTHORITY = "authority"
TREE_NAMES = (FACT, SUPP, AUTHORITY)
MAX_SELECTORS = 8


def layout_seed(anchor):
    """Pin all three canonical treaps to this workspace, not local history."""
    return h(canon(["composite-layout-seed-v1", anchor]))


def fact_key(fid):
    """FactTree address for a fact's bounded authenticated record."""
    return "fact:" + fid


def action_key(sid):
    """FactTree corroboration slot for one SuppTree action state."""
    return "action:" + sid


principal_sid = facts.principal_sid


def need_key(name, a0, a1=None, requires=()):
    """Canonical authority address; full keys may bind required co-offers."""
    return canon([
        "need", name, a0, a1,
        sorted([list(row) for row in requires]),
    ]).decode()


def build(
        anchor, idx, fact_of, emit, *, previous=None, fetch=None,
        changed_fids=None, changed_sids=()):
    """Build or path-update Fact/Supp/Authority for one logical commit.

    ``changed_fids`` is an additions-only commit and ``changed_sids`` is the
    exact effective-action/evidence delta. Prune, restore, proof-winner
    changes, and format upgrades pass ``None`` and take the canonical bulk
    path. ``previous`` is only a path-copy optimization: it cannot affect the
    logical rows or resulting roots.

    The caller supplies one derived-index snapshot and publishes the returned
    descriptors together with the range manifest. This function emits
    immutable objects but never advances the mutable root itself.
    """
    seed = layout_seed(anchor)
    previous = previous or {}
    fetch = fetch or (lambda oid: None)
    incremental = changed_fids is not None and all(
        previous.get(name, {}).get("root") for name in TREE_NAMES)

    action_by_sid, action_evidence = {}, {}

    def checked_action(sid, fid):
        fact = fact_of(fid)
        if fact is None or sid not in facts.action_sids(fact):
            raise ValueError("action archive integrity")
        return fact

    if not incremental:
        for sid, fid, evidence in idx.execute(
                "SELECT sid, fid, evidence FROM actions ORDER BY sid"):
            checked_action(sid, fid)
            action_by_sid[sid] = (fid, evidence)
            action_evidence[fid] = min(
                evidence, action_evidence.get(fid, evidence))

    active_cache = {}

    def active_binding(sid):
        if sid not in active_cache:
            row = idx.execute(
                "SELECT fid, evidence FROM actions WHERE sid=?",
                (sid,)).fetchone()
            if row is not None:
                checked_action(sid, row[0])
            active_cache[sid] = row
        return active_cache[sid]

    def evidence_for(fid):
        if not incremental:
            return action_evidence.get(fid, "")
        row = idx.execute(
            "SELECT evidence FROM actions WHERE fid=? "
            "ORDER BY evidence LIMIT 1", (fid,)).fetchone()
        return row[0] if row else ""

    def fact_record(fact):
        selectors = sorted(facts.fact_scopes(fact))
        if len(selectors) > MAX_SELECTORS:
            raise ValueError("fact selector budget")
        def edges_of(fid):
            return dict(idx.execute(
                "SELECT role, dst FROM edges WHERE src=? ORDER BY role",
                (fid,)).fetchall())

        # Selectors answer whether this fact is suppressed. Liveness ids
        # answer whether authority it depends on remains usable. Keeping both
        # in the record makes Worker reads explicit and bounded.
        liveness = set(facts.authority_scopes(
            fact, edges_of, fact_of)) - set(selectors)
        return {
            "evidence": evidence_for(fact.fid),
            "liveness": sorted(liveness),
            "offers": [list(row) for row in fact.offers()],
            "selectors": selectors,
        }

    def active_slot(sid):
        # CLEAR is authenticated state for a reserved id, never shorthand for
        # an absent tree row. ACTIVE carries the deterministic archive winner.
        row = active_binding(sid) if incremental \
            else action_by_sid.get(sid)
        return {"state": "active", "action": row[0]} \
            if row is not None else {"state": "clear"}

    def reservations(fact):
        """Precreate every slot whose absence must not mean permission.

        Explicit selectors reserve SuppTree ids. Directly deletable facts and
        principal providers also reserve FactTree corroboration slots so
        action sync can cross-check an enumerated ACTIVE entry.
        """
        fact_slots, supp_slots = {}, {}
        selectors = facts.fact_scopes(fact)
        for sid in selectors:
            supp_slots[sid] = active_slot(sid)
        family = facts.family_for(fact.t)
        policy = family.POLICY if family is not None else None
        if policy is not None and policy.direct_targets:
            sid = fact_key(fact.fid)
            fact_slots[action_key(sid)] = active_slot(sid)
        for sid in facts.principal_sids(fact):
            fact_slots[action_key(sid)] = active_slot(sid)
            supp_slots[sid] = active_slot(sid)
        return fact_slots, supp_slots

    def authority_value(address):
        name, a0, a1 = address
        if a1 is None:
            row = idx.execute(
                "SELECT p.rank, o.src FROM fact_index o "
                "JOIN proofs p ON p.fid=o.src "
                "WHERE o.kind=? AND o.k0=? "
                "ORDER BY p.rank, o.src LIMIT 1",
                (name, a0),
            ).fetchone()
        else:
            row = idx.execute(
                "SELECT p.rank, o.src FROM fact_index o "
                "JOIN proofs p ON p.fid=o.src "
                "WHERE o.kind=? AND o.k0=? AND o.k1=? "
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

        fact_reader = btreap.Reader(previous[FACT]["root"], seed, fetch)
        for sid in sorted(set(changed_sids)):
            if not isinstance(sid, str) or not sid:
                raise ValueError("changed suppression id")
            slot = active_slot(sid)
            address = action_key(sid)
            previous_slot = fact_reader.get(address)
            fact_changes[address] = slot
            supp_changes[sid] = slot
            current_fid = slot.get("action") \
                if slot["state"] == "active" else None
            if current_fid is not None:
                current = checked_action(sid, current_fid)
                fact_changes[fact_key(current_fid)] = fact_record(current)
            old_fid = previous_slot.get("action") \
                if isinstance(previous_slot, dict) \
                and previous_slot.get("state") == "active" else None
            if old_fid is not None and old_fid != current_fid:
                old = fact_of(old_fid)
                fact_changes[fact_key(old_fid)] = \
                    fact_record(old) if old is not None else None

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
        for (fid,) in idx.execute("SELECT fid FROM proofs ORDER BY fid")
    ]
    for fact in current:
        fact_rows[fact_key(fact.fid)] = fact_record(fact)
        fact_slots, supp_slots = reservations(fact)
        for key, value in fact_slots.items():
            fact_rows.setdefault(key, value)
        for key, value in supp_slots.items():
            supp_rows.setdefault(key, value)
    for _, sid in idx.execute(
            "SELECT s.fid, s.k FROM supp s "
            "JOIN proofs p ON p.fid=s.fid ORDER BY s.fid, s.k"):
        supp_rows.setdefault(sid, active_slot(sid))

    for sid, (fid, _) in action_by_sid.items():
        active = {"state": "active", "action": fid}
        supp_rows[sid] = active
        fact_rows[action_key(sid)] = active

    authority_rows, candidates = {}, defaultdict(list)
    internal = tuple(sorted(INTERNAL_INDEXES))
    for name, a0, a1, src, rank in idx.execute(
            "SELECT o.kind, o.k0, o.k1, o.src, p.rank "
            "FROM fact_index o JOIN proofs p ON p.fid=o.src "
            f"WHERE o.kind NOT IN ({','.join('?' for _ in internal)}) "
            "ORDER BY p.rank, o.src",
            internal):
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
