"""Pure compiler from validated facts to one canonical repository snapshot.

The input is the monotone set ``fid -> Fact``.  Validation happened once, at
the closed-pile boundary; this compiler never reruns family judgment and never
labels a fact eligible, dormant, winning, or losing.  It emits canonical fact
residences plus mechanical Fact, Suppression, Authority, and order maps.
"""

from collections import defaultdict
from dataclasses import dataclass

import facts

from . import indexes, merkle_map, snapshot
from .crypto import h
from .fact import bound_to, encode
from .fact_index import INTERNAL_INDEXES
from .shape import valid_fid


@dataclass(frozen=True, slots=True)
class CompiledSnapshot:
    """Canonical root proposal and every immutable object it emits."""

    root: bytes | None
    outbox: tuple
    objects: dict


def _checked_facts(anchor, facts_by_fid):
    if not valid_fid(anchor) or not isinstance(facts_by_fid, dict):
        raise ValueError("validated fact set")
    checked = {}
    for fid, fact in sorted(facts_by_fid.items()):
        family = facts.family_for(getattr(fact, "t", None))
        if getattr(fact, "fid", None) != fid \
                or not bound_to(fact, anchor) \
                or family is None or not family.DURABLE:
            raise ValueError("validated fact")
        checked[fid] = fact
    return checked


def action_bindings(facts_by_fid):
    """Select the first immutable action for each typed suppression id."""
    selected = {}
    for fact in sorted(
            facts_by_fid.values(), key=lambda item: (item.key, item.fid)):
        for sid in sorted(facts.action_sids(fact)):
            selected.setdefault(sid, fact.fid)
    return selected


def _active(fact, actions):
    return not any(sid in actions for sid in facts.current_scopes(fact))


def derived_rows(facts_by_fid):
    """Derive current SuppTree and AuthorityTree from validated fact bytes."""
    actions = action_bindings(facts_by_fid)

    def slot(sid):
        action = actions.get(sid)
        return {"state": "clear"} if action is None else {
            "state": "active", "action": action}

    fact_actions, supp = {}, {}
    for fid, fact in facts_by_fid.items():
        for sid in facts.current_scopes(fact):
            supp[sid] = slot(sid)
        policy = facts.family_for(fact.t).POLICY
        if policy.direct_targets:
            sid = indexes.fact_key(fid)
            fact_actions[indexes.action_key(sid)] = slot(sid)
        for sid in facts.principal_sids(fact):
            fact_actions[indexes.action_key(sid)] = slot(sid)

    for sid, fid in sorted(actions.items()):
        fact = facts_by_fid.get(fid)
        if fact is None or sid not in facts.action_sids(fact):
            raise ValueError("action evidence binding")
        active = {"state": "active", "action": fid}
        supp[sid] = active
        fact_actions[indexes.action_key(sid)] = active

    choices = defaultdict(list)
    for fid, fact in facts_by_fid.items():
        for name, a0, a1 in fact.offers():
            if name in INTERNAL_INDEXES:
                raise ValueError("reserved authority offer")
            order = (fact.key, fid)
            choices[(name, a0, a1)].append(order)
            choices[(name, a0, None)].append(order)

    authority = {}
    for address, providers in choices.items():
        live = [
            (order, fid)
            for order, fid in providers
            if _active(facts_by_fid[fid], actions)
        ]
        authority[indexes.need_key(*address)] = (
            {"state": "none"} if not live else {
                "state": "provider",
                "fid": min(live)[1],
            }
        )
    return fact_actions, supp, authority


def logical_rows(anchor, facts_by_fid):
    """Return every logical row from the monotone validated set."""
    checked = _checked_facts(anchor, facts_by_fid)
    objects = {
        fid: h(encode(fact))
        for fid, fact in checked.items()
    }
    fact_rows = {
        indexes.fact_key(fid): objects[fid]
        for fid in checked
    }
    for fid, fact in checked.items():
        value = {"state": indexes.POSTING_VALUE, "fid": fid}
        for key in indexes.record_postings(fact):
            if key in fact_rows:
                raise ValueError("duplicate FactTree row")
            fact_rows[key] = value

    fact_actions, supp_rows, authority_rows = derived_rows(checked)
    for key, value in fact_actions.items():
        incumbent = fact_rows.setdefault(key, value)
        if incumbent != value:
            raise ValueError("conflicting FactTree action slot")

    return {
        snapshot.FACT_ORDER: {
            fact.key: objects[fid]
            for fid, fact in checked.items()
        },
        indexes.FACT: fact_rows,
        indexes.SUPP: supp_rows,
        indexes.AUTHORITY: authority_rows,
    }, objects


def compile_snapshot(anchor, facts_by_fid):
    """Build one history-independent root and immutable object outbox."""
    if not facts_by_fid:
        return CompiledSnapshot(None, (), {})
    if anchor not in facts_by_fid:
        raise ValueError("repository anchor fact")
    rows, objects = logical_rows(anchor, facts_by_fid)
    pending = {}

    def emit(raw):
        oid = h(raw)
        incumbent = pending.setdefault(oid, raw)
        if incumbent != raw:
            raise ValueError("repository object hash collision")
        return oid

    for fact in facts_by_fid.values():
        emit(encode(fact))
    seed = snapshot.layout_seed(anchor)
    maps = {}
    for name in snapshot.MAP_NAMES:
        built = merkle_map.build(
            tuple(rows[name].items()), seed, emit)
        maps[name] = snapshot.descriptor(built)
    root = snapshot.encode_root(anchor, maps, seed=seed)
    return CompiledSnapshot(
        root,
        tuple(sorted(pending.items())),
        objects,
    )
