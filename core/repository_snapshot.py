"""Pure compiler from validated facts to one canonical repository snapshot.

The input is the monotone set ``fid -> Fact``.  Validation happened once, at
the closed-pile boundary; this compiler never reruns family judgment and never
labels a fact eligible, dormant, winning, or losing.  It emits canonical fact
residences plus mechanical Fact, Suppression, and order maps.
"""

from collections import defaultdict
from dataclasses import dataclass

import facts

from . import indexes, merkle_map, snapshot
from .crypto import h
from .fact import bound_to, encode
from .shape import valid_fid


@dataclass(frozen=True, slots=True)
class CompiledSnapshot:
    """Canonical root proposal and every immutable object it emits."""

    root: bytes | None
    outbox: tuple
    fact_oids: dict


def _compiled(anchor, maps, pending, fact_oids, seed):
    return CompiledSnapshot(
        snapshot.encode_root(anchor, maps, seed=seed),
        tuple(sorted(pending.items())),
        fact_oids,
    )


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


def _merge_rows(target, rows):
    for key, value in rows.items():
        incumbent = target.setdefault(key, value)
        if incumbent != value:
            raise ValueError("conflicting repository row")


def _fact_rows(fact, oid, slot):
    """Rows contributed by one fact under the supplied current-slot reader."""
    rows = {indexes.fact_key(fact.fid): oid}
    posting = {"state": indexes.POSTING_VALUE, "fid": fact.fid}
    rows.update((key, posting) for key in indexes.record_postings(fact))
    action_sids = set(facts.principal_sids(fact))
    if facts.family_for(fact.t).POLICY.direct_targets:
        action_sids.add(indexes.fact_key(fact.fid))
    action_sids.update(facts.action_sids(fact))
    rows.update(
        (indexes.action_key(sid), slot(sid))
        for sid in action_sids
    )
    return rows


def logical_rows(anchor, facts_by_fid):
    """Return every logical row from the monotone validated set."""
    checked = _checked_facts(anchor, facts_by_fid)
    objects = {
        fid: h(encode(fact))
        for fid, fact in checked.items()
    }
    actions = action_bindings(checked)
    slot = lambda sid: indexes.suppression_slot(actions.get(sid))
    fact_rows, supp_rows = {}, {}
    for fid, fact in checked.items():
        _merge_rows(fact_rows, _fact_rows(fact, objects[fid], slot))
        supp_rows.update(
            (sid, slot(sid)) for sid in facts.current_scopes(fact))
    for sid, fid in actions.items():
        fact = checked.get(fid)
        if fact is None or sid not in facts.action_sids(fact):
            raise ValueError("action evidence binding")
        value = indexes.suppression_slot(fid)
        supp_rows[sid] = value
        _merge_rows(
            fact_rows, {indexes.action_key(sid): value})

    return {
        snapshot.FACT_ORDER: {
            fact.key: objects[fid]
            for fid, fact in checked.items()
        },
        indexes.FACT: fact_rows,
        indexes.SUPP: supp_rows,
    }, objects


def extend_snapshot(anchor, base_root, facts_by_fid, fetch):
    """Path-copy one validated fact batch onto an authenticated snapshot.

    Only newly resident fact rows and their suppression routes are visited.
    The full compiler below remains the history-independent oracle; this
    function emits the same root without enumerating unrelated validated
    facts.
    """
    checked = _checked_facts(anchor, facts_by_fid)
    if base_root is None:
        return compile_snapshot(anchor, checked)

    from .repository_reader import RepositoryReader

    view = RepositoryReader(anchor, base_root, fetch).validated()
    fact_reader = view._reader(indexes.FACT)
    supp_reader = view._reader(indexes.SUPP)

    encoded = {fid: encode(fact) for fid, fact in checked.items()}
    object_ids = {fid: h(raw) for fid, raw in encoded.items()}
    fresh = {}
    for fid, fact in checked.items():
        incumbent = fact_reader.get(indexes.fact_key(fid))
        if incumbent is None:
            fresh[fid] = fact
            continue
        if indexes.checked_fact_oid(incumbent) != object_ids[fid] \
                or encode(view.fact(fid)) != encoded[fid]:
            raise ValueError("repository fact conflict")

    pending = {}

    def emit(raw):
        oid = h(raw)
        incumbent = pending.setdefault(oid, raw)
        if incumbent != raw:
            raise ValueError("repository object hash collision")
        return oid

    for fid in fresh:
        emit(encoded[fid])

    old_slots = {}

    def old_slot(sid):
        if sid not in old_slots:
            value = supp_reader.get(sid)
            old_slots[sid] = None if value is None \
                else indexes.checked_suppression_slot(value)
        return old_slots[sid]

    actions = defaultdict(list)
    affected_sids = set()
    for fact in fresh.values():
        scopes = facts.current_scopes(fact)
        action_sids = facts.action_sids(fact)
        affected_sids.update(scopes)
        affected_sids.update(action_sids)
        for sid in action_sids:
            actions[sid].append(fact)

    next_slots = {}
    for sid in sorted(affected_sids):
        previous = old_slot(sid)
        candidates = list(actions[sid])
        if previous is not None and previous["state"] == "active":
            incumbent = view.fact(previous["action"])
            if sid not in facts.action_sids(incumbent) \
                    or fact_reader.get(indexes.action_key(sid)) != previous:
                raise ValueError("action evidence binding")
            candidates.append(incumbent)
        selected = min(
            candidates, key=lambda fact: (fact.key, fact.fid)
        ).fid if candidates else None
        next_slots[sid] = indexes.suppression_slot(selected)

    def current_slot(sid):
        value = next_slots.get(sid)
        if value is None:
            value = old_slot(sid)
        if value is None:
            raise ValueError("missing suppression scope")
        return value

    fact_changes = {}
    order_changes = {}
    for fid, fact in fresh.items():
        _merge_rows(
            fact_changes,
            _fact_rows(fact, object_ids[fid], current_slot),
        )
        order_changes[fact.key] = object_ids[fid]
    for sid in affected_sids:
        if next_slots[sid]["state"] == "active":
            _merge_rows(fact_changes, {
                indexes.action_key(sid): next_slots[sid]})

    changes = {
        snapshot.FACT_ORDER: order_changes,
        indexes.FACT: fact_changes,
        indexes.SUPP: next_slots,
    }
    maps = {}
    for name in snapshot.MAP_NAMES:
        descriptor = view.root.maps[name]
        if not changes[name]:
            maps[name] = descriptor
            continue
        built = merkle_map.update(
            descriptor["root"],
            view.root.layout_seed,
            tuple(changes[name].items()),
            view.fetch,
            emit,
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )
        maps[name] = snapshot.descriptor(built)
    return _compiled(
        anchor, maps, pending, object_ids, view.root.layout_seed)


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
    return _compiled(anchor, maps, pending, objects, seed)
