"""Pure compiler from validated facts to one canonical repository snapshot.

The input is the monotone set ``fid -> Fact``.  Validation happened once, at
the closed-pile boundary; this compiler never reruns family judgment and never
labels a fact eligible, dormant, winning, or losing.  It emits canonical fact
residences plus mechanical Fact, Suppression, and order maps.
"""

from dataclasses import dataclass

import facts

from . import indexes, merkle_map, snapshot
from .crypto import h
from .fact import bound_to, decode, encode
from .shape import valid_fid


@dataclass(frozen=True, slots=True)
class CompiledSnapshot:
    """Canonical root proposal and every immutable object it emits."""

    root: bytes | None
    outbox: tuple
    fact_oids: dict


@dataclass(frozen=True, slots=True)
class _Points:
    name: str
    descriptor: dict
    keys: tuple


@dataclass(frozen=True, slots=True)
class _Object:
    oid: str


@dataclass(frozen=True, slots=True)
class _Establish:
    raw: bytes


@dataclass(frozen=True, slots=True)
class _Change:
    name: str
    descriptor: dict
    rows: tuple


def _root_bytes(anchor, maps, seed):
    return snapshot.encode_root(anchor, maps, seed=seed)


def _compiled(anchor, maps, pending, fact_oids, seed):
    return CompiledSnapshot(
        _root_bytes(anchor, maps, seed),
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


def _fact_rows(fact, oid):
    """Mechanical FactTree rows contributed by one validated fact."""
    rows = {indexes.fact_key(fact.fid): oid}
    posting = {"state": indexes.POSTING_VALUE, "fid": fact.fid}
    rows.update((key, posting) for key in indexes.record_postings(fact))
    return rows


def _fact_routes(fact, oid):
    """Collect all authenticated routes contributed by one running family."""
    rows = _fact_rows(fact, oid)
    scopes = facts.current_scopes(fact)
    actions = facts.action_sids(fact)
    return rows, scopes, actions


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
        rows, _, _ = _fact_routes(fact, objects[fid])
        _merge_rows(fact_rows, rows)
        supp_rows.update(
            (sid, slot(sid)) for sid in facts.current_scopes(fact))
    for sid, fid in actions.items():
        fact = checked.get(fid)
        if fact is None or sid not in facts.action_sids(fact):
            raise ValueError("action evidence binding")
        supp_rows[sid] = indexes.suppression_slot(fid)

    return {
        snapshot.FACT_ORDER: {
            fact.key: objects[fid]
            for fid, fact in checked.items()
        },
        indexes.FACT: fact_rows,
        indexes.SUPP: supp_rows,
    }, objects


def _existing_fact(anchor, fid, oid, raw):
    if not isinstance(raw, bytes) or h(raw) != oid:
        raise ValueError("repository object integrity")
    fact = decode(raw)
    family = facts.family_for(fact.t)
    if fact.fid != fid or not bound_to(fact, anchor) \
            or family is None or not family.DURABLE:
        raise ValueError("repository fact identity")
    return fact


def _extension_program(anchor, base_root, facts_by_fid):
    """Yield semantic reads, immutable establishes, and three map batches."""
    checked = _checked_facts(anchor, facts_by_fid)
    encoded = {fid: encode(fact) for fid, fact in checked.items()}
    object_ids = {fid: h(raw) for fid, raw in encoded.items()}
    if base_root is None:
        seed = snapshot.layout_seed(anchor)
        maps = {
            name: snapshot.empty_descriptor()
            for name in snapshot.MAP_NAMES
        }
        if checked and anchor not in checked:
            raise ValueError("repository anchor fact")
    else:
        root = snapshot.decode_root(base_root)
        if root.anchor != anchor \
                or root.layout_seed != indexes.layout_seed(anchor):
            raise ValueError("repository snapshot anchor")
        seed, maps = root.layout_seed, {
            name: dict(root.maps[name])
            for name in snapshot.MAP_NAMES
        }

    residence_keys = {
        fid: indexes.fact_key(fid)
        for fid in checked
    }
    residences = yield _Points(
        indexes.FACT,
        maps[indexes.FACT],
        tuple(residence_keys.values()),
    )
    fresh = {}
    for fid, fact in checked.items():
        incumbent = residences[residence_keys[fid]]
        if incumbent is None:
            fresh[fid] = fact
            continue
        oid = indexes.checked_fact_oid(incumbent)
        raw = yield _Object(oid)
        if oid != object_ids[fid] \
                or encode(_existing_fact(
                    anchor, fid, oid, raw)) != encoded[fid]:
            raise ValueError("repository fact conflict")

    for fid in fresh:
        if (yield _Establish(encoded[fid])) != object_ids[fid]:
            raise ValueError("repository object identity")

    actions, affected_sids = {}, set()
    fact_changes, order_changes = {}, {}
    for fid, fact in fresh.items():
        rows, scopes, action_sids = _fact_routes(
            fact, object_ids[fid])
        _merge_rows(fact_changes, rows)
        incumbent = order_changes.setdefault(
            fact.key, object_ids[fid])
        if incumbent != object_ids[fid]:
            raise ValueError("conflicting repository row")
        affected_sids.update(scopes)
        affected_sids.update(action_sids)
        candidate = (fact.key, fact.fid)
        for sid in action_sids:
            actions[sid] = min(actions.get(sid, candidate), candidate)

    ordered_sids = tuple(sorted(affected_sids))
    previous_slots = yield _Points(
        indexes.SUPP,
        maps[indexes.SUPP],
        ordered_sids,
    )
    active_fids = {
        value["action"]
        for value in (
            None if raw is None
            else indexes.checked_suppression_slot(raw)
            for raw in previous_slots.values()
        )
        if value is not None and value["state"] == "active"
    }
    action_keys = {
        fid: indexes.fact_key(fid)
        for fid in sorted(active_fids)
    }
    action_oids = yield _Points(
        indexes.FACT,
        maps[indexes.FACT],
        tuple(action_keys.values()),
    )
    incumbents = {}
    for fid, key in action_keys.items():
        incumbent_oid = action_oids[key]
        if incumbent_oid is None:
            raise ValueError("missing validated fact")
        incumbent_oid = indexes.checked_fact_oid(incumbent_oid)
        incumbent = _existing_fact(
            anchor,
            fid,
            incumbent_oid,
            (yield _Object(incumbent_oid)),
        )
        incumbents[fid] = (
            incumbent.key,
            incumbent.fid,
            facts.action_sids(incumbent),
        )

    next_slots = {}
    for sid in ordered_sids:
        previous = previous_slots[sid]
        previous = None if previous is None \
            else indexes.checked_suppression_slot(previous)
        selected = actions.get(sid)
        if previous is not None and previous["state"] == "active":
            action_fid = previous["action"]
            incumbent_key, incumbent_fid, incumbent_sids = \
                incumbents[action_fid]
            if sid not in incumbent_sids:
                raise ValueError("action evidence binding")
            candidate = (incumbent_key, incumbent_fid)
            selected = min(selected, candidate) \
                if selected is not None else candidate
        next_slots[sid] = indexes.suppression_slot(
            None if selected is None else selected[1])

    changes = {
        snapshot.FACT_ORDER: order_changes,
        indexes.FACT: fact_changes,
        indexes.SUPP: next_slots,
    }
    for name in snapshot.MAP_NAMES:
        rows = tuple(sorted(changes[name].items()))
        if rows:
            maps[name] = yield _Change(name, maps[name], rows)

    root = None if not checked and base_root is None \
        else _root_bytes(anchor, maps, seed)
    return CompiledSnapshot(root, (), object_ids)


def _drive_extension(program, fetch, seed):
    pending = {}

    def available(oid):
        return pending[oid] if oid in pending else fetch(oid)

    def emit(raw):
        oid = h(raw)
        incumbent = pending.setdefault(oid, raw)
        if incumbent != raw:
            raise ValueError("repository object hash collision")
        return oid

    try:
        operation = next(program)
        while True:
            if isinstance(operation, _Points):
                descriptor = operation.descriptor
                answer, _ = merkle_map.get_many(
                    descriptor["root"],
                    seed,
                    operation.keys,
                    available,
                    max_page_depth=descriptor["depth"],
                    expected_count=descriptor["count"],
                    expected_depth=descriptor["depth"],
                )
            elif isinstance(operation, _Object):
                answer = available(operation.oid)
            elif isinstance(operation, _Establish):
                answer = emit(operation.raw)
            elif isinstance(operation, _Change):
                descriptor = operation.descriptor
                built = merkle_map.update(
                    descriptor["root"],
                    seed,
                    operation.rows,
                    available,
                    emit,
                    expected_count=descriptor["count"],
                    expected_depth=descriptor["depth"],
                )
                answer = snapshot.descriptor(built)
            else:
                raise TypeError("repository extension operation")
            operation = program.send(answer)
    except StopIteration as done:
        compiled = done.value
        return CompiledSnapshot(
            compiled.root,
            tuple(sorted(pending.items())),
            compiled.fact_oids,
        )
    finally:
        program.close()


def extend_snapshot(anchor, base_root, facts_by_fid, fetch):
    """Pure one-route path-copy driver; the full compiler remains its oracle."""
    return _drive_extension(
        _extension_program(anchor, base_root, facts_by_fid),
        fetch,
        snapshot.layout_seed(anchor),
    )


async def extend_snapshot_awaited(
        anchor, base_root, facts_by_fid, fetch, establish):
    """Run the same semantic plan with one live page and immediate writes."""
    seed = snapshot.layout_seed(anchor)
    program = _extension_program(anchor, base_root, facts_by_fid)
    try:
        operation = next(program)
        while True:
            if isinstance(operation, _Points):
                descriptor = operation.descriptor
                answer, _ = await merkle_map.get_many_awaited(
                    descriptor["root"],
                    seed,
                    operation.keys,
                    fetch,
                    max_page_depth=descriptor["depth"],
                    expected_count=descriptor["count"],
                    expected_depth=descriptor["depth"],
                )
            elif isinstance(operation, _Object):
                answer = await fetch(operation.oid)
            elif isinstance(operation, _Establish):
                answer = await establish(operation.raw)
            elif isinstance(operation, _Change):
                descriptor = operation.descriptor
                built = await merkle_map.update_awaited(
                    descriptor["root"],
                    seed,
                    operation.rows,
                    fetch,
                    establish,
                    expected_count=descriptor["count"],
                    expected_depth=descriptor["depth"],
                )
                answer = snapshot.descriptor(built)
            else:
                raise TypeError("repository extension operation")
            operation = program.send(answer)
    except StopIteration as done:
        return done.value
    finally:
        program.close()


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
