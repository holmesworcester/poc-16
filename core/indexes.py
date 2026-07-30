"""Exact authenticated read views over the committed fact set.

The range manifest is shaped for reconciliation, not point authorization. A
Worker should not download it, enumerate facts, or reconstruct SQLite merely
to decide whether one principal or fact is live. This module projects the
same admitted snapshot into three maps over the history-independent Merkle map:

``FactTree``
    ``fact:<fid>`` maps to the bounded data needed for an exact Worker or
    publisher read: reconciliation key, selected admission proof, explicit
    eligibility state, canonical fact oid, resolved dependencies, offers,
    suppression selectors, and continuing liveness ids. Every raw fact lives
    at its content address; RangeTree leaves additionally group eligible
    facts for reconciliation. ``index:...`` rows are authenticated
    counterpart of the client catalog's generic index. One row per
    ``(kind, k0, k1, state, rank, fid)`` supports bounded type, key,
    explicit-ref, offer-candidate, suppression-scope, and reverse-dependency
    ranges without hiding an unbounded posting list in one value. Ordinary
    application ranges select only the eligible prefix.
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
    that proposal ineligible. Its historical admission witness is reached
    through the action's FactRecord.

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
import base64
from collections import defaultdict
from dataclasses import dataclass
from typing import NamedTuple

import facts

from . import merkle_map
from .catalog import Catalog, INTERNAL_INDEXES, index_rows
from .crypto import h
from .fact import canon, encode
from .shape import fid_of, is_key, valid_fid

FACT = "fact"
SUPP = "supp"
AUTHORITY = "authority"
TREE_NAMES = (FACT, SUPP, AUTHORITY)
MAX_SELECTORS = 8
MAX_DEPENDENCIES = 64
MAX_PROOF_RANK = (1 << 63) - 1
SCOPE_INDEX = "fact.scope"
DEPENDENCY_INDEX = "fact.dependency"
POSTING = "index:"
DORMANT_POSTING = "dormant-index:"
POSTING_VALUE = "candidate"


class IndexPosting(NamedTuple):
    """One authenticated generic-index row in canonical proof order."""

    kind: str
    k0: str
    k1: str
    rank: int | None
    fid: str
    state: str = "eligible"


class PostingPage(NamedTuple):
    """A bounded posting page plus its opaque resume key and fetch count."""

    rows: tuple[IndexPosting, ...]
    cursor: str | None
    pages_read: int


@dataclass(frozen=True)
class IndexBuild:
    """Canonical descriptors plus candidate records this invocation emitted."""

    seed: str
    trees: dict
    represented: frozenset

    def __iter__(self):
        """Preserve the established ``seed, trees = build(...)`` surface."""
        yield self.seed
        yield self.trees


def layout_seed(anchor):
    """Pin all three canonical maps to this workspace, not local history."""
    return h(canon(["composite-layout-seed-v1", anchor]))


def fact_key(fid):
    """FactTree address for a fact's bounded authenticated record."""
    return "fact:" + fid


def action_key(sid):
    """FactTree corroboration slot for one SuppTree action state."""
    return "action:" + sid


def _component(value):
    if not isinstance(value, str):
        raise ValueError("fact index component")
    return base64.urlsafe_b64encode(
        value.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_component(value):
    try:
        if not isinstance(value, str):
            raise ValueError("fact index component")
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_", validate=True)
        decoded = raw.decode("utf-8")
        if _component(decoded) != value:
            raise ValueError("fact index component")
        return decoded
    except (UnicodeError, ValueError) as error:
        raise ValueError("fact index component") from error


def posting_prefix(kind, k0=None, k1=None, *, state="eligible"):
    """Collision-free ordered prefix for one generic index address."""
    if state not in {"eligible", "dormant"} \
            or not isinstance(kind, str) or not kind \
            or k1 is not None and k0 is None:
        raise ValueError("fact index address")
    parts = [_component(kind)]
    if k0 is not None:
        parts.append(_component(k0))
    if k1 is not None:
        parts.append(_component(k1))
    namespace = POSTING if state == "eligible" else DORMANT_POSTING
    return namespace + ":".join(parts) + ":"


def posting_key(kind, k0, k1, rank, fid, state="eligible"):
    """FactTree key ordered by address, standing/rank, then source fid."""
    if (
            state not in {"eligible", "dormant"}
            or not valid_fid(fid)
            or state == "eligible" and (
                type(rank) is not int or not 0 <= rank <= MAX_PROOF_RANK)
            or state == "dormant" and rank is not None):
        raise ValueError("fact index posting")
    order = f"{rank:020d}" if rank is not None else "-"
    return (
        posting_prefix(kind, k0, k1, state=state)
        + f"{order}:{fid}"
    )


def decode_posting_key(key):
    """Strictly decode and re-encode one authenticated posting key."""
    try:
        namespace, kind, k0, k1, rank, fid = key.split(":")
        state = {
            POSTING[:-1]: "eligible",
            DORMANT_POSTING[:-1]: "dormant",
        }[namespace]
        row = IndexPosting(
            _decode_component(kind),
            _decode_component(k0),
            _decode_component(k1),
            int(rank) if state == "eligible" else None,
            fid,
            state,
        )
        if (
                state == "eligible" and len(rank) != 20
                or state == "dormant" and rank != "-"
                or posting_key(*row) != key):
            raise ValueError("fact index posting")
        return row
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError("fact index posting") from error


def posting_page(
        reader, kind, k0=None, k1=None, *, after=None,
        limit=merkle_map.MAX_RANGE_ROWS, include_dormant=False):
    """Read one authenticated posting range without enumerating FactTree."""
    def read(state, cursor, count):
        prefix = posting_prefix(kind, k0, k1, state=state)
        return reader.range_page(
            prefix, prefix + "\uffff", after=cursor, limit=count)

    state, cursor = "eligible", after
    if include_dormant and after is not None:
        try:
            marker, cursor = after.split("|", 1)
            state = {"e": "eligible", "d": "dormant"}[marker]
            cursor = cursor or None
        except (AttributeError, KeyError, ValueError) as error:
            raise ValueError("fact index cursor") from error
    page = read(state, cursor, limit)
    pages_read = reader.pages_read
    pages = [(state, page)]
    if include_dormant and state == "eligible" and page.cursor is None:
        remaining = limit - len(page.rows)
        if remaining:
            dormant = read("dormant", None, remaining)
            pages_read += reader.pages_read
            pages.append(("dormant", dormant))
    rows = []
    for expected_state, current in pages:
        for key, value in current.rows:
            row = decode_posting_key(key)
            if value != {
                    "state": POSTING_VALUE,
                    "fid": row.fid,
                    "eligibility": row.state,
            }:
                raise ValueError("fact index posting value")
            if row.state != expected_state \
                    or row.kind != kind \
                    or k0 is not None and row.k0 != k0 \
                    or k1 is not None and row.k1 != k1:
                raise ValueError("fact index posting range")
            rows.append(row)
    last_state, last_page = pages[-1]
    if not include_dormant:
        next_cursor = last_page.cursor
    elif last_page.cursor is not None:
        next_cursor = (
            "e" if last_state == "eligible" else "d"
        ) + "|" + last_page.cursor
    elif last_state == "eligible" and len(rows) == limit:
        next_cursor = "d|"
    else:
        next_cursor = None
    return PostingPage(tuple(rows), next_cursor, pages_read)


def is_posting_key(key):
    return isinstance(key, str) and key.startswith(
        (POSTING, DORMANT_POSTING))


principal_sid = facts.principal_sid


def checked_fact_record(record, fid=None):
    """Return one strict FactRecord or fail before trusting its routes."""
    fields = {
        "admission", "dependencies", "fact_oid", "key", "liveness",
        "offers", "rank", "selectors", "state",
    }
    if (
            not isinstance(record, dict)
            or set(record) != fields
            or not is_key(record["key"])
            or fid is not None and fid_of(record["key"]) != fid
            or record["state"] not in {"eligible", "dormant"}
            or record["state"] == "eligible" and (
                type(record["rank"]) is not int
                or not 0 <= record["rank"] <= MAX_PROOF_RANK)
            or record["state"] == "dormant" and record["rank"] is not None
            or not valid_fid(record["admission"])
            or not valid_fid(record["fact_oid"])):
        raise ValueError("FactRecord shape")
    selectors, liveness = record["selectors"], record["liveness"]
    if not isinstance(selectors, list) or selectors != sorted(set(selectors)) \
            or len(selectors) > MAX_SELECTORS \
            or not all(isinstance(sid, str) and sid for sid in selectors) \
            or not isinstance(liveness, list) \
            or liveness != sorted(set(liveness)) \
            or len(liveness) > facts.MAX_AUTHORITY_SCOPES \
            or not all(isinstance(sid, str) and sid for sid in liveness):
        raise ValueError("FactRecord shape")
    offers = record["offers"]
    if not isinstance(offers, list) or not all(
            isinstance(offer, list) and len(offer) == 3
            and all(isinstance(value, str) for value in offer)
            for offer in offers):
        raise ValueError("FactRecord shape")
    dependencies = record["dependencies"]
    if not isinstance(dependencies, list) \
            or dependencies != sorted(dependencies) \
            or len(dependencies) > MAX_DEPENDENCIES \
            or not all(
                isinstance(edge, list) and len(edge) == 3
                and isinstance(edge[0], str) and edge[0]
                and valid_fid(edge[1])
                and edge[2] in {"need", "ref"}
                for edge in dependencies):
        raise ValueError("FactRecord shape")
    return record


def _record_index_rows(fact, record):
    """Mechanical immutable and current-derivation postings for one fact."""
    checked_fact_record(record, fact.fid)
    rows = set(index_rows(fact))
    rows.update(
        (SCOPE_INDEX, sid, "", fact.fid)
        for sid in (*record["selectors"], *record["liveness"])
    )
    rows.update(
        (
            DEPENDENCY_INDEX,
            target,
            canon([kind, role]).decode(),
            fact.fid,
        )
        for role, target, kind in record["dependencies"]
    )
    return tuple(sorted(rows))


def record_postings(fact, record):
    """Mechanical authenticated posting keys for one checked candidate."""
    return {
        posting_key(kind, k0, k1, record["rank"], fact.fid, record["state"])
        for kind, k0, k1, _ in _record_index_rows(fact, record)
    }


def _posting_changes(fact, record, value):
    return {key: value for key in record_postings(fact, record)}


def need_key(name, a0, a1=None, requires=()):
    """Canonical authority address; full keys may bind required co-offers."""
    return canon([
        "need", name, a0, a1,
        sorted([list(row) for row in requires]),
    ]).decode()


def build(
        anchor, idx, emit, *, previous=None, fetch=None,
        changed_fids=None, removed_fids=(), changed_sids=(),
        candidate_fids=None):
    """Build or path-update Fact/Supp/Authority for one logical commit.

    ``candidate_fids`` is the exact root-authorized candidate population;
    omitted callers use the whole proof-backed catalog. ``changed_fids``
    names added candidates, selected-witness changes, and
    eligibility/rank/dependency transitions. ``removed_fids`` is reserved for
    a future proven candidate-GC protocol and must remain empty.
    ``changed_sids`` is the exact effective-action/evidence delta. Format
    upgrades pass ``None`` and take the canonical bulk path. ``previous`` is
    only a path-copy optimization: it cannot affect logical rows or roots.

    The caller supplies one derived-index snapshot and publishes the returned
    descriptors together with the range manifest. Candidate deletion is not a
    standing transition and is deliberately unsupported. This function emits
    immutable objects but never advances the mutable root itself.
    """
    seed = layout_seed(anchor)
    previous = previous or {}
    fetch = fetch or (lambda oid: None)
    incremental = changed_fids is not None and all(
        previous.get(name, {}).get("root") for name in TREE_NAMES)

    admitted = Catalog(idx, anchor)
    fact_of = admitted.admitted
    if candidate_fids is None:
        candidate_fids = (
            tuple(sorted(set(changed_fids or ())))
            if incremental else admitted.admitted_ids()
        )
    else:
        candidate_fids = tuple(sorted(set(candidate_fids)))
    if any(fact_of(fid) is None for fid in candidate_fids):
        raise ValueError("missing retained fact candidate")
    action_by_sid = {}

    def checked_action(sid, fid):
        fact = fact_of(fid)
        if fact is None or sid not in facts.action_sids(fact):
            raise ValueError("action archive integrity")
        return fact

    if not incremental:
        for sid, fid in idx.execute(
                "SELECT sid, fid FROM actions ORDER BY sid"):
            checked_action(sid, fid)
            action_by_sid[sid] = fid

    active_cache = {}

    def active_binding(sid):
        if sid not in active_cache:
            row = idx.execute(
                "SELECT fid FROM actions WHERE sid=?",
                (sid,)).fetchone()
            if row is not None:
                checked_action(sid, row[0])
            active_cache[sid] = row[0] if row is not None else None
        return active_cache[sid]

    def fact_record(fact):
        selectors = sorted(facts.fact_scopes(fact))
        if len(selectors) > MAX_SELECTORS:
            raise ValueError("fact selector budget")
        proof = idx.execute(
            "SELECT rank FROM proofs WHERE fid=?", (fact.fid,)).fetchone()
        state = "eligible" if proof is not None else "dormant"
        exact_edges = admitted.edges(fact.fid) if proof is not None \
            else admitted.admission_edges(fact.fid)
        # Admission is historical replicated state: the lexicographically
        # smallest complete witness actually observed for these exact bytes.
        # Current dependencies are a separate canonical settlement result.
        admission_oid = admitted.admission_proof(fact.fid)
        if exact_edges is None or admission_oid is None:
            raise ValueError("FactRecord admission")
        dependencies = [
            [edge.role, edge.fid, edge.kind]
            for edge in exact_edges
        ]
        if len(dependencies) > MAX_DEPENDENCIES:
            raise ValueError("fact dependency budget")

        def edges_of(fid):
            if fid == fact.fid:
                return {
                    role: target
                    for role, target, _ in dependencies
                }
            standing = idx.execute(
                "SELECT 1 FROM proofs WHERE fid=?", (fid,)).fetchone()
            edges = admitted.edges(fid) if standing is not None \
                else admitted.admission_edges(fid)
            return {
                edge.role: edge.fid
                for edge in (edges or ())
            }

        # Selectors answer whether this fact is suppressed. Liveness ids
        # answer whether authority it depends on remains usable. Keeping both
        # in the record makes Worker reads explicit and bounded.
        liveness = set(facts.authority_scopes(
            fact, edges_of, fact_of)) - set(selectors)
        raw = encode(fact)
        raw_oid = h(raw)
        emitted = emit(raw)
        if emitted is not None and emitted != raw_oid:
            raise ValueError("candidate residence identity")
        return checked_fact_record({
            "admission": admission_oid,
            "dependencies": dependencies,
            "fact_oid": raw_oid,
            "key": fact.key,
            "liveness": sorted(liveness),
            "offers": [list(row) for row in fact.offers()],
            "rank": proof[0] if proof is not None else None,
            "selectors": selectors,
            "state": state,
        }, fact.fid)

    def active_slot(sid):
        # CLEAR is authenticated state for a reserved id, never shorthand for
        # an absent tree row. ACTIVE carries the deterministic archive winner.
        row = active_binding(sid) if incremental \
            else action_by_sid.get(sid)
        return {"state": "active", "action": row} \
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

    def principal_reserved(sid, fact):
        """Whether current standing still reserves this principal id."""
        family = facts.family_for(fact.t)
        policy = family.POLICY if family is not None else None
        declarations = {
            row.name: row.namespace
            for row in policy.principal_offers
        } if policy is not None else {}
        addresses = {
            (name, a0)
            for name, a0, _ in fact.offers()
            if name in declarations
            and facts.principal_sid(declarations[name], a0) == sid
        }
        for name, a0 in addresses:
            for (fid,) in idx.execute(
                    "SELECT o.src FROM fact_index o "
                    "JOIN proofs p ON p.fid=o.src "
                    "WHERE o.kind=? AND o.k0=? ORDER BY o.src",
                    (name, a0)):
                current = fact_of(fid)
                if current is not None and sid in facts.principal_sids(current):
                    return True
        return False

    def selector_reserved(sid):
        return idx.execute(
            "SELECT 1 FROM supp s JOIN proofs p ON p.fid=s.fid "
            "WHERE s.k=? LIMIT 1", (sid,)).fetchone() is not None

    def reserved_slot(sid, reserved):
        row = active_binding(sid)
        if row is not None:
            return {"state": "active", "action": row}
        return {"state": "clear"} if reserved else None

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
        changed_set = set(changed_fids)
        removed_set = set(removed_fids)
        if changed_set.intersection(removed_set):
            raise ValueError("overlapping fact index delta")
        if removed_set:
            raise ValueError("candidate deletion is unsupported")
        if not changed_set <= set(candidate_fids):
            raise ValueError("unpublished candidate index delta")
        fact_changes, supp_changes, addresses = {}, {}, set()
        represented = set()
        fact_reader = merkle_map.Reader(previous[FACT]["root"], seed, fetch)
        for fid in sorted(changed_set):
            fact = admitted.admitted(fid)
            if fact is None:
                raise ValueError("missing retained fact candidate")
            old_record = fact_reader.get(fact_key(fid))
            if old_record is not None:
                checked_fact_record(old_record, fid)
                fact_changes.update(
                    _posting_changes(fact, old_record, None))

            for name, a0, a1 in fact.offers():
                addresses.add((name, a0, a1))
                addresses.add((name, a0, None))

            current = fact_record(fact)
            value = {
                "state": POSTING_VALUE,
                "fid": fid,
                "eligibility": current["state"],
            }
            fact_changes.update(_posting_changes(fact, current, value))
            fact_changes[fact_key(fid)] = current
            represented.add(fid)
            if current["state"] == "eligible":
                fact_slots, supp_slots = reservations(fact)
                fact_changes.update(fact_slots)
                supp_changes.update(supp_slots)
                continue

            # Loss of standing changes the posting prefix but never deletes
            # the admitted candidate or its canonical fact object. Only
            # current authority reservations are withdrawn below.
            principal = facts.principal_sids(fact)
            for sid in facts.fact_scopes(fact):
                supp_changes[sid] = reserved_slot(
                    sid,
                    selector_reserved(sid)
                    or principal_reserved(sid, fact),
                )
            family = facts.family_for(fact.t)
            policy = family.POLICY if family is not None else None
            if policy is not None and policy.direct_targets:
                sid = fact_key(fid)
                fact_changes[action_key(sid)] = reserved_slot(sid, False)
            for sid in principal:
                reserved = principal_reserved(sid, fact)
                slot = reserved_slot(
                    sid, reserved or selector_reserved(sid))
                fact_changes[action_key(sid)] = reserved_slot(sid, reserved)
                supp_changes[sid] = slot

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
            result = merkle_map.update(
                previous[name]["root"], seed, change_sets[name], fetch, emit)
            built[name] = {
                "root": result.root,
                "count": result.count,
                "depth": result.page_depth,
            }
        return IndexBuild(seed, built, frozenset(represented))

    # Full rebuild is the reference definition of all three logical maps.
    # The action fact's historical admission pointer is the sole evidence;
    # no replica-local arrival order or duplicate pointer leaks into the map.
    fact_rows, supp_rows = {}, {}
    current = [admitted.admitted(fid) for fid in candidate_fids]
    represented = set()
    for fact in current:
        if fact is None:
            raise ValueError("missing admitted fact candidate")
        record = fact_record(fact)
        fact_rows[fact_key(fact.fid)] = record
        represented.add(fact.fid)
        fact_rows.update(_posting_changes(
            fact, record,
            {
                "state": POSTING_VALUE,
                "fid": fact.fid,
                "eligibility": record["state"],
            },
        ))
        if record["state"] == "eligible":
            fact_slots, supp_slots = reservations(fact)
            for key, value in fact_slots.items():
                fact_rows.setdefault(key, value)
            for key, value in supp_slots.items():
                supp_rows.setdefault(key, value)
    for _, sid in idx.execute(
            "SELECT s.fid, s.k FROM supp s "
            "JOIN proofs p ON p.fid=s.fid ORDER BY s.fid, s.k"):
        supp_rows.setdefault(sid, active_slot(sid))

    for sid, fid in action_by_sid.items():
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
        result = merkle_map.build(tuple(rows.items()), seed, emit)
        built[name] = {
            "root": result.root,
            "count": result.count,
            "depth": result.page_depth,
        }
    return IndexBuild(seed, built, frozenset(represented))
