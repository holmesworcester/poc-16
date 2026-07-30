"""Authenticated index keys, values, and bounded read helpers.

This module defines no repository build path.  ``repository_snapshot`` is the
one compiler that derives FactTree, SuppTree, AuthorityTree, and FactOrder.

FactTree contains one bounded record per admitted candidate plus mechanical
type/key/reference/offer postings and action corroboration slots.  SuppTree
maps every declared suppression id to either:

* ``CLEAR``: the id is known and currently has no effective suppression action;
* ``ACTIVE(action_fid)``: the named immutable action is effective at this root.

An absent required suppression row is not CLEAR; readers fail closed.  This
supports explicit SELF, parent, grandparent, and multi-ancestor suppression
keys without guessing from fact shape.  Families that expose no suppression
keys produce no suppressible slot.

AuthorityTree maps a canonical family need address to its selected provider
and proof rank.  A reader can therefore check authentication, member/device
liveness, suppression, and family policy with bounded authenticated point or
range reads and without loading the fact set or SQLite.
"""

import base64
from typing import NamedTuple

import facts

from . import merkle_map
from .crypto import h
from .fact import canon
from .fact_index import index_rows
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
    kind: str
    k0: str
    k1: str
    rank: int | None
    fid: str
    state: str = "eligible"


class PostingPage(NamedTuple):
    rows: tuple[IndexPosting, ...]
    cursor: str | None
    pages_read: int


def layout_seed(anchor):
    """Pin every authenticated map to the workspace and current layout."""
    return h(canon(["composite-layout-seed-v1", anchor]))


def fact_key(fid):
    return "fact:" + fid


def action_key(sid):
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
            altchars=b"-_",
            validate=True,
        )
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
    """Address a posting in eligibility/rank/fid order."""
    if state not in {"eligible", "dormant"} \
            or not valid_fid(fid) \
            or state == "eligible" and (
                type(rank) is not int or not 0 <= rank <= MAX_PROOF_RANK) \
            or state == "dormant" and rank is not None:
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
        if state == "eligible" and len(rank) != 20 \
                or state == "dormant" and rank != "-" \
                or posting_key(*row) != key:
            raise ValueError("fact index posting")
        return row
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError("fact index posting") from error


def posting_page(
        reader, kind, k0=None, k1=None, *, after=None,
        limit=merkle_map.MAX_RANGE_ROWS, include_dormant=False):
    """Read one authenticated posting page without scanning FactTree."""
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
    if not isinstance(record, dict) \
            or set(record) != fields \
            or not is_key(record["key"]) \
            or fid is not None and fid_of(record["key"]) != fid \
            or record["state"] not in {"eligible", "dormant"} \
            or record["state"] == "eligible" and (
                type(record["rank"]) is not int
                or not 0 <= record["rank"] <= MAX_PROOF_RANK) \
            or record["state"] == "dormant" and record["rank"] is not None \
            or not valid_fid(record["admission"]) \
            or not valid_fid(record["fact_oid"]):
        raise ValueError("FactRecord shape")

    selectors, liveness = record["selectors"], record["liveness"]
    if not isinstance(selectors, list) \
            or selectors != sorted(set(selectors)) \
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


def need_key(name, a0, a1=None):
    """Canonical base authority address.

    Required co-offers never alter this key. Readers check them on the
    selected provider's authenticated FactRecord.
    """
    return canon(["need", name, a0, a1]).decode()


__all__ = (
    "AUTHORITY",
    "DEPENDENCY_INDEX",
    "DORMANT_POSTING",
    "FACT",
    "IndexPosting",
    "MAX_DEPENDENCIES",
    "MAX_PROOF_RANK",
    "MAX_SELECTORS",
    "POSTING",
    "POSTING_VALUE",
    "PostingPage",
    "SCOPE_INDEX",
    "SUPP",
    "TREE_NAMES",
    "action_key",
    "checked_fact_record",
    "decode_posting_key",
    "fact_key",
    "is_posting_key",
    "layout_seed",
    "need_key",
    "posting_key",
    "posting_page",
    "posting_prefix",
    "principal_sid",
    "record_postings",
)
