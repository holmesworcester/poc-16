"""Authenticated mechanical indexes over the monotone validated fact set.

The repository stores each durable fact exactly once as canonical bytes.  The
FactTree binds ``fact:<fid>`` directly to that blob's object id and adds one
posting for every type, reconciliation key, explicit reference, offer, and
family-declared suppression/liveness scope.  No row records a validation
path, proof rank, admission witness, eligibility verdict, or dormant state.

SuppTree maps each known suppression id to CLEAR or ACTIVE(action_fid).
Provider offers remain mechanical FactTree postings. A proof names its exact
provider, so a database-free reader authenticates that fact directly and then
checks its declared SuppTree scopes instead of maintaining a redundant winner
projection.
"""

import base64
from typing import NamedTuple

import facts

from . import merkle_map
from .crypto import h
from .fact import canon
from .fact_index import SCOPE_INDEX, index_rows
from .shape import valid_fid

FACT = "fact"
SUPP = "supp"
TREE_NAMES = (FACT, SUPP)

MAX_SCOPES = 64
POSTING = "index:"
POSTING_VALUE = "validated"


class IndexPosting(NamedTuple):
    kind: str
    k0: str
    k1: str
    fid: str


class PostingPage(NamedTuple):
    rows: tuple[IndexPosting, ...]
    cursor: str | None
    pages_read: int


def layout_seed(anchor):
    """Pin every authenticated map to the workspace and current layout."""
    return h(canon(["composite-layout-seed-v1", anchor]))


def fact_key(fid):
    return "fact:" + fid


def checked_fact_oid(value):
    """Validate a FactTree residence value before it can drive an object read."""
    if not valid_fid(value):
        raise ValueError("fact object id")
    return value


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


def posting_prefix(kind, k0=None, k1=None):
    """Collision-free ordered prefix for one generic index address."""
    if not isinstance(kind, str) or not kind or k1 is not None and k0 is None:
        raise ValueError("fact index address")
    parts = [_component(kind)]
    if k0 is not None:
        parts.append(_component(k0))
    if k1 is not None:
        parts.append(_component(k1))
    return POSTING + ":".join(parts) + ":"


def posting_key(kind, k0, k1, fid):
    """Address one immutable posting without proof or eligibility ordering."""
    if not valid_fid(fid):
        raise ValueError("fact index posting")
    return posting_prefix(kind, k0, k1) + fid


def decode_posting_key(key):
    """Strictly decode and re-encode one authenticated posting key."""
    try:
        namespace, kind, k0, k1, fid = key.split(":")
        row = IndexPosting(
            _decode_component(kind),
            _decode_component(k0),
            _decode_component(k1),
            fid,
        )
        if namespace != POSTING[:-1] or posting_key(*row) != key:
            raise ValueError("fact index posting")
        return row
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("fact index posting") from error


def posting_page(
        reader, kind, k0=None, k1=None, *, after=None,
        limit=merkle_map.MAX_RANGE_ROWS):
    """Read one authenticated posting page without scanning FactTree."""
    prefix = posting_prefix(kind, k0, k1)
    page = reader.range_page(
        prefix, prefix + "\uffff", after=after, limit=limit)
    rows = []
    for key, value in page.rows:
        row = decode_posting_key(key)
        if value != {"state": POSTING_VALUE, "fid": row.fid}:
            raise ValueError("fact index posting value")
        if row.kind != kind \
                or k0 is not None and row.k0 != k0 \
                or k1 is not None and row.k1 != k1:
            raise ValueError("fact index posting range")
        rows.append(row)
    return PostingPage(tuple(rows), page.cursor, reader.pages_read)


def is_posting_key(key):
    return isinstance(key, str) and key.startswith(POSTING)


principal_sid = facts.principal_sid


def _record_index_rows(fact):
    rows = set(index_rows(fact))
    scopes = facts.current_scopes(fact)
    if len(scopes) > MAX_SCOPES:
        raise ValueError("fact scope budget")
    return tuple(sorted(rows))


def record_postings(fact):
    """Mechanical authenticated posting keys contributed by one fact."""
    return {
        posting_key(kind, k0, k1, fact.fid)
        for kind, k0, k1, _ in _record_index_rows(fact)
    }


__all__ = (
    "FACT",
    "IndexPosting",
    "MAX_SCOPES",
    "POSTING",
    "POSTING_VALUE",
    "PostingPage",
    "SCOPE_INDEX",
    "SUPP",
    "TREE_NAMES",
    "checked_fact_oid",
    "decode_posting_key",
    "fact_key",
    "is_posting_key",
    "layout_seed",
    "posting_key",
    "posting_page",
    "posting_prefix",
    "principal_sid",
    "record_postings",
)
