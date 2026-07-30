"""Mechanical generic-index rows contributed by one canonical fact.

This module is deliberately storage-free.  Both the disposable SQLite client
projection and the authenticated repository compiler consume this exact
function, so adding a fact family cannot create two indexing definitions.
"""
import facts

TYPE_INDEX = "fact.type"
KEY_INDEX = "fact.key"
REF_INDEX = "fact.ref"
STATE_INDEX = "projection.state"
EDGE_INDEX = "projection.edge"
ACTION_INDEX = "projection.action"
INTERNAL_INDEXES = frozenset((
    TYPE_INDEX,
    KEY_INDEX,
    REF_INDEX,
    STATE_INDEX,
    EDGE_INDEX,
    ACTION_INDEX,
))


def index_rows(fact):
    """Return every family-neutral lookup row contributed by ``fact``."""
    if any(name in INTERNAL_INDEXES for name, _, _ in fact.offers()):
        raise ValueError("reserved fact index kind")
    return (
        (TYPE_INDEX, fact.t, "", fact.fid),
        (KEY_INDEX, fact.key, "", fact.fid),
        *((REF_INDEX, role, target, fact.fid)
          for role, target in fact.refs()),
        *((*offer, fact.fid) for offer in fact.offers()),
    )
