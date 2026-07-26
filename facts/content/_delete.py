"""facts/content/delete.py — a member-signed single-message deletion.

Cutover skeleton (oyd.7, docs/CUTOVER.md §4.7): the first PRODUCTION
deletion family, replacing tests/util.py's monkeypatched DeletionFamily as
the thing suppression laws run against. Underscore-prefixed until its body
lands: tests/test_fact_contract.py counts every non-underscore file here as
a registered family, so oyd.7 renames this to delete.py AND adds it to
content.MODULES in the same change. The removal-index entry is derived from
this fact at the author chokepoint (REMOVALS.md I6: the span comes from the
actual victim, never from a parameter).
"""
from core.fact import Fact
from core.suppression import TARGET, atom as supp

TAG = "delete"
TABLES = ()  # no projection rows: this family only retracts others' rows


# SHAPE
def delete(pk, channel, target, ts):
    """Clear envelope: one deletion marker for ``channel`` plus the hard
    target ref — ``[supp(channel, deletion=True), ["ref", TARGET, target]]``
    — body ``{"pk": pk}``. The target ref makes the victim a hard dep, so a
    closed store always holds the victim before the deletion (see
    core/node.py:apply_removals). The channel in the death marker is inert
    for reach (kind = TARGET ref); reach is exactly the target."""
    raise NotImplementedError


# NEEDS — author signature + membership, exactly like message.needs.
def needs(f):
    raise NotImplementedError


# VALIDATE — shape-exact (f == delete(...)), target must not itself be a
# deletion (I2), and exactly one death marker (I3's admission rule;
# suppression.is_deletion enforces exactly-one — reject, never collapse).
def validate(f, ctx):
    raise NotImplementedError


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE — nothing to insert; victims' rows leave via pump.retract.
def materialize(db, workspace, valid):
    raise NotImplementedError


# COMMANDS
def remove(node, workspace, target, ts=None):
    """Author-owned construction chokepoint: load the victim, derive the
    channel from it, author delete + signature, publish through the
    ordinary ingress (facts._commands.publish)."""
    raise NotImplementedError


# QUERIES — none: deletion is visible only as the victim's absence.
