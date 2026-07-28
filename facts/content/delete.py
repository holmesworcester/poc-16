"""facts/content/delete.py — a member-signed single-message deletion.

The first PRODUCTION deletion family (oyd.7, docs/CUTOVER.md §4.7),
replacing tests/util.py's monkeypatched DeletionFamily as the thing
suppression laws run against. The removal-index entry is derived from this
fact at the author chokepoint (REMOVALS.md I6: the span comes from the
actual victim, never from a parameter). Deletion is visible only as the
victim's absence: no projection rows — victims' rows leave via pump.retract.

TRANSITION POLICY: docs/TODO.md now settles the replacement as two ordinary
OWNER/ADMIN handlers over a target's type-owned DeleteOffer and retained
OwnerBinding. This legacy body intentionally remains authorship + membership,
so any member can still delete any member's content until the coordinated S5
semantic cut installs receipts and switches the handler atomically. Changing
this function alone would fork old and new validation during shadow mode.
"""
import json

from core.fact import Fact
from core.suppression import TARGET, atom as supp, is_deletion, suppkeys
from .._commands import publish
from ..auth import signature

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
    return Fact(
        TAG, ts, [supp(channel, deletion=True), ["ref", TARGET, target]],
        {"pk": pk})


# NEEDS — author signature + membership, exactly like message.needs.
def needs(f):
    pk = f.body.get("pk", "")
    return (("author", f.fid, pk), ("member", pk, None))


# VALIDATE — shape-exact (f == delete(...) AND is_deletion): exactly one
# death marker (I3's admission rule) and one TARGET ref, so mixed extra
# markers reject structurally. The shape check alone would admit a
# non-string channel as a delete-family fact that is no deletion; the
# family owns that guarantee rather than borrowing it from the wire codec.
# The victim must be a DURABLE fact of a known family: a deletion is a
# permanent statement about a permanent fact, and an ephemeral target is
# never resident, so its entry has no key to span (node.removal_entries) —
# admitting one lets any member wedge every peer's turn() forever.
# Target-is-a-deletion (I2) rejects at the family-tag level — the judge's
# scratch db holds only (fid, ts, t) — while the marker-level guard stays
# load-bearing in removals.applies.
def validate(f, ctx):
    try:
        import facts  # function-local: the router imports this package
        pk = f.body.get("pk")
        ((name, target),) = f.refs()
        row = ctx.db.execute(
            "SELECT t FROM facts WHERE fid=?", (target,)).fetchone()
        victim = facts.handler_for(row[0]) if row else None
        return isinstance(pk, str) and name == TARGET \
            and victim is not None and victim.DURABLE and row[0] != TAG \
            and is_deletion(f) \
            and f == delete(pk, f.atoms[0][2], target, f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE — nothing to insert; victims' rows leave via pump.retract.
def materialize(db, workspace, valid):
    return None


# COMMANDS
def remove(node, workspace, target, ts=None):
    """Author-owned construction chokepoint: load the victim, derive the
    channel from it (its first suppression group — inert for reach, so the
    pick only scopes display/auth), author delete + signature, publish
    through the ordinary ingress (facts._commands.publish). Rejects a victim
    that is itself a deletion (I2), that declares no suppression group
    (auth facts are outside this content family's domain), or that a known
    entry already suppresses — the index is grow-only (I1), so a second
    entry for one victim costs every syncing peer bytes and buys nothing.
    That last one is hygiene, not a bound: a hostile author signs a
    duplicate directly, and peers admit it."""
    from core.node import now_ms

    with node.lock:
        victim = node.fact_of(workspace, target)
        if victim is not None and node.suppressed(
                workspace, victim, node.removal_entries(workspace)):
            raise ValueError("already removed")
    if victim is None:
        raise ValueError("no such fact")
    if is_deletion(victim):
        raise ValueError("removals are never victims")  # I2
    groups = sorted(json.loads(group)[1] for group in suppkeys(victim))
    if not groups:
        raise ValueError("victim declares no suppression group")
    ts = ts or now_ms()
    secret, public = node.identity(workspace)
    item = delete(public, groups[0], victim.fid, ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts))


# QUERIES — none: deletion is visible only as the victim's absence.
