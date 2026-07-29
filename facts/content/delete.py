"""facts/content/delete.py — an OWNER- or ADMIN-authorized exact action.

The proposal binds the target's canonical key, its exact ref, and the SELF
selector named by the target family's policy.  OWNER and ADMIN are ordinary
offer/need paths: OWNER compares durable member principals (so sibling devices
share ownership), while ADMIN requires an admin offer for the signing key.
"""

from core.fact import Fact, Need
from core.shape import fid_of, key_parts
from core.suppression import (
    SELF,
    TARGET,
    action,
    action_markers,
    action_target_key,
    is_deletion,
)
from .. import _policy
from .._commands import offer_source, publish
from ..auth import signature

TAG = "delete"
POLICY = _policy.FamilyPolicy(
    authorization_guards=("actor_authority",),
)


# SHAPE
def delete(pk, target_key, mode, ts):
    """Exact target address + selector token + hard target dependency."""
    target = fid_of(target_key)
    return Fact(
        TAG, ts,
        [
            action(_policy.CONTENT_DELETE, SELF, target_key),
            ["ref", TARGET, target],
        ],
        {"pk": pk, "mode": mode})


# NEEDS — OWNER and ADMIN are distinct conjunctive authority modes.
def needs(f):
    pk = f.body.get("pk", "")
    authority = "member" if f.body.get("mode") == _policy.OWNER else "admin"
    return (
        Need("author", "author", f.fid, pk),
        Need("actor_authority", authority, pk),
    )


# VALIDATE
def validate(f, ctx):
    try:
        import facts  # function-local: the router imports this package
        if set(f.body) != {"pk", "mode"}:
            return False
        pk, mode = f.body["pk"], f.body["mode"]
        if not isinstance(pk, str) or mode not in {
                _policy.OWNER, _policy.ADMIN}:
            return False
        ((name, target),) = f.refs()
        row = ctx.fact_meta(target)
        if row is None:
            return False
        target_ts, target_tag = row
        victim = facts.family_for(target_tag)
        target_key = action_target_key(f)
        if name != TARGET or victim is None or not victim.DURABLE \
                or target_tag == TAG or target_key is None \
                or key_parts(target_ts, target) != target_key \
                or action_markers(f) != (
                    action(_policy.CONTENT_DELETE, SELF, target_key),) \
                or not _policy.allows_direct_target(
                    victim.POLICY, _policy.CONTENT_DELETE, SELF, mode):
            return False

        target_policy = victim.POLICY
        if mode == _policy.OWNER:
            target_provider = ctx.edge_source(target, target_policy.owner_edge)
            actor_provider = ctx.provider("member", pk)
            if target_provider is None or actor_provider is None:
                return False
            target_members = ctx.offers_from(target_provider, "member")
            if not target_members:
                return False
            target_principal = _policy.member_principal(
                ctx, target_provider, target_members[0][0])
            actor_principal = _policy.member_principal(
                ctx, actor_provider, pk)
            if target_principal is None or target_principal != actor_principal:
                return False

        return is_deletion(f) and f == delete(pk, target_key, mode, f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


# COMMANDS
def remove(node, workspace, target, ts=None):
    """Choose OWNER when principals match, otherwise require ADMIN."""
    import facts
    from core.node import now_ms

    with node.lock:
        victim = node.fact_of(workspace, target)
        if victim is not None and node.suppressed(workspace, victim):
            raise ValueError("already removed")
    if victim is None:
        raise ValueError("no such fact")
    if is_deletion(victim):
        raise ValueError("removals are never victims")
    family = facts.family_for(victim.t)
    policy = family.POLICY if family is not None else None
    if policy is None or not _policy.allows_direct_target(
            policy, _policy.CONTENT_DELETE, SELF, _policy.OWNER):
        raise ValueError("fact type is not directly deleteable")
    ts = now_ms() if ts is None else ts
    secret, public = node.identity(workspace)
    with node.lock:
        actor_member = offer_source(node, workspace, "member", public)
        target_provider = node.idx(workspace).execute(
            "SELECT dst FROM edges WHERE src=? AND role=?",
            (victim.fid, policy.owner_edge)).fetchone()
        actor_principal = _policy.member_principal(
            node.idx(workspace), actor_member, public) if actor_member else None
        target_member = node.fact_of(
            workspace, target_provider[0]) if target_provider else None
        target_actor = None
        if target_member is not None:
            row = node.idx(workspace).execute(
                "SELECT k0 FROM fact_index "
                "WHERE src=? AND kind='member' "
                "ORDER BY k0 LIMIT 1", (target_provider[0],)).fetchone()
            target_actor = row[0] if row else None
        target_principal = _policy.member_principal(
            node.idx(workspace), target_provider[0], target_actor
        ) if target_provider and target_actor else None
        mode = _policy.OWNER if actor_principal is not None \
            and actor_principal == target_principal else _policy.ADMIN
        if mode == _policy.ADMIN and offer_source(
                node, workspace, "admin", public) is None:
            raise ValueError("only the owner or an admin may delete this fact")
    item = delete(public, victim.key, mode, ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts),
                   role="member" if mode == _policy.OWNER else "admin")


# QUERIES — none: deletion is visible only as the victim's absence.
CLI = {"content.delete.remove": remove}
