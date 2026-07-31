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
POLICY = _policy.FamilyPolicy()


# SHAPE
def delete(workspace, pk, target_key, mode, ts, owner=None):
    """Exact target address + selector token + hard target dependency."""
    target = fid_of(target_key)
    owner = pk if owner is None else owner
    return Fact(
        TAG, ts,
        [
            action(_policy.CONTENT_DELETE, SELF, target_key),
            ["ref", TARGET, target],
        ],
        {"pk": pk, "owner": owner, "mode": mode}, workspace)


# NEEDS — OWNER and ADMIN are distinct conjunctive authority modes.
def needs(f):
    pk = f.body.get("pk", "")
    authority = "member" if f.body.get("mode") == _policy.OWNER else "admin"
    owner = f.body.get("owner", "")
    return (
        Need("author", "author", f.fid, pk),
        Need(
            "actor_authority", authority, pk,
            owner if authority == "member" else None),
    )


# VALIDATE
def validate(f, ctx):
    try:
        import facts  # function-local: the router imports this package
        if set(f.body) != {"pk", "owner", "mode"}:
            return False
        pk, owner, mode = f.body["pk"], f.body["owner"], f.body["mode"]
        if not isinstance(pk, str) or not isinstance(owner, str) \
                or mode not in {
                _policy.OWNER, _policy.ADMIN}:
            return False
        ((name, target),) = f.refs()
        target_fact = ctx.fact_of(target)
        if target_fact is None:
            return False
        target_ts, target_tag = target_fact.ts, target_fact.t
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
        if target_policy.owner_field is None \
                or target_fact.body.get(target_policy.owner_field) != owner:
            return False

        return is_deletion(f) and f == delete(
            f.ws, pk, target_key, mode, f.ts, owner)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def remove(node, workspace, target, ts=None):
    """Choose OWNER when principals match, otherwise require ADMIN."""
    import facts
    from core.node import now_ms
    from .._commands import member_source

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
        target_principal = victim.body.get(policy.owner_field, "")
        actor_member, _ = member_source(
            node, workspace, public, target_principal)
        mode = _policy.OWNER if actor_member is not None else _policy.ADMIN
        if mode == _policy.ADMIN and offer_source(
                node, workspace, "admin", public) is None:
            raise ValueError("only the owner or an admin may delete this fact")
    item = delete(
        workspace, public, victim.key, mode, ts, target_principal)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts),
                   role="member" if mode == _policy.OWNER else "admin")


# QUERIES — none: deletion is visible only as the victim's absence.
CLI = {"content.delete.remove": remove}
