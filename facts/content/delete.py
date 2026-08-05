"""facts/content/delete.py — an OWNER- or ADMIN-authorized exact action.

The proposal binds the target's canonical key, its exact ref, and the SELF
selector named by the target family's policy.  OWNER and ADMIN are ordinary
offer/need paths: OWNER compares durable member principals (so sibling devices
share ownership), while ADMIN requires an admin offer for the device's owner.
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
from .._identity import actor_needs
from ..auth import signature

TAG = "delete"
POLICY = _policy.FamilyPolicy(control_fact=True)


# SHAPE
def delete(
        workspace, pk, target_key, mode, ts, owner=None, actor=None):
    """Exact target address + selector token + hard target dependency."""
    target = fid_of(target_key)
    owner = pk if owner is None else owner
    actor = pk if actor is None else actor
    return Fact(
        TAG, ts,
        [
            action(_policy.CONTENT_DELETE, SELF, target_key),
            ["ref", TARGET, target],
        ],
        {"actor": actor, "mode": mode, "owner": owner, "pk": pk},
        workspace,
    )


# NEEDS — OWNER and ADMIN are distinct conjunctive authority modes.
def needs(f):
    pk = f.body.get("pk", "")
    actor = f.body.get("actor", "")
    required = actor_needs(f, pk, actor)
    if f.body.get("mode") == _policy.ADMIN:
        required += (Need("actor_admin", "admin", actor),)
    return required


# VALIDATE
def validate(f, ctx):
    try:
        import facts  # function-local: the router imports this package
        if set(f.body) != {"actor", "mode", "owner", "pk"}:
            return False
        pk, actor = f.body["pk"], f.body["actor"]
        owner, mode = f.body["owner"], f.body["mode"]
        if not all(isinstance(value, str) for value in (pk, actor, owner)) \
                or mode not in {
                    _policy.OWNER, _policy.ADMIN} \
                or mode == _policy.OWNER and actor != owner:
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
            f.ws, pk, target_key, mode, f.ts, owner, actor)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def project_control(fact, fact_of):
    """Retain an exact deletion only when its target is authority state."""
    try:
        target = fact_of(fact.refs()[0][1])
        import facts

        family = None if target is None else facts.family_for(target.t)
        return family is not None and family.DURABLE \
            and family.POLICY.control_fact
    except (IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def remove(node, workspace, target, ts=None):
    """Choose OWNER when principals match, otherwise require ADMIN."""
    import facts
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
    ts = node.now_ms() if ts is None else ts
    secret, public = node.identity(workspace)
    with node.lock:
        target_principal = victim.body.get(policy.owner_field, "")
        actor_member, actor = member_source(node, workspace, public)
        if actor_member is None:
            raise ValueError("publishing device is not owned by a member")
        mode = _policy.OWNER \
            if actor == target_principal else _policy.ADMIN
        if mode == _policy.ADMIN and offer_source(
                node, workspace, "admin", actor) is None:
            raise ValueError("only the owner or an admin may delete this fact")
    item = delete(
        workspace, public, victim.key, mode, ts, target_principal, actor)
    return publish(
        node, workspace, item,
        signature.signature(secret, public, item, ts),
    )


# QUERIES — none: deletion is visible only as the victim's absence.
CLI = {"content.delete.remove": remove}
