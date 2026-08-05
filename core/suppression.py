"""Clear-envelope explicit selectors and exact action targets."""

from . import shape
from .limits import (
    MAX_ATOM_NAME_BYTES,
    valid_bounded_text,
)

ATOM = "supp"
TARGET = "target"
SELF = "self"
PARENT = "parent"
ANCESTOR = "ancestor"
ACTION = "action"


def scoped_id(namespace, value):
    """A typed suppression id whose namespace is declared by a fact family."""
    if not isinstance(namespace, str) or not namespace \
            or not isinstance(value, str) or not value \
            or ":" in namespace:
        raise ValueError("suppression id")
    return f"{namespace}:{value}"


def suppression_slot(action_fid=None):
    """Construct one canonical current suppression value."""
    if action_fid is None:
        return {"state": "clear"}
    if not shape.valid_fid(action_fid):
        raise ValueError("suppression action")
    return {"state": "active", "action": action_fid}


def checked_suppression_slot(value):
    """Validate one authenticated RemovalTree value."""
    if value == {"state": "clear"}:
        return value
    if isinstance(value, dict) \
            and set(value) == {"state", "action"} \
            and value.get("state") == "active" \
            and shape.valid_fid(value.get("action")):
        return value
    raise ValueError("missing SuppSlot")


def self_selector():
    """Non-circular SELF placeholder; readers expand it after fid integrity."""
    return [ATOM, SELF]


def parent_selector(role, fid):
    if not valid_bounded_text(
            role, MAX_ATOM_NAME_BYTES) or not shape.valid_fid(fid):
        raise ValueError("parent selector")
    return [ATOM, PARENT, role, fid]


def _valid_ancestor_path(path):
    if not valid_bounded_text(path, MAX_ATOM_NAME_BYTES):
        return False
    roles = path.split("/")
    return len(roles) >= 2 and all(
        valid_bounded_text(role, MAX_ATOM_NAME_BYTES)
        for role in roles
    )


def ancestor_selector(path, fid):
    if not _valid_ancestor_path(path) \
            or not shape.valid_fid(fid):
        raise ValueError("ancestor selector")
    return [ATOM, ANCESTOR, path, fid]


def action(name, selector, target_key):
    """Bind an action to an exact target address and selector token."""
    if not valid_bounded_text(
            name, MAX_ATOM_NAME_BYTES) or selector != SELF \
            or not shape.is_key(target_key):
        raise ValueError("suppression action")
    return [ACTION, name, selector, target_key]


def valid_selector_marker(entry):
    return entry == [ATOM, SELF] or (
        isinstance(entry, list) and len(entry) == 4
        and entry[0] == ATOM and entry[1] == PARENT
        and valid_bounded_text(entry[2], MAX_ATOM_NAME_BYTES)
        and shape.valid_fid(entry[3])
    ) or (
        isinstance(entry, list) and len(entry) == 4
        and entry[0] == ATOM and entry[1] == ANCESTOR
        and _valid_ancestor_path(entry[2])
        and shape.valid_fid(entry[3])
    )


def selector_markers(fact):
    """Every syntactically valid explicit selector, preserving wire order."""
    out = []
    for entry in fact.atoms:
        if valid_selector_marker(entry):
            out.append(entry)
    return tuple(out)


def valid_action_marker(entry):
    return isinstance(entry, list) and len(entry) == 4 \
        and entry[0] == ACTION \
        and valid_bounded_text(entry[1], MAX_ATOM_NAME_BYTES) \
        and entry[2] == SELF and shape.is_key(entry[3])


def action_markers(fact):
    return tuple(
        entry for entry in fact.atoms
        if valid_action_marker(entry)
    )


def suppkeys(fact):
    """Resolved suppression ids offered by the clear envelope.

    SELF expands only after ``fact.fid`` has passed envelope integrity.
    Parent and ancestor selectors already carry exact ancestor fids.
    """
    return frozenset({
        "fact:" + (fact.fid if marker[1] == SELF else marker[3])
        for marker in selector_markers(fact)
    })


def deathkey(fact):
    """The one sid activated by an exact action."""
    actions = action_markers(fact)
    return "fact:" + shape.fid_of(actions[0][3]) \
        if len(actions) == 1 else None


def action_target_key(fact):
    actions = action_markers(fact)
    return actions[0][3] if len(actions) == 1 else None


def action_target_fid(fact):
    target_key = action_target_key(fact)
    return shape.fid_of(target_key) if target_key else None


def is_deletion(fact):
    """Whether the envelope carries exactly one canonical suppression action."""
    return deathkey(fact) is not None
