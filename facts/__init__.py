"""Fact-family router.

Core code dispatches through this table and contains no auth/content tags.
Scope packages are deliberately just tables of contents.
"""
import inspect

from . import auth, content
from core.suppression import deathkey, is_deletion, scoped_id, suppkeys
from ._policy import validate_fact_policy, validate_family_policy

MODULES = auth.MODULES + content.MODULES


def _principal_namespaces(modules):
    """Map each globally resolved principal offer to one namespace."""
    out = {}
    for module in modules:
        for declaration in module.POLICY.principal_offers:
            incumbent = out.setdefault(
                declaration.name, declaration.namespace)
            if incumbent != declaration.namespace:
                raise ValueError(
                    f"principal offer namespace conflict: "
                    f"{declaration.name!r}")
    return out


def compile_families(modules):
    """Validate and freeze the one behavior+policy dispatch inventory."""
    modules = tuple(modules)
    families = {module.TAG: module for module in modules}
    if len(families) != len(modules):
        raise ValueError("duplicate fact tag")
    if any(not hasattr(module, "POLICY") for module in modules):
        raise ValueError("every fact family must own its policy")
    for module in modules:
        validate_family_policy(module.POLICY)
    _principal_namespaces(modules)
    if sum(bool(getattr(module, "GENESIS", False)) for module in modules) != 1:
        raise ValueError("exactly one genesis family required")
    return families


FAMILIES = compile_families(MODULES)
MAX_AUTHORITY_SCOPES = 64


PRINCIPAL_NAMESPACES = _principal_namespaces(MODULES)


class WorkspaceNotFound(LookupError):
    """A command named no unique local workspace."""


def compile_commands(modules):
    """Merge the explicit family-owned ``scope.family.verb`` inventory."""
    commands = {}
    for module in modules:
        declared = getattr(module, "CLI", {})
        if not isinstance(declared, dict):
            raise ValueError(f"{module.__name__} CLI must be a dict")
        for path, handler in declared.items():
            if not isinstance(path, str) or path.count(".") < 2 \
                    or not path.replace(".", "_").isidentifier() \
                    or path != path.lower() \
                    or not callable(handler):
                raise ValueError(f"bad CLI declaration: {path!r}")
            if path in commands:
                raise ValueError(f"duplicate CLI command: {path}")
            commands[path] = handler
    return commands


COMMANDS = compile_commands(MODULES)


def compile_proof_commands(modules):
    """Merge family-owned ephemeral proof constructors by exact purpose."""
    commands = {}
    for module in modules:
        declared = getattr(module, "PROOF_COMMANDS", {})
        if not isinstance(declared, dict):
            raise ValueError(f"{module.__name__} PROOF_COMMANDS must be a dict")
        for purpose, handler in declared.items():
            if not isinstance(purpose, str) or not purpose \
                    or purpose in commands or not callable(handler):
                raise ValueError(f"bad proof command: {purpose!r}")
            commands[purpose] = handler
    return commands


PROOF_COMMANDS = compile_proof_commands(MODULES)


def proof_payload(node, workspace, purpose, exp, ts):
    """Ask the registered fact family to author one ephemeral proof closure."""
    try:
        command = PROOF_COMMANDS[purpose]
    except KeyError:
        raise ValueError(f"unknown proof purpose: {purpose}") from None
    return command(node, workspace, purpose, exp, ts)


def workspace_for(node, prefix):
    """Resolve an exact workspace id or unique prefix at the host boundary."""
    hits = [ws for ws in node.workspaces() if prefix and ws.startswith(prefix)]
    if len(hits) != 1:
        state = "ambiguous" if hits else "unknown"
        raise WorkspaceNotFound(f"{state} workspace prefix: {prefix}")
    return hits[0]


def invoke_command(node, path, argv):
    """Bind raw tokens; resolve ``workspace`` prefixes and parse ``ts``."""
    command = COMMANDS[path]
    try:
        bound = inspect.signature(command).bind(node, *argv)
    except TypeError as error:
        raise ValueError(f"{path}: {error}") from None
    if "workspace" in bound.arguments:
        bound.arguments["workspace"] = workspace_for(
            node, bound.arguments["workspace"])
    if (value := bound.arguments.get("ts")) is not None:
        try:
            bound.arguments["ts"] = int(value)
        except ValueError:
            raise ValueError("ts must be an integer") from None
    return command(*bound.args, **bound.kwargs)


def family_for(tag):
    """The one checked dispatch table: behavior and policy travel together."""
    return FAMILIES.get(tag)


def authorize_writer_head(
        judgment, stream, view, writer, proposed_head, trusted_now):
    """Dispatch one pinned-current exact-head decision through its family."""
    decisions = []
    for valid in judgment.valids:
        family = family_for(valid.fact.t)
        authorize = getattr(family, "authorize_head", None)
        if callable(authorize):
            decision = authorize(
                view, valid, stream, writer, proposed_head, trusted_now)
            if decision is not None:
                decisions.append(decision)
    return decisions[0] if len(decisions) == 1 else None


def authorize_access(judgment, stream, view, trusted_now, *, purpose):
    """Dispatch one ephemeral access request from a signed pile judgment.

    The caller supplies a verifier-pinned current-authority view.  The pile
    supplies its complete historical membership closure, while the view
    decides whether the exact selected provider is still current and clear.
    """
    ephemeral = []
    for valid in judgment.valids:
        family = family_for(valid.fact.t)
        if family is not None and not family.DURABLE:
            ephemeral.append((family, valid))
    if len(ephemeral) != 1:
        return None
    family, valid = ephemeral[0]
    authorize = getattr(family, "authorize", None)
    return authorize(
        view,
        valid,
        stream,
        trusted_now,
        purpose=purpose,
    ) if callable(authorize) else None


def is_genesis(tag):
    """Whether ``tag`` owns the registry's sole ws-less fact shape."""
    family = family_for(tag)
    return family is not None and bool(getattr(family, "GENESIS", False))


def _offer_sids(fact, declarations):
    return {
        scoped_id(row.namespace, a0)
        for row in declarations
        for name, a0, _ in fact.offers()
        if name == row.name
    }


def fact_scopes(fact):
    """Explicit SELF/parent/ancestor ids which may suppress this fact."""
    return frozenset(suppkeys(fact))


def principal_sids(fact):
    """Family-declared typed ids for authority offered by this fact."""
    family = family_for(fact.t)
    return frozenset() if family is None else frozenset(
        _offer_sids(fact, family.POLICY.principal_offers))


def authority_scopes(fact):
    """Return continuing-liveness ids declared by this fact's own policy.

    Liveness must be recoverable from immutable fact bytes.  A guard names one
    of the family's declared Needs; the Need address contributes the typed
    principal id directly.  No selected provider, admission edge, or
    historical validation path is persisted or replayed.
    """
    family = family_for(fact.t)
    if family is None:
        raise ValueError("authority liveness family")
    declared = tuple(family.needs(fact))
    needs = {need.role: need for need in declared}
    if len(needs) != len(declared):
        raise ValueError("duplicate authority need role")
    out = set()
    for role in family.POLICY.authority_liveness_guards:
        need = needs.get(role)
        namespace = None if need is None else \
            PRINCIPAL_NAMESPACES.get(need.name)
        if namespace is None:
            raise ValueError("authority liveness declaration")
        # Principal-bearing offers use a1 for the durable identity and a0 for
        # the concrete signing key. Direct users have the same value in both
        # positions; devices thereby inherit their owner's liveness.
        out.add(principal_sid(namespace, need.a1 or need.a0))
    if len(out) > MAX_AUTHORITY_SCOPES:
        raise ValueError("authority liveness scope budget")
    return frozenset(out)


def current_scopes(fact):
    """All explicit, principal, and policy-declared current liveness ids."""
    return fact_scopes(fact) | principal_sids(fact) | authority_scopes(fact)


def explicit_provider(fact, role):
    """Return a provider fid explicitly named by a suppression path.

    A parent selector may pin a direct Need. Ancestor paths traverse immutable
    refs only, so they never select an interchangeable provider here.
    """
    from core.suppression import selector_markers

    matches = {
        marker[3]
        for marker in selector_markers(fact)
        if len(marker) == 4
        and marker[1] == "parent"
        and marker[2] == role
    }
    if len(matches) > 1:
        raise ValueError(f"ambiguous explicit provider for {role!r}")
    return next(iter(matches), None)


def action_sids(fact):
    """Every typed id activated by this validated action family."""
    family = family_for(fact.t)
    out = {deathkey(fact)} if is_deletion(fact) else set()
    if family is not None:
        out.update(_offer_sids(fact, family.POLICY.action_offers))
    return frozenset(out)


def principal_sid(namespace, public_key):
    """Address one family-declared principal slot for an exact Worker read."""
    return scoped_id(namespace, public_key)
