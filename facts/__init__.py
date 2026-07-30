"""Fact-family router.

Core code dispatches through this table and contains no auth/content tags.
Scope packages are deliberately just tables of contents.
"""
import inspect

from . import auth, content
from core.suppression import deathkey, is_deletion, scoped_id, suppkeys
from ._policy import validate_fact_policy, validate_family_policy

MODULES = auth.MODULES + content.MODULES


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
    if sum(bool(getattr(module, "GENESIS", False)) for module in modules) != 1:
        raise ValueError("exactly one genesis family required")
    return families


FAMILIES = compile_families(MODULES)
MAX_AUTHORITY_SCOPES = 64


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


def is_genesis(tag):
    """Whether ``tag`` owns the registry's sole ws-less fact shape."""
    family = family_for(tag)
    return family is not None and bool(getattr(family, "GENESIS", False))


def _offer_sids(fact, declarations):
    by_name = {row.name: row.namespace for row in declarations}
    return {
        scoped_id(by_name[name], a0)
        for name, a0, _ in fact.offers()
        if name in by_name
    }


def fact_scopes(fact):
    """Explicit SELF/parent/ancestor ids which may suppress this fact."""
    return frozenset(suppkeys(fact))


def principal_sids(fact):
    """Family-declared typed ids for authority offered by this fact."""
    family = family_for(fact.t)
    return frozenset() if family is None else frozenset(
        _offer_sids(fact, family.POLICY.principal_offers))


def authority_scopes(fact, edges_of, fact_of):
    """Transitively expand the declared continuing liveness of authority.

    Only family-declared ``authority_liveness_guards`` are followed.  This is
    not a walk over every dependency: it is a bounded expansion of explicit
    policy edges, so a delegated admin carried by a child device inherits that
    device provider's user/device liveness without making unrelated proof
    support revocable.
    """
    out, seen, pending = set(), set(), [fact]
    while pending:
        provider = pending.pop()
        if provider.fid in seen:
            continue
        seen.add(provider.fid)
        if len(seen) > MAX_AUTHORITY_SCOPES:
            raise ValueError("authority liveness budget")
        out.update(fact_scopes(provider))
        out.update(principal_sids(provider))
        family = family_for(provider.t)
        if family is None:
            raise ValueError("authority liveness family")
        edges = edges_of(provider.fid)
        for role in family.POLICY.authority_liveness_guards:
            guarded = fact_of(edges.get(role))
            if guarded is None:
                raise ValueError("authority liveness edge")
            pending.append(guarded)
    if len(out) > MAX_AUTHORITY_SCOPES:
        raise ValueError("authority liveness scope budget")
    return frozenset(out)


def authorization_scopes(fact, edges, edges_of, fact_of):
    """Exact live scopes required to admit this irreversible effect."""
    family = family_for(fact.t)
    if family is None:
        raise ValueError("authorization family")
    by_role = {edge.role: edge.fid for edge in edges}
    out = set()
    for role in family.POLICY.authorization_guards:
        provider = fact_of(by_role.get(role))
        if provider is None:
            raise ValueError("authorization guard edge")
        out.update(authority_scopes(provider, edges_of, fact_of))
    if len(out) > MAX_AUTHORITY_SCOPES:
        raise ValueError("authorization scope budget")
    return frozenset(out)


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


def blob_refs(fact):
    """Return immutable object hashes named by a fact, if that family has any."""
    hook = getattr(FAMILIES[fact.t], "blob_refs", None)
    return tuple(hook(fact)) if hook is not None else ()
