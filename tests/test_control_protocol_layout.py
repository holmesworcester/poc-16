"""Structural ratchets for the one-CAS control-head transaction.

Behavioral suites exercise failures and provider outcomes.  These checks keep
the authority flow itself small: evaluate once, authenticate the resulting
plan, apply one removal-root turn, then CAS one final writer slot.
"""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (
    "core", "facts", "full_peer", "adapters", "deploy", "notifications")
EXCLUDED_PARTS = {
    "__pycache__", ".pytest_cache", ".venv", ".venv-workers", ".wrangler",
    "build", "generated", "node_modules", "python_modules",
}


def text(path):
    return (ROOT / path).read_text()


def parsed(path):
    return ast.parse(text(path), filename=path)


def definition(path, name, owner=None):
    body = parsed(path).body
    if owner is not None:
        body = next(
            item.body for item in body
            if isinstance(item, ast.ClassDef) and item.name == owner)
    return next(
        item for item in body
        if isinstance(item, (ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef))
        and item.name == name)


def segment(path, node):
    return ast.get_source_segment(text(path), node)


def production_text():
    sources = []
    for root_name in PRODUCTION_ROOTS:
        for path in (ROOT / root_name).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if EXCLUDED_PARTS.intersection(relative.parts) \
                    or any(part.startswith(".") for part in relative.parts) \
                    or path.name.startswith("test_") \
                    or "tests" in relative.parts:
                continue
            sources.append(path.read_text())
    return "\n".join(sources)


def test_control_permit_evaluates_once_then_applies_and_cas_final_slot():
    permit = text("core/head_permit.py")
    assert 'FORMAT = "poc16-control-head-permit-v3"' in permit
    claims = definition("core/head_permit.py", "_claims")
    returned = next(
        item.value for item in ast.walk(claims)
        if isinstance(item, ast.Return) and isinstance(item.value, ast.Dict))
    assert {
        key.value for key in returned.keys if isinstance(key, ast.Constant)
    } == {
        "base_head", "device", "head", "removal_root", "updates",
        "workspace",
    }
    assert all(name not in permit for name in (
        "control_oids", "proof_oid", "effects_oid"))

    commit_encoder = definition(
        "core/http.py", "encode_head_commit_request")
    assert [argument.arg for argument in commit_encoder.args.args] == [
        "permit"]
    assert "_encode_head_control" not in segment(
        "core/http.py", commit_encoder)

    issue = segment(
        "core/access.py",
        definition("core/access.py", "issue_head_permit", "AccessGate"),
    )
    assert issue.count("plan_control_missing(") == 1
    assert issue.count("encode_permit(") == 1

    commit = segment(
        "core/access.py",
        definition("core/access.py", "commit_head_permit", "AccessGate"),
    )
    freshness = commit.index("pin = await self.state.pin()")
    apply = commit.index("apply_updates(")
    finish = commit.index("advance_control(")
    assert freshness < apply < finish
    assert "plan_control(" not in commit
    assert "control_piles" not in commit

    removal_apply = segment(
        "core/removal_state.py",
        definition("core/removal_state.py", "_apply", "RecipientRemovalState"),
    )
    assert removal_apply.count("self.tree.apply(") == 1


def test_writer_slot_has_one_durable_shape_and_one_control_cas():
    production = production_text()
    assert "PendingHeadSlot" not in production
    assert "reserve_control" not in production
    assert "finish_control" not in production

    slot_document = segment(
        "core/writer_head.py",
        definition("core/writer_head.py", "slot_document"),
    )
    assert "HeadSlot" in slot_document
    assert "pending" not in slot_document

    advance = segment(
        "core/writer_repository.py",
        definition(
            "core/writer_repository.py", "_advance_slot", "OpaqueHeadGate"),
    )
    assert advance.count("self.store.cas(") == 1


def test_control_apply_and_owner_retry_loops_are_named_and_bounded():
    sync_slot = definition(
        "core/writer_repository.py", "_sync_slot", "RepositoryMirror")
    loops = [node for node in ast.walk(sync_slot) if isinstance(node, ast.For)]
    assert any(ast.unparse(node.iter) == "range(MAX_CONTROL_APPLY_ATTEMPTS)"
               for node in loops)

    publish = definition(
        "core/writer_repository.py", "publish", "OwnerPublisher")
    assert not any(isinstance(node, ast.While) for node in ast.walk(publish))
    loops = [node for node in ast.walk(publish) if isinstance(node, ast.For)]
    assert any(ast.unparse(node.iter)
               == "range(MAX_OWNER_CONTROL_COMMIT_ATTEMPTS)"
               for node in loops)


def test_signed_control_subsequence_cannot_bypass_the_fenced_route():
    writer_head = text("core/writer_head.py")
    head = definition("core/writer_head.py", "WriterHead")
    fields = {
        item.target.id for item in head.body
        if isinstance(item, ast.AnnAssign)
        and isinstance(item.target, ast.Name)
    }
    assert 'HEAD_FORMAT = "poc16-writer-head-v2"' in writer_head
    assert {"tree", "control"} <= fields
    assert '"control": tree_document(control)' in writer_head
    assert "head.control" in segment(
        "core/writer_head.py",
        definition("core/writer_head.py", "verify_head"),
    )

    repository = text("core/writer_repository.py")
    prepare = segment(
        "core/writer_repository.py",
        definition("core/writer_repository.py", "prepare", "WriterLog"),
    )
    assert "control_oids.append(oid)" in prepare
    assert "control = await append_piles_awaited(" in prepare

    access = text("core/access.py")
    ordinary = segment(
        "core/access.py",
        definition("core/access.py", "authorize_head", "AccessGate"),
    )
    issue = segment(
        "core/access.py",
        definition("core/access.py", "issue_head_permit", "AccessGate"),
    )
    assert "control_extension(" in ordinary and "if controls:" in ordinary
    assert "control_extension(" in issue
    assert "if supplied != declared:" in issue

    publish = segment(
        "core/writer_repository.py",
        definition("core/writer_repository.py", "publish", "OwnerPublisher"),
    )
    mirror = segment(
        "core/writer_repository.py",
        definition("core/writer_repository.py", "_sync_slot", "RepositoryMirror"),
    )
    assert 'raise ValueError("writer head control declaration")' in publish
    assert 'raise ValueError("writer head control declaration")' in mirror
    assert "control_extension" in repository


def test_control_observer_escape_hatch_is_confined_to_non_authority_roles():
    found = {}
    for root_name in PRODUCTION_ROOTS:
        for path in (ROOT / root_name).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if EXCLUDED_PARTS.intersection(relative.parts) \
                    or path.name.startswith("test_") \
                    or "tests" in relative.parts:
                continue
            count = sum(
                1 for call in ast.walk(ast.parse(path.read_text()))
                if isinstance(call, ast.Call)
                and any(
                    keyword.arg == "observe_controls"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in call.keywords
                )
            )
            if count:
                found[str(relative)] = count
    assert found == {
        "full_peer/sync.py": 1,
        "notifications/discovery.py": 2,
        "notifications/forest.py": 1,
    }
    node = text("full_peer/node.py")
    assert "control_state=access.state" in node


def test_permit_secret_is_stable_and_separate_from_bearer_grants():
    http = text("core/http.py")
    assert "self.permit_secret = permit_secret" in http
    assert "self.secret, self.now = secret, now" in http

    keychain = text("full_peer/keychain.py")
    stdlib = text("core/http_stdlib.py")
    assert '"permit_secret": os.urandom(32).hex()' in keychain
    assert '"permit_secret": self.peer.permit_secret' in stdlib
    assert "self.secret," in stdlib

    aws_template = text("deploy/aws_lambda/template.yaml")
    aws_runtime = text("deploy/aws_lambda/app.py")
    assert "GrantSecret:" in aws_template and "PermitSecret:" in aws_template
    assert "TINYP2P_GRANT_SECRET_ARN" in aws_runtime
    assert "TINYP2P_PERMIT_SECRET_ARN" in aws_runtime
    assert "grant_secret == permit_secret" in aws_runtime

    cf_config = text("deploy/cloudflare_worker/wrangler.jsonc")
    cf_runtime = text("deploy/cloudflare_worker/runtime.py")
    assert '"GRANT_SECRET"' in cf_config and '"PERMIT_SECRET"' in cf_config
    assert "permit_secret == grant_secret" in cf_runtime


def test_retired_authority_publication_surface_stays_absent():
    production = production_text()
    assert "AuthorityRepository.publish" not in production
    assert "_publish_authority" not in production
    assert "POST /authority" not in production

    handle = definition("core/http.py", "handle", "HttpGate")
    routes = {
        item.value for item in ast.walk(handle)
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.startswith("/")
    }
    assert "/authority" not in routes
    assert "/removal/apply" not in routes


def test_docs_state_the_one_cas_control_contract_and_cut_scope():
    design = text("DESIGN.md")
    readme = text("README.md")
    assert "Permit issuance is the only closed-pile evaluation in this turn." \
        in design
    assert "The commit body is exactly the returned bounded permit bytes" \
        in design
    assert "one base-guarded CAS of the sole final slot shape" in design
    assert "recipient-local audit and exact-replay metadata" in design
    assert "distinct from short-lived bearer-grant material" in design
    assert "append-only control-only pile subsequence" in design
    assert "independently recomputes" in readme
    assert "control declaration" in readme
    assert "There is no `POST /authority`," in design
    assert "`AuthorityRepository`, or mirror/replay" in design
    assert "defines the running architecture" in design
    assert "accepted target while" not in design
    assert "accepted target while" not in readme
    assert "with exactly the returned permit" in readme
    assert "`GRANT_SECRET` and `PERMIT_SECRET`" in readme
