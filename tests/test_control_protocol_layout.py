"""Structural ratchets for the v2 control-head transaction.

Behavioral suites exercise failures and provider outcomes.  These checks keep
the authority flow itself small: evaluate once, authenticate the resulting
plan, reserve one writer slot, apply one removal-root turn, then finalize.
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


def test_control_permit_evaluates_once_then_reserves_applies_and_finalizes():
    permit = text("core/head_permit.py")
    assert 'FORMAT = "poc16-control-head-permit-v2"' in permit
    claims = definition("core/head_permit.py", "_claims")
    returned = next(
        item.value for item in ast.walk(claims)
        if isinstance(item, ast.Return) and isinstance(item.value, ast.Dict))
    assert {
        key.value for key in returned.keys if isinstance(key, ast.Constant)
    } == {
        "base_head", "device", "head", "removal_root", "terminal_sids",
        "updates", "workspace",
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
    assert issue.count("plan_control(") == 1
    assert issue.count("encode_permit(") == 1

    commit = segment(
        "core/access.py",
        definition("core/access.py", "commit_head_permit", "AccessGate"),
    )
    reserve = commit.index("reserve_control(")
    apply = commit.index("apply_updates(")
    finish = commit.index("finish_control(")
    assert reserve < apply < finish
    assert "plan_control(" not in commit
    assert "control_piles" not in commit

    removal_apply = segment(
        "core/removal_state.py",
        definition("core/removal_state.py", "_apply", "RecipientRemovalState"),
    )
    assert removal_apply.count("self.tree.apply(") == 1


def test_pending_writer_slot_is_private_and_projects_the_previous_final():
    writer_head = text("core/writer_head.py")
    pending = segment(
        "core/writer_head.py",
        definition("core/writer_head.py", "PendingHeadSlot"),
    )
    visible = segment(
        "core/writer_head.py",
        definition("core/writer_head.py", "visible_slot"),
    )
    assert "previous: HeadSlot | None" in pending
    assert "head: str" in pending and "permit: str" in pending
    assert "state.previous" in visible
    assert "pending head slot is private" in writer_head

    repository = text("core/writer_repository.py")
    reserve = segment(
        "core/writer_repository.py",
        definition(
            "core/writer_repository.py", "reserve_control", "OpaqueHeadGate"),
    )
    finish = segment(
        "core/writer_repository.py",
        definition(
            "core/writer_repository.py", "finish_control", "OpaqueHeadGate"),
    )
    assert "PendingHeadSlot(" in reserve and ".store.cas(" in reserve
    assert "HeadSlot(" in finish and ".store.cas(" in finish
    assert repository.count("visible_slot_at(") >= 2
    assert "visible_slot_at(" in text("core/http.py")


def test_mirror_pending_recovery_is_local_and_attempt_bounded():
    finish = definition(
        "core/writer_repository.py",
        "_finish_reserved_control",
        "RepositoryMirror",
    )
    assert not any(isinstance(node, ast.While) for node in ast.walk(finish))
    loops = [node for node in ast.walk(finish) if isinstance(node, ast.For)]
    assert len(loops) == 1
    assert ast.unparse(loops[0].iter) \
        == "range(MAX_MIRROR_CONTROL_ATTEMPTS)"

    pending = segment(
        "core/writer_repository.py",
        definition(
            "core/writer_repository.py",
            "_pending_transition",
            "RepositoryMirror",
        ),
    )
    assert "self.store" in pending
    assert "source" not in pending
    repair = segment(
        "core/writer_repository.py",
        definition(
            "core/writer_repository.py",
            "_repair_local_slot",
            "RepositoryMirror",
        ),
    )
    replay = segment(
        "core/writer_repository.py",
        definition(
            "core/writer_repository.py",
            "replay_local",
            "RepositoryMirror",
        ),
    )
    assert "_resume_pending(" in repair
    assert "_repair_local_slot(" in replay


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


def test_docs_state_the_v2_control_contract_and_cut_scope():
    design = text("DESIGN.md")
    readme = text("README.md")
    assert "Permit issuance is the only closed-pile evaluation in this turn." \
        in design
    assert "The commit body is exactly the returned bounded permit bytes" \
        in design
    assert "private pending value" in design
    assert "recipient-local audit, replay, and fencing metadata" in design
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
