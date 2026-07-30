"""Cloudflare R2 ingress-role policy, signer, and lifecycle tests."""
import json
from pathlib import Path

import pytest

from core.staged_intent import staging_key, staging_prefix
from deploy.cloudflare_upload import manage
from deploy.cloudflare_upload.boundary import (
    BROKER_SECRET_NAMES,
    OWNER_BINDING,
    READ_GROUP,
    ROLE_BINDING,
    WRITE_GROUP,
    Deployment,
    access_policies,
    broker_config,
    bucket_resource,
    generated_boundary,
    ingress_lifecycle,
    publisher_config,
)


def deployment(**changes):
    values = {
        "account_id": "a" * 32,
        "workspace": "b" * 64,
        "canonical_bucket": "poc16-canonical",
        "ingress_bucket": "poc16-untrusted-ingress",
        "owner": "production-west",
        "broker_name": "poc16-upload-broker",
        "publisher_name": "poc16-upload-publisher",
        "read_permission_group_id": "c" * 32,
        "write_permission_group_id": "d" * 32,
    }
    values.update(changes)
    return Deployment(**values)


def _policy_allows(candidate, policy, bucket, action):
    """Interpret the documented R2 bucket-item permission categories."""
    resource = bucket_resource(candidate, bucket)
    actions = {
        READ_GROUP: frozenset({"GET", "HEAD", "LIST"}),
        WRITE_GROUP: frozenset({
            "GET", "HEAD", "LIST", "PUT", "DELETE",
        }),
    }
    for statement in policy["policies"]:
        if statement["effect"] != "allow" \
                or resource not in statement["resources"]:
            continue
        if any(action in actions[group["name"]]
               for group in statement["permission_groups"]):
            return True
    return False


def test_generated_roles_put_provider_enforcement_before_python_wrappers():
    candidate = deployment()
    broker = broker_config(candidate)
    publisher = publisher_config(candidate)

    assert broker["r2_buckets"] == []
    assert broker["secrets"]["required"] == list(BROKER_SECRET_NAMES)
    assert broker["vars"] == {
        "WORKSPACE": candidate.workspace,
        "CANONICAL_BUCKET_PROFILE": "dedicated-workspace",
        "UPLOAD_PROTOCOL": "isolated-ingress-v1",
        "UPLOAD_ORDER": "objects-first-pile-last",
        OWNER_BINDING: candidate.owner,
        ROLE_BINDING: "broker",
        "R2_ENDPOINT": candidate.endpoint,
        "CANONICAL_BUCKET": candidate.canonical_bucket,
        "CANONICAL_PREFIX": candidate.canonical_prefix,
        "INGRESS_BUCKET": candidate.ingress_bucket,
        "INGRESS_PREFIX": candidate.ingress_prefix,
        "PRESIGN_TTL_SECONDS": candidate.presign_ttl_seconds,
        "CANONICAL_READ_POLICY_SHA256":
            broker["vars"]["CANONICAL_READ_POLICY_SHA256"],
        "INGRESS_PARENT_POLICY_SHA256":
            broker["vars"]["INGRESS_PARENT_POLICY_SHA256"],
    }
    assert len(broker["vars"]["CANONICAL_READ_POLICY_SHA256"]) == 64
    assert len(broker["vars"]["INGRESS_PARENT_POLICY_SHA256"]) == 64

    assert publisher["r2_buckets"] == [
        {
            "binding": "INGRESS",
            "bucket_name": candidate.ingress_bucket,
            "jurisdiction": "default",
        },
        {
            "binding": "CANONICAL",
            "bucket_name": candidate.canonical_bucket,
            "jurisdiction": "default",
        },
    ]
    assert publisher["vars"][ROLE_BINDING] == "publisher"
    assert broker["routes"] == publisher["routes"] == []
    assert broker["workers_dev"] is publisher["workers_dev"] is False
    assert broker["base_dir"] == publisher["base_dir"] == "worker"


def test_checked_in_wrangler_input_is_an_inert_fail_closed_placeholder():
    package = Path(__file__).parents[1] / "deploy" / "cloudflare_upload"
    config = json.loads((package / "wrangler.jsonc").read_text())

    assert config["name"] == "poc16-upload-boundary-placeholder"
    assert config["main"] == "worker/broker_stub.py"
    assert config["base_dir"] == "worker"
    assert config["r2_buckets"] == []
    assert config["routes"] == []
    assert config["workers_dev"] is False
    assert (package / "pylock.toml").read_text().count(
        'name = "workers-runtime-sdk"') == 1
    assert (package / "uv.lock").is_file()


def test_upload_package_has_no_credential_shaped_client_transport():
    package = Path(__file__).parents[1] / "deploy" / "cloudflare_upload"

    assert not (package / "credentials.py").exists()
    assert (package / "signer.py").is_file()


def test_ingress_parent_cannot_address_any_canonical_operation():
    candidate = deployment()
    policies = access_policies(candidate)
    ingress = policies["broker_ingress_parent"]
    reader = policies["broker_canonical_reader"]

    for operation in ("GET", "LIST", "PUT", "DELETE"):
        assert not _policy_allows(
            candidate, ingress, candidate.canonical_bucket, operation)
    for operation in ("GET", "LIST", "PUT", "DELETE"):
        assert _policy_allows(
            candidate, ingress, candidate.ingress_bucket, operation)

    assert _policy_allows(
        candidate, reader, candidate.canonical_bucket, "GET")
    assert _policy_allows(
        candidate, reader, candidate.canonical_bucket, "LIST")
    assert not _policy_allows(
        candidate, reader, candidate.canonical_bucket, "PUT")
    assert not _policy_allows(
        candidate, reader, candidate.canonical_bucket, "DELETE")
    for operation in ("GET", "LIST", "PUT", "DELETE"):
        assert not _policy_allows(
            candidate, reader, candidate.ingress_bucket, operation)

    canonical_resource = bucket_resource(
        candidate, candidate.canonical_bucket)
    ingress_resource = bucket_resource(
        candidate, candidate.ingress_bucket)
    assert set(ingress["policies"][0]["resources"]) == {ingress_resource}
    assert set(reader["policies"][0]["resources"]) == {canonical_resource}


@pytest.mark.parametrize("changes", (
    {"canonical_bucket": "same", "ingress_bucket": "same"},
    {"broker_name": "same-worker", "publisher_name": "same-worker"},
    {"canonical_bucket": "UPPERCASE"},
    {"canonical_bucket": "ab"},
    {"canonical_bucket": "a" * 64},
    {"ingress_prefix": "../escape"},
    {"ingress_prefix": "some/other/safe/prefix"},
    {"canonical_bucket_profile": "shared-prefixes"},
    {"presign_ttl_seconds": 3601},
    {"stage_retention_seconds": 23 * 60 * 60},
    {"stage_retention_seconds": 900, "presign_ttl_seconds": 900},
))
def test_deployment_rejects_ambiguous_or_collapsed_authority(changes):
    with pytest.raises(ValueError):
        deployment(**changes)


def test_r2_bucket_name_bounds_accept_exactly_three_through_sixty_three():
    assert deployment(canonical_bucket="abc").canonical_bucket == "abc"
    assert deployment(
        canonical_bucket="a" * 63).canonical_bucket == "a" * 63


def test_selected_logical_key_grammar_is_exact_for_objects_and_pile_marker():
    candidate = deployment()
    member = "e" * 16
    session = "f" * 32
    digest = "1" * 64
    base = f"ingress/v1/workspaces/{candidate.workspace}"

    assert staging_key(
        candidate.workspace, member, session, "obj", digest,
    ) == f"{base}/objects/{session}/{digest}"
    assert staging_key(
        candidate.workspace, member, session, "pile", digest,
    ) == f"{base}/piles/{session}/{member}/{digest}"


def test_staging_capability_makes_no_false_canonical_body_binding_claim():
    candidate = deployment()
    claim = generated_boundary(candidate)["provider_claim"]

    assert claim == {
        "kind": "isolated-ingress-presigned-put-v1",
        "live_verified": False,
        "canonical_raw_put_sha256_safe": False,
        "payload_mode": "UNSIGNED-PAYLOAD",
        "upload_protocol": "isolated-ingress-v1",
        "upload_order": "objects-first-pile-last",
        "session_nonce": "32-lowercase-hex",
        "object_key": (
            "ingress/v1/workspaces/<ws64>/objects/"
            "<nonce32>/<sha256>"
        ),
        "ready_marker_key": (
            "ingress/v1/workspaces/<ws64>/piles/"
            "<nonce32>/<member16>/<sha256>"
        ),
        "ready_marker_is_sole_durable_intent": True,
    }


def test_lifecycle_collects_loose_objects_but_never_durable_pile_markers():
    candidate = deployment()
    lifecycle = ingress_lifecycle(candidate)
    rule = lifecycle["rules"][0]

    assert rule["enabled"] is True
    assert rule["conditions"] == {
        "prefix": staging_prefix(candidate.workspace, "obj"),
    }
    assert rule["deleteObjectsTransition"]["condition"] == {
        "type": "Age",
        "maxAge": 7 * 24 * 60 * 60,
    }
    assert candidate.canonical_bucket not in json.dumps(lifecycle)
    assert rule["conditions"]["prefix"] != candidate.canonical_prefix + "/"
    assert not staging_prefix(
        candidate.workspace, "pile").startswith(
            rule["conditions"]["prefix"])


def _deploy_environment():
    return {
        "CF_UPLOAD_ENABLE_STUB_DEPLOY": "1",
        "CF_UPLOAD_CREATE": "1",
        "CLOUDFLARE_API_TOKEN": "not-logged",
        "CANONICAL_READ_ACCESS_KEY_ID": "reader-id",
        "CANONICAL_READ_SECRET_ACCESS_KEY": "reader-secret",
        "INGRESS_PARENT_ACCESS_KEY_ID": "parent-id",
        "INGRESS_PARENT_SECRET_ACCESS_KEY": "parent-secret",
    }


def test_one_command_deploy_remove_mutates_only_exact_compute_roles(
        tmp_path, monkeypatch):
    candidate = deployment()
    generated = tmp_path / "generated"
    monkeypatch.setattr(manage, "GENERATED", generated)
    workers = {}
    buckets = {
        candidate.canonical_bucket: {"root": b"canonical-root"},
        candidate.ingress_bucket: {"stage/sentinel": b"unpublished"},
    }
    calls = []
    secret_documents = []

    def identity_reader(_deployment, config, _environment):
        return workers.get(config["name"], manage._ABSENT)

    def runner(command):
        calls.append(tuple(command))
        if command[3] == "deploy":
            path = Path(command[command.index("--config") + 1])
            config = json.loads(path.read_text())
            workers[config["name"]] = (
                config["vars"][OWNER_BINDING],
                config["vars"][ROLE_BINDING],
            )
            if "--secrets-file" in command:
                secret_path = Path(
                    command[command.index("--secrets-file") + 1])
                secret_documents.append(json.loads(
                    secret_path.read_text()))
        elif command[3] == "delete":
            workers.pop(command[4])
        else:
            raise AssertionError(command)

    paths = manage.deploy(
        candidate,
        _deploy_environment(),
        runner=runner,
        identity_reader=identity_reader,
    )
    assert list(workers.values()) == [
        (candidate.owner, "publisher"),
        (candidate.owner, "broker"),
    ]
    assert [call[3] for call in calls] == ["deploy", "deploy"]
    assert json.loads(paths["broker"].read_text())["r2_buckets"] == []
    assert secret_documents == [{
        "CANONICAL_READ_ACCESS_KEY_ID": "reader-id",
        "CANONICAL_READ_SECRET_ACCESS_KEY": "reader-secret",
        "INGRESS_PARENT_ACCESS_KEY_ID": "parent-id",
        "INGRESS_PARENT_SECRET_ACCESS_KEY": "parent-secret",
    }]
    generated_bytes = b"".join(
        path.read_bytes() for path in generated.iterdir())
    assert b"reader-secret" not in generated_bytes
    assert b"parent-secret" not in generated_bytes

    before = {
        name: dict(objects) for name, objects in buckets.items()}
    manage.remove(
        candidate,
        _deploy_environment(),
        runner=runner,
        identity_reader=identity_reader,
    )

    assert workers == {}
    assert buckets == before
    assert [call[3] for call in calls] == [
        "deploy", "deploy", "delete", "delete",
    ]
    assert [call[4] for call in calls[-2:]] == [
        candidate.broker_name, candidate.publisher_name,
    ]
    assert all("r2" not in call[3:] for call in calls)


def test_build_dry_runs_both_exact_generated_worker_configs(
        tmp_path, monkeypatch):
    candidate = deployment()
    monkeypatch.setattr(manage, "GENERATED", tmp_path / "generated")
    calls = []

    def runner(command):
        calls.append(tuple(command))
        target = Path(command[command.index("--outdir") + 1])
        config = json.loads(Path(
            command[command.index("--config") + 1]).read_text())
        role = config["vars"][ROLE_BINDING]
        target.mkdir(parents=True)
        (target / f"{role}_stub.py").write_text("dry-run artifact")

    manage.build(candidate, runner=runner)

    assert len(calls) == 2
    assert all(call[:4] == (
        "uv", "run", "pywrangler", "deploy") for call in calls)
    assert all("--dry-run" in call for call in calls)
    configs = [
        json.loads(Path(
            call[call.index("--config") + 1]).read_text())
        for call in calls
    ]
    assert [config["vars"][ROLE_BINDING] for config in configs] == [
        "publisher", "broker",
    ]


def test_remove_resolves_both_owned_targets_before_first_delete(
        tmp_path, monkeypatch):
    candidate = deployment()
    monkeypatch.setattr(manage, "GENERATED", tmp_path / "generated")
    calls = []
    identities = {
        candidate.publisher_name: ("someone-else", "publisher"),
        candidate.broker_name: (candidate.owner, "broker"),
    }

    with pytest.raises(RuntimeError, match="unowned publisher"):
        manage.remove(
            candidate,
            _deploy_environment(),
            runner=lambda command: calls.append(command),
            identity_reader=lambda _deployment, config, _environment:
                identities[config["name"]],
        )
    assert calls == []


class _APIResponse:
    def __init__(self, document):
        self.raw = json.dumps(document).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, amount):
        assert amount == manage.API_RESPONSE_BYTES + 1
        return self.raw[:amount]


def test_control_plane_identity_requires_one_exact_owner_and_role(
        monkeypatch):
    candidate = deployment()
    config = broker_config(candidate)
    environment = {"CLOUDFLARE_API_TOKEN": "control-secret"}
    seen = []

    def response(bindings):
        def open_settings(request, timeout):
            seen.append((request, timeout))
            return _APIResponse({
                "success": True,
                "result": {"bindings": bindings},
            })
        return open_settings

    exact = [
        {
            "name": OWNER_BINDING,
            "type": "plain_text",
            "text": candidate.owner,
        },
        {
            "name": ROLE_BINDING,
            "type": "plain_text",
            "text": "broker",
        },
    ]
    monkeypatch.setattr(manage, "urlopen", response(exact))
    assert manage._worker_identity(
        candidate, config, environment) == (
            candidate.owner, "broker")
    request, timeout = seen[-1]
    assert request.get_header(
        "Authorization") == "Bearer control-secret"
    assert request.full_url.endswith(
        f"/workers/scripts/{candidate.broker_name}/settings")
    assert timeout == manage.SETTINGS_TIMEOUT_SECONDS

    monkeypatch.setattr(
        manage,
        "urlopen",
        response(exact + [dict(exact[0])]),
    )
    assert manage._worker_identity(
        candidate, config, environment) is None


def test_environment_requires_explicit_dedicated_canonical_profile():
    values = {
        "CLOUDFLARE_ACCOUNT_ID": "a" * 32,
        "CF_UPLOAD_WORKSPACE": "b" * 64,
        "CF_UPLOAD_CANONICAL_BUCKET": "poc16-canonical",
        "CF_UPLOAD_INGRESS_BUCKET": "poc16-ingress",
        "CF_UPLOAD_DEPLOYMENT_OWNER": "production-west",
        "CF_R2_BUCKET_ITEM_READ_PERMISSION_ID": "c" * 32,
        "CF_R2_BUCKET_ITEM_WRITE_PERMISSION_ID": "d" * 32,
    }
    with pytest.raises(ValueError, match="dedicated-workspace"):
        Deployment.from_environment(values)

    values["CF_UPLOAD_CANONICAL_BUCKET_PROFILE"] = "dedicated-workspace"
    assert Deployment.from_environment(
        values).canonical_bucket_profile == "dedicated-workspace"
