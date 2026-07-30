#!/usr/bin/env python3
"""Render and operate the fail-closed Cloudflare upload role boundary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from deploy.cloudflare_upload.boundary import (
    BROKER_SECRET_NAMES,
    OWNER_BINDING,
    ROLE_BINDING,
    Deployment,
    generated_boundary,
)


PACKAGE = Path(__file__).resolve().parent
REPOSITORY = PACKAGE.parents[1]
GENERATED = PACKAGE / "generated"
CONTROL_TIMEOUT_SECONDS = 120
SETTINGS_TIMEOUT_SECONDS = 15
API_RESPONSE_BYTES = 64 * 1024
_ABSENT = object()
ROLE_ORDER = ("publisher", "broker")
REMOVE_ORDER = tuple(reversed(ROLE_ORDER))


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, delete=False,
            prefix=path.name + ".", suffix=".pending") as pending:
        pending.write(raw)
        pending_path = Path(pending.name)
    pending_path.replace(path)


def render(deployment):
    """Write non-secret Worker configs and provider-policy inputs."""
    boundary = generated_boundary(deployment)
    paths = {}
    for role in ROLE_ORDER:
        path = GENERATED / f"wrangler.{role}.json"
        config = dict(boundary[role])
        config["main"] = f"../{config['main']}"
        config["base_dir"] = "../worker"
        _write_json(path, config)
        paths[role] = path
    for name, value in (
            ("access-policies", boundary["access_policies"]),
            ("ingress-lifecycle", boundary["ingress_lifecycle"]),
            ("boundary-claim", boundary["provider_claim"])):
        path = GENERATED / f"{name}.json"
        _write_json(path, value)
        paths[name] = path
    return paths


def _run(command):
    return subprocess.run(
        command,
        cwd=PACKAGE,
        check=True,
        timeout=CONTROL_TIMEOUT_SECONDS,
    )


def build(deployment, *, runner=None):
    """Dry-run both exact generated configs through locked pywrangler."""
    runner = _run if runner is None else runner
    paths = render(deployment)
    with tempfile.TemporaryDirectory(
            prefix="poc16-cloudflare-upload-build-") as output:
        output = Path(output)
        for role in ROLE_ORDER:
            target = output / role
            runner([
                "uv", "run", "pywrangler", "deploy",
                "--dry-run",
                "--outdir", str(target),
                "--config", str(paths[role]),
            ])
            entry = target / f"{role}_stub.py"
            if not entry.is_file():
                raise RuntimeError(
                    f"pywrangler omitted the {role} entrypoint")


def test(deployment):
    _run([
        "uv", "run", "python", "-m", "pytest", "-q",
        str(REPOSITORY / "tests" / "test_cloudflare_upload_boundary.py"),
    ])
    build(deployment)


def _control_token(environment):
    value = environment.get("CLOUDFLARE_API_TOKEN", "")
    if not isinstance(value, str) or not value:
        raise ValueError("CLOUDFLARE_API_TOKEN is required")
    return value


def _worker_identity(
        deployment, config, environment=os.environ):
    """Read the exact non-secret owner/role pair from Worker settings."""
    token = _control_token(environment)
    name = config["name"]
    endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{quote(deployment.account_id, safe='')}/workers/scripts/"
        f"{quote(name, safe='')}/settings"
    )
    request = Request(endpoint, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    try:
        with urlopen(
                request, timeout=SETTINGS_TIMEOUT_SECONDS) as response:
            raw = response.read(API_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code == 404:
            return _ABSENT
        raise RuntimeError("Cloudflare Worker identity lookup failed") \
            from error
    except (OSError, URLError) as error:
        raise RuntimeError("Cloudflare Worker identity lookup failed") \
            from error
    if len(raw) > API_RESPONSE_BYTES:
        raise RuntimeError("Cloudflare Worker settings response is too large")
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) \
                or document.get("success") is not True \
                or not isinstance(document.get("result"), dict) \
                or not isinstance(
                    document["result"].get("bindings"), list):
            raise ValueError
        bindings = document["result"]["bindings"]
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed Cloudflare Worker settings response") \
            from error

    def marker(name):
        matches = [
            binding.get("text")
            for binding in bindings
            if isinstance(binding, dict)
            and binding.get("name") == name
            and binding.get("type") == "plain_text"
            and isinstance(binding.get("text"), str)
        ]
        return matches[0] if len(matches) == 1 else None

    owner = marker(OWNER_BINDING)
    role = marker(ROLE_BINDING)
    if owner is None or role is None:
        return None
    return owner, role


def _expected(config):
    return (
        config["vars"][OWNER_BINDING],
        config["vars"][ROLE_BINDING],
    )


def _preflight(
        deployment, configs, environment, *,
        create, identity_reader):
    observed = {}
    for role in ROLE_ORDER:
        identity = identity_reader(
            deployment, configs[role], environment)
        observed[role] = identity
        if identity is _ABSENT:
            if not create:
                raise RuntimeError(
                    f"{role} Worker is absent; explicit creation is required")
        elif identity != _expected(configs[role]):
            raise RuntimeError(
                f"refusing to mutate an unowned {role} Worker")
    return observed


def _broker_secrets(environment):
    values = {}
    for name in BROKER_SECRET_NAMES:
        value = environment.get(name, "")
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} is required")
        values[name] = value
    return values


def _deploy_one(role, path, environment, runner):
    command = [
        "uv", "run", "pywrangler", "deploy",
        "--config", str(path),
    ]
    if role == "broker":
        values = _broker_secrets(environment)
        with tempfile.NamedTemporaryFile(
                mode="w", prefix="poc16-upload-secrets-",
                suffix=".json") as secrets:
            json.dump(values, secrets)
            secrets.flush()
            runner(command + ["--secrets-file", secrets.name])
        return
    runner(command)


def deploy(
        deployment, environment=os.environ, *,
        runner=None, identity_reader=None):
    """Deploy publisher then broker after checking both exact identities.

    The checked-in entries are deliberately non-public, fail-closed stubs.
    Requiring an explicit opt-in prevents this boundary package from being
    mistaken for the still-unbuilt upload service.
    """
    if environment.get("CF_UPLOAD_ENABLE_STUB_DEPLOY") != "1":
        raise ValueError(
            "set CF_UPLOAD_ENABLE_STUB_DEPLOY=1 for boundary deployment")
    runner = _run if runner is None else runner
    identity_reader = (
        _worker_identity if identity_reader is None else identity_reader)
    paths = render(deployment)
    boundary = generated_boundary(deployment)
    configs = {role: boundary[role] for role in ROLE_ORDER}
    _preflight(
        deployment,
        configs,
        environment,
        create=environment.get("CF_UPLOAD_CREATE") == "1",
        identity_reader=identity_reader,
    )
    for role in ROLE_ORDER:
        _deploy_one(role, paths[role], environment, runner)
        if identity_reader(
                deployment, configs[role], environment) \
                != _expected(configs[role]):
            raise RuntimeError(
                f"{role} Worker identity was not installed")
    return paths


def remove(
        deployment, environment=os.environ, *,
        runner=None, identity_reader=None):
    """Remove both compute roles, never either bucket or bucket policy."""
    runner = _run if runner is None else runner
    identity_reader = (
        _worker_identity if identity_reader is None else identity_reader)
    paths = render(deployment)
    boundary = generated_boundary(deployment)
    configs = {role: boundary[role] for role in ROLE_ORDER}
    # Resolve every target before the first destructive control-plane call.
    _preflight(
        deployment,
        configs,
        environment,
        create=False,
        identity_reader=identity_reader,
    )
    for role in REMOVE_ORDER:
        runner([
            "uv", "run", "pywrangler", "delete",
            configs[role]["name"],
            "--config", str(paths[role]),
            "--force",
        ])


def help_text():
    return """usage: python -m deploy.cloudflare_upload.manage COMMAND

Commands:
  render  generate non-secret broker/publisher configs and R2 policy inputs
  build   dry-run both generated configs through locked pywrangler/Workers
  test    run the credential-free corpus and both pywrangler dry-runs
  deploy  opt-in deployment of non-public fail-closed boundary stubs
  remove  remove the two exactly owned Workers while preserving both buckets
  help    show this help
"""


def main(argv=None):
    argv = sys.argv if argv is None else argv
    command = argv[1] if len(argv) > 1 else "help"
    if len(argv) != 2:
        print(help_text(), file=sys.stderr, end="")
        return 2
    if command == "help":
        print(help_text(), end="")
        return 0
    deployment = Deployment.from_environment(os.environ)
    if command == "render":
        paths = render(deployment)
        print(json.dumps({
            name: str(path) for name, path in paths.items()
        }, indent=2, sort_keys=True))
        return 0
    if command == "build":
        build(deployment)
        return 0
    if command == "test":
        test(deployment)
        return 0
    if command == "deploy":
        deploy(deployment)
        return 0
    if command == "remove":
        remove(deployment)
        return 0
    print(help_text(), file=sys.stderr, end="")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
