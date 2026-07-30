#!/usr/bin/env python3
"""Render and operate the fail-closed Cloudflare upload role boundary."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from deploy.cloudflare_python import (
    MINT_CORE_MODULES,
    copy_python_modules,
    patch_pynacl,
)
from deploy.cloudflare_upload.boundary import (
    BROKER_SECRET_NAMES,
    OWNER_BINDING,
    ROLE_BINDING,
    Deployment,
    generated_boundary,
)
from deploy.cloudflare_upload.signer import R2UploadSigner
from deploy.upload_keyring import (
    UploadKeyring,
    decode_keyring,
    encode_keyring,
)
from deploy.upload_session import SessionKey, UploadSessionPolicy


PACKAGE = Path(__file__).resolve().parent
REPOSITORY = PACKAGE.parents[1]
GENERATED = PACKAGE / "generated"
BUILD = PACKAGE / "build"
BROKER_WORKER = BUILD / "broker"
PUBLISHER_WORKER = BUILD / "publisher"
VENDORED = PACKAGE / "python_modules"
CONTROL_TIMEOUT_SECONDS = 120
SETTINGS_TIMEOUT_SECONDS = 15
API_RESPONSE_BYTES = 64 * 1024
_ABSENT = object()
ROLE_ORDER = ("publisher", "broker")
REMOVE_ORDER = tuple(reversed(ROLE_ORDER))
BROKER_CORE_MODULES = MINT_CORE_MODULES + ("staged_intent.py",)
BROKER_DEPLOY_MODULES = (
    "__init__.py",
    "gateway.py",
    "upload_broker.py",
    "upload_broker_http.py",
    "upload_keyring.py",
    "upload_session.py",
    "upload_wire.py",
)
BROKER_PROVIDER_MODULES = (
    "__init__.py",
    "boundary.py",
    "reader.py",
    "signer.py",
)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, delete=False,
            prefix=path.name + ".", suffix=".pending") as pending:
        pending.write(raw)
        pending_path = Path(pending.name)
    pending_path.replace(path)


def _copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def stage_broker():
    """Stage the exact DB-free broker import tree for pywrangler."""
    patch_pynacl(VENDORED)
    pending = BUILD / "broker.pending"
    if pending.exists():
        shutil.rmtree(pending)
    pending.mkdir(parents=True)
    _copy(
        PACKAGE / "worker" / "broker.py",
        pending / "entry.py",
    )
    _copy(
        PACKAGE / "worker" / "runtime.py",
        pending / "runtime.py",
    )
    for name in BROKER_CORE_MODULES:
        _copy(
            REPOSITORY / "core" / name,
            pending / "core" / name,
        )
    shutil.copytree(
        REPOSITORY / "facts",
        pending / "facts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for name in BROKER_DEPLOY_MODULES:
        _copy(
            REPOSITORY / "deploy" / name,
            pending / "deploy" / name,
        )
    for name in BROKER_PROVIDER_MODULES:
        _copy(
            PACKAGE / name,
            pending / "deploy" / "cloudflare_upload" / name,
        )
    if BROKER_WORKER.exists():
        shutil.rmtree(BROKER_WORKER)
    pending.rename(BROKER_WORKER)
    return BROKER_WORKER


def stage_publisher():
    """Stage only the fail-closed placeholder for the unfinished publisher."""
    pending = BUILD / "publisher.pending"
    if pending.exists():
        shutil.rmtree(pending)
    pending.mkdir(parents=True)
    _copy(
        PACKAGE / "worker" / "publisher_stub.py",
        pending / "entry.py",
    )
    if PUBLISHER_WORKER.exists():
        shutil.rmtree(PUBLISHER_WORKER)
    pending.rename(PUBLISHER_WORKER)
    return PUBLISHER_WORKER


def render(deployment):
    """Write non-secret Worker configs and provider-policy inputs."""
    boundary = generated_boundary(deployment)
    paths = {}
    for role in ROLE_ORDER:
        path = GENERATED / role / "wrangler.json"
        config = dict(boundary[role])
        config["main"] = f"../../{config['main']}"
        config["base_dir"] = f"../../{config['base_dir']}"
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


def stage_broker_dependencies():
    """Put the patched locked dependencies beside the broker's config."""
    target = GENERATED / "broker" / "python_modules"
    if target.exists():
        shutil.rmtree(target)
    copy_python_modules(VENDORED, target)


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
    runner([
        "uv", "run", "pywrangler", "sync", "--allow-build",
    ])
    stage_broker()
    stage_publisher()
    paths = render(deployment)
    stage_broker_dependencies()
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
            if role == "broker":
                _verify_broker_bundle(target)
            elif not (target / "entry.py").is_file():
                raise RuntimeError(
                    "pywrangler omitted the publisher entrypoint")


def _verify_broker_bundle(directory):
    paths = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*") if path.is_file()
    }
    required = {
        "entry.py",
        "runtime.py",
        "core/candidate_archive.py",
        "core/repository_reader.py",
        "core/staged_intent.py",
        "facts/auth/request.py",
        "deploy/upload_broker.py",
        "deploy/upload_broker_http.py",
        "deploy/upload_keyring.py",
        "deploy/cloudflare_upload/reader.py",
        "deploy/cloudflare_upload/signer.py",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(
            f"pywrangler omitted broker modules: {sorted(missing)}")
    forbidden = {
        "core/node.py",
        "core/daemon.py",
        "core/runtime.py",
        "adapters/r2/worker.py",
        "adapters/r2/s3.py",
        "adapters/s3/store.py",
    } & paths
    if forbidden:
        raise RuntimeError(
            f"broker artifact contains host modules: {sorted(forbidden)}")
    sodium = tuple(
        directory.glob("python_modules/nacl/_sodium*.so"))
    if len(sodium) != 1 \
            or b"__start_em_asm" in sodium[0].read_bytes():
        raise RuntimeError(
            "broker artifact omitted the patched PyNaCl runtime")


def _workerd_secrets(deployment):
    ingress_id = "workerd-ingress-parent"
    ingress_secret = "workerd-ingress-secret"
    provider = R2UploadSigner(
        deployment,
        ingress_id,
        ingress_secret,
        clock=lambda: 0,
    ).provider_binding
    key = SessionKey("key00001", b"k" * 32, 0, 9_000_000_000_000)
    keyring = encode_keyring(UploadKeyring(
        provider,
        UploadSessionPolicy(
            deployment.upload_issuer,
            key.key_id,
            (key,),
        ),
    )).decode("ascii")
    return {
        "CANONICAL_READ_ACCESS_KEY_ID": "workerd-canonical-reader",
        "CANONICAL_READ_SECRET_ACCESS_KEY": "workerd-reader-secret",
        "INGRESS_PARENT_ACCESS_KEY_ID": ingress_id,
        "INGRESS_PARENT_SECRET_ACCESS_KEY": ingress_secret,
        "UPLOAD_SESSION_KEYRING": keyring,
    }


def workerd_test(deployment):
    """Load the production broker entrypoint in local workerd."""
    runner = _run
    runner([
        "uv", "run", "pywrangler", "sync", "--allow-build",
    ])
    stage_broker()
    paths = render(deployment)
    stage_broker_dependencies()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    environment = {**os.environ, **_workerd_secrets(deployment)}
    with tempfile.NamedTemporaryFile(
            mode="w+", prefix="poc16-upload-workerd-",
            suffix=".log") as log:
        process = subprocess.Popen(
            [
                "uv", "run", "pywrangler", "dev",
                "--ip", "127.0.0.1",
                "--port", str(port),
                "--config", str(paths["broker"]),
            ],
            cwd=PACKAGE,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline, error = time.monotonic() + 30, None
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    urlopen(
                        f"http://127.0.0.1:{port}/not-an-upload-route",
                        timeout=1,
                    )
                    error = RuntimeError(
                        "unknown upload route unexpectedly succeeded")
                except HTTPError as caught:
                    if caught.code == 404 \
                            and caught.read() == b"" \
                            and caught.headers.get(
                                "Cache-Control") == "no-store" \
                            and caught.headers.get(
                                "X-Content-Type-Options") == "nosniff":
                        return
                    error = RuntimeError(
                        "unexpected upload route response")
                except (OSError, URLError) as caught:
                    error = caught
                time.sleep(0.1)
            log.seek(0)
            raise RuntimeError(
                f"upload broker workerd test failed: {error}\n{log.read()}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def test(deployment):
    _run([
        "uv", "run", "python", "-m", "pytest", "-q",
        str(REPOSITORY / "tests" / "test_cloudflare_upload_boundary.py"),
        str(REPOSITORY / "tests" / "test_cloudflare_upload_worker.py"),
        str(REPOSITORY / "tests" / "test_r2_upload_signer.py"),
    ])
    build(deployment)
    workerd_test(deployment)


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


def _broker_secrets(deployment, environment):
    values = {}
    for name in BROKER_SECRET_NAMES:
        value = environment.get(name, "")
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} is required")
        values[name] = value
    try:
        signer = R2UploadSigner(
            deployment,
            values["INGRESS_PARENT_ACCESS_KEY_ID"],
            values["INGRESS_PARENT_SECRET_ACCESS_KEY"],
        )
        decode_keyring(
            values["UPLOAD_SESSION_KEYRING"].encode("ascii"),
            signer.provider_binding,
        )
    except (UnicodeError, ValueError) as error:
        raise ValueError("UPLOAD_SESSION_KEYRING is invalid") from error
    return values


def _deploy_one(role, path, runner, broker_secrets):
    command = [
        "uv", "run", "pywrangler", "deploy",
        "--strict",
        "--config", str(path),
    ]
    if role == "broker":
        with tempfile.NamedTemporaryFile(
                mode="w", prefix="poc16-upload-secrets-",
                suffix=".json") as secrets:
            json.dump(broker_secrets, secrets)
            secrets.flush()
            runner(command + ["--secrets-file", secrets.name])
        return
    runner(command)


def deploy(
        deployment, environment=os.environ, *,
        runner=None, identity_reader=None):
    """Deploy publisher then broker after checking both exact identities.

    The broker is real, but the publisher is deliberately fail-closed and
    neither generated role has a public route. Requiring an explicit opt-in
    prevents this partial pair from being mistaken for the complete service.
    """
    if environment.get("CF_UPLOAD_ENABLE_PARTIAL_DEPLOY") != "1":
        raise ValueError(
            "set CF_UPLOAD_ENABLE_PARTIAL_DEPLOY=1 for partial deployment")
    runner = _run if runner is None else runner
    identity_reader = (
        _worker_identity if identity_reader is None else identity_reader)
    # Resolve and validate every required secret before the publisher is the
    # first provider mutation. A malformed broker key ring must not leave a
    # half-installed role pair.
    broker_secrets = _broker_secrets(deployment, environment)
    boundary = generated_boundary(deployment)
    configs = {role: boundary[role] for role in ROLE_ORDER}
    _preflight(
        deployment,
        configs,
        environment,
        create=environment.get("CF_UPLOAD_CREATE") == "1",
        identity_reader=identity_reader,
    )
    runner([
        "uv", "run", "pywrangler", "sync", "--allow-build",
    ])
    stage_broker()
    stage_publisher()
    paths = render(deployment)
    stage_broker_dependencies()
    for role in ROLE_ORDER:
        _deploy_one(
            role, paths[role], runner, broker_secrets)
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
  test    run host, clean-bundle, and local-workerd broker checks
  deploy  opt-in deployment of the broker plus fail-closed publisher
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
