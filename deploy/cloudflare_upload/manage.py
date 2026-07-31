#!/usr/bin/env python3
"""Build and operate Cloudflare broker plus hosted repository compartments."""
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
from deploy.python_role_modules import UPLOAD_BROKER_CORE_MODULES


PACKAGE = Path(__file__).resolve().parent
REPOSITORY = PACKAGE.parents[1]
GENERATED = PACKAGE / "generated"
BUILD = PACKAGE / "build"
BROKER_WORKER = BUILD / "broker"
APPLIER_WORKER = BUILD / "applier"
VENDORED = PACKAGE / "python_modules"
CONTROL_TIMEOUT_SECONDS = 120
SETTINGS_TIMEOUT_SECONDS = 15
API_RESPONSE_BYTES = 64 * 1024
_ABSENT = object()
ROLE_ORDER = ("applier", "broker")
REMOVE_ORDER = tuple(reversed(ROLE_ORDER))
BROKER_CORE_MODULES = UPLOAD_BROKER_CORE_MODULES
BROKER_DEPLOY_MODULES = (
    "__init__.py",
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
APPLIER_CORE_MODULES = (
    "__init__.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "indexes.py",
    "ingress.py",
    "kernel.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "repository_applier.py",
    "repository_snapshot.py",
    "shape.py",
    "snapshot.py",
    "staged_intent.py",
    "suppression.py",
    "validated_set.py",
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


def stage_applier():
    """Stage the exact DB-free RepositoryApplier import closure."""
    pending = BUILD / "applier.pending"
    if pending.exists():
        shutil.rmtree(pending)
    pending.mkdir(parents=True)
    _copy(
        PACKAGE / "worker" / "applier.py",
        pending / "entry.py",
    )
    _copy(
        PACKAGE / "worker" / "applier_runtime.py",
        pending / "applier_runtime.py",
    )
    for relative in (
            "deploy/__init__.py",
            "deploy/repository_apply_wire.py"):
        _copy(REPOSITORY / relative, pending / relative)
    for name in APPLIER_CORE_MODULES:
        _copy(
            REPOSITORY / "core" / name,
            pending / "core" / name,
        )
    shutil.copytree(
        REPOSITORY / "facts",
        pending / "facts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    _copy(
        REPOSITORY / "adapters" / "__init__.py",
        pending / "adapters" / "__init__.py",
    )
    for name in ("__init__.py", "worker.py"):
        _copy(
            REPOSITORY / "adapters" / "r2" / name,
            pending / "adapters" / "r2" / name,
        )
    if APPLIER_WORKER.exists():
        shutil.rmtree(APPLIER_WORKER)
    pending.rename(APPLIER_WORKER)
    return APPLIER_WORKER


def render(deployment):
    """Write non-secret Worker configs and provider-policy inputs."""
    boundary = generated_boundary(deployment)
    obsolete = GENERATED / "ingress-lifecycle.json"
    if obsolete.exists() or obsolete.is_symlink():
        obsolete.unlink()
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
            ("ingress-lock", boundary["ingress_lock"]),
            ("boundary-claim", boundary["provider_claim"])):
        path = GENERATED / f"{name}.json"
        _write_json(path, value)
        paths[name] = path
    return paths


def stage_dependencies():
    """Put the patched locked dependencies beside both exact configs."""
    for role in ROLE_ORDER:
        target = GENERATED / role / "python_modules"
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
    stage_applier()
    paths = render(deployment)
    stage_dependencies()
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
            else:
                _verify_applier_bundle(target)


def _verify_applier_bundle(directory):
    paths = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*") if path.is_file()
    }
    required = {
        "entry.py",
        "applier_runtime.py",
        "deploy/repository_apply_wire.py",
        "core/repository_applier.py",
        "core/repository_snapshot.py",
        "core/staged_intent.py",
        "adapters/r2/worker.py",
        "facts/auth/workspace.py",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(
            f"pywrangler omitted applier modules: {sorted(missing)}")
    forbidden = {
        "full_peer/sql_store.py",
        "full_peer/node.py",
        "core/store.py",
        "full_peer/daemon.py",
        "core/runtime.py",
        "core/admission.py",
        "core/publication.py",
        "adapters/r2/s3.py",
        "adapters/s3/store.py",
    } & paths
    if forbidden:
        raise RuntimeError(
            f"applier artifact contains forbidden modules: "
            f"{sorted(forbidden)}")


def _verify_broker_bundle(directory):
    paths = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*") if path.is_file()
    }
    required = {
        "entry.py",
        "runtime.py",
        "core/validated_set.py",
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
        "full_peer/node.py",
        "full_peer/daemon.py",
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
    stage_dependencies()
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


def _lock_url(deployment):
    return (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{quote(deployment.account_id, safe='')}/r2/buckets/"
        f"{quote(deployment.ingress_bucket, safe='')}/lock"
    )


def _control_request(
        endpoint, environment, *, method="GET", document=None,
        headers=None, absent_404=False):
    """Perform one bounded Cloudflare control-plane JSON exchange."""
    headers = {
        "Authorization": f"Bearer {_control_token(environment)}",
        "Accept": "application/json",
        **({} if headers is None else headers),
    }
    body = None
    if document is not None:
        body = json.dumps(
            document, sort_keys=True, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    request = Request(
        endpoint,
        data=body,
        method=method,
        headers=headers,
    )
    try:
        with urlopen(
                request, timeout=SETTINGS_TIMEOUT_SECONDS) as response:
            raw = response.read(API_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if absent_404 and error.code == 404:
            return _ABSENT
        raise RuntimeError("Cloudflare control request failed") from error
    except (OSError, URLError) as error:
        raise RuntimeError("Cloudflare control request failed") from error
    if len(raw) > API_RESPONSE_BYTES:
        raise RuntimeError("Cloudflare control response is too large")
    try:
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) \
                or envelope.get("success") is not True \
                or "result" not in envelope:
            raise ValueError
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed Cloudflare control response") from error
    return envelope["result"]


def _lock_headers(deployment):
    headers = {}
    if deployment.jurisdiction != "default":
        headers["cf-r2-jurisdiction"] = deployment.jurisdiction
    return headers


def _read_ingress_lock(deployment, environment):
    """Read the documented lock document, normalizing omitted rules."""
    result = _control_request(
        _lock_url(deployment),
        environment,
        headers=_lock_headers(deployment),
    )
    if not isinstance(result, dict):
        raise RuntimeError("malformed Cloudflare ingress bucket lock")
    rules = result.get("rules", [])
    if not isinstance(rules, list):
        raise RuntimeError("malformed Cloudflare ingress bucket lock")
    return {"rules": rules}


def _write_ingress_lock(deployment, environment, document):
    """Replace the lock document; the provider's response is opaque."""
    _control_request(
        _lock_url(deployment),
        environment,
        method="PUT",
        document=document,
        headers=_lock_headers(deployment),
    )


def ensure_ingress_lock(
        deployment, environment, *, reader=None, writer=None):
    """Install the lock under one exclusive bucket-configuration owner.

    Cloudflare's whole-document lock PUT has no compare precondition.  The
    ``exclusive-dedicated`` profile therefore declares this deployment the
    sole configuration writer; Cloudflare does not enforce bucket-scoped REST
    configuration tokens.  A pre-existing foreign document is refused,
    concurrent same-owner installers write identical bytes, and a lost PUT
    response is reconciled by the following exact GET.  This read check does
    not pretend to defeat a racing account administrator.
    """
    desired = generated_boundary(deployment)["ingress_lock"]
    reader = reader or (
        lambda: _read_ingress_lock(deployment, environment))
    writer = writer or (
        lambda value: _write_ingress_lock(
            deployment, environment, value))
    observed = reader()
    if observed == desired:
        return False
    if observed != {"rules": []}:
        raise RuntimeError(
            "refusing to replace foreign ingress bucket lock rules")
    write_error = None
    try:
        writer(desired)
    except (OSError, RuntimeError) as error:
        write_error = error
    if reader() != desired:
        if write_error is not None:
            raise write_error
        raise RuntimeError(
            "Cloudflare ingress bucket lock was not preserved")
    return True


def _worker_identity(
        deployment, config, environment=os.environ):
    """Read the exact non-secret owner/role pair from Worker settings."""
    name = config["name"]
    endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{quote(deployment.account_id, safe='')}/workers/scripts/"
        f"{quote(name, safe='')}/settings"
    )
    result = _control_request(
        endpoint, environment, absent_404=True)
    if result is _ABSENT:
        return _ABSENT
    if not isinstance(result, dict) \
            or not isinstance(result.get("bindings"), list):
        raise RuntimeError("malformed Cloudflare Worker settings")
    bindings = result["bindings"]

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
        runner=None, identity_reader=None, lock_configurer=None):
    """Deploy Applier then broker after checking both exact identities."""
    runner = _run if runner is None else runner
    identity_reader = (
        _worker_identity if identity_reader is None else identity_reader)
    # Resolve and validate every required secret before the Applier is the
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
    (ensure_ingress_lock if lock_configurer is None else lock_configurer)(
        deployment, environment)
    runner([
        "uv", "run", "pywrangler", "sync", "--allow-build",
    ])
    stage_broker()
    stage_applier()
    paths = render(deployment)
    stage_dependencies()
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
  render  generate non-secret broker/applier configs and R2 policy inputs
  build   dry-run both generated configs through locked pywrangler/Workers
  test    run host, clean-bundle, and local-workerd checks
  deploy  deploy the broker plus database-free RepositoryApplier
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
