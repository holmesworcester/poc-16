#!/usr/bin/env python3
"""Build and operate the Cloudflare Python Worker package."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

PACKAGE = Path(__file__).resolve().parent
REPOSITORY = PACKAGE.parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from deploy.cloudflare_python import (  # noqa: E402
    patch_pynacl as patch_vendored_pynacl,
)
from deploy.cloudflare_pack.contract import (  # noqa: E402
    PACK_TICKET_SECRET_BYTES,
    R2PackTarget,
)
from deploy.cloudflare_sigv4 import (  # noqa: E402
    ACCESS_KEY_PATTERN,
    MAX_ACCESS_KEY_ID_CHARS,
    MAX_SECRET_ACCESS_KEY_CHARS,
    credential,
)
from deploy.python_role_modules import (  # noqa: E402
    HOSTED_GATE_CORE_MODULES,
)
from core.object_store import validate_store_prefix  # noqa: E402
from core.pack_access import MAX_SCOPED_TTL_MS  # noqa: E402

BUILD = PACKAGE / "build"
WORKER = BUILD / "worker"
VENDORED = PACKAGE / "python_modules"
TEMPLATE = PACKAGE / "wrangler.jsonc"
GENERATED = PACKAGE / "wrangler.generated.json"
TEST_FILE = PACKAGE / "test_worker.py"

FID = re.compile(r"^[0-9a-f]{64}$")
WORKERS_URL = re.compile(r"https://[a-z0-9.-]+\.workers\.dev")
WORKER_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
OWNER = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
OWNER_BINDING = "POC16_DEPLOYMENT_OWNER"
API_RESPONSE_BYTES = 64 * 1024
CONTROL_TIMEOUT_SECONDS = 120
SMOKE_ACTIVATION_TIMEOUT_SECONDS = 30
SMOKE_ACTIVATION_POLL_SECONDS = 0.5
SMOKE_ACTIVATION_STATUSES = frozenset({404, 500, 502, 503})
EDGE_SECRET_BYTES = 32
PERMIT_SECRET_BYTES = 32
DEFAULT_PACK_TTL_SECONDS = MAX_SCOPED_TTL_MS // 1000
_ABSENT = object()

CORE_MODULES = HOSTED_GATE_CORE_MODULES
SECRET_NAMES = (
    "GRANT_SECRET",
    "PERMIT_SECRET",
    "PACK_TICKET_SECRET",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
)


def _copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def patch_pynacl():
    """Disable PyNaCl's eager EM_ASM registration in the Workers runtime.

    Libsodium's browser random source embeds EM_ASM. Workerd deliberately
    rejects that module-local JavaScript at load time. The Worker uses
    ``crypto_compat`` instead: randomness comes from Python's runtime-backed
    ``os.urandom`` and PyNaCl supplies only deterministic box primitives.
    """
    patch_vendored_pynacl(VENDORED)


def stage():
    """Stage one minimal Worker import tree from canonical repository sources."""
    patch_pynacl()
    pending = BUILD / "worker.pending"
    if pending.exists():
        shutil.rmtree(pending)
    pending.mkdir(parents=True)
    _copy(PACKAGE / "entry.py", pending / "entry.py")
    _copy(PACKAGE / "runtime.py", pending / "runtime.py")
    _copy(PACKAGE / "crypto_compat.py", pending / "crypto_compat.py")
    for name in CORE_MODULES:
        _copy(REPOSITORY / "core" / name, pending / "core" / name)
    shutil.copytree(
        REPOSITORY / "facts",
        pending / "facts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    for name in ("__init__.py",):
        _copy(REPOSITORY / "adapters" / name, pending / "adapters" / name)
    for name in ("__init__.py", "listing.py", "reader.py", "worker.py"):
        _copy(
            REPOSITORY / "adapters" / "r2" / name,
            pending / "adapters" / "r2" / name,
        )
    _copy(
        REPOSITORY / "deploy" / "__init__.py",
        pending / "deploy" / "__init__.py")
    _copy(
        REPOSITORY / "deploy" / "cloudflare_sigv4.py",
        pending / "deploy" / "cloudflare_sigv4.py")
    for name in ("__init__.py", "contract.py", "issuer.py", "put.py"):
        _copy(
            REPOSITORY / "deploy" / "cloudflare_pack" / name,
            pending / "deploy" / "cloudflare_pack" / name,
        )
    if WORKER.exists():
        shutil.rmtree(WORKER)
    pending.rename(WORKER)


def _run(
        command, *, capture=False, input_text=None, env=None, timeout=None):
    try:
        return subprocess.run(
            command,
            cwd=PACKAGE,
            check=True,
            capture_output=capture,
            text=True,
            input=input_text,
            env=env,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            f"required executable is unavailable: {command[0]}") from error


def _pywrangler(*arguments, capture=False, env=None, timeout=None):
    return _run(
        ["uv", "run", "pywrangler", *arguments],
        capture=capture,
        env=env,
        timeout=timeout,
    )


def _base64_secret(environment, name, expected_bytes):
    value = environment.get(name, "")
    if not isinstance(value, str):
        raise ValueError(f"{name} must be base64")
    value = value.strip()
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{name} must be base64") from error
    if len(raw) != expected_bytes:
        raise ValueError(
            f"{name} must encode exactly {expected_bytes} bytes")
    return value


def _secrets(environment):
    access = credential(
        environment.get("R2_ACCESS_KEY_ID", ""),
        "R2_ACCESS_KEY_ID is invalid",
        MAX_ACCESS_KEY_ID_CHARS,
    )
    if ACCESS_KEY_PATTERN.fullmatch(access) is None:
        raise ValueError("R2_ACCESS_KEY_ID is invalid")
    secret = credential(
        environment.get("R2_SECRET_ACCESS_KEY", ""),
        "R2_SECRET_ACCESS_KEY is invalid",
        MAX_SECRET_ACCESS_KEY_CHARS,
    )
    grant_secret = _base64_secret(
        environment, "GRANT_SECRET", EDGE_SECRET_BYTES)
    permit_secret = _base64_secret(
        environment, "PERMIT_SECRET", PERMIT_SECRET_BYTES)
    if permit_secret == grant_secret:
        raise ValueError("PERMIT_SECRET must differ from GRANT_SECRET")
    return {
        "GRANT_SECRET": grant_secret,
        "PERMIT_SECRET": permit_secret,
        "PACK_TICKET_SECRET": _base64_secret(
            environment, "PACK_TICKET_SECRET", PACK_TICKET_SECRET_BYTES),
        "R2_ACCESS_KEY_ID": access,
        "R2_SECRET_ACCESS_KEY": secret,
    }


def _store_prefix(value):
    try:
        validate_store_prefix(value)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("CF_STORE_PREFIX must be a relative object key")
    return value


def generated_config(environment=os.environ, *, smoke=False):
    """Resolve one explicit workspace, R2 binding, and route configuration."""
    config = json.loads(TEMPLATE.read_text())
    workspace = environment.get("CF_WORKSPACE")
    bucket = environment.get("CF_R2_BUCKET")
    owner = environment.get("CF_DEPLOYMENT_OWNER")
    if not FID.fullmatch(workspace or ""):
        raise ValueError("CF_WORKSPACE must be 64 lowercase hex characters")
    if not bucket:
        raise ValueError("CF_R2_BUCKET is required")
    if not OWNER.fullmatch(owner or ""):
        raise ValueError(
            "CF_DEPLOYMENT_OWNER must be 8-128 identifier characters")
    prefix = _store_prefix(environment.get(
        "CF_STORE_PREFIX", f"workspaces/{workspace}").strip("/"))
    try:
        ttl = int(environment.get(
            "CF_PACK_TTL_SECONDS", str(DEFAULT_PACK_TTL_SECONDS)))
    except (TypeError, ValueError) as error:
        raise ValueError("CF_PACK_TTL_SECONDS is invalid") from error
    target = R2PackTarget(
        environment.get("CF_R2_ENDPOINT"),
        bucket,
        prefix,
        environment.get("CF_PACK_PUT_ENDPOINT"),
        ttl,
    )
    config["name"] = environment.get(
        "CF_WORKER_NAME", "poc-16-owner-gateway")
    if not WORKER_NAME.fullmatch(config["name"]):
        raise ValueError("CF_WORKER_NAME is not a safe Worker script name")
    config["r2_buckets"][0].update({
        "bucket_name": bucket,
        "preview_bucket_name": environment.get(
            "CF_R2_PREVIEW_BUCKET", bucket),
    })
    config["vars"]["WORKSPACE"] = workspace
    config["vars"]["STORE_PREFIX"] = prefix
    config["vars"]["R2_ENDPOINT"] = target.endpoint
    config["vars"]["PACK_BUCKET"] = target.bucket
    config["vars"]["PACK_PUT_ENDPOINT"] = target.put_endpoint
    config["vars"]["PACK_TTL_SECONDS"] = target.ttl_seconds
    config["vars"][OWNER_BINDING] = owner
    if smoke:
        config["name"] = f"poc16-smoke-{os.urandom(16).hex()}"
        config["workers_dev"] = True
        config["routes"] = []
        # Cloudflare's Free plan rejects an explicit Worker limits object,
        # including the production subrequest ceiling, before the smoke
        # Worker can be uploaded.  The ephemeral smoke exercises only one
        # mint request, so the plan defaults are sufficient here.
        config.pop("limits", None)
    else:
        route = environment.get("CF_ROUTE")
        if not route:
            raise ValueError("CF_ROUTE is required")
        route_config = {"pattern": route}
        if environment.get("CF_CUSTOM_DOMAIN") == "1":
            route_config["custom_domain"] = True
        elif zone := environment.get("CF_ZONE_NAME"):
            route_config["zone_name"] = zone
        config["routes"] = [route_config]
    return config


def _write_config(config):
    GENERATED.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")


def _verify_bundle(directory):
    paths = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*") if path.is_file()
    }
    required = {
        "entry.py",
        "runtime.py",
        "crypto_compat.py",
        "core/access.py",
        "core/kernel.py",
        "core/removal_path.py",
        "core/removal_state.py",
        "core/removal_tree.py",
        "core/writer_repository.py",
        "facts/auth/request.py",
        "facts/auth/service_binding.py",
        "facts/auth/service_request.py",
        "adapters/r2/listing.py",
        "adapters/r2/worker.py",
        "adapters/r2/reader.py",
        "core/http.py",
        "deploy/cloudflare_sigv4.py",
        "deploy/cloudflare_pack/contract.py",
        "deploy/cloudflare_pack/issuer.py",
        "deploy/cloudflare_pack/put.py",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(f"dry-run omitted modules: {sorted(missing)}")
    forbidden = {
        "core/authority.py",
        "core/repository_reader.py",
        "core/repository_applier.py",
        "core/store.py",
        "full_peer/node.py",
        "full_peer/daemon.py",
        "core/runtime.py",
        "adapters/r2/s3.py",
        "adapters/s3/store.py",
        "deploy/aws_lambda/app.py",
    } & paths
    if forbidden:
        raise RuntimeError(f"dry-run included host modules: {sorted(forbidden)}")
    if any(part.startswith(".venv") for path in paths
           for part in Path(path).parts):
        raise RuntimeError("dry-run included a virtual environment")
    sodium = tuple(
        directory.glob("python_modules/nacl/_sodium*.so"))
    if len(sodium) != 1 or b"__start_em_asm" in sodium[0].read_bytes():
        raise RuntimeError("dry-run did not contain patched PyNaCl")


def build():
    """Perform a clean Wrangler dry-run and inspect its exact artifact."""
    with tempfile.TemporaryDirectory(prefix="poc16-cf-build-") as output:
        _pywrangler("deploy", "--dry-run", "--outdir", output)
        _verify_bundle(Path(output))


def workerd_test():
    """Start local workerd and make a crypto-gated request."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    environment = {
        **os.environ,
        "GRANT_SECRET": base64.b64encode(
            bytes(EDGE_SECRET_BYTES)).decode(),
        "PERMIT_SECRET": base64.b64encode(
            b"m" * PERMIT_SECRET_BYTES).decode(),
        "PACK_TICKET_SECRET": base64.b64encode(
            b"p" * PACK_TICKET_SECRET_BYTES).decode(),
        "R2_ACCESS_KEY_ID": "workerd-access",
        "R2_SECRET_ACCESS_KEY": "workerd-secret",
    }
    with tempfile.NamedTemporaryFile(
            mode="w+", prefix="poc16-workerd-", suffix=".log") as log:
        process = subprocess.Popen(
            [
                "uv", "run", "pywrangler", "dev",
                "--ip", "127.0.0.1", "--port", str(port),
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
                    with urlopen(
                            f"http://127.0.0.1:{port}/healthz",
                            timeout=1) as response:
                        if response.status == 200 \
                                and response.read() == b'{"ok":true}':
                            return
                        error = RuntimeError("unexpected health response")
                except (OSError, URLError) as caught:
                    error = caught
                time.sleep(0.1)
            log.seek(0)
            output = log.read()
            raise RuntimeError(
                f"workerd health test failed: {error}\n{output}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def test():
    _run([
        "uv", "run", "python", "-m", "pytest", "-q", str(TEST_FILE),
    ])
    build()
    workerd_test()


def dev(extra):
    _secrets(os.environ)
    _pywrangler("dev", *extra, env=os.environ)


def _deploy(
        config, secret_values, *, capture=False,
        timeout=CONTROL_TIMEOUT_SECONDS):
    _write_config(config)
    with tempfile.NamedTemporaryFile(
            mode="w", prefix="poc16-secrets-", suffix=".json") as pending:
        json.dump(secret_values, pending)
        pending.flush()
        return _pywrangler(
            "deploy",
            "--no-experimental-provision",
            "--strict",
            "--config", str(GENERATED),
            "--secrets-file", pending.name,
            capture=capture,
            env=os.environ,
            timeout=timeout,
        )


def _control_environment(environment=os.environ):
    account = environment.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = environment.get("CLOUDFLARE_API_TOKEN", "")
    if not ACCOUNT_ID.fullmatch(account):
        raise ValueError(
            "CLOUDFLARE_ACCOUNT_ID must be 32 lowercase hex characters")
    if not token:
        raise ValueError("CLOUDFLARE_API_TOKEN is required")
    return account, token


def _worker_settings(config, environment=os.environ):
    """Read the deployed binding marker through Cloudflare's direct API."""
    account, token = _control_environment(environment)
    name = config["name"]
    if not WORKER_NAME.fullmatch(name):
        raise ValueError("unsafe Worker script name")
    endpoint = (
        "https://api.cloudflare.com/client/v4/accounts/"
        f"{quote(account, safe='')}/workers/scripts/"
        f"{quote(name, safe='')}/settings"
    )
    request = Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read(API_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code == 404:
            return _ABSENT
        raise RuntimeError("Cloudflare Worker ownership lookup failed") \
            from error
    except (OSError, URLError) as error:
        raise RuntimeError("Cloudflare Worker ownership lookup failed") \
            from error
    if len(raw) > API_RESPONSE_BYTES:
        raise RuntimeError("Cloudflare Worker settings response is too large")
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) \
                or document.get("success") is not True \
                or not isinstance(document.get("result"), dict):
            raise ValueError
        bindings = document["result"].get("bindings")
        if not isinstance(bindings, list):
            raise ValueError
        matches = [
            binding for binding in bindings
            if isinstance(binding, dict)
            and binding.get("name") == OWNER_BINDING
        ]
        if len(matches) != 1 \
                or matches[0].get("type") != "plain_text" \
                or not isinstance(matches[0].get("text"), str):
            return None
        return matches[0]["text"]
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed Cloudflare Worker settings response") \
            from error


def _expected_owner(config):
    owner = config.get("vars", {}).get(OWNER_BINDING)
    if not OWNER.fullmatch(owner or ""):
        raise ValueError("generated Worker config has no valid owner")
    return owner


def _preflight_deploy(config, *, allow_create):
    observed = _worker_settings(config)
    if observed is _ABSENT:
        if not allow_create:
            raise RuntimeError(
                "Worker is absent; set CF_CREATE=1 for explicit creation")
        return
    if observed != _expected_owner(config):
        raise RuntimeError("refusing to overwrite an unowned Worker")


def _require_owned(config):
    if _worker_settings(config) != _expected_owner(config):
        raise RuntimeError("refusing to mutate an absent or unowned Worker")


def _delete(
        config, *, force=False,
        timeout=CONTROL_TIMEOUT_SECONDS):
    _write_config(config)
    arguments = [
        "delete", "--no-experimental-provision", config["name"],
        "--config", str(GENERATED),
    ]
    if force:
        arguments.append("--force")
    try:
        _pywrangler(
            *arguments,
            env=os.environ,
            timeout=timeout,
        )
    except subprocess.CalledProcessError:
        # Wrangler can report a failure after Cloudflare has already applied
        # the delete (for example, while inspecting unrelated provisionable
        # resources).  Authoritative absence is successful cleanup.
        if _worker_settings(config) is _ABSENT:
            return
        raise


def deploy():
    secrets = _secrets(os.environ)
    config = generated_config()
    _preflight_deploy(
        config,
        allow_create=os.environ.get("CF_CREATE") == "1",
    )
    _deploy(config, secrets)
    _require_owned(config)


def remove(*, force=False, config=None):
    config = generated_config() if config is None else config
    _require_owned(config)
    _delete(config, force=force)


def smoke():
    """Deploy a unique live Worker, authorize once, and always remove it."""
    if os.environ.get("CF_LIVE_SMOKE") != "1":
        raise ValueError("set CF_LIVE_SMOKE=1 to authorize live smoke changes")
    request_path = os.environ.get("CF_SMOKE_MINT_FILE")
    if not request_path:
        raise ValueError("CF_SMOKE_MINT_FILE is required")
    request_body = Path(request_path).read_bytes()
    secrets = _secrets(os.environ)
    config = generated_config(smoke=True)
    if _worker_settings(config) is not _ABSENT:
        raise RuntimeError("generated smoke Worker name already exists")
    attempted = False
    primary = None
    try:
        attempted = True
        result = _deploy(config, secrets, capture=True)
        _require_owned(config)
        print(result.stdout, end="")
        match = WORKERS_URL.search(result.stdout + result.stderr)
        if match is None:
            raise RuntimeError("Wrangler did not report a workers.dev URL")
        workspace = config["vars"]["WORKSPACE"]
        request = Request(
            f"{match.group(0)}/mint?ws={workspace}",
            data=request_body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                # Cloudflare's edge rejects urllib's default fingerprint with
                # error 1010 before the request reaches a workers.dev route.
                "User-Agent": "poc-16-live-smoke/1",
            },
        )
        deadline = time.monotonic() + SMOKE_ACTIVATION_TIMEOUT_SECONDS
        while True:
            try:
                with urlopen(request, timeout=30) as response:
                    value = json.loads(response.read())
                    if response.status != 200 \
                            or value.get("cap") != "sync-v1/owner":
                        raise RuntimeError("live mint smoke failed")
                break
            except HTTPError as error:
                if error.code not in SMOKE_ACTIVATION_STATUSES \
                        or time.monotonic() >= deadline:
                    raise
                error.close()
                time.sleep(SMOKE_ACTIVATION_POLL_SECONDS)
    except Exception as error:
        primary = error
    cleanup = None
    if attempted:
        try:
            _delete(config, force=True, timeout=60)
        except Exception as error:
            cleanup = error
    if primary is not None and cleanup is not None:
        raise ExceptionGroup(
            "Cloudflare smoke and cleanup both failed",
            [primary, cleanup],
        )
    if primary is not None:
        raise primary
    if cleanup is not None:
        raise cleanup


def stress():
    """Run the opt-in disposable live HTTP/R2 head-contention proof."""
    from bench.cloudflare_http_contention import live_run

    print(json.dumps(live_run(), indent=2, sort_keys=True))


def help_text():
    return """usage: manage.py COMMAND

Commands:
  help      show this help
  test      run host, clean dry-run, and local workerd tests
  build     create and inspect a clean pywrangler dry-run artifact
  dev       run the local Worker with its direct local R2 binding
  deploy    deploy one configured workspace with validated secrets
  remove    remove the configured production Worker
  smoke     opt-in live mint test using a unique, automatically removed Worker
  stress    opt-in live HTTP head-contention test with exact R2 cleanup
  stage     internal custom-build hook used by Wrangler
"""


def main(argv):
    command = argv[1] if len(argv) >= 2 else "help"
    if command == "stage":
        stage()
        return 0
    if command == "help" and len(argv) == 2:
        print(help_text(), end="")
        return 0
    if command == "test" and len(argv) == 2:
        test()
        return 0
    if command == "build" and len(argv) == 2:
        build()
        return 0
    if command == "dev":
        dev(argv[2:])
        return 0
    if command == "deploy" and len(argv) == 2:
        deploy()
        return 0
    if command == "remove" and len(argv) == 2:
        remove()
        return 0
    if command == "smoke" and len(argv) == 2:
        smoke()
        return 0
    if command == "stress" and len(argv) == 2:
        stress()
        return 0
    print(help_text(), file=sys.stderr, end="")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
