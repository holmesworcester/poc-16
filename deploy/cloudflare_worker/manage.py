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
BUILD = PACKAGE / "build"
WORKER = BUILD / "worker"
VENDORED = PACKAGE / "python_modules"
TEMPLATE = PACKAGE / "wrangler.jsonc"
GENERATED = PACKAGE / "wrangler.generated.json"
TEST_FILE = PACKAGE / "test_worker.py"

FID = re.compile(r"^[0-9a-f]{64}$")
STORE_KEY = re.compile(r"^[a-z0-9:._/-]+$")
WORKERS_URL = re.compile(r"https://[a-z0-9.-]+\.workers\.dev")
WORKER_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
OWNER = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
OWNER_BINDING = "POC16_DEPLOYMENT_OWNER"
API_RESPONSE_BYTES = 64 * 1024
CONTROL_TIMEOUT_SECONDS = 120
_ABSENT = object()

CORE_MODULES = (
    "__init__.py",
    "bao.py",
    "merkle_map.py",
    "catalog.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "grants.py",
    "indexes.py",
    "kernel.py",
    "manifest.py",
    "mint.py",
    "object_store.py",
    "limits.py",
    "peer_capability.py",
    "shape.py",
    "suppression.py",
    "suppression_state.py",
    "worker.py",
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
    matches = tuple((VENDORED / "nacl").glob("_sodium*.so"))
    if len(matches) != 1:
        raise RuntimeError("expected one vendored PyNaCl _sodium module")
    module = matches[0]
    raw = module.read_bytes()
    if not raw.startswith(b"\x00asm"):
        raise RuntimeError("vendored PyNaCl _sodium is not WebAssembly")
    pairs = (
        (b"__start_em_asm", b"__start_em_xsm"),
        (b"__stop_em_asm", b"__stop_em_xsm"),
    )
    for original, disabled in pairs:
        if raw.count(original) == 1 and disabled not in raw:
            raw = raw.replace(original, disabled)
        elif raw.count(disabled) != 1 or original in raw:
            raise RuntimeError("unexpected PyNaCl EM_ASM export layout")
    temporary = module.with_suffix(".patched")
    temporary.write_bytes(raw)
    temporary.replace(module)

    bindings = VENDORED / "nacl" / "bindings" / "__init__.py"
    source = bindings.read_text()
    initializer = "# Initialize Sodium\nsodium_init()\n"
    disabled = "# Workerd compatibility: deterministic primitives need no RNG init.\n"
    if initializer in source and disabled not in source:
        source = source.replace(initializer, disabled)
        bindings.write_text(source)
    elif source.count(disabled) != 1 or initializer in source:
        raise RuntimeError("unexpected PyNaCl sodium initializer layout")


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
    for name in ("__init__.py", "worker.py"):
        _copy(
            REPOSITORY / "adapters" / "r2" / name,
            pending / "adapters" / "r2" / name,
        )
    for name in ("__init__.py", "gateway.py"):
        _copy(REPOSITORY / "deploy" / name, pending / "deploy" / name)
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


def _secret(environment):
    value = environment.get("GRANT_SECRET", "").strip()
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("GRANT_SECRET must be base64") from error
    if len(raw) != 32:
        raise ValueError("GRANT_SECRET must encode exactly 32 bytes")
    return value


def _store_prefix(value):
    parts = value.split("/")
    if not STORE_KEY.fullmatch(value) \
            or any(not part or part in {".", ".."} for part in parts):
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
    config["name"] = environment.get(
        "CF_WORKER_NAME", "poc-16-readonly-gateway")
    if not WORKER_NAME.fullmatch(config["name"]):
        raise ValueError("CF_WORKER_NAME is not a safe Worker script name")
    config["r2_buckets"][0].update({
        "bucket_name": bucket,
        "preview_bucket_name": environment.get(
            "CF_R2_PREVIEW_BUCKET", bucket),
    })
    config["vars"]["WORKSPACE"] = workspace
    config["vars"]["STORE_PREFIX"] = prefix
    config["vars"][OWNER_BINDING] = owner
    if smoke:
        config["name"] = f"poc16-smoke-{os.urandom(16).hex()}"
        config["workers_dev"] = True
        config["routes"] = []
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
        "core/mint.py",
        "core/worker.py",
        "facts/auth/request.py",
        "adapters/r2/worker.py",
        "deploy/gateway.py",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(f"dry-run omitted modules: {sorted(missing)}")
    forbidden = {
        "core/store.py",
        "core/node.py",
        "core/daemon.py",
        "core/runtime.py",
        "adapters/r2/s3.py",
        "adapters/s3/store.py",
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
        "GRANT_SECRET": base64.b64encode(bytes(32)).decode(),
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
    _secret(os.environ)
    _pywrangler("dev", *extra, env=os.environ)


def _deploy(
        config, secret, *, capture=False,
        timeout=CONTROL_TIMEOUT_SECONDS):
    _write_config(config)
    with tempfile.NamedTemporaryFile(
            mode="w", prefix="poc16-secrets-", suffix=".json") as secrets:
        json.dump({"GRANT_SECRET": secret}, secrets)
        secrets.flush()
        return _pywrangler(
            "deploy",
            "--config", str(GENERATED),
            "--secrets-file", secrets.name,
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
        "delete", config["name"], "--config", str(GENERATED),
    ]
    if force:
        arguments.append("--force")
    _pywrangler(
        *arguments,
        env=os.environ,
        timeout=timeout,
    )


def deploy():
    config = generated_config()
    _preflight_deploy(
        config,
        allow_create=os.environ.get("CF_CREATE") == "1",
    )
    _deploy(config, _secret(os.environ))
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
    config = generated_config(smoke=True)
    if _worker_settings(config) is not _ABSENT:
        raise RuntimeError("generated smoke Worker name already exists")
    attempted = False
    primary = None
    try:
        attempted = True
        result = _deploy(config, _secret(os.environ), capture=True)
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
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=30) as response:
            value = json.loads(response.read())
            if response.status != 200 \
                    or value.get("cap") != "sync-v1/read":
                raise RuntimeError("live mint smoke failed")
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


def help_text():
    return """usage: manage.py COMMAND

Commands:
  help      show this help
  test      run host, clean dry-run, and local workerd tests
  build     create and inspect a clean pywrangler dry-run artifact
  dev       run the local Worker with its direct local R2 binding
  deploy    deploy one configured workspace and encrypted grant secret
  remove    remove the configured production Worker
  smoke     opt-in live mint test using a unique, automatically removed Worker
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
    print(help_text(), file=sys.stderr, end="")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
