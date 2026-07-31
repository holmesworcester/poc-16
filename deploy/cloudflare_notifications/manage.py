#!/usr/bin/env python3
"""Build and safely operate the Cloudflare notification compartments.

Queue and R2 data are intentionally never deleted by this tool.  Worker
removal first disables the producer and checks the deployment-owner marker;
the retained cursor, primary queue, and DLQ make rollback recoverable.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


PACKAGE = Path(__file__).resolve().parent
REPOSITORY = PACKAGE.parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from adapters.cloudflare.queue import (  # noqa: E402
    MAX_CLOUDFLARE_QUEUE_BODY_BYTES,
)
from core.crypto import load_sk  # noqa: E402
from core.object_store import validate_store_prefix  # noqa: E402
from deploy.cloudflare_python import patch_pynacl  # noqa: E402
from deploy.notification_launch import (  # noqa: E402
    require_mobile_launches,
    tree_digest,
)
from deploy.python_role_modules import (  # noqa: E402
    REPOSITORY_READER_CORE_MODULES,
)
from notifications.delivery import delivery_domain_id  # noqa: E402


SCANNER_TEMPLATE = PACKAGE / "wrangler.scanner.jsonc"
CONSUMER_TEMPLATE = PACKAGE / "wrangler.consumer.jsonc"
READER_TEMPLATE = PACKAGE / "wrangler.reader.jsonc"
FCM_TEMPLATE = PACKAGE / "wrangler.fcm.jsonc"
SCANNER_CONFIG = PACKAGE / "wrangler.scanner.generated.json"
CONSUMER_CONFIG = PACKAGE / "wrangler.consumer.generated.json"
READER_CONFIG = PACKAGE / "wrangler.reader.generated.json"
FCM_CONFIG = PACKAGE / "wrangler.fcm.generated.json"
HARNESS_CONFIG = PACKAGE / "wrangler.launch-harness.generated.json"
HARNESS_SOURCE = PACKAGE / "launch_harness" / "worker.mjs"
BUILD = PACKAGE / "build"
VENDORED = PACKAGE / "python_modules"
RELEASE = BUILD / "release"
RELEASE_MANIFEST_FORMAT = "poc16-cloudflare-notification-release-v1"
RELEASE_MANIFEST_ENV = "CF_NOTIFICATION_RELEASE_MANIFEST"
COMPLETION_PROTOCOL = "poc16-notification-completion-v1"
EXPECTED_FCM_VERSION_BINDING = "POC16_EXPECTED_FCM_VERSION"
BUILD_VERSION_ID = "00000000-0000-4000-8000-000000000000"

OWNER_BINDING = "POC16_DEPLOYMENT_OWNER"
IDENTITY_BINDING = "POC16_DEPLOYMENT_IDENTITY"
SOFTWARE_BINDING = "POC16_SOFTWARE_DIGEST"
RELEASE_BINDING = "POC16_RELEASE_ID"
ROLE_BINDING = "POC16_DEPLOYMENT_ROLE"
ACCOUNT_BINDING = "POC16_CLOUDFLARE_ACCOUNT_ID"
WRANGLER = "wrangler@4.118.0"
# The free plan fixes retention at 24 hours. Correctness does not depend on
# Queue retention because the scanner republishes the durable pending body.
RETENTION_SECONDS = 24 * 60 * 60
MAX_BATCH_SIZE = 10
MAX_RETRIES = 25
MAX_CONCURRENCY = 4
RETRY_DELAY_SECONDS = 30
API_RESPONSE_BYTES = 512 * 1024
CONTROL_TIMEOUT_SECONDS = 120
BOOTSTRAP_NONE = "none"
BOOTSTRAP_CURRENT = "current"
BOOTSTRAP_BACKFILL = "backfill"
BOOTSTRAP_MODES = {
    BOOTSTRAP_NONE, BOOTSTRAP_CURRENT, BOOTSTRAP_BACKFILL,
}

FID = re.compile(r"^[0-9a-f]{64}$")
VERSION_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
OWNER = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
APPLICATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
ENVIRONMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,62}$")
WORKERS_SUBDOMAIN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ABSENT = object()

ROLE_KEYS = ("reader", "scanner", "consumer", "fcm")
ROLE_NAMES = {
    "reader": "notification-canonical-reader",
    "scanner": "notification-scanner",
    "consumer": "notification-consumer",
    "fcm": "notification-fcm-boundary",
}
CONFIG_PATHS = {
    "reader": READER_CONFIG,
    "scanner": SCANNER_CONFIG,
    "consumer": CONSUMER_CONFIG,
    "fcm": FCM_CONFIG,
}

CORE_MODULES = tuple(dict.fromkeys(
    (*REPOSITORY_READER_CORE_MODULES, "fetch_budget.py")))


def _copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def stage():
    """Stage exact role import trees without RepositoryApplier."""
    patch_pynacl(VENDORED)
    pending = BUILD / "pending"
    if pending.exists():
        shutil.rmtree(pending)
    for role, entry in (
            ("reader", "reader_entry.py"),
            ("scanner", "scanner_entry.py"),
            ("consumer", "consumer_entry.py")):
        root = pending / role
        root.mkdir(parents=True)
        _copy(PACKAGE / entry, root / "entry.py")
        _copy(PACKAGE / f"{role}.py", root / f"{role}.py")
        _copy(PACKAGE / "settings.py", root / "settings.py")
        for name in CORE_MODULES:
            _copy(REPOSITORY / "core" / name, root / "core" / name)
        if role != "reader":
            shutil.copytree(
                REPOSITORY / "facts", root / "facts",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            shutil.copytree(
                REPOSITORY / "notifications", root / "notifications",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        _copy(
            REPOSITORY / "adapters" / "__init__.py",
            root / "adapters" / "__init__.py")
        if role in {"reader", "scanner"}:
            names = ("__init__.py", "reader.py") if role == "reader" else (
                "__init__.py", "reader.py", "worker.py")
            for name in names:
                _copy(
                    REPOSITORY / "adapters" / "r2" / name,
                    root / "adapters" / "r2" / name)
            if role == "reader":
                (root / "adapters" / "r2" / "__init__.py").write_text(
                    "from .reader import R2ReadBindingStore\n"
                    "__all__ = ('R2ReadBindingStore',)\n")
        if role != "reader":
            for source in (
                    REPOSITORY / "adapters" / "cloudflare").glob("*.py"):
                _copy(source, root / "adapters" / "cloudflare" / source.name)

    # This tree is the exact release subject used by the physical-device
    # launch records.  Keep it independent of bytecode caches and generated
    # configs so the digest is deterministic while still covering every
    # deployed source, locked dependency, and runtime configuration template.
    release = pending / "release"
    for role in ("reader", "scanner", "consumer"):
        shutil.copytree(
            pending / role, release / role,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(
        VENDORED, release / "python_modules",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for source in (
            PACKAGE / "fcm_bridge" / "core.mjs",
            PACKAGE / "fcm_bridge" / "worker.js",
            HARNESS_SOURCE,
            PACKAGE / "manage.py",
            PACKAGE / "pylock.toml",
            PACKAGE / "pyproject.toml",
            PACKAGE / "uv.lock",
            REPOSITORY / "deploy" / "cloudflare_python.py",
            REPOSITORY / "deploy" / "notification_launch.py",
            REPOSITORY / "deploy" / "python_role_modules.py",
            *(
                PACKAGE / name for name in (
                    "wrangler.reader.jsonc", "wrangler.scanner.jsonc",
                    "wrangler.consumer.jsonc", "wrangler.fcm.jsonc")),
    ):
        _copy(source, release / source.relative_to(REPOSITORY))
    for role in ("reader", "scanner", "consumer", "release"):
        destination = BUILD / role
        if destination.exists():
            shutil.rmtree(destination)
        (pending / role).rename(destination)
    pending.rmdir()


def _software_digest():
    return tree_digest(RELEASE)


def _prepare_software():
    sync()
    stage()
    return _software_digest()


def _stage_locked(expected):
    if not FID.fullmatch(expected or ""):
        raise ValueError("expected software digest")
    stage()
    if _software_digest() != expected:
        raise RuntimeError("Cloudflare notification deploy inputs changed")


def _text(environment, name):
    value = environment.get(name, "")
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    return value


def _safe_name(environment, name, default):
    value = environment.get(name, default)
    if not SAFE_NAME.fullmatch(value or ""):
        raise ValueError(f"{name} is not a safe Cloudflare name")
    return value


def _prefix(value, label):
    value = value.strip("/")
    try:
        return validate_store_prefix(value)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError(f"{label} is not a safe store prefix") from error


def _worker_versions(value):
    if not isinstance(value, dict) or set(value) != set(ROLE_KEYS):
        raise ValueError("exact Cloudflare Worker versions")
    result = {}
    for role in ROLE_KEYS:
        version = value.get(role)
        if not isinstance(version, str) or not VERSION_ID.fullmatch(version):
            raise ValueError(f"invalid {role} Worker version")
        result[role] = version
    if len(set(result.values())) != len(result):
        raise ValueError("Cloudflare Worker versions must differ")
    return result


def _manifest_path(environment=os.environ):
    raw = _text(environment, RELEASE_MANIFEST_ENV)
    path = Path(raw).expanduser().resolve()
    if path == Path("/") or path.is_dir():
        raise ValueError("release manifest must name a file")
    return path


def _release_manifest(document):
    if not isinstance(document, dict) or set(document) != {
            "deployment_identity", "format", "release_id",
            "software_digest", "worker_versions"} \
            or document.get("format") != RELEASE_MANIFEST_FORMAT \
            or not FID.fullmatch(document.get("deployment_identity", "")) \
            or not FID.fullmatch(document.get("release_id", "")) \
            or not FID.fullmatch(document.get("software_digest", "")):
        raise ValueError("Cloudflare notification release manifest")
    return {
        **document,
        "worker_versions": _worker_versions(document["worker_versions"]),
    }


def _load_release(environment=os.environ):
    path = _manifest_path(environment)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RuntimeError("cannot read Cloudflare release manifest") from error
    if not 0 < len(raw) <= 4096 or raw.endswith(b"\n"):
        raise RuntimeError("non-canonical Cloudflare release manifest")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed Cloudflare release manifest") from error
    document = _release_manifest(document)
    canonical = json.dumps(
        document, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True).encode("ascii")
    if raw != canonical:
        raise RuntimeError("non-canonical Cloudflare release manifest")
    return document


def _write_release(document, environment=os.environ):
    document = _release_manifest(document)
    path = _manifest_path(environment)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise RuntimeError("release manifest already exists")
    raw = json.dumps(
        document, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True).encode("ascii")
    temporary = path.with_name(path.name + ".pending")
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise RuntimeError("release manifest staging file already exists") \
            from error
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        try:
            # Same-directory hard-link publication is create-if-absent.  An
            # os.replace here would silently clobber a concurrent operator's
            # complete manifest after the precheck above.
            os.link(temporary, path)
        except FileExistsError as error:
            raise RuntimeError("release manifest already exists") from error
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _mobile_launch_binding(configs, worker_versions=None):
    reader, scanner, consumer, fcm = configs
    binding = {
        "canonical_bucket": reader["r2_buckets"][0]["bucket_name"],
        "canonical_prefix": reader["vars"]["CANONICAL_PREFIX"],
        "cloudflare_account_id": scanner["vars"][ACCOUNT_BINDING],
        "deployment_identity": scanner["vars"][IDENTITY_BINDING],
        "deployment_owner": scanner["vars"][OWNER_BINDING],
        "firebase_application": fcm["vars"]["FCM_APPLICATION"],
        "firebase_environment": fcm["vars"]["FCM_ENVIRONMENT"],
        "firebase_project": fcm["vars"]["FCM_PROJECT_ID"],
        "notification_queue": scanner["queues"]["producers"][0]["queue"],
        "notification_state_bucket": scanner["r2_buckets"][0]["bucket_name"],
        "notification_state_prefix": scanner["vars"][
            "NOTIFICATION_STATE_PREFIX"],
        "provider": "cloudflare",
        "push_node_id": consumer["vars"]["PUSH_NODE"],
        "release_id": scanner["vars"][RELEASE_BINDING],
        "software_digest": scanner["vars"][SOFTWARE_BINDING],
        "workspace": scanner["vars"]["WORKSPACE"],
    }
    if worker_versions is not None:
        binding["worker_versions"] = _worker_versions(worker_versions)
    return binding


def generated_configs(
        environment=os.environ, *, bootstrap_mode=BOOTSTRAP_NONE,
        software_digest=None, release_id=None, worker_versions=None,
        launch_gate=True):
    """Resolve one workspace and keep live effects disabled by default."""
    if bootstrap_mode not in BOOTSTRAP_MODES:
        raise ValueError("notification bootstrap mode")
    software_digest = "0" * 64 \
        if software_digest is None else software_digest
    if not FID.fullmatch(software_digest or ""):
        raise ValueError("software digest must be 64 lowercase hex")
    release_id = "0" * 64 if release_id is None else release_id
    if not FID.fullmatch(release_id or ""):
        raise ValueError("release id must be 64 lowercase hex")
    workspace = _text(environment, "CF_WORKSPACE")
    account = _text(environment, "CLOUDFLARE_ACCOUNT_ID")
    owner = _text(environment, "CF_DEPLOYMENT_OWNER")
    canonical = _text(environment, "CF_CANONICAL_BUCKET")
    state = _text(environment, "CF_NOTIFICATION_STATE_BUCKET")
    if not FID.fullmatch(workspace):
        raise ValueError("CF_WORKSPACE must be 64 lowercase hex characters")
    if not ACCOUNT_ID.fullmatch(account):
        raise ValueError("CLOUDFLARE_ACCOUNT_ID must be 32 lowercase hex")
    if not OWNER.fullmatch(owner):
        raise ValueError("CF_DEPLOYMENT_OWNER is not a safe owner marker")
    if canonical == state:
        raise ValueError("canonical and notification-state buckets must differ")
    queue = _safe_name(
        environment, "CF_NOTIFICATION_QUEUE",
        f"poc16-notify-{workspace[:12]}")
    dlq = _safe_name(
        environment, "CF_NOTIFICATION_DLQ", queue + "-dlq")
    if queue == dlq:
        raise ValueError("notification queue and DLQ must differ")
    scanner_name = _safe_name(
        environment, "CF_NOTIFICATION_SCANNER",
        f"poc16-notify-scan-{workspace[:12]}")
    consumer_name = _safe_name(
        environment, "CF_NOTIFICATION_CONSUMER",
        f"poc16-notify-send-{workspace[:12]}")
    reader_name = _safe_name(
        environment, "CF_NOTIFICATION_READER",
        f"poc16-notify-read-{workspace[:12]}")
    fcm_name = _safe_name(
        environment, "CF_FCM_SERVICE", "poc16-fcm-boundary")
    names = (reader_name, scanner_name, consumer_name, fcm_name)
    if len(set(names)) != len(names):
        raise ValueError("notification Worker names must differ")
    application = _text(environment, "CF_FIREBASE_APPLICATION")
    firebase_environment = _text(environment, "CF_FIREBASE_ENVIRONMENT")
    firebase_project = _text(environment, "CF_FIREBASE_PROJECT_ID")
    push_node = _text(environment, "CF_PUSH_NODE_PUBLIC")
    if not APPLICATION.fullmatch(application):
        raise ValueError("CF_FIREBASE_APPLICATION is invalid")
    if not ENVIRONMENT.fullmatch(firebase_environment):
        raise ValueError("CF_FIREBASE_ENVIRONMENT is invalid")
    if not PROJECT.fullmatch(firebase_project):
        raise ValueError("CF_FIREBASE_PROJECT_ID is invalid")
    if not FID.fullmatch(push_node):
        raise ValueError("CF_PUSH_NODE_PUBLIC must be 64 lowercase hex")
    enabled = environment.get("CF_NOTIFICATIONS_ENABLED", "0")
    test_mode = environment.get("CF_NOTIFICATION_TEST_MODE", "0")
    if enabled not in {"0", "1"} or test_mode not in {"0", "1"}:
        raise ValueError("notification enablement bindings must be 0 or 1")
    if enabled == "1" and test_mode == "1" \
            and (firebase_environment.lower() in {"prod", "production"}
                 or environment.get("CF_FIREBASE_TEST_PROJECT_ID")
                 != firebase_project):
        raise ValueError(
            "test mode requires a non-production environment and the exact "
            "allowed Firebase test project")
    delivery_domain = delivery_domain_id(push_node, ((
        application, firebase_environment, firebase_project),))

    canonical_prefix = _prefix(environment.get(
        "CF_CANONICAL_PREFIX", f"workspaces/{workspace}"),
        "CF_CANONICAL_PREFIX")
    state_prefix = _prefix(environment.get(
        "CF_NOTIFICATION_STATE_PREFIX", f"notifications/v1/{workspace}"),
        "CF_NOTIFICATION_STATE_PREFIX")
    identity_document = {
        "canonical_bucket": canonical,
        "canonical_prefix": canonical_prefix,
        "cloudflare_account_id": account,
        "completion_protocol": COMPLETION_PROTOCOL,
        "delivery_domain": delivery_domain,
        "state_bucket": state,
        "state_prefix": state_prefix,
        "workspace": workspace,
    }
    identity = hashlib.sha256(json.dumps(
        identity_document, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True).encode("ascii")).hexdigest()
    common = {
        "WORKSPACE": workspace,
        "NOTIFICATIONS_ENABLED": enabled,
        "NOTIFICATION_TEST_MODE": test_mode,
        IDENTITY_BINDING: identity,
        OWNER_BINDING: owner,
        SOFTWARE_BINDING: software_digest,
        RELEASE_BINDING: release_id,
        ACCOUNT_BINDING: account,
    }

    reader = json.loads(READER_TEMPLATE.read_text())
    reader["name"] = reader_name
    reader["vars"].update({
        "WORKSPACE": workspace,
        "CANONICAL_PREFIX": canonical_prefix,
        "NOTIFICATIONS_ENABLED": enabled,
        "NOTIFICATION_TEST_MODE": test_mode,
        IDENTITY_BINDING: identity,
        OWNER_BINDING: owner,
        SOFTWARE_BINDING: software_digest,
        RELEASE_BINDING: release_id,
        ACCOUNT_BINDING: account,
    })
    reader["r2_buckets"][0].update({
        "bucket_name": canonical, "preview_bucket_name": canonical})

    scanner = json.loads(SCANNER_TEMPLATE.read_text())
    scanner["name"] = scanner_name
    scanner["vars"].update({
        **common,
        "NOTIFICATION_BOOTSTRAP_MODE": bootstrap_mode,
        "NOTIFICATION_STATE_PREFIX": state_prefix,
    })
    scanner["r2_buckets"][0].update({
        "bucket_name": state, "preview_bucket_name": state})
    scanner["services"][0]["service"] = reader_name
    scanner["queues"]["producers"][0]["queue"] = queue
    # Cron and Queue consumption are version-agnostic provider controls.  They
    # are attached only after exact-version promotion and never baked into a
    # candidate upload.
    scanner["triggers"]["crons"] = []

    consumer = json.loads(CONSUMER_TEMPLATE.read_text())
    consumer["name"] = consumer_name
    consumer["vars"].update(common)
    consumer["vars"]["PUSH_NODE"] = push_node
    consumer["services"][0]["service"] = reader_name
    consumer["services"][1]["service"] = scanner_name
    consumer["services"][2]["service"] = fcm_name
    consumer["queues"]["consumers"] = []
    fcm = json.loads(FCM_TEMPLATE.read_text())
    fcm["name"] = fcm_name
    fcm["main"] = (RELEASE / "deploy" / "cloudflare_notifications"
                   / "fcm_bridge" / "worker.js").relative_to(
                       PACKAGE).as_posix()
    fcm["vars"].update({
        IDENTITY_BINDING: identity,
        OWNER_BINDING: owner,
        SOFTWARE_BINDING: software_digest,
        RELEASE_BINDING: release_id,
        ACCOUNT_BINDING: account,
        "NOTIFICATIONS_ENABLED": enabled,
        "NOTIFICATION_TEST_MODE": test_mode,
        "FCM_APPLICATION": application,
        "FCM_ENVIRONMENT": firebase_environment,
        "FCM_PROJECT_ID": firebase_project,
    })
    for config in (reader, scanner, consumer):
        config["build"]["command"] = (
            f"python manage.py stage-locked {software_digest}")
    configs = reader, scanner, consumer, fcm
    if enabled == "1" and test_mode == "0" and launch_gate:
        if worker_versions is None:
            raise RuntimeError("exact Cloudflare Worker versions are required")
        require_mobile_launches({
            "ios": environment.get("CF_IOS_LAUNCH_RECORD"),
            "android": environment.get("CF_ANDROID_LAUNCH_RECORD"),
        }, _mobile_launch_binding(configs, worker_versions))
    return configs


def _write_configs(configs):
    for path, config in zip(
            (READER_CONFIG, SCANNER_CONFIG, CONSUMER_CONFIG, FCM_CONFIG),
            configs):
        path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")


def _harness_name(configs):
    account = configs[1]["vars"].get(ACCOUNT_BINDING, "")
    workspace = configs[1]["vars"].get("WORKSPACE", "")
    if not ACCOUNT_ID.fullmatch(account) or not FID.fullmatch(workspace):
        raise ValueError("launch harness identity")
    name = f"poc16-notify-launch-{account[:8]}-{workspace[:12]}"
    if not SAFE_NAME.fullmatch(name):
        raise ValueError("launch harness name")
    if name in {config["name"] for config in configs}:
        raise ValueError("launch harness name must differ from release Workers")
    return name


def _harness_config(configs, fcm_version):
    _reader, _scanner, _consumer, fcm = configs
    if not VERSION_ID.fullmatch(fcm_version or ""):
        raise ValueError("exact FCM Worker version")
    return {
        "$schema": "node_modules/wrangler/config-schema.json",
        "name": _harness_name(configs),
        "main": HARNESS_SOURCE.relative_to(PACKAGE).as_posix(),
        "compatibility_date": "2026-07-31",
        "workers_dev": True,
        "preview_urls": False,
        "routes": [],
        "services": [{"binding": "FCM_BOUNDARY", "service": fcm["name"]}],
        "vars": {
            ACCOUNT_BINDING: fcm["vars"][ACCOUNT_BINDING],
            IDENTITY_BINDING: fcm["vars"][IDENTITY_BINDING],
            OWNER_BINDING: fcm["vars"][OWNER_BINDING],
            RELEASE_BINDING: fcm["vars"][RELEASE_BINDING],
            ROLE_BINDING: "notification-launch-harness",
            SOFTWARE_BINDING: fcm["vars"][SOFTWARE_BINDING],
            EXPECTED_FCM_VERSION_BINDING: fcm_version,
            "NOTIFICATIONS_ENABLED": "1",
        },
    }


def _write_harness(config):
    HARNESS_CONFIG.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n")


def _run(command, *, capture=False, timeout=CONTROL_TIMEOUT_SECONDS,
         input_text=None, extra_environment=None):
    try:
        environment = dict(os.environ)
        if extra_environment:
            environment.update(extra_environment)
        return subprocess.run(
            command, cwd=PACKAGE, env=environment, check=True,
            capture_output=capture, text=True, input=input_text,
            timeout=timeout)
    except FileNotFoundError as error:
        raise RuntimeError(
            f"required executable is unavailable: {command[0]}") from error


def _pywrangler(
        *arguments, capture=False, input_text=None, extra_environment=None):
    return _run(
        ["uv", "run", "pywrangler", *arguments],
        capture=capture, input_text=input_text,
        extra_environment=extra_environment)


def _wrangler(
        *arguments, capture=False, input_text=None, extra_environment=None):
    return _run(
        ["npx", "--yes", WRANGLER, *arguments],
        capture=capture, input_text=input_text,
        extra_environment=extra_environment)


def _json_output(result, label):
    raw = getattr(result, "stdout", "")
    if not isinstance(raw, str) or not 0 < len(raw) <= API_RESPONSE_BYTES:
        raise RuntimeError(f"malformed Cloudflare {label} response")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"malformed Cloudflare {label} response") from error


def _wrangler_event(role, config_path, arguments, secrets_document=None):
    """Run one upload and return Wrangler's machine-readable exact result."""
    runner = _wrangler if role == "fcm" else _pywrangler
    with tempfile.TemporaryDirectory(
            prefix="poc16-cf-notify-version-") as directory:
        output = Path(directory) / "wrangler.ndjson"
        command = [*arguments, "--config", str(config_path)]
        if secrets_document is not None:
            if not isinstance(secrets_document, dict) or not secrets_document:
                raise ValueError("version secrets")
            secrets_path = Path(directory) / "secrets.json"
            secrets_path.write_text(json.dumps(
                secrets_document, ensure_ascii=True, separators=(",", ":"),
                sort_keys=True))
            command.extend(("--secrets-file", str(secrets_path)))
        runner(*command, extra_environment={
            "WRANGLER_OUTPUT_FILE_PATH": str(output),
        })
        try:
            raw = output.read_bytes()
        except OSError as error:
            raise RuntimeError("Wrangler omitted operation evidence") from error
    if not 0 < len(raw) <= 64 * 1024:
        raise RuntimeError("malformed Wrangler operation evidence")
    events = []
    try:
        for line in raw.splitlines():
            value = json.loads(line)
            if isinstance(value, dict) and value.get("type") != \
                    "wrangler-session":
                events.append(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed Wrangler operation evidence") from error
    if len(events) != 1:
        raise RuntimeError("ambiguous Wrangler operation evidence")
    return events[0]


def _upload_version(role, config, *, release_id, secrets_document=None):
    if role not in ROLE_KEYS or not FID.fullmatch(release_id or ""):
        raise ValueError("Worker release upload")
    arguments = [
        "versions", "upload", "--strict", "--tag", release_id[:32],
        "--message", f"poc16 notification release {release_id}",
    ]
    event = _wrangler_event(
        role, CONFIG_PATHS[role], arguments, secrets_document)
    if event.get("type") != "version-upload" \
            or event.get("version") != 1 \
            or event.get("worker_name") != config["name"] \
            or not VERSION_ID.fullmatch(event.get("version_id", "")):
        raise RuntimeError("malformed Wrangler version-upload evidence")
    return event["version_id"]


def _active_version(config, environment=os.environ):
    """Return the sole live version, or ABSENT when none is deployed."""
    try:
        document = _api(
            "GET", "/workers/scripts/" + quote(config["name"], safe="")
            + "/deployments", environment=environment)
    except RuntimeError as error:
        cause = error.__cause__
        if isinstance(cause, HTTPError) and cause.code == 404:
            return _ABSENT
        raise
    deployments = document.get("deployments") \
        if isinstance(document, dict) else None
    if not isinstance(deployments, list) or len(deployments) > 100 \
            or any(not isinstance(row, dict) for row in deployments):
        raise RuntimeError("malformed Cloudflare deployments")
    # Uploading a first version creates the Worker but not a deployment.  That
    # is still active absence and must remain stable through candidate upload.
    if not deployments:
        return _ABSENT
    versions = deployments[0].get("versions")
    if not isinstance(versions, list) or len(versions) != 1:
        raise RuntimeError("notification Worker has a split deployment")
    row = versions[0]
    version = row.get("version_id") if isinstance(row, dict) else None
    percentage = row.get("percentage") if isinstance(row, dict) else None
    if not VERSION_ID.fullmatch(version or "") \
            or percentage not in {100, 100.0}:
        raise RuntimeError("malformed Cloudflare deployment status")
    return version


def _config_role(config):
    role_name = config.get("vars", {}).get(ROLE_BINDING)
    matches = [role for role, name in ROLE_NAMES.items()
               if name == role_name]
    if len(matches) != 1:
        raise ValueError("notification Worker role")
    return matches[0]


def _version_bindings_at(runner, config_path, version_id):
    result = runner(
        "versions", "view", version_id, "--json", "--config",
        str(config_path), capture=True)
    document = _json_output(result, "Worker version")
    if not isinstance(document, dict) or document.get("id") != version_id:
        raise RuntimeError("Cloudflare returned the wrong Worker version")
    resources = document.get("resources")
    bindings = resources.get("bindings") if isinstance(resources, dict) \
        else None
    if not isinstance(bindings, list):
        raise RuntimeError("malformed Cloudflare Worker version")
    return bindings


def _version_bindings(role, config, version_id):
    runner = _wrangler if role == "fcm" else _pywrangler
    return _version_bindings_at(runner, CONFIG_PATHS[role], version_id)


def _binding_values(bindings, names):
    values = []
    for name in names:
        matches = [item for item in bindings
                   if isinstance(item, dict) and item.get("name") == name]
        if len(matches) != 1 or matches[0].get("type") != "plain_text" \
                or not isinstance(matches[0].get("text"), str):
            return None
        values.append(matches[0]["text"])
    return tuple(values)


def _version_markers(role, config, version_id):
    return _binding_values(_version_bindings(role, config, version_id), (
        OWNER_BINDING, IDENTITY_BINDING, SOFTWARE_BINDING, RELEASE_BINDING,
        "NOTIFICATIONS_ENABLED", ROLE_BINDING,
    ))


def _owned_incumbent(role, config, *, allow_absent=False):
    """Pin one active version and prove its immutable mutation authority."""
    version = _active_version(config)
    if version is _ABSENT:
        if allow_absent:
            return version, _ABSENT
        raise RuntimeError("notification Worker is absent")
    markers = _version_markers(role, config, version)
    variables = config["vars"]
    if markers is None or (markers[0], markers[1], markers[5]) != (
            variables[OWNER_BINDING], variables[IDENTITY_BINDING],
            variables[ROLE_BINDING]):
        raise RuntimeError(
            "refusing to mutate an unowned or rebound notification Worker")
    if _active_version(config) != version:
        raise RuntimeError("concurrent notification deployment")
    return version, markers


def _expected_markers(config):
    variables = config["vars"]
    return (
        variables[OWNER_BINDING], variables[IDENTITY_BINDING],
        variables[SOFTWARE_BINDING], variables[RELEASE_BINDING],
        variables["NOTIFICATIONS_ENABLED"], variables[ROLE_BINDING],
    )


def _require_candidate(role, config, version_id, secrets=()):
    bindings = _version_bindings(role, config, version_id)
    if _binding_values(bindings, (
            OWNER_BINDING, IDENTITY_BINDING, SOFTWARE_BINDING,
            RELEASE_BINDING, "NOTIFICATIONS_ENABLED", ROLE_BINDING,
    )) != _expected_markers(config):
        raise RuntimeError("Cloudflare candidate version markers differ")
    for name in secrets:
        matches = [item for item in bindings
                   if isinstance(item, dict) and item.get("name") == name]
        if len(matches) != 1 or matches[0].get("type") != "secret_text":
            raise RuntimeError(
                f"candidate Worker is missing required secret {name}")


def _promote(role, config, version_id):
    runner = _wrangler if role == "fcm" else _pywrangler
    runner(
        "versions", "deploy", "--version-id", version_id, "-y",
        "--message", "poc16 exact notification release",
        "--config", str(CONFIG_PATHS[role]))


def sync():
    _pywrangler("sync", "--allow-build")


def build():
    software_digest = _prepare_software()
    configs = generated_configs({
        "CF_WORKSPACE": "a" * 64,
        "CLOUDFLARE_ACCOUNT_ID": "b" * 32,
        "CF_DEPLOYMENT_OWNER": "local-build-owner",
        "CF_CANONICAL_BUCKET": "canonical-build",
        "CF_NOTIFICATION_STATE_BUCKET": "notification-state-build",
        "CF_FIREBASE_APPLICATION": "poc16.mobile",
        "CF_FIREBASE_ENVIRONMENT": "production",
        "CF_FIREBASE_PROJECT_ID": "firebase-build",
        "CF_PUSH_NODE_PUBLIC": "c" * 64,
        "CF_NOTIFICATIONS_ENABLED": "0",
    }, software_digest=software_digest)
    _write_configs(configs)
    harness = _harness_config(configs, BUILD_VERSION_ID)
    _write_harness(harness)
    for config in (READER_CONFIG, SCANNER_CONFIG, CONSUMER_CONFIG):
        with tempfile.TemporaryDirectory(
                prefix="poc16-cf-notify-") as output:
            _pywrangler(
                "deploy", "--dry-run", "--outdir", output,
                "--config", str(config))
            paths = {
                path.relative_to(output).as_posix()
                for path in Path(output).rglob("*") if path.is_file()
            }
            if not any(path.endswith("entry.py") for path in paths):
                raise RuntimeError("notification dry-run omitted entrypoint")
            if any("repository_applier" in path for path in paths):
                raise RuntimeError("notification bundle contains applier")
    with tempfile.TemporaryDirectory(
            prefix="poc16-cf-notify-fcm-") as output:
        _wrangler(
            "deploy", "--dry-run", "--outdir", output,
            "--config", str(FCM_CONFIG))
        if not any(
                path.suffix in {".js", ".mjs"}
                for path in Path(output).rglob("*")):
            raise RuntimeError("FCM dry-run omitted bridge code")
    with tempfile.TemporaryDirectory(
            prefix="poc16-cf-notify-harness-") as output:
        _wrangler(
            "deploy", "--dry-run", "--outdir", output,
            "--config", str(HARNESS_CONFIG))
        if not any(
                path.suffix in {".js", ".mjs"}
                for path in Path(output).rglob("*")):
            raise RuntimeError("launch harness dry-run omitted code")


def print_launch_binding():
    """Print the exact immutable provider release tested by mobile devices."""
    software_digest = _prepare_software()
    manifest = _load_release()
    configs = generated_configs(
        software_digest=software_digest,
        release_id=manifest["release_id"],
        worker_versions=manifest["worker_versions"], launch_gate=False)
    identity, release_id, observed_software = _release_identity(configs)
    if identity != manifest["deployment_identity"] \
            or release_id != manifest["release_id"] \
            or observed_software != manifest["software_digest"]:
        raise RuntimeError("release manifest does not match local deployment")
    print(json.dumps(
        _mobile_launch_binding(configs, manifest["worker_versions"]),
        sort_keys=True,
        separators=(",", ":")))


def prepare_launch():
    """Upload, but do not activate, one exact production candidate set."""
    software_digest = _prepare_software()
    release_id = secrets.token_hex(32)
    configs = generated_configs(
        software_digest=software_digest, release_id=release_id,
        launch_gate=False)
    if configs[0]["vars"]["NOTIFICATIONS_ENABLED"] != "1" \
            or configs[0]["vars"]["NOTIFICATION_TEST_MODE"] != "0":
        raise ValueError("prepare-launch requires production enablement")
    _write_configs(configs)
    credentials = _release_secrets(configs)
    _stage_locked(software_digest)
    create = os.environ.get("CF_CREATE") == "1"
    for config in configs:
        _require_deployable(config, create=create)
    _require_effects_detached(configs)
    _require_retained_notification_objects(configs[0], configs[1])
    versions = _upload_release(configs, release_id, credentials)
    identity, release_id, software_digest = _release_identity(configs)
    document = {
        "deployment_identity": identity,
        "format": RELEASE_MANIFEST_FORMAT,
        "release_id": release_id,
        "software_digest": software_digest,
        "worker_versions": versions,
    }
    _write_release(document)
    print(json.dumps(
        _mobile_launch_binding(configs, versions), sort_keys=True,
        separators=(",", ":")))


def stage_launch_fcm():
    """Activate only the exact FCM candidate for a private test harness."""
    software_digest = _prepare_software()
    manifest = _load_release()
    configs = generated_configs(
        software_digest=software_digest,
        release_id=manifest["release_id"],
        worker_versions=manifest["worker_versions"], launch_gate=False)
    identity, release_id, observed_software = _release_identity(configs)
    if (identity, release_id, observed_software) != (
            manifest["deployment_identity"], manifest["release_id"],
            manifest["software_digest"]):
        raise RuntimeError("release manifest does not match local deployment")
    _write_configs(configs)
    _release_secrets(configs)
    _stage_locked(software_digest)
    _require_effects_detached(configs)
    allow_absent = os.environ.get("CF_CREATE") == "1"
    incumbent = {}
    for role, config in zip(ROLE_KEYS, configs):
        incumbent[role], _markers = _owned_incumbent(
            role, config, allow_absent=allow_absent)
    _require_snapshot(configs, incumbent)
    for role, config in zip(ROLE_KEYS, configs):
        _require_candidate(
            role, config, manifest["worker_versions"][role],
            (("FIREBASE_SERVICE_ACCOUNT_JSON",) if role == "fcm" else
             (("PUSH_NODE_SECRET",) if role == "consumer" else ())))
    # FCM may be invoked only through a temporary private service-bound
    # harness.  Scanner and Queue effects remain detached throughout.
    _require_snapshot(configs, incumbent)
    expected = dict(incumbent)
    expected["fcm"] = manifest["worker_versions"]["fcm"]
    if incumbent["fcm"] != expected["fcm"]:
        _promote("fcm", configs[3], expected["fcm"])
    _require_snapshot(configs, expected)
    _require_effects_detached(configs)


def _manifest_configs(*, launch_gate=False):
    software_digest = _prepare_software()
    manifest = _load_release()
    configs = generated_configs(
        software_digest=software_digest,
        release_id=manifest["release_id"],
        worker_versions=manifest["worker_versions"],
        launch_gate=launch_gate)
    if _release_identity(configs) != (
            manifest["deployment_identity"], manifest["release_id"],
            manifest["software_digest"]):
        raise RuntimeError("release manifest does not match local deployment")
    return manifest, configs


def deploy_launch_harness():
    """Create one temporary authenticated route to the staged FCM RPC."""
    manifest, configs = _manifest_configs()
    fcm_version = manifest["worker_versions"]["fcm"]
    harness = _harness_config(configs, fcm_version)
    _write_configs(configs)
    _write_harness(harness)
    _stage_locked(manifest["software_digest"])
    _require_effects_detached(configs)
    if _active_version(configs[3]) != fcm_version:
        raise RuntimeError("exact staged FCM version is not active")
    _require_candidate(
        "fcm", configs[3], fcm_version,
        ("FIREBASE_SERVICE_ACCOUNT_JSON",))
    if _active_version(harness) is not _ABSENT:
        raise RuntimeError("temporary launch harness already exists")
    secret = _text(os.environ, "CF_NOTIFICATION_HARNESS_SECRET")
    if not FID.fullmatch(secret):
        raise ValueError(
            "CF_NOTIFICATION_HARNESS_SECRET must be 32-byte hex")
    event = _wrangler_event("fcm", HARNESS_CONFIG, (
        "versions", "upload", "--strict", "--tag",
        manifest["release_id"][:32], "--message",
        "temporary poc16 mobile launch harness",
    ), {"LAUNCH_HARNESS_SECRET": secret})
    version = event.get("version_id") if isinstance(event, dict) else None
    if event.get("type") != "version-upload" or event.get("version") != 1 \
            or event.get("worker_name") != harness["name"] \
            or not VERSION_ID.fullmatch(version or ""):
        raise RuntimeError("malformed launch harness upload evidence")
    bindings = _version_bindings_at(_wrangler, HARNESS_CONFIG, version)
    if _binding_values(bindings, (
            OWNER_BINDING, IDENTITY_BINDING, SOFTWARE_BINDING,
            RELEASE_BINDING, "NOTIFICATIONS_ENABLED", ROLE_BINDING,
            EXPECTED_FCM_VERSION_BINDING,
    )) != (*_expected_markers(harness), fcm_version) or len([
        row for row in bindings if isinstance(row, dict)
        and row.get("name") == "LAUNCH_HARNESS_SECRET"
        and row.get("type") == "secret_text"
    ]) != 1:
        raise RuntimeError("launch harness candidate bindings differ")
    _wrangler(
        "versions", "deploy", "--version-id", version, "-y",
        "--config", str(HARNESS_CONFIG))
    _require_owned(harness)
    if _active_version(harness) != version:
        raise RuntimeError("Cloudflare promoted the wrong launch harness")
    subdomain = _text(os.environ, "CF_WORKERS_SUBDOMAIN")
    if not WORKERS_SUBDOMAIN.fullmatch(subdomain):
        raise ValueError("CF_WORKERS_SUBDOMAIN")
    print(f"https://{harness['name']}.{subdomain}.workers.dev/v1/send")


def remove_launch_harness():
    """Delete only the exact temporary harness; never touch release state."""
    manifest, configs = _manifest_configs()
    harness = _harness_config(configs, manifest["worker_versions"]["fcm"])
    _write_harness(harness)
    _require_owned(harness)
    _wrangler(
        "delete", harness["name"], "--force", "--config",
        str(HARNESS_CONFIG))
    _require_harness_absent(configs, manifest["worker_versions"]["fcm"])


def _require_harness_absent(configs, fcm_version):
    if _active_version(_harness_config(configs, fcm_version)) is not _ABSENT:
        raise RuntimeError("remove the temporary launch harness before enablement")


def _control_environment(environment=os.environ):
    account = environment.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = environment.get("CLOUDFLARE_API_TOKEN", "")
    if not ACCOUNT_ID.fullmatch(account):
        raise ValueError("CLOUDFLARE_ACCOUNT_ID must be 32 lowercase hex")
    if not token:
        raise ValueError("CLOUDFLARE_API_TOKEN is required")
    return account, token


def _api(method, suffix, document=None, environment=os.environ):
    account, token = _control_environment(environment)
    raw = None if document is None else json.dumps(document).encode()
    request = Request(
        "https://api.cloudflare.com/client/v4/accounts/"
        + quote(account, safe="") + suffix,
        data=raw,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            **({"Content-Type": "application/json"}
               if raw is not None else {}),
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            body = response.read(API_RESPONSE_BYTES + 1)
    except (HTTPError, OSError, URLError) as error:
        raise RuntimeError("Cloudflare control request failed") from error
    if len(body) > API_RESPONSE_BYTES:
        raise RuntimeError("Cloudflare control response is too large")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("malformed Cloudflare control response") from error
    if not isinstance(value, dict) or value.get("success") is not True:
        raise RuntimeError("Cloudflare control request was rejected")
    return value.get("result")


def _require_prefix_synchronously_readable(
        config, prefix_binding, label, environment=os.environ):
    """Reject overlapping expiry or a storage class requiring restore."""
    rows = config.get("r2_buckets")
    if not isinstance(rows, list) or len(rows) != 1:
        raise RuntimeError(f"{label} R2 binding is malformed")
    bucket = rows[0].get("bucket_name")
    prefix = config.get("vars", {}).get(prefix_binding)
    if not isinstance(bucket, str) or not bucket \
            or not isinstance(prefix, str) or not prefix:
        raise RuntimeError(f"{label} binding is malformed")
    result = _api(
        "GET",
        "/r2/buckets/" + quote(bucket, safe="") + "/lifecycle",
        environment=environment)
    if not isinstance(result, dict) or not isinstance(
            result.get("rules", []), list):
        raise RuntimeError("malformed R2 lifecycle response")
    for rule in result.get("rules", []):
        if not isinstance(rule, dict) or type(rule.get("enabled")) is not bool:
            raise RuntimeError("malformed R2 lifecycle rule")
        if not rule["enabled"]:
            continue
        deletes = "deleteObjectsTransition" in rule
        transitions = rule.get("storageClassTransitions", [])
        if not isinstance(transitions, list):
            raise RuntimeError("malformed R2 storage lifecycle rule")
        asynchronous = any(
                not isinstance(transition, dict)
                or transition.get("storageClass") != "InfrequentAccess"
                for transition in transitions)
        if not deletes and not transitions:
            continue
        conditions = rule.get("conditions")
        rule_prefix = conditions.get("prefix") \
            if isinstance(conditions, dict) else None
        if not isinstance(rule_prefix, str):
            raise RuntimeError("malformed R2 object lifecycle rule")
        if prefix.startswith(rule_prefix) or rule_prefix.startswith(prefix):
            if deletes:
                raise RuntimeError(f"{label} objects must never expire")
            if asynchronous:
                raise RuntimeError(
                    f"{label} objects must remain synchronously readable")


def _require_retained_notification_objects(
        reader, scanner, environment=os.environ):
    # Cursor root bytes alone are insufficient: historical FactTree pages and
    # fact objects are fetched from canonical state during lag and redrive.
    _require_prefix_synchronously_readable(
        reader, "CANONICAL_PREFIX", "canonical notification history",
        environment)
    _require_prefix_synchronously_readable(
        scanner, "NOTIFICATION_STATE_PREFIX", "notification cursor/root",
        environment)


def _worker_bindings(config, environment=os.environ):
    version = _active_version(config, environment)
    if version is _ABSENT:
        return _ABSENT
    role_name = config.get("vars", {}).get(ROLE_BINDING)
    if role_name == "notification-launch-harness":
        return _version_bindings_at(
            _wrangler, HARNESS_CONFIG, version)
    role = _config_role(config)
    return _version_bindings(role, config, version)


def _worker_markers(config, environment=os.environ):
    bindings = _worker_bindings(config, environment)
    if bindings is _ABSENT:
        return _ABSENT
    return _binding_values(bindings, (
        OWNER_BINDING, IDENTITY_BINDING, SOFTWARE_BINDING, RELEASE_BINDING,
        "NOTIFICATIONS_ENABLED", ROLE_BINDING,
    ))


def _worker_owner(config, environment=os.environ):
    markers = _worker_markers(config, environment)
    return markers if markers in {_ABSENT, None} else markers[0]


def _require_deployable(config, *, create):
    observed = _worker_markers(config)
    production = config["vars"]["NOTIFICATIONS_ENABLED"] == "1" \
        and config["vars"]["NOTIFICATION_TEST_MODE"] == "0"
    immutable = (
        config["vars"][OWNER_BINDING],
        config["vars"][IDENTITY_BINDING],
    )
    if observed is _ABSENT:
        if production:
            raise RuntimeError(
                "deploy notifications disabled before production enablement")
        if not create:
            raise RuntimeError(
                "Worker is absent; set CF_CREATE=1 for explicit creation")
    elif observed is None or observed[:2] != immutable \
            or observed[5] != config["vars"][ROLE_BINDING]:
        raise RuntimeError(
            "refusing to overwrite a Worker with different ownership or "
            "immutable notification bindings or role")
    elif production and observed[4] != "0" \
            and observed != _expected_markers(config):
        raise RuntimeError(
            "disable notifications before preparing production software, "
            "or resume the exact staged candidate")
    elif config["vars"]["NOTIFICATION_TEST_MODE"] == "0" \
            and (observed[2], observed[3]) != (
                config["vars"][SOFTWARE_BINDING],
                config["vars"][RELEASE_BINDING]) \
            and observed[4] != "0":
        raise RuntimeError(
            "disable the incumbent release before replacing it")


def _require_owned(config):
    if _worker_markers(config) != _expected_markers(config):
        raise RuntimeError(
            "refusing to mutate an absent, unowned, or rebound Worker")


def _require_immutable_owned(config):
    observed = _worker_markers(config)
    expected = (
        config["vars"][OWNER_BINDING],
        config["vars"][IDENTITY_BINDING],
    )
    if observed in {_ABSENT, None} or observed[:2] != expected \
            or observed[5] != config["vars"][ROLE_BINDING]:
        raise RuntimeError(
            "refusing to mutate an absent, unowned, or rebound Worker")


def _require_secret(config, name):
    bindings = _worker_bindings(config)
    matches = [
        item for item in bindings
        if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1 or matches[0].get("type") != "secret_text":
        raise RuntimeError(f"Worker is missing required secret {name}")


def _require_bootstrap_sealed(config, environment=os.environ):
    bindings = _worker_bindings(config, environment)
    if bindings is _ABSENT:
        raise RuntimeError("notification scanner is absent")
    matches = [
        item for item in bindings
        if isinstance(item, dict)
        and item.get("name") == "NOTIFICATION_BOOTSTRAP_MODE"]
    if len(matches) != 1 or matches[0].get("type") != "plain_text" \
            or matches[0].get("text") != BOOTSTRAP_NONE:
        raise RuntimeError(
            "notification scanner bootstrap is not sealed")


def _firebase_secret(expected_project, environment=os.environ):
    if not PROJECT.fullmatch(expected_project or ""):
        raise ValueError("expected Firebase project is invalid")
    raw = _text(environment, "FIREBASE_SERVICE_ACCOUNT_JSON")
    if len(raw) > 64 * 1024:
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_JSON is too large")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_JSON is malformed") \
            from error
    if not isinstance(value, dict) or not all(
            isinstance(value.get(name), str) and value[name]
            for name in ("project_id", "client_email", "private_key")):
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_JSON is incomplete")
    if value["project_id"] != expected_project:
        raise ValueError(
            "Firebase service account does not match the bound project")
    return raw


def _release_secrets(configs, environment=os.environ):
    push_secret = _text(environment, "CF_PUSH_NODE_SECRET")
    if not FID.fullmatch(push_secret):
        raise ValueError("CF_PUSH_NODE_SECRET must be a 32-byte hex seed")
    try:
        actual_push_node = load_sk(push_secret).verify_key.encode().hex()
    except (TypeError, ValueError) as error:
        raise ValueError("CF_PUSH_NODE_SECRET is invalid") from error
    if actual_push_node != configs[2]["vars"]["PUSH_NODE"]:
        raise ValueError(
            "CF_PUSH_NODE_SECRET does not match CF_PUSH_NODE_PUBLIC")
    firebase_secret = _firebase_secret(
        configs[3]["vars"]["FCM_PROJECT_ID"], environment)
    return {
        "consumer": {"PUSH_NODE_SECRET": push_secret},
        "fcm": {"FIREBASE_SERVICE_ACCOUNT_JSON": firebase_secret},
    }


def _release_identity(configs):
    identities = {
        config["vars"][IDENTITY_BINDING] for config in configs}
    releases = {config["vars"][RELEASE_BINDING] for config in configs}
    software = {config["vars"][SOFTWARE_BINDING] for config in configs}
    if len(identities) != 1 or len(releases) != 1 or len(software) != 1:
        raise RuntimeError("notification release configs disagree")
    return identities.pop(), releases.pop(), software.pop()


def _upload_release(configs, release_id, secrets_by_role):
    versions = {}
    configs_by_role = dict(zip(ROLE_KEYS, configs))
    # A first upload must establish every service-binding target before the
    # role that references it: FCM, reader, scanner, then consumer.
    for role in ("fcm", "reader", "scanner", "consumer"):
        config = configs_by_role[role]
        version = _upload_version(
            role, config, release_id=release_id,
            secrets_document=secrets_by_role.get(role))
        versions[role] = version
        _require_candidate(
            role, config, version,
            tuple((secrets_by_role.get(role) or {}).keys()))
    return versions


def _snapshot(configs):
    return {
        role: _active_version(config)
        for role, config in zip(ROLE_KEYS, configs)
    }


def _require_snapshot(configs, expected):
    for role, config in zip(ROLE_KEYS, configs):
        if _active_version(config) != expected[role]:
            raise RuntimeError("concurrent notification deployment")


def _promote_release(configs, versions, initial):
    enabled = configs[0]["vars"]["NOTIFICATIONS_ENABLED"] == "1"
    order = ("fcm", "reader", "consumer", "scanner") if enabled else (
        "fcm", "scanner", "consumer", "reader")
    expected = dict(initial)
    configs_by_role = dict(zip(ROLE_KEYS, configs))
    for role in order:
        _require_snapshot(configs, expected)
        config = configs_by_role[role]
        if expected[role] != versions[role]:
            _promote(role, config, versions[role])
            if _active_version(config) != versions[role]:
                raise RuntimeError(
                    "Cloudflare promoted the wrong Worker version")
        expected[role] = versions[role]
    _require_snapshot(configs, versions)


def _queue_consumers(scanner):
    queue = scanner["queues"]["producers"][0]["queue"]
    result = _wrangler(
        "queues", "consumer", "worker", "list", queue, "--json",
        capture=True)
    document = _json_output(result, "Queue consumers")
    if not isinstance(document, list) or len(document) > 1 \
            or any(not isinstance(row, dict) for row in document):
        raise RuntimeError("malformed Cloudflare Queue consumers")
    return document


def _cron_schedules(scanner, environment=os.environ):
    result = _api(
        "GET", "/workers/scripts/" + quote(scanner["name"], safe="")
        + "/schedules", environment=environment)
    if not isinstance(result, list) or len(result) > 16:
        raise RuntimeError("malformed Cloudflare Cron schedules")
    schedules = []
    for row in result:
        if not isinstance(row, dict) or not isinstance(row.get("cron"), str):
            raise RuntimeError("malformed Cloudflare Cron schedule")
        schedules.append(row["cron"])
    return schedules


def _require_effects_detached(configs, *, scanner_absent=False):
    _reader, scanner, consumer, _fcm = configs
    rows = _queue_consumers(scanner)
    if rows:
        raise RuntimeError("notification Queue consumer must be detached")
    # Cron triggers cannot exist without their Worker.  Querying schedules for
    # a first-create scanner is not merely redundant: Cloudflare returns 404.
    if not scanner_absent and _cron_schedules(scanner):
        raise RuntimeError("notification Cron must be detached")


def _require_effects_attached(configs, environment=os.environ):
    _reader, scanner, consumer, _fcm = configs
    queue = scanner["queues"]["producers"][0]["queue"]
    dlq = _safe_name(environment, "CF_NOTIFICATION_DLQ", queue + "-dlq")
    rows = _queue_consumers(scanner)
    row = rows[0] if len(rows) == 1 else None
    settings = row.get("settings") if isinstance(row, dict) else None
    script = (row.get("script") or row.get("service")) \
        if isinstance(row, dict) else None
    expected_settings = {
        "batch_size": MAX_BATCH_SIZE,
        "max_retries": MAX_RETRIES,
        "max_wait_time_ms": 5000,
        "max_concurrency": MAX_CONCURRENCY,
        "retry_delay": RETRY_DELAY_SECONDS,
    }
    if row is None or row.get("type") != "worker" \
            or script != consumer["name"] \
            or row.get("dead_letter_queue") != dlq \
            or not isinstance(settings, dict) \
            or any(settings.get(name) != value
                   for name, value in expected_settings.items()):
        raise RuntimeError("notification Queue consumer differs")
    cron = environment.get("CF_NOTIFICATION_CRON", "* * * * *")
    if _cron_schedules(scanner, environment) != [cron]:
        raise RuntimeError("notification Cron differs")


def _detach_effects(configs, *, scanner_absent=False):
    _reader, scanner, consumer, _fcm = configs
    # Stop discovery first, then delivery.  Repeated calls are safe and do not
    # touch queued bodies or cursor state.
    if not scanner_absent:
        _wrangler(
            "triggers", "deploy", "--config", str(SCANNER_CONFIG))
    rows = _queue_consumers(scanner)
    if rows:
        row = rows[0]
        script = row.get("script") or row.get("service")
        if row.get("type") != "worker" or script != consumer["name"]:
            raise RuntimeError("notification Queue has another consumer")
        queue = scanner["queues"]["producers"][0]["queue"]
        _wrangler(
            "queues", "consumer", "worker", "remove", queue,
            consumer["name"])
    _require_effects_detached(configs, scanner_absent=scanner_absent)


def _attach_effects(configs, environment=os.environ):
    _reader, scanner, consumer, _fcm = configs
    _require_effects_detached(configs)
    queue = scanner["queues"]["producers"][0]["queue"]
    dlq = _safe_name(environment, "CF_NOTIFICATION_DLQ", queue + "-dlq")
    _wrangler(
        "queues", "consumer", "worker", "add", queue, consumer["name"],
        "--batch-size", str(MAX_BATCH_SIZE),
        "--batch-timeout", "5",
        "--message-retries", str(MAX_RETRIES),
        "--dead-letter-queue", dlq,
        "--max-concurrency", str(MAX_CONCURRENCY),
        "--retry-delay-secs", str(RETRY_DELAY_SECONDS))
    cron = environment.get("CF_NOTIFICATION_CRON", "* * * * *")
    if not isinstance(cron, str) or not 0 < len(cron) <= 128:
        raise ValueError("CF_NOTIFICATION_CRON")
    _wrangler(
        "triggers", "deploy", "--triggers", cron,
        "--config", str(SCANNER_CONFIG))
    _require_effects_attached(configs, environment)


def _activate_effects(configs, versions):
    """Attach traffic only while the exact complete release remains active."""
    _require_snapshot(configs, versions)
    _require_harness_absent(configs, versions["fcm"])
    try:
        _attach_effects(configs)
        _require_snapshot(configs, versions)
        _require_harness_absent(configs, versions["fcm"])
    except Exception:
        rollback_error = None
        try:
            _detach_effects(configs)
        except Exception as detach_error:
            rollback_error = detach_error
        try:
            _require_harness_absent(configs, versions["fcm"])
        except Exception as harness_error:
            if rollback_error is None:
                rollback_error = harness_error
        if rollback_error is not None:
            raise RuntimeError(
                "notification activation failed and rollback verification "
                "failed") from rollback_error
        raise


def provision():
    """Explicitly create both finite-retention queues; never adopt names."""
    if os.environ.get("CF_CREATE") != "1":
        raise ValueError("set CF_CREATE=1 to create notification queues")
    _reader, scanner, _consumer, _fcm = generated_configs()
    queue = scanner["queues"]["producers"][0]["queue"]
    # Disabled configs omit the consumer declaration, so the durable DLQ name
    # comes from the same validated environment/default calculation.
    dlq = _safe_name(
        os.environ, "CF_NOTIFICATION_DLQ", queue + "-dlq")
    for name in (queue, dlq):
        _wrangler(
            "queues", "create", name,
            "--message-retention-period-secs", str(RETENTION_SECONDS))


def deploy():
    """Promote exact versions; attach effects only after a complete release."""
    software_digest = _prepare_software()
    production = os.environ.get("CF_NOTIFICATIONS_ENABLED", "0") == "1" \
        and os.environ.get("CF_NOTIFICATION_TEST_MODE", "0") == "0"
    manifest_name = os.environ.get(RELEASE_MANIFEST_ENV)
    disabled_manifest = not production and isinstance(manifest_name, str) \
        and manifest_name and Path(manifest_name).expanduser().is_file()
    manifest = _load_release() if production or disabled_manifest else None
    release_id = manifest["release_id"] if manifest else secrets.token_hex(32)
    versions = manifest["worker_versions"] if production else None
    configs = generated_configs(
        software_digest=software_digest, release_id=release_id,
        worker_versions=versions)
    identity, release_id, observed_software = _release_identity(configs)
    if manifest and (identity, release_id, observed_software) != (
            manifest["deployment_identity"], manifest["release_id"],
            manifest["software_digest"]):
        raise RuntimeError("release manifest does not match local deployment")
    _write_configs(configs)
    credentials = _release_secrets(configs)
    _stage_locked(software_digest)
    create = os.environ.get("CF_CREATE") == "1"
    for config in configs:
        _require_deployable(config, create=create)
    _require_retained_notification_objects(configs[0], configs[1])
    initial = _snapshot(configs)
    if production:
        _require_effects_detached(configs)
        _require_harness_absent(configs, versions["fcm"])
        for role, config in zip(ROLE_KEYS, configs):
            _require_candidate(
                role, config, versions[role],
                tuple((credentials.get(role) or {}).keys()))
        if initial["fcm"] != versions["fcm"]:
            raise RuntimeError(
                "stage and physically test the exact FCM version first")
    else:
        _detach_effects(
            configs, scanner_absent=initial["scanner"] is _ABSENT)
        versions = _upload_release(configs, release_id, credentials)
    _promote_release(configs, versions, initial)
    if production or configs[0]["vars"]["NOTIFICATION_TEST_MODE"] == "1" \
            and configs[0]["vars"]["NOTIFICATIONS_ENABLED"] == "1":
        _activate_effects(configs, versions)
    else:
        _require_effects_detached(configs)


def disable():
    """Stop new notification traffic without building or changing code."""
    configs = generated_configs()
    _write_configs(configs)
    # Establish ownership of the complete release before the first provider
    # mutation.  This command deliberately needs no push credential, Firebase
    # secret, release manifest, R2 lifecycle read, upload, or promotion.
    for config in configs:
        _require_immutable_owned(config)
    _detach_effects(configs)


def _deploy_scanner_mode(mode):
    """Promote one exact scanner mode without rebuilding another release."""
    if mode not in BOOTSTRAP_MODES:
        raise ValueError("notification bootstrap mode")
    software_digest = _prepare_software()
    ordinary = generated_configs(software_digest=software_digest)
    incumbent = {}
    observed = []
    for role, config in zip(ROLE_KEYS, ordinary):
        version, markers = _owned_incumbent(role, config)
        incumbent[role] = version
        observed.append(markers)
    releases = {value[3] for value in observed}
    software = {value[2] for value in observed}
    enabled_states = {value[4] for value in observed}
    if len(releases) != 1 or software != {software_digest} \
            or enabled_states != {"0"}:
        raise RuntimeError(
            "bootstrap requires one complete disabled current release")
    release_id = releases.pop()
    configs = generated_configs(
        bootstrap_mode=mode, software_digest=software_digest,
        release_id=release_id)
    _write_configs(configs)
    if mode == BOOTSTRAP_NONE:
        _require_snapshot(configs, incumbent)
        _wrangler(
            "triggers", "deploy", "--config", str(SCANNER_CONFIG))
    else:
        _require_effects_detached(configs)
    _require_retained_notification_objects(configs[0], configs[1])
    _require_snapshot(configs, incumbent)
    version = _upload_version(
        "scanner", configs[1], release_id=release_id)
    _require_candidate("scanner", configs[1], version)
    _require_snapshot(configs, incumbent)
    _promote("scanner", configs[1], version)
    expected = dict(incumbent)
    expected["scanner"] = version
    _require_snapshot(configs, expected)
    if mode == BOOTSTRAP_NONE:
        _require_effects_detached(configs)
    else:
        cron = os.environ.get("CF_NOTIFICATION_CRON", "* * * * *")
        if not isinstance(cron, str) or not 0 < len(cron) <= 128:
            raise ValueError("CF_NOTIFICATION_CRON")
        _require_snapshot(configs, expected)
        _wrangler(
            "triggers", "deploy", "--triggers", cron,
            "--config", str(SCANNER_CONFIG))


def bootstrap_current():
    """Temporarily schedule an idempotent current-root bootstrap."""
    _deploy_scanner_mode(BOOTSTRAP_CURRENT)


def bootstrap_backfill():
    """Temporarily schedule an idempotent historical backfill bootstrap."""
    _deploy_scanner_mode(BOOTSTRAP_BACKFILL)


def seal_bootstrap():
    """Return an initialized scanner to its ordinary fail-closed mode."""
    _deploy_scanner_mode(BOOTSTRAP_NONE)


def _nonproduction_release_configs():
    """Reconstruct one disabled/test release from active version markers."""
    software_digest = _prepare_software()
    probe = generated_configs(
        software_digest=software_digest, launch_gate=False)
    observed = [_worker_markers(config) for config in probe]
    if any(value in {_ABSENT, None} for value in observed):
        raise RuntimeError("notification release is not fully deployed")
    for config, markers in zip(probe, observed):
        if markers[:2] != (
                config["vars"][OWNER_BINDING],
                config["vars"][IDENTITY_BINDING]) \
                or markers[5] != config["vars"][ROLE_BINDING]:
            raise RuntimeError("active notification release is not owned")
    releases = {value[3] for value in observed}
    software = {value[2] for value in observed}
    enabled = {value[4] for value in observed}
    expected_enabled = probe[0]["vars"]["NOTIFICATIONS_ENABLED"]
    if len(releases) != 1 or software != {software_digest} \
            or enabled != {expected_enabled}:
        raise RuntimeError(
            "active notification release differs from local configuration")
    configs = generated_configs(
        software_digest=software_digest, release_id=releases.pop(),
        launch_gate=False)
    return _snapshot(configs), configs


def verify():
    production = os.environ.get("CF_NOTIFICATIONS_ENABLED", "0") == "1" \
        and os.environ.get("CF_NOTIFICATION_TEST_MODE", "0") == "0"
    if production:
        manifest, configs = _manifest_configs(launch_gate=True)
        versions = manifest["worker_versions"]
    else:
        versions, configs = _nonproduction_release_configs()
    for role, config in zip(ROLE_KEYS, configs):
        if _active_version(config) != versions[role]:
            raise RuntimeError("active Worker version differs from release")
        _require_owned(config)
    _require_harness_absent(configs, versions["fcm"])
    _require_bootstrap_sealed(configs[1])
    _require_secret(configs[3], "FIREBASE_SERVICE_ACCOUNT_JSON")
    _require_secret(configs[2], "PUSH_NODE_SECRET")
    _require_retained_notification_objects(configs[0], configs[1])
    if configs[0]["vars"]["NOTIFICATIONS_ENABLED"] == "1":
        _require_effects_attached(configs)
    else:
        _require_effects_detached(configs)
    queue = configs[1]["queues"]["producers"][0]["queue"]
    dlq = _safe_name(os.environ, "CF_NOTIFICATION_DLQ", queue + "-dlq")
    for name in (queue, dlq):
        result = _wrangler("queues", "info", name, capture=True)
        print(result.stdout, end="")
    print(
        "ALERT REQUIRED: page on DLQ backlog_count > 0 and stale primary "
        "work; the R2 pending cursor preserves correctness while schedules "
        "recreate expired wakes")
    print(
        "R2 VERIFIED: no enabled deletion lifecycle overlaps canonical "
        "history or the permanent notification cursor/root prefix; this "
        "tool never mutates lifecycle")


def redrive():
    """Move at most ten exact text bodies from DLQ to primary, safely."""
    if os.environ.get("CF_REDRIVE") != "1":
        raise ValueError("set CF_REDRIVE=1 to authorize one bounded redrive")
    primary = _text(os.environ, "CF_NOTIFICATION_QUEUE_ID")
    dlq = _text(os.environ, "CF_NOTIFICATION_DLQ_ID")
    if not ACCOUNT_ID.fullmatch(primary) or not ACCOUNT_ID.fullmatch(dlq) \
            or primary == dlq:
        raise ValueError("exact primary and DLQ queue IDs are required")
    pulled = _api("POST", f"/queues/{dlq}/messages/pull", {
        "batch_size": MAX_BATCH_SIZE,
        "visibility_timeout_ms": 60_000,
    })
    if not isinstance(pulled, dict) or not isinstance(
            pulled.get("messages"), list):
        raise RuntimeError("malformed DLQ pull response")
    messages = pulled["messages"]
    if len(messages) > MAX_BATCH_SIZE:
        raise RuntimeError("DLQ pull exceeded redrive bound")
    leases = []
    for message in messages:
        if not isinstance(message, dict) \
                or not isinstance(message.get("body"), str) \
                or not isinstance(message.get("lease_id"), str):
            raise RuntimeError("DLQ contains malformed work")
        try:
            raw = message["body"].encode("ascii")
        except UnicodeEncodeError as error:
            raise RuntimeError("DLQ contains non-ASCII work") from error
        if not 0 < len(raw) <= MAX_CLOUDFLARE_QUEUE_BODY_BYTES:
            raise RuntimeError("DLQ work exceeds carrier bound")
        _api("POST", f"/queues/{primary}/messages", {
            "body": message["body"], "content_type": "text"})
        leases.append({"lease_id": message["lease_id"]})
    if leases:
        # If any primary write or this ACK has an unknown outcome, leases are
        # not acknowledged here and the next redrive can only duplicate.
        _api("POST", f"/queues/{dlq}/messages/ack", {
            "acks": leases, "retries": []})


def remove():
    """Remove owned Workers only; preserve R2 state and both queues."""
    configs = generated_configs()
    _write_configs(configs)
    for config in configs:
        _require_immutable_owned(config)
    # Stop new discovery before removing delivery capacity.
    for config in (configs[1], configs[2], configs[0]):
        _pywrangler(
            "delete", config["name"], "--force",
            "--config", str({
                configs[0]["name"]: READER_CONFIG,
                configs[1]["name"]: SCANNER_CONFIG,
                configs[2]["name"]: CONSUMER_CONFIG,
            }[config["name"]]))
    _wrangler(
        "delete", configs[3]["name"], "--force",
        "--config", str(FCM_CONFIG))


def help_text():
    return """usage: manage.py COMMAND

Commands:
  sync       materialize locked Python Worker dependencies
  stage      internal exact-source build hook
  build      dry-run all four default-disabled Worker bundles
  prepare-launch     upload one inert exact production candidate release
  stage-launch-fcm   promote only its FCM boundary for private device tests
  deploy-launch-harness  create a temporary authenticated FCM test route
  remove-launch-harness  delete that exact temporary test route
  launch-binding     print the exact four-version real-device test subject
  provision  explicitly create primary and DLQ with one-day retention
  deploy     promote exact versions, then attach Queue/Cron effects
  disable    stop Queue/Cron traffic without uploading another version
  bootstrap-current   initialize at the current root on the next schedule
  bootstrap-backfill  initialize from the empty FactTree on the next schedule
  seal-bootstrap      disable initialization after observing its completion
  verify     verify ownership and print queue status/required alarms
  redrive    safely move one bounded DLQ batch to the primary queue
  remove     remove only owned Workers; retain queues and R2 state
"""


def main(argv):
    if len(argv) == 3 and argv[1] == "stage-locked":
        _stage_locked(argv[2])
        return 0
    command = argv[1] if len(argv) == 2 else "help"
    commands = {
        "sync": sync,
        "stage": stage,
        "build": build,
        "prepare-launch": prepare_launch,
        "stage-launch-fcm": stage_launch_fcm,
        "deploy-launch-harness": deploy_launch_harness,
        "remove-launch-harness": remove_launch_harness,
        "launch-binding": print_launch_binding,
        "provision": provision,
        "deploy": deploy,
        "disable": disable,
        "bootstrap-current": bootstrap_current,
        "bootstrap-backfill": bootstrap_backfill,
        "seal-bootstrap": seal_bootstrap,
        "verify": verify,
        "redrive": redrive,
        "remove": remove,
    }
    if command == "help":
        print(help_text(), end="")
        return 0 if len(argv) <= 2 else 2
    function = commands.get(command)
    if function is None:
        print(help_text(), file=sys.stderr, end="")
        return 2
    function()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
