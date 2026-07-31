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


SCANNER_TEMPLATE = PACKAGE / "wrangler.scanner.jsonc"
CONSUMER_TEMPLATE = PACKAGE / "wrangler.consumer.jsonc"
READER_TEMPLATE = PACKAGE / "wrangler.reader.jsonc"
FCM_TEMPLATE = PACKAGE / "wrangler.fcm.jsonc"
SCANNER_CONFIG = PACKAGE / "wrangler.scanner.generated.json"
CONSUMER_CONFIG = PACKAGE / "wrangler.consumer.generated.json"
READER_CONFIG = PACKAGE / "wrangler.reader.generated.json"
FCM_CONFIG = PACKAGE / "wrangler.fcm.generated.json"
BUILD = PACKAGE / "build"
VENDORED = PACKAGE / "python_modules"
RELEASE = BUILD / "release"

OWNER_BINDING = "POC16_DEPLOYMENT_OWNER"
IDENTITY_BINDING = "POC16_DEPLOYMENT_IDENTITY"
SOFTWARE_BINDING = "POC16_SOFTWARE_DIGEST"
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
ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
OWNER = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
APPLICATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
ENVIRONMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,62}$")
_ABSENT = object()

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
        if role != "reader":
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


def _mobile_launch_binding(configs):
    reader, scanner, consumer, fcm = configs
    return {
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
        "software_digest": scanner["vars"][SOFTWARE_BINDING],
        "workspace": scanner["vars"]["WORKSPACE"],
    }


def generated_configs(
        environment=os.environ, *, bootstrap_mode=BOOTSTRAP_NONE,
        software_digest=None):
    """Resolve one workspace and keep live effects disabled by default."""
    if bootstrap_mode not in BOOTSTRAP_MODES:
        raise ValueError("notification bootstrap mode")
    software_digest = "0" * 64 \
        if software_digest is None else software_digest
    if not FID.fullmatch(software_digest or ""):
        raise ValueError("software digest must be 64 lowercase hex")
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
        "consumer": consumer_name,
        "fcm_application": application,
        "fcm_environment": firebase_environment,
        "fcm_project": firebase_project,
        "fcm_worker": fcm_name,
        "format": "poc16-cloudflare-notification-deployment-v1",
        "notification_dlq": dlq,
        "notification_queue": queue,
        "push_node": push_node,
        "reader": reader_name,
        "scanner": scanner_name,
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
    scanner["triggers"]["crons"] = (
        [environment.get("CF_NOTIFICATION_CRON", "* * * * *")]
        if enabled == "1" or bootstrap_mode != BOOTSTRAP_NONE else [])

    consumer = json.loads(CONSUMER_TEMPLATE.read_text())
    consumer["name"] = consumer_name
    consumer["vars"].update(common)
    consumer["vars"]["PUSH_NODE"] = push_node
    consumer["services"][0]["service"] = reader_name
    consumer["services"][1]["service"] = scanner_name
    consumer["services"][2]["service"] = fcm_name
    consumer["queues"]["consumers"] = ([{
        "queue": queue,
        "max_batch_size": MAX_BATCH_SIZE,
        "max_batch_timeout": 5,
        "max_retries": MAX_RETRIES,
        "dead_letter_queue": dlq,
        "max_concurrency": MAX_CONCURRENCY,
        "retry_delay": RETRY_DELAY_SECONDS,
    }] if enabled == "1" else [])
    fcm = json.loads(FCM_TEMPLATE.read_text())
    fcm["name"] = fcm_name
    fcm["vars"].update({
        IDENTITY_BINDING: identity,
        OWNER_BINDING: owner,
        SOFTWARE_BINDING: software_digest,
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
    if enabled == "1" and test_mode == "0":
        require_mobile_launches({
            "ios": environment.get("CF_IOS_LAUNCH_RECORD"),
            "android": environment.get("CF_ANDROID_LAUNCH_RECORD"),
        }, _mobile_launch_binding(configs))
    return configs


def _write_configs(configs):
    for path, config in zip(
            (READER_CONFIG, SCANNER_CONFIG, CONSUMER_CONFIG, FCM_CONFIG),
            configs):
        path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")


def _run(command, *, capture=False, timeout=CONTROL_TIMEOUT_SECONDS,
         input_text=None):
    try:
        return subprocess.run(
            command, cwd=PACKAGE, env=os.environ, check=True,
            capture_output=capture, text=True, input=input_text,
            timeout=timeout)
    except FileNotFoundError as error:
        raise RuntimeError(
            f"required executable is unavailable: {command[0]}") from error


def _pywrangler(*arguments, capture=False, input_text=None):
    return _run(
        ["uv", "run", "pywrangler", *arguments],
        capture=capture, input_text=input_text)


def _wrangler(*arguments, capture=False, input_text=None):
    return _run(
        ["npx", "--yes", WRANGLER, *arguments],
        capture=capture, input_text=input_text)


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


def print_launch_binding():
    """Print the exact tested-deployment subject for the device harness."""
    software_digest = _prepare_software()
    environment = dict(os.environ)
    environment["CF_NOTIFICATIONS_ENABLED"] = "0"
    environment["CF_NOTIFICATION_TEST_MODE"] = "0"
    configs = generated_configs(
        environment, software_digest=software_digest)
    print(json.dumps(
        _mobile_launch_binding(configs), sort_keys=True,
        separators=(",", ":")))


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


def _require_prefix_no_expiry(
        config, prefix_binding, label, environment=os.environ):
    """Reject every enabled deletion rule overlapping named objects."""
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
        if not rule["enabled"] or "deleteObjectsTransition" not in rule:
            continue
        conditions = rule.get("conditions")
        rule_prefix = conditions.get("prefix") \
            if isinstance(conditions, dict) else None
        if not isinstance(rule_prefix, str):
            raise RuntimeError("malformed R2 deletion lifecycle rule")
        if prefix.startswith(rule_prefix) or rule_prefix.startswith(prefix):
            raise RuntimeError(
                f"{label} objects must never expire")


def _require_retained_notification_objects(
        reader, scanner, environment=os.environ):
    # Cursor root bytes alone are insufficient: historical FactTree pages and
    # fact objects are fetched from canonical state during lag and redrive.
    _require_prefix_no_expiry(
        reader, "CANONICAL_PREFIX", "canonical notification history",
        environment)
    _require_prefix_no_expiry(
        scanner, "NOTIFICATION_STATE_PREFIX", "notification cursor/root",
        environment)


def _worker_bindings(config, environment=os.environ):
    account, _token = _control_environment(environment)
    try:
        result = _api(
            "GET",
            "/workers/scripts/" + quote(config["name"], safe="")
            + "/settings",
            environment=environment)
    except RuntimeError as error:
        cause = error.__cause__
        if isinstance(cause, HTTPError) and cause.code == 404:
            return _ABSENT
        raise
    if not isinstance(result, dict) or not isinstance(
            result.get("bindings"), list):
        raise RuntimeError("malformed Cloudflare Worker settings")
    return result["bindings"]


def _worker_markers(config, environment=os.environ):
    bindings = _worker_bindings(config, environment)
    if bindings is _ABSENT:
        return _ABSENT
    values = []
    for name in (
            OWNER_BINDING, IDENTITY_BINDING, SOFTWARE_BINDING,
            "NOTIFICATIONS_ENABLED"):
        matches = [
            item for item in bindings
            if isinstance(item, dict) and item.get("name") == name]
        if name in {SOFTWARE_BINDING, "NOTIFICATIONS_ENABLED"} \
                and not matches:
            values.append(None)
            continue
        if len(matches) != 1 or matches[0].get("type") != "plain_text":
            return None
        values.append(matches[0].get("text"))
    return tuple(values)


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
    elif observed is None or observed[:2] != immutable:
        raise RuntimeError(
            "refusing to overwrite a Worker with different ownership or "
            "immutable notification bindings")
    elif production and observed[2] != config["vars"][SOFTWARE_BINDING]:
        raise RuntimeError(
            "disable notifications before changing software; production "
            "may enable only the exact tested digest")
    elif config["vars"]["NOTIFICATION_TEST_MODE"] == "0" \
            and observed[2] != config["vars"][SOFTWARE_BINDING] \
            and (observed[3] != "0"
                 or config["vars"]["NOTIFICATIONS_ENABLED"] != "0"):
        raise RuntimeError(
            "disable the incumbent software before changing its digest")


def _require_owned(config):
    expected = (
        config["vars"][OWNER_BINDING],
        config["vars"][IDENTITY_BINDING],
        config["vars"][SOFTWARE_BINDING],
        config["vars"]["NOTIFICATIONS_ENABLED"],
    )
    if _worker_markers(config) != expected:
        raise RuntimeError(
            "refusing to mutate an absent, unowned, or rebound Worker")


def _require_immutable_owned(config):
    observed = _worker_markers(config)
    expected = (
        config["vars"][OWNER_BINDING],
        config["vars"][IDENTITY_BINDING],
    )
    if observed in {_ABSENT, None} or observed[:2] != expected:
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
    """Deploy private boundaries before the default-inert queue roles."""
    software_digest = _prepare_software()
    configs = generated_configs(software_digest=software_digest)
    _write_configs(configs)
    create = os.environ.get("CF_CREATE") == "1"
    for config in configs:
        _require_deployable(config, create=create)
    _require_retained_notification_objects(configs[0], configs[1])
    secret = _text(os.environ, "CF_PUSH_NODE_SECRET")
    if not FID.fullmatch(secret):
        raise ValueError("CF_PUSH_NODE_SECRET must be a 32-byte hex seed")
    try:
        actual_push_node = load_sk(secret).verify_key.encode().hex()
    except (TypeError, ValueError) as error:
        raise ValueError("CF_PUSH_NODE_SECRET is invalid") from error
    if actual_push_node != configs[2]["vars"]["PUSH_NODE"]:
        raise ValueError(
            "CF_PUSH_NODE_SECRET does not match CF_PUSH_NODE_PUBLIC")
    firebase_secret = _firebase_secret(
        configs[3]["vars"]["FCM_PROJECT_ID"])
    _stage_locked(software_digest)
    _wrangler("deploy", "--config", str(FCM_CONFIG))
    _require_owned(configs[3])
    _wrangler(
        "secret", "put", "FIREBASE_SERVICE_ACCOUNT_JSON",
        "--config", str(FCM_CONFIG), input_text=firebase_secret + "\n")
    _require_owned(configs[3])
    _pywrangler("deploy", "--strict", "--config", str(READER_CONFIG))
    _require_owned(configs[0])
    with tempfile.NamedTemporaryFile(
            mode="w", prefix="poc16-cf-notify-", suffix=".json") as file:
        json.dump({"PUSH_NODE_SECRET": secret}, file)
        file.flush()
        _pywrangler(
            "deploy", "--strict", "--config", str(CONSUMER_CONFIG),
            "--secrets-file", file.name)
    _require_owned(configs[2])
    _pywrangler("deploy", "--strict", "--config", str(SCANNER_CONFIG))
    _require_owned(configs[1])


def _deploy_scanner_mode(mode):
    """Deploy one explicit initialization mode on an existing scanner."""
    if mode not in BOOTSTRAP_MODES:
        raise ValueError("notification bootstrap mode")
    software_digest = _prepare_software()
    configs = generated_configs(
        bootstrap_mode=mode, software_digest=software_digest)
    _write_configs(configs)
    _require_owned(configs[1])
    _require_retained_notification_objects(configs[0], configs[1])
    _pywrangler("deploy", "--strict", "--config", str(SCANNER_CONFIG))
    _require_owned(configs[1])


def bootstrap_current():
    """Temporarily schedule an idempotent current-root bootstrap."""
    _deploy_scanner_mode(BOOTSTRAP_CURRENT)


def bootstrap_backfill():
    """Temporarily schedule an idempotent historical backfill bootstrap."""
    _deploy_scanner_mode(BOOTSTRAP_BACKFILL)


def seal_bootstrap():
    """Return an initialized scanner to its ordinary fail-closed mode."""
    _deploy_scanner_mode(BOOTSTRAP_NONE)


def verify():
    software_digest = _prepare_software()
    configs = generated_configs(software_digest=software_digest)
    for config in configs:
        _require_owned(config)
    _require_bootstrap_sealed(configs[1])
    _require_secret(configs[3], "FIREBASE_SERVICE_ACCOUNT_JSON")
    _require_retained_notification_objects(configs[0], configs[1])
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
  launch-binding     print the exact real-device launch subject
  provision  explicitly create primary and DLQ with one-day retention
  deploy     deploy owned FCM/read boundaries, consumer, then scanner
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
        "launch-binding": print_launch_binding,
        "provision": provision,
        "deploy": deploy,
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
