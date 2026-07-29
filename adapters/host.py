"""Strict host-daemon configuration for filesystem-independent stores.

Provider names, SDK loading, bucket layout, and credential-chain decisions
belong here rather than in ``core``.  The returned callable is the generic
``workspace id -> ObjectStore`` seam already accepted by ``Node``.
"""
import importlib
import json
import os
import re


SCHEMA = "poc16-host-store-v1"
MAX_CONFIG_BYTES = 64 * 1024
_WORKSPACE_RE = re.compile(r"^[0-9a-f]{64}$")
_LONGEST_NODE_KEY = f"pile/{'0' * 16}/{'0' * 64}"
_CREDENTIAL_WORDS = (
    "access_key", "credential", "password", "secret", "session", "token")
_COMMON = frozenset({
    "backend",
    "base_prefix",
    "bucket",
    "connect_timeout",
    "list_page_size",
    "max_list_pages",
    "max_pool_connections",
    "read_timeout",
    "read_total_max_attempts",
    "schema",
})
_S3_ONLY = frozenset({
    "bucket_key_enabled",
    "expected_bucket_owner",
    "region_name",
    "retry_mode",
    "server_side_encryption",
    "sse_kms_key_id",
})
_R2_ONLY = frozenset({"account_id"})


def workspace_prefix(base_prefix, workspace):
    """Injectively map a full workspace id below one configured namespace."""
    if not isinstance(base_prefix, str) or not base_prefix:
        raise ValueError("base_prefix must be a non-empty string")
    if not isinstance(workspace, str) \
            or not _WORKSPACE_RE.fullmatch(workspace):
        raise ValueError("workspace id must be 64 lowercase hex characters")
    return f"{base_prefix}/workspace/{workspace}"


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate store config field {key!r}")
        out[key] = value
    return out


def _reject_json_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def _strict(document, required, allowed):
    if not isinstance(document, dict):
        raise ValueError("store config must be a JSON object")
    if any(
            isinstance(key, str)
            and any(word in key.lower() for word in _CREDENTIAL_WORDS)
            for key in document):
        raise ValueError(
            "credentials are not accepted in store config; "
            "use the provider SDK credential chain")
    keys = set(document)
    if not all(isinstance(key, str) for key in keys):
        raise ValueError("store config field names must be strings")
    missing = required - keys
    unknown = keys - allowed
    if missing:
        raise ValueError(
            "missing store config fields: " + ", ".join(sorted(missing)))
    if unknown:
        raise ValueError(
            "unknown store config fields: " + ", ".join(sorted(unknown)))
    if document["schema"] != SCHEMA:
        raise ValueError(f"store config schema must be {SCHEMA!r}")


def _require_sdk():
    try:
        importlib.import_module("boto3")
        importlib.import_module("botocore.config")
    except ImportError as error:
        raise RuntimeError(
            "the selected cloud store requires boto3 and botocore") from error


def _provider_arguments(document, excluded):
    return {
        key: value for key, value in document.items()
        if key not in excluded
    }


def factory_from_mapping(document, *, client_factory=None):
    """Validate one mapping and return a workspace-isolating store factory.

    ``client_factory`` is a provider-test seam. Production callers omit it and
    let boto use its normal environment/shared-config/instance credential
    chain; credentials are never accepted by this schema.
    """
    if not isinstance(document, dict):
        raise ValueError("store config must be a JSON object")
    backend = document.get("backend")
    if backend == "s3":
        required = frozenset({
            "backend", "base_prefix", "bucket", "schema"})
        allowed = _COMMON | _S3_ONLY
    elif backend == "r2":
        required = frozenset({
            "account_id", "backend", "base_prefix", "bucket", "schema"})
        allowed = _COMMON | _R2_ONLY
    else:
        raise ValueError("store config backend must be 's3' or 'r2'")
    _strict(document, required, allowed)

    base = document["base_prefix"]
    probe_prefix = workspace_prefix(base, "0" * 64)
    excluded = {"backend", "base_prefix", "schema"}
    options = _provider_arguments(document, excluded)

    if backend == "s3":
        from adapters.s3 import S3Config, S3Store

        # Validate all provider options and the longest fixed layout segment
        # before importing an optional SDK or touching a bucket.
        S3Config(prefix=probe_prefix, **options)
        config_type, store_type = S3Config, S3Store
    else:
        from adapters.r2 import R2S3Config, R2S3Store

        R2S3Config(prefix=probe_prefix, **options)
        config_type, store_type = R2S3Config, R2S3Store

    if len(
            f"{probe_prefix}/{_LONGEST_NODE_KEY}".encode("ascii")) > 1024:
        raise ValueError("configured workspace object prefix exceeds 1024 bytes")
    if client_factory is None:
        _require_sdk()

    def factory(workspace):
        prefix = workspace_prefix(base, workspace)
        config = config_type(prefix=prefix, **options)
        if client_factory is None:
            return store_type(config)
        client = client_factory(backend, workspace)
        return store_type(config, client=client)

    return factory


def load_store_factory(path, *, client_factory=None):
    """Load a bounded duplicate-free JSON config without exposing its values."""
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise TypeError("store config path")
    with open(path, "rb") as source:
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("store config exceeds byte limit")
    try:
        document = json.loads(
            raw, object_pairs_hook=_pairs,
            parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise ValueError("invalid store config JSON") from error
    return factory_from_mapping(
        document, client_factory=client_factory)


__all__ = (
    "SCHEMA",
    "factory_from_mapping",
    "load_store_factory",
    "workspace_prefix",
)
