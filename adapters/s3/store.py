"""Amazon S3 implementation of the writable ObjectStore contract.

The module deliberately has no import-time dependency on boto3 or botocore.
An injected client is enough for tests and embedded runtimes; the SDK is
loaded only when this module must construct its own clients.
"""
from dataclasses import dataclass
import base64
import hashlib
import importlib
import math
import re

from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
    STALE,
    StoreError,
    Versioned,
    VersionToken,
    KEY_RE,
    authoritative_key,
    validate_key,
)


_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_IP_STYLE_BUCKET_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
_RESERVED_BUCKET_PREFIXES = ("xn--", "sthree-")
_RESERVED_BUCKET_SUFFIXES = (
    "-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
_KEY_MISSING_CODES = frozenset({"404", "NoSuchKey", "NotFound"})
_CONFIG_ERROR_NAMES = frozenset({
    "InvalidRegionError",
    "NoCredentialsError",
    "NoRegionError",
    "ParamValidationError",
    "PartialCredentialsError",
    "UnknownParameterError",
})
_STATUS_BY_CODE = {
    "AccessDenied": 403,
    "ConditionalRequestConflict": 409,
    "NoSuchBucket": 404,
    "NoSuchKey": 404,
    "NotFound": 404,
    "PreconditionFailed": 412,
    "SlowDown": 503,
    "ThrottledException": 429,
    "Throttling": 429,
    "TooManyRequestsException": 429,
}


def _positive_int(value, name, *, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(name)
    if maximum is not None and value > maximum:
        raise ValueError(name)


def _validate_prefix(prefix):
    if not isinstance(prefix, str):
        raise TypeError("S3 prefix")
    if not prefix:
        return
    if prefix.startswith("/") or prefix.endswith("/"):
        raise ValueError("S3 prefix must not start or end with '/'")
    if not KEY_RE.fullmatch(prefix) \
            or any(part in {"", ".", ".."} for part in prefix.split("/")):
        raise ValueError("S3 prefix")


def _value_bytes(value):
    if not isinstance(value, bytes):
        raise TypeError("object value must be bytes")
    return value


def _checksum(value):
    return base64.b64encode(hashlib.sha256(value).digest()).decode("ascii")


def _error_details(error):
    response = getattr(error, "response", None)
    status = None
    code = None
    if isinstance(response, dict):
        metadata = response.get("ResponseMetadata")
        if isinstance(metadata, dict):
            status = metadata.get("HTTPStatusCode")
        detail = response.get("Error")
        if isinstance(detail, dict):
            code = detail.get("Code")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    code = str(code) if code is not None else None
    if status is None:
        status = _STATUS_BY_CODE.get(code)
    return status, code


def _error_label(operation, error):
    status, code = _error_details(error)
    detail = code or (f"HTTP {status}" if status is not None else
                      type(error).__name__)
    return f"S3 {operation} failed: {detail}"


def _is_configuration_error(error):
    return type(error).__name__ in _CONFIG_ERROR_NAMES


def _is_missing_key(error):
    status, code = _error_details(error)
    return status == 404 and (
        code is None or code in _KEY_MISSING_CODES)


def _raise_read_error(operation, error):
    status, _ = _error_details(error)
    message = _error_label(operation, error)
    if _is_configuration_error(error):
        raise StoreError(message) from error
    if status in {408, 409, 429} \
            or status is not None and 500 <= status <= 599 \
            or status is None:
        raise RetryableStoreError(message) from error
    raise StoreError(message) from error


def _raise_mutation_error(operation, error):
    status, _ = _error_details(error)
    message = _error_label(operation, error)
    if _is_configuration_error(error):
        raise StoreError(message) from error
    if status in {409, 429}:
        raise RetryableStoreError(message) from error
    if status == 408 \
            or status is not None and 500 <= status <= 599 \
            or status is None:
        raise OutcomeUnknown(message) from error
    raise StoreError(message) from error


def _validate_mutation_client_retries(client):
    """Reject an injected botocore client whose retries hide CAS outcomes."""
    meta = getattr(client, "meta", None)
    sdk_config = getattr(meta, "config", None)
    retries = getattr(sdk_config, "retries", None)
    if retries is None:
        # Small injected clients and provider fakes do not expose botocore
        # metadata. Their call behavior is the injection boundary.
        return
    if not isinstance(retries, dict):
        raise ValueError("mutation client retry configuration")
    total = retries.get("total_max_attempts")
    max_after_initial = retries.get("max_attempts")
    if total != 1 and not (
            total is None and max_after_initial == 0):
        raise ValueError(
            "mutation client must use exactly one total attempt")


@dataclass(frozen=True)
class S3Config:
    """Connection, isolation, and request policy for one S3-backed store."""

    bucket: str
    prefix: str = ""
    region_name: str | None = None
    endpoint_url: str | None = None
    expected_bucket_owner: str | None = None
    server_side_encryption: str | None = None
    sse_kms_key_id: str | None = None
    bucket_key_enabled: bool | None = None
    connect_timeout: float = 5.0
    read_timeout: float = 30.0
    max_pool_connections: int = 10
    read_total_max_attempts: int = 3
    retry_mode: str = "standard"
    addressing_style: str | None = None
    list_page_size: int = 1000
    max_list_pages: int = 10_000

    def __post_init__(self):
        if not isinstance(self.bucket, str) \
                or not _BUCKET_RE.fullmatch(self.bucket) \
                or ".." in self.bucket \
                or _IP_STYLE_BUCKET_RE.fullmatch(self.bucket) \
                or self.bucket.startswith(_RESERVED_BUCKET_PREFIXES) \
                or self.bucket.endswith(_RESERVED_BUCKET_SUFFIXES):
            raise ValueError("general-purpose S3 bucket name")
        _validate_prefix(self.prefix)
        for value, name in (
                (self.region_name, "region_name"),
                (self.endpoint_url, "endpoint_url"),
                (self.expected_bucket_owner, "expected_bucket_owner")):
            if value is not None and (
                    not isinstance(value, str) or not value):
                raise ValueError(name)
        if self.server_side_encryption not in {
                None, "AES256", "aws:kms", "aws:kms:dsse"}:
            raise ValueError("server_side_encryption")
        if self.sse_kms_key_id is not None and (
                not isinstance(self.sse_kms_key_id, str)
                or not self.sse_kms_key_id
                or self.server_side_encryption not in {
                    "aws:kms", "aws:kms:dsse"}):
            raise ValueError("sse_kms_key_id")
        if self.bucket_key_enabled is not None \
                and not isinstance(self.bucket_key_enabled, bool):
            raise ValueError("bucket_key_enabled")
        if self.bucket_key_enabled is not None \
                and self.server_side_encryption != "aws:kms":
            raise ValueError("bucket_key_enabled requires aws:kms")
        for value, name in (
                (self.connect_timeout, "connect_timeout"),
                (self.read_timeout, "read_timeout")):
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(value) or value <= 0:
                raise ValueError(name)
        _positive_int(self.max_pool_connections, "max_pool_connections")
        _positive_int(
            self.read_total_max_attempts, "read_total_max_attempts")
        if self.retry_mode not in {"legacy", "standard", "adaptive"}:
            raise ValueError("retry_mode")
        if self.addressing_style not in {None, "auto", "path", "virtual"}:
            raise ValueError("addressing_style")
        _positive_int(self.list_page_size, "list_page_size", maximum=1000)
        _positive_int(self.max_list_pages, "max_list_pages")


class S3Store:
    """A strongly consistent, direct-API S3 ObjectStore.

    Passing ``client`` uses one injected client for every operation. Otherwise
    the adapter constructs separate read and mutation clients: reads use the
    configured retry count, while mutations always use exactly one total
    attempt so an SDK retry cannot turn an applied-but-lost response into a
    false precondition failure.
    """

    def __init__(
            self, config: S3Config, *, client=None, read_client=None,
            mutation_client=None):
        if not isinstance(config, S3Config):
            raise TypeError("S3Config required")
        if client is not None and (
                read_client is not None or mutation_client is not None):
            raise ValueError("inject one client or a read/mutation pair")
        if client is not None:
            read_client = mutation_client = client
        elif (read_client is None) != (mutation_client is None):
            raise ValueError("both read_client and mutation_client are required")
        elif read_client is None:
            read_client, mutation_client = self._sdk_clients(config)
        _validate_mutation_client_retries(mutation_client)
        self.config = config
        self._read_client = read_client
        self._mutation_client = mutation_client

    @staticmethod
    def _sdk_clients(config, **provider_credentials):
        try:
            boto3 = importlib.import_module("boto3")
            botocore_config = importlib.import_module("botocore.config")
        except ImportError as error:
            raise RuntimeError(
                "boto3 and botocore are required unless S3 clients are "
                "injected") from error

        base = {
            "connect_timeout": config.connect_timeout,
            "read_timeout": config.read_timeout,
            "max_pool_connections": config.max_pool_connections,
        }
        if config.addressing_style is not None:
            base["s3"] = {"addressing_style": config.addressing_style}
        read_config = botocore_config.Config(
            **base,
            retries={
                "mode": config.retry_mode,
                "total_max_attempts": config.read_total_max_attempts,
            })
        mutation_config = botocore_config.Config(
            **base,
            retries={
                "mode": config.retry_mode,
                "total_max_attempts": 1,
            })
        client_args = dict(provider_credentials)
        if config.region_name is not None:
            client_args["region_name"] = config.region_name
        if config.endpoint_url is not None:
            client_args["endpoint_url"] = config.endpoint_url
        return (
            boto3.client("s3", config=read_config, **client_args),
            boto3.client("s3", config=mutation_config, **client_args),
        )

    def _physical(self, key):
        key = validate_key(key)
        physical = (
            f"{self.config.prefix}/{key}" if self.config.prefix else key)
        if len(physical.encode("ascii")) > 1024:
            raise ValueError("S3 object key exceeds 1024 bytes")
        return physical

    def _owner_args(self):
        owner = self.config.expected_bucket_owner
        return {"ExpectedBucketOwner": owner} if owner is not None else {}

    def _read_args(self, key):
        return {
            "Bucket": self.config.bucket,
            "Key": self._physical(key),
            **self._owner_args(),
        }

    def _put_args(self, key, value):
        value = _value_bytes(value)
        args = {
            **self._read_args(key),
            "Body": value,
            "ChecksumAlgorithm": "SHA256",
            "ChecksumSHA256": _checksum(value),
        }
        encryption = self.config.server_side_encryption
        if encryption is not None:
            args["ServerSideEncryption"] = encryption
        if self.config.sse_kms_key_id is not None:
            args["SSEKMSKeyId"] = self.config.sse_kms_key_id
        if self.config.bucket_key_enabled is not None:
            args["BucketKeyEnabled"] = self.config.bucket_key_enabled
        return args

    @staticmethod
    def _response_etag(response, operation, *, mutation):
        etag = response.get("ETag") if isinstance(response, dict) else None
        if not isinstance(etag, str) or not etag or etag.startswith("W/"):
            error = ValueError(
                "successful response has no usable strong ETag")
            if mutation:
                raise OutcomeUnknown(
                    f"S3 {operation} applied without a usable strong ETag"
                ) from error
            raise StoreError(
                f"S3 {operation} response has no usable strong ETag") from error
        return etag

    @staticmethod
    def _response_body(response, operation):
        body = response.get("Body") if isinstance(response, dict) else None
        if body is None or not callable(getattr(body, "read", None)):
            raise StoreError(f"S3 {operation} response has no readable body")
        try:
            value = body.read()
        except Exception as error:
            _raise_read_error(operation, error)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    # Closing an already-complete response cannot change the
                    # bytes that were returned. Do not let cleanup obscure a
                    # classified read failure.
                    pass
        if not isinstance(value, bytes):
            raise StoreError(f"S3 {operation} response body is not bytes")
        return value

    def _get_response(self, key, operation):
        try:
            return self._read_client.get_object(**self._read_args(key))
        except Exception as error:
            if _is_missing_key(error):
                return None
            _raise_read_error(operation, error)

    def get(self, key):
        response = self._get_response(key, "GetObject")
        return None if response is None else self._response_body(
            response, "GetObject")

    def read_versioned(self, key):
        response = self._get_response(key, "GetObject")
        if response is None:
            return ABSENT
        etag = self._response_etag(response, "GetObject", mutation=False)
        value = self._response_body(response, "GetObject")
        return Versioned(value, VersionToken(etag))

    def has(self, key):
        try:
            self._read_client.head_object(**self._read_args(key))
            return True
        except Exception as error:
            if _is_missing_key(error):
                return False
            _raise_read_error("HeadObject", error)

    def put(self, key, value):
        key = validate_key(key)
        if authoritative_key(key):
            raise ValueError(
                "authoritative keys require conditional writes")
        try:
            self._mutation_client.put_object(**self._put_args(key, value))
        except Exception as error:
            _raise_mutation_error("PutObject", error)

    def put_if_absent(self, key, value):
        key = validate_key(key)
        value = _value_bytes(value)
        if key == "root" or key.startswith("root/"):
            raise ValueError("root requires compare-and-swap")
        if key == "obj" or (
                key.startswith("obj/") and key[4:] != h(value)):
            raise ValueError("immutable object address")
        args = self._put_args(key, value)
        args["IfNoneMatch"] = "*"
        try:
            self._mutation_client.put_object(**args)
        except Exception as error:
            status, _ = _error_details(error)
            if status == 412:
                return EXISTS
            _raise_mutation_error("conditional PutObject", error)
        return CREATED

    def cas(self, key, token, value):
        if validate_key(key) != "root":
            raise ValueError("only root is mutable by CAS")
        if token is not ABSENT and not isinstance(token, VersionToken):
            raise TypeError("CAS requires an absent marker or version token")
        args = self._put_args(key, value)
        if token is ABSENT:
            args["IfNoneMatch"] = "*"
        else:
            args["IfMatch"] = token.value
        try:
            response = self._mutation_client.put_object(**args)
        except Exception as error:
            status, _ = _error_details(error)
            if status == 412 or (
                    token is not ABSENT and _is_missing_key(error)):
                return STALE
            _raise_mutation_error("conditional root PutObject", error)
        etag = self._response_etag(
            response, "conditional root PutObject", mutation=True)
        return Applied(VersionToken(etag))

    def list(self, prefix):
        if not isinstance(prefix, str):
            raise TypeError("list prefix")
        logical_prefix = prefix[:-1] if prefix.endswith("/") else prefix
        if prefix and not logical_prefix:
            raise ValueError("bad list prefix")
        if logical_prefix:
            validate_key(logical_prefix)
        namespace = (
            self.config.prefix + "/" if self.config.prefix else "")
        physical_prefix = namespace + (
            logical_prefix + "/" if logical_prefix else "")
        if len(physical_prefix.encode("ascii")) > 1024:
            raise ValueError("S3 list prefix exceeds 1024 bytes")
        base_args = {
            "Bucket": self.config.bucket,
            "Prefix": physical_prefix,
            "MaxKeys": self.config.list_page_size,
            **self._owner_args(),
        }
        out = set()
        continuation = None
        seen_tokens = set()
        for _ in range(self.config.max_list_pages):
            args = dict(base_args)
            if continuation is not None:
                args["ContinuationToken"] = continuation
            try:
                response = self._read_client.list_objects_v2(**args)
            except Exception as error:
                _raise_read_error("ListObjectsV2", error)
            if not isinstance(response, dict):
                raise StoreError("S3 ListObjectsV2 response is not a mapping")
            contents = response.get("Contents", ())
            if contents is None:
                contents = ()
            if not isinstance(contents, (list, tuple)):
                raise StoreError("S3 ListObjectsV2 Contents is not a sequence")
            for item in contents:
                physical = item.get("Key") if isinstance(item, dict) else None
                if not isinstance(physical, str) \
                        or not physical.startswith(physical_prefix):
                    raise StoreError(
                        "S3 ListObjectsV2 returned an out-of-prefix key")
                logical = physical[len(namespace):]
                validate_key(logical)
                out.add(logical)
            truncated = response.get("IsTruncated", False)
            if not isinstance(truncated, bool):
                raise StoreError(
                    "S3 ListObjectsV2 IsTruncated is not boolean")
            if not truncated:
                return sorted(out)
            continuation = response.get("NextContinuationToken")
            if not isinstance(continuation, str) or not continuation \
                    or continuation in seen_tokens:
                raise StoreError(
                    "S3 ListObjectsV2 pagination token did not advance")
            seen_tokens.add(continuation)
        raise StoreError("S3 ListObjectsV2 page bound exceeded")

    def delete(self, key):
        key = validate_key(key)
        if authoritative_key(key):
            raise ValueError("authoritative keys are not deletable")
        try:
            self._mutation_client.delete_object(**self._read_args(key))
        except Exception as error:
            _raise_mutation_error("DeleteObject", error)
