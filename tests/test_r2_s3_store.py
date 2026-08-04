"""R2's host adapter reuses S3 CAS without AWS-only headers."""
import base64
import hashlib
import io

import pytest

from adapters.r2 import R2S3Config, R2S3Store
from core.crypto import h
from core.object_store import ABSENT, Applied, Versioned


class Client:
    def __init__(self):
        self.data = {}
        self.tokens = {}
        self.calls = []
        self.generation = 0

    def _etag(self):
        self.generation += 1
        return f'"r2-{self.generation}"'

    def get_object(self, **request):
        self.calls.append(("get", request))
        key = request["Key"]
        if key not in self.data:
            error = RuntimeError("missing")
            error.response = {
                "ResponseMetadata": {"HTTPStatusCode": 404},
                "Error": {"Code": "NoSuchKey"},
            }
            raise error
        return {"Body": io.BytesIO(self.data[key]), "ETag": self.tokens[key]}

    def put_object(self, **request):
        self.calls.append(("put", request))
        key = request["Key"]
        if request.get("IfNoneMatch") == "*" and key in self.data:
            error = RuntimeError("stale")
            error.response = {
                "ResponseMetadata": {"HTTPStatusCode": 412},
                "Error": {"Code": "PreconditionFailed"},
            }
            raise error
        if "IfMatch" in request \
                and self.tokens.get(key) != request["IfMatch"]:
            error = RuntimeError("stale")
            error.response = {
                "ResponseMetadata": {"HTTPStatusCode": 412},
                "Error": {"Code": "PreconditionFailed"},
            }
            raise error
        self.data[key] = request["Body"]
        self.tokens[key] = self._etag()
        return {"ETag": self.tokens[key]}


def config(**changes):
    values = {
        "account_id": "a" * 32,
        "bucket": "workspace-bucket",
        "prefix": "tenant",
    }
    values.update(changes)
    return R2S3Config(**values)


def test_r2_config_can_only_name_the_direct_account_endpoint():
    configured = config()

    assert configured.endpoint_url \
        == "https://" + "a" * 32 + ".r2.cloudflarestorage.com"
    assert configured.as_s3().region_name == "auto"
    assert configured.as_s3().expected_bucket_owner is None
    with pytest.raises(ValueError, match="account"):
        config(account_id="https://cached.example")
    with pytest.raises(ValueError, match="connect_timeout"):
        config(connect_timeout=float("nan"))


def test_r2_host_path_uses_content_md5_and_s3_conditionals():
    client = Client()
    store = R2S3Store(config(), client=client)
    first = store.cas("authority", ABSENT, b"one")
    versioned = store.read_versioned("authority")
    second = store.cas("authority", versioned.token, b"two")

    assert isinstance(first, Applied)
    assert isinstance(versioned, Versioned)
    assert isinstance(second, Applied)
    put_requests = [
        request for operation, request in client.calls if operation == "put"]
    assert put_requests[0]["IfNoneMatch"] == "*"
    assert put_requests[1]["IfMatch"] == versioned.token.value
    for request in put_requests:
        assert request["ContentMD5"] == base64.b64encode(
            hashlib.md5(
                request["Body"], usedforsecurity=False).digest()
        ).decode("ascii")
        assert "ChecksumAlgorithm" not in request
        assert "ChecksumSHA256" not in request
        assert "ExpectedBucketOwner" not in request
        assert "ServerSideEncryption" not in request


def test_r2_host_path_keeps_content_address_validation():
    client = Client()
    store = R2S3Store(config(), client=client)
    raw = b"immutable"

    store.put_if_absent("obj/" + h(raw), raw)
    with pytest.raises(ValueError, match="address"):
        store.put_if_absent("obj/" + "0" * 64, raw)


def test_r2_explicit_credentials_are_complete_and_not_mixed_with_clients():
    client = Client()
    with pytest.raises(ValueError, match="both"):
        R2S3Store(config(), access_key_id="only")
    with pytest.raises(ValueError, match="injected"):
        R2S3Store(
            config(), access_key_id="id", secret_access_key="secret",
            client=client)
