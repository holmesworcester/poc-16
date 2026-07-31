"""Deterministic SigV4 and AWS policy refinement for direct S3 uploads."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from urllib.parse import (
    parse_qs,
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)
from unittest.mock import patch

import pytest

from deploy.aws_upload_broker.policy import ingress_cors, presigner_policy
from deploy.aws_upload_broker.signer import (
    S3UploadConfig,
    S3UploadSigner,
)
from deploy.upload_broker import AuthorizedPilePut


ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
FIXED_TIME = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)
FIXED_TIME_MS = int(FIXED_TIME.timestamp() * 1000)
WORKSPACE = "a" * 64
MEMBER = "b" * 16
SESSION = "d" * 32
BODY = b"provider-enforced collision-resistant body"
DIGEST = hashlib.sha256(BODY).hexdigest()


def authorized(body=BODY, not_after_ms=FIXED_TIME_MS + 60_000):
    digest = hashlib.sha256(body).hexdigest()
    return AuthorizedPilePut(
        WORKSPACE,
        MEMBER,
        SESSION,
        digest,
        len(body),
        not_after_ms,
    )


def actual_client():
    boto3 = pytest.importorskip("boto3")
    pytest.importorskip("botocore")
    from botocore.config import Config

    return boto3.client(
        "s3",
        region_name="us-west-2",
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        config=Config(
            signature_version="s3v4",
            ignore_configured_endpoint_urls=True,
            s3={"addressing_style": "virtual"},
        ),
    )


def minted(*, expected_owner=None, put=None):
    client = actual_client()
    config = S3UploadConfig(
        "direct-upload-bucket",
        "us-west-2",
        ttl_seconds=60,
        expected_bucket_owner=expected_owner,
    )
    signer = S3UploadSigner(config, client)
    with patch(
            "botocore.auth.get_current_datetime",
            return_value=FIXED_TIME):
        capability = signer.sign(put or authorized())
    return client, config, capability


def without_signature(url):
    parsed = urlsplit(url)
    pairs = [
        (name, value)
        for name, value in parse_qsl(
            parsed.query, keep_blank_values=True)
        if name != "X-Amz-Signature"
    ]
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(pairs),
        parsed.fragment,
    ))


def signature_valid(method, url, headers):
    pytest.importorskip("botocore")
    from botocore.auth import S3SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    query = parse_qs(urlsplit(url).query)
    presented = query.get("X-Amz-Signature", [None])
    if len(presented) != 1 or presented[0] is None:
        return False
    try:
        request = AWSRequest(
            method=method,
            url=without_signature(url),
            headers=headers,
        )
        request.context["timestamp"] = query["X-Amz-Date"][0]
        verifier = S3SigV4QueryAuth(
            Credentials(ACCESS_KEY, SECRET_KEY),
            "s3",
            "us-west-2",
            expires=int(query["X-Amz-Expires"][0]),
        )
        canonical = verifier.canonical_request(request)
        expected = verifier.signature(
            verifier.string_to_sign(request, canonical),
            request,
        )
    except Exception:
        return False
    return hmac.compare_digest(presented[0], expected)


class DeterministicS3:
    """Only the documented PUT checks this design relies upon."""

    def __init__(self):
        self.data = {}

    def execute(
            self, capability, body, *,
            method=None, url=None, headers=None, now=None):
        method = method or "PUT"
        url = url or capability.url
        headers = dict(capability.headers) \
            if headers is None else dict(headers)
        now = FIXED_TIME if now is None else now
        if not signature_valid(method, url, headers):
            return 403
        query = parse_qs(urlsplit(url).query)
        issued = datetime.strptime(
            query["X-Amz-Date"][0],
            "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        if now > issued + timedelta(
                seconds=int(query["X-Amz-Expires"][0])):
            return 403
        try:
            if method != "PUT" \
                    or headers["if-none-match"] != "*" \
                    or int(headers["content-length"]) != len(body) \
                    or headers["content-type"] \
                    != "application/octet-stream" \
                    or not hmac.compare_digest(
                        base64.b64decode(
                            headers["x-amz-checksum-sha256"],
                            validate=True),
                        hashlib.sha256(body).digest()):
                return 400
        except (KeyError, TypeError, ValueError):
            return 400
        key = urlsplit(url).path.removeprefix("/")
        if key in self.data:
            return 412
        self.data[key] = body
        return 200


class FixedPresigner:
    """A checked SigV4 response surface with a fixed provider clock."""

    class Meta:
        endpoint_url = "https://s3.us-west-2.amazonaws.com"

    meta = Meta()

    def __init__(self):
        self.ttls = []

    def generate_presigned_url(
            self, operation, *, Params, ExpiresIn, HttpMethod):
        assert operation == "put_object"
        assert HttpMethod == "PUT"
        self.ttls.append(ExpiresIn)
        signed_headers = (
            "content-length;content-type;host;if-none-match;"
            "x-amz-checksum-sha256"
        )
        query = urlencode({
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential":
                "AKID/20260729/us-west-2/s3/aws4_request",
            "X-Amz-Date": "20260729T120000Z",
            "X-Amz-Expires": str(ExpiresIn),
            "X-Amz-Signature": "a" * 64,
            "X-Amz-SignedHeaders": signed_headers,
        })
        return (
            f"https://{Params['Bucket']}.s3.us-west-2.amazonaws.com/"
            f"{Params['Key']}?{query}"
        )


def test_signer_attenuates_to_deadline_and_rejects_subsecond_window():
    client = FixedPresigner()
    signer = S3UploadSigner(
        S3UploadConfig("direct-upload-bucket", "us-west-2"),
        client,
    )

    capability = signer.sign(authorized(
        not_after_ms=FIXED_TIME_MS + 5_500))

    assert client.ttls == [60, 5]
    assert parse_qs(urlsplit(capability.url).query)[
        "X-Amz-Expires"] == ["5"]
    assert capability.expires_at_ms == FIXED_TIME_MS + 5_000

    too_late = FixedPresigner()
    with pytest.raises(RuntimeError, match="no whole-second capability"):
        S3UploadSigner(
            S3UploadConfig("direct-upload-bucket", "us-west-2"),
            too_late,
        ).sign(authorized(not_after_ms=FIXED_TIME_MS + 999))
    assert too_late.ttls == [60]


def test_botocore_generates_the_exact_signed_put_request_shape():
    client = actual_client()
    captured = []

    class Capturing:
        meta = client.meta

        def generate_presigned_url(self, *args, **kwargs):
            captured.append((args, kwargs))
            return client.generate_presigned_url(*args, **kwargs)

    config = S3UploadConfig(
        "direct-upload-bucket", "us-west-2",
        expected_bucket_owner="123456789012")
    with patch(
            "botocore.auth.get_current_datetime",
            return_value=FIXED_TIME):
        signer = S3UploadSigner(config, Capturing())
        capability = signer.sign(authorized())

    method, request = captured[0]
    assert signer.provider_binding == (
        "aws-s3-v1:us-west-2:direct-upload-bucket:123456789012")
    assert method == ("put_object",)
    assert request == {
        "ExpiresIn": 60,
        "HttpMethod": "PUT",
        "Params": {
            "Bucket": "direct-upload-bucket",
            "ChecksumSHA256": base64.b64encode(
                hashlib.sha256(BODY).digest()).decode(),
            "ContentLength": len(BODY),
            "ContentType": "application/octet-stream",
            "ExpectedBucketOwner": "123456789012",
            "IfNoneMatch": "*",
            "Key": authorized().key,
        },
    }
    query = parse_qs(urlsplit(capability.url).query)
    assert query["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert query["X-Amz-Date"] == ["20260729T120000Z"]
    assert query["X-Amz-Expires"] == ["60"]
    assert query["X-Amz-SignedHeaders"] == [
        "content-length;content-type;host;if-none-match;"
        "x-amz-checksum-sha256;x-amz-expected-bucket-owner"]
    assert capability.headers == (
        ("content-length", str(len(BODY))),
        ("content-type", "application/octet-stream"),
        ("if-none-match", "*"),
        ("x-amz-checksum-sha256", base64.b64encode(
            hashlib.sha256(BODY).digest()).decode()),
        ("x-amz-expected-bucket-owner", "123456789012"),
    )
    assert capability.expires_at_ms == 1_785_326_460_000


def test_actual_sigv4_and_s3_checks_reject_every_authority_mutation():
    _, _, capability = minted()
    store = DeterministicS3()
    headers = dict(capability.headers)
    foreign_workspace = capability.url.replace(
        f"/workspaces/{WORKSPACE}/",
        f"/workspaces/{'e' * 64}/")
    foreign_bucket = capability.url.replace(
        "direct-upload-bucket.s3.",
        "foreign-upload-bucket.s3.")
    foreign_member = capability.url.replace(
        f"/piles/{SESSION}/{MEMBER}/",
        f"/piles/{SESSION}/{'e' * 16}/")
    wrong_key = capability.url.replace(
        f"/{DIGEST}?", f"/{'f' * 64}?")
    root_key = capability.url.replace(
        urlsplit(capability.url).path,
        "/root")
    surplus_signed = capability.url.replace(
        "X-Amz-SignedHeaders=",
        "X-Amz-SignedHeaders=x-amz-meta-extra%3B")
    cases = (
        ("GET", capability.url, headers, BODY, FIXED_TIME),
        ("DELETE", capability.url, headers, BODY, FIXED_TIME),
        ("PUT", foreign_workspace, headers, BODY, FIXED_TIME),
        ("PUT", foreign_bucket, headers, BODY, FIXED_TIME),
        ("PUT", foreign_member, headers, BODY, FIXED_TIME),
        ("PUT", wrong_key, headers, BODY, FIXED_TIME),
        ("PUT", root_key, headers, BODY, FIXED_TIME),
        ("PUT", surplus_signed, headers, BODY, FIXED_TIME),
        ("PUT", capability.url, {
            key: value for key, value in headers.items()
            if key != "content-type"}, BODY, FIXED_TIME),
        ("PUT", capability.url, {
            **headers, "content-type": "text/plain"}, BODY, FIXED_TIME),
        ("PUT", capability.url, {
            **headers, "content-length": str(len(BODY) + 1)},
         BODY, FIXED_TIME),
        ("PUT", capability.url, {
            **headers, "x-amz-checksum-sha256":
                base64.b64encode(b"z" * 32).decode()},
         BODY, FIXED_TIME),
        ("PUT", capability.url, headers, BODY + b"!", FIXED_TIME),
        ("PUT", capability.url, headers, BODY,
         FIXED_TIME + timedelta(seconds=61)),
    )

    for method, url, mutated_headers, body, now in cases:
        assert store.execute(
            capability, body, method=method, url=url,
            headers=mutated_headers, now=now) != 200
    assert store.data == {}


def test_create_only_replay_and_collision_never_clobber_ingress():
    _, _, capability = minted()
    store = DeterministicS3()
    key = urlsplit(capability.url).path.removeprefix("/")

    assert store.execute(capability, BODY) == 200
    assert store.execute(capability, BODY) == 412
    assert store.execute(capability, b"different bytes") != 200
    assert store.data == {key: BODY}

    occupied = DeterministicS3()
    occupied.data[key] = b"incumbent"
    assert occupied.execute(capability, BODY) == 412
    assert occupied.data == {key: b"incumbent"}


def test_signer_rejects_a_provider_response_that_drops_constraints():
    client = actual_client()

    class Weak:
        meta = client.meta

        def generate_presigned_url(self, *args, **kwargs):
            valid = client.generate_presigned_url(*args, **kwargs)
            return valid.replace(
                "content-length%3Bcontent-type%3B",
                "content-type%3B")

    config = S3UploadConfig("direct-upload-bucket", "us-west-2")
    with patch(
            "botocore.auth.get_current_datetime",
            return_value=FIXED_TIME):
        with pytest.raises(
                RuntimeError, match="sign every constraint"):
            S3UploadSigner(config, Weak()).sign(authorized())


@pytest.mark.parametrize(
    "put",
    (
        lambda value: AuthorizedPilePut(
            "z" * 64, value.member, value.session,
            value.digest, value.size, value.not_after_ms),
        lambda value: AuthorizedPilePut(
            value.workspace, value.member, value.session,
            value.digest, -1, value.not_after_ms),
        lambda value: AuthorizedPilePut(
            value.workspace, value.member, value.session,
            "z" * 64, value.size, value.not_after_ms),
        lambda value: AuthorizedPilePut(
            value.workspace, value.member, value.session,
            value.digest, value.size, "later"),
    ),
)
def test_signer_does_not_treat_forged_internal_values_as_authority(put):
    client = actual_client()
    signer = S3UploadSigner(
        S3UploadConfig("direct-upload-bucket", "us-west-2"),
        client)

    with pytest.raises(ValueError, match="authorized S3 upload"):
        signer.sign(put(authorized()))


def test_presigner_role_and_cors_expose_only_exact_put_authority():
    config = S3UploadConfig(
        "direct-upload-bucket",
        "us-west-2",
        ttl_seconds=90,
        expected_bucket_owner="123456789012",
    )
    document = presigner_policy(config, WORKSPACE)
    statement = document["Statement"][0]

    assert statement["Action"] == "s3:PutObject"
    assert statement["Resource"] == (
        "arn:aws:s3:::direct-upload-bucket/"
        f"ingress/v1/workspaces/{WORKSPACE}/piles/*"
    )
    assert statement["Condition"] == {
        "Null": {"s3:if-none-match": "false"},
        "NumericLessThanEquals": {"s3:signatureAge": 90_000},
        "StringEquals": {
            "s3:ResourceAccount": "123456789012",
            "s3:authType": "REST-QUERY-STRING",
            "s3:signatureversion": "AWS4-HMAC-SHA256",
        },
    }
    encoded = str(document)
    for forbidden in (
            "ListBucket", "DeleteObject", "GetObject", "/root",
            "s3:*"):
        assert forbidden not in encoded

    cors = ingress_cors([
        "https://app.example",
        "https://backup.example:8443",
    ])
    assert cors == {"CORSRules": [{
        "AllowedHeaders": [
            "content-type",
            "if-none-match",
            "x-amz-checksum-sha256",
            "x-amz-expected-bucket-owner",
        ],
        "AllowedMethods": ["PUT"],
        "AllowedOrigins": [
            "https://app.example",
            "https://backup.example:8443",
        ],
        "ExposeHeaders": [
            "etag",
            "x-amz-checksum-sha256",
        ],
        "MaxAgeSeconds": 300,
    }]}
    assert "content-length" not in cors["CORSRules"][0]["AllowedHeaders"]


@pytest.mark.parametrize(
    "config",
    (
        lambda: S3UploadConfig("has.dot", "us-west-2"),
        lambda: S3UploadConfig("UPPERCASE", "us-west-2"),
        lambda: S3UploadConfig("amzn-s3-demo-reserved", "us-west-2"),
        lambda: S3UploadConfig("xn--reserved", "us-west-2"),
        lambda: S3UploadConfig("reserved--x-s3", "us-west-2"),
        lambda: S3UploadConfig("valid-bucket", "../region"),
        lambda: S3UploadConfig("valid-bucket", "us-west-2", 0),
        lambda: S3UploadConfig("valid-bucket", "us-west-2", 901),
        lambda: S3UploadConfig(
            "valid-bucket", "us-west-2",
            expected_bucket_owner="not-an-account"),
    ),
)
def test_upload_config_rejects_ambiguous_deployment_inputs(config):
    with pytest.raises(ValueError):
        config()


@pytest.mark.parametrize(
    "origin",
    (
        "http://insecure.example",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?query",
        "*",
    ),
)
def test_cors_never_widens_to_an_ambiguous_origin(origin):
    with pytest.raises(ValueError):
        ingress_cors([origin])
