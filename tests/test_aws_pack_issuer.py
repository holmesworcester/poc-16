"""Exact SigV4 confinement for metadata-only S3 writer-pack access."""
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from urllib.parse import parse_qs, parse_qsl, quote, urlsplit

import pytest

from adapters.s3 import S3Config
from core import peer_capability
from core.crypto import h
from core.grants import make_token
from core.http import AsyncFromSyncReader, HttpGate
from core.pack_access import (
    PackOpen,
    decode_scoped_request,
    encode_pack_open,
)
from deploy.aws_lambda import app
from deploy.aws_lambda.pack_issuer import (
    PACK_CONTENT_TYPE,
    S3PackBinding,
    S3PackIssuer,
)


ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
REGION = "us-west-2"
BUCKET = "writer-pack-bucket"
WORKSPACE = h(b"workspace")
MEMBER = h(b"member")
PREFIX = f"tenant/workspaces/{WORKSPACE}"
OWNER = "123456789012"
BODY = b"0123456789writer-pack-body"
OID = h(BODY)
FIXED_TIME = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)
NOW = int(FIXED_TIME.timestamp() * 1000)


def _encode(value):
    return quote(str(value), safe="-_.~")


def _canonical_query(pairs):
    return "&".join(
        f"{_encode(name)}={_encode(value)}"
        for name, value in sorted(pairs))


def _mac(key, value):
    return hmac.new(key, value.encode(), hashlib.sha256).digest()


def _signing_key(secret, date, region):
    date_key = _mac(("AWS4" + secret).encode(), date)
    region_key = _mac(date_key, region)
    service_key = _mac(region_key, "s3")
    return _mac(service_key, "aws4_request")


def _normalized(value):
    return " ".join(str(value).strip().split())


def _signature(method, url, headers, *, secret=SECRET_KEY):
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = dict(pairs)
    signed = query["X-Amz-SignedHeaders"].split(";")
    values = {name.lower(): _normalized(value)
              for name, value in headers.items()}
    values["host"] = parsed.netloc
    if any(name not in values for name in signed):
        return None
    canonical_headers = "".join(
        f"{name}:{values[name]}\n" for name in signed)
    canonical = "\n".join((
        method,
        quote(parsed.path, safe="/-_.~"),
        _canonical_query(
            (name, value) for name, value in pairs
            if name != "X-Amz-Signature"),
        canonical_headers,
        ";".join(signed),
        "UNSIGNED-PAYLOAD",
    ))
    credential = query["X-Amz-Credential"].split("/")
    scope = "/".join(credential[1:])
    string_to_sign = "\n".join((
        "AWS4-HMAC-SHA256",
        query["X-Amz-Date"],
        scope,
        hashlib.sha256(canonical.encode()).hexdigest(),
    ))
    return hmac.new(
        _signing_key(secret, credential[1], credential[2]),
        string_to_sign.encode(), hashlib.sha256).hexdigest()


def _headers_from_params(params):
    mapped = {}
    for parameter, header in (
            ("BucketKeyEnabled",
             "x-amz-server-side-encryption-bucket-key-enabled"),
            ("ChecksumSHA256", "x-amz-checksum-sha256"),
            ("ContentLength", "content-length"),
            ("ContentType", "content-type"),
            ("ExpectedBucketOwner", "x-amz-expected-bucket-owner"),
            ("IfNoneMatch", "if-none-match"),
            ("Range", "range"),
            ("SSEKMSKeyId",
             "x-amz-server-side-encryption-aws-kms-key-id"),
            ("ServerSideEncryption", "x-amz-server-side-encryption")):
        if parameter in params:
            value = params[parameter]
            mapped[header] = (
                str(value).lower() if isinstance(value, bool)
                else str(value))
    return mapped


class DeterministicS3:
    """Small SigV4 S3 model for exactly the GET/PUT surface we buy."""

    class Meta:
        endpoint_url = f"https://s3.{REGION}.amazonaws.com"

    meta = Meta()

    def __init__(self):
        self.calls = []
        self.data = {}

    def generate_presigned_url(
            self, operation, *, Params, ExpiresIn, HttpMethod):
        self.calls.append((operation, Params, ExpiresIn, HttpMethod))
        host = f"{Params['Bucket']}.s3.{REGION}.amazonaws.com"
        path = "/" + Params["Key"]
        headers = _headers_from_params(Params)
        signed = ";".join(sorted({"host", *headers}))
        date = FIXED_TIME.strftime("%Y%m%d")
        pairs = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential",
             f"{ACCESS_KEY}/{date}/{REGION}/s3/aws4_request"),
            ("X-Amz-Date", FIXED_TIME.strftime("%Y%m%dT%H%M%SZ")),
            ("X-Amz-Expires", str(ExpiresIn)),
            ("X-Amz-SignedHeaders", signed),
        ]
        unsigned = f"https://{host}{path}?{_canonical_query(pairs)}"
        signature = _signature(HttpMethod, unsigned, headers)
        return unsigned + "&X-Amz-Signature=" + signature

    @staticmethod
    def _valid(method, url, headers, now):
        try:
            query = parse_qs(
                urlsplit(url).query,
                keep_blank_values=True, strict_parsing=True)
            presented = query["X-Amz-Signature"]
            if len(presented) != 1:
                return False
            expected = _signature(method, url, headers)
            issued = datetime.strptime(
                query["X-Amz-Date"][0],
                "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            expires = int(query["X-Amz-Expires"][0])
            return expected is not None \
                and hmac.compare_digest(presented[0], expected) \
                and issued <= now <= issued + timedelta(seconds=expires)
        except (KeyError, TypeError, ValueError):
            return False

    def execute(
            self, scoped, body=b"", *, method=None, url=None,
            headers=None, now=FIXED_TIME):
        method = scoped.method if method is None else method
        url = scoped.url if url is None else url
        headers = dict(scoped.headers) if headers is None else dict(headers)
        if not self._valid(method, url, headers, now):
            return 403, {}, b""
        parsed = urlsplit(url)
        key = parsed.path.removeprefix("/")
        if headers.get("x-amz-expected-bucket-owner") != OWNER:
            return 403, {}, b""
        if method == "PUT":
            try:
                checksum = base64.b64decode(
                    headers["x-amz-checksum-sha256"], validate=True)
                valid = headers["content-type"] == PACK_CONTENT_TYPE \
                    and headers["if-none-match"] == "*" \
                    and int(headers["content-length"]) == len(body) \
                    and hmac.compare_digest(
                        checksum, hashlib.sha256(body).digest())
            except (KeyError, TypeError, ValueError):
                valid = False
            if not valid:
                return 400, {}, b""
            if key in self.data:
                return 412, {}, b""
            self.data[key] = body
            return 200, {"etag": '"created"'}, b""
        if method != "GET" or key not in self.data:
            return 404, {}, b""
        value = self.data[key]
        byte_range = headers.get("range")
        if byte_range is None:
            return 200, {
                "accept-ranges": "bytes",
                "content-length": str(len(value)),
            }, value
        try:
            start, end = map(int, byte_range.removeprefix("bytes=").split("-"))
        except (TypeError, ValueError):
            return 416, {}, b""
        if not 0 <= start <= end < len(value):
            return 416, {}, b""
        selected = value[start:end + 1]
        return 206, {
            "accept-ranges": "bytes",
            "content-length": str(len(selected)),
            "content-range": f"bytes {start}-{end}/{len(value)}",
        }, selected


def issuer(store=None, **config):
    store = DeterministicS3() if store is None else store
    values = {
        "bucket": BUCKET,
        "prefix": PREFIX,
        "region_name": REGION,
        "expected_bucket_owner": OWNER,
    }
    values.update(config)
    return store, S3PackIssuer(
        S3PackBinding(S3Config(**values)), store)


def test_issuer_maps_whole_range_and_create_to_exact_s3_requests():
    store, signer = issuer()
    whole = signer.open(MEMBER, PackOpen("GET", OID, len(BODY)), NOW)
    ranged = signer.open(
        MEMBER, PackOpen("GET", OID, len(BODY), 4, 9), NOW)
    create = signer.open(MEMBER, PackOpen("PUT", OID, len(BODY)), NOW)

    assert [call[0] for call in store.calls] == [
        "get_object", "get_object", "put_object"]
    assert [call[3] for call in store.calls] == ["GET", "GET", "PUT"]
    exact_key = f"{PREFIX}/pack/{OID}"
    assert store.calls[0][1] == {
        "Bucket": BUCKET,
        "ExpectedBucketOwner": OWNER,
        "Key": exact_key,
    }
    assert store.calls[1][1] == {
        **store.calls[0][1], "Range": "bytes=4-12"}
    assert store.calls[2][1] == {
        **store.calls[0][1],
        "ChecksumSHA256": base64.b64encode(
            hashlib.sha256(BODY).digest()).decode(),
        "ContentLength": len(BODY),
        "ContentType": PACK_CONTENT_TYPE,
        "IfNoneMatch": "*",
    }
    assert dict(whole.headers) == {
        "x-amz-expected-bucket-owner": OWNER}
    assert dict(ranged.headers) == {
        "range": "bytes=4-12",
        "x-amz-expected-bucket-owner": OWNER,
    }
    assert dict(create.headers) == {
        "content-length": str(len(BODY)),
        "content-type": PACK_CONTENT_TYPE,
        "if-none-match": "*",
        "x-amz-checksum-sha256": base64.b64encode(
            hashlib.sha256(BODY).digest()).decode(),
        "x-amz-expected-bucket-owner": OWNER,
    }
    assert all(item.expires_at_ms == NOW + 60_000
               for item in (whole, ranged, create))


def test_fake_s3_returns_exact_whole_and_single_range_shapes():
    store, signer = issuer()
    key = f"{PREFIX}/pack/{OID}"
    store.data[key] = BODY

    whole = signer.open(MEMBER, PackOpen("GET", OID, len(BODY)), NOW)
    status, headers, body = store.execute(whole)
    assert (status, body) == (200, BODY)
    assert headers == {
        "accept-ranges": "bytes", "content-length": str(len(BODY))}

    ranged = signer.open(
        MEMBER, PackOpen("GET", OID, len(BODY), 5, 7), NOW)
    status, headers, body = store.execute(ranged)
    assert (status, body) == (206, BODY[5:12])
    assert headers == {
        "accept-ranges": "bytes",
        "content-length": "7",
        "content-range": f"bytes 5-11/{len(BODY)}",
    }


def test_signed_create_is_provider_hashed_create_only_and_never_clobbers():
    store, signer = issuer()
    opened = PackOpen("PUT", OID, len(BODY))
    scoped = signer.open(MEMBER, opened, NOW)
    key = f"{PREFIX}/pack/{OID}"

    assert store.execute(scoped, BODY)[0] == 200
    assert store.execute(scoped, BODY)[0] == 412
    assert store.execute(scoped, b"wrong bytes")[0] != 200
    assert store.data == {key: BODY}

    occupied, second = issuer()
    occupied.data[key] = b"incumbent"
    assert occupied.execute(
        second.open(MEMBER, opened, NOW), BODY)[0] == 412
    assert occupied.data[key] == b"incumbent"


def _query_mutation(url, name, value):
    parsed = urlsplit(url)
    pairs = [
        (key, value if key == name else item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" \
        + _canonical_query(pairs)


def test_fake_s3_rejects_every_signed_authority_mutation():
    store, signer = issuer()
    get = signer.open(
        MEMBER, PackOpen("GET", OID, len(BODY), 2, 8), NOW)
    put = signer.open(MEMBER, PackOpen("PUT", OID, len(BODY)), NOW)
    get_headers, put_headers = dict(get.headers), dict(put.headers)
    cases = (
        (get, "PUT", get.url, get_headers, b""),
        (get, "GET", get.url.replace(BUCKET, "foreign-bucket"),
         get_headers, b""),
        (get, "GET", get.url.replace(PREFIX, "foreign/workspace"),
         get_headers, b""),
        (get, "GET", get.url.replace(OID, h(b"other")),
         get_headers, b""),
        (get, "GET", get.url,
         {**get_headers, "range": "bytes=2-10"}, b""),
        (get, "GET", _query_mutation(
            get.url, "X-Amz-Expires", "600"), get_headers, b""),
        (put, "PUT", put.url,
         {**put_headers, "content-length": str(len(BODY) + 1)}, BODY),
        (put, "PUT", put.url,
         {**put_headers, "if-none-match": "present"}, BODY),
        (put, "PUT", put.url,
         {**put_headers, "x-amz-checksum-sha256": base64.b64encode(
             b"x" * 32).decode()}, BODY),
        (put, "PUT", put.url,
         {**put_headers, "x-amz-expected-bucket-owner": "0" * 12}, BODY),
    )
    for scoped, method, url, headers, body in cases:
        assert store.execute(
            scoped, body, method=method, url=url, headers=headers)[0] != 200
    assert store.data == {}


def test_issuer_rejects_presigner_scope_widening_before_return():
    class Weak(DeterministicS3):
        def generate_presigned_url(self, *args, **kwargs):
            valid = super().generate_presigned_url(*args, **kwargs)
            return valid.replace(
                "range%3Bx-amz-expected-bucket-owner",
                "x-amz-expected-bucket-owner")

    weak, signer = issuer(Weak())
    with pytest.raises(RuntimeError, match="sign every constraint"):
        signer.open(
            MEMBER, PackOpen("GET", OID, len(BODY), 1, 2), NOW)
    assert len(weak.calls) == 1


def test_issuer_preserves_declared_kms_headers_in_the_signature():
    key = "arn:aws:kms:us-west-2:123456789012:key/pack-key"
    store, signer = issuer(
        server_side_encryption="aws:kms",
        sse_kms_key_id=key,
        bucket_key_enabled=True,
    )
    scoped = signer.open(
        MEMBER, PackOpen("PUT", OID, len(BODY)), NOW)
    params = store.calls[0][1]
    assert params["ServerSideEncryption"] == "aws:kms"
    assert params["SSEKMSKeyId"] == key
    assert params["BucketKeyEnabled"] is True
    assert dict(scoped.headers) | {
        "x-amz-server-side-encryption": "aws:kms",
        "x-amz-server-side-encryption-aws-kms-key-id": key,
        "x-amz-server-side-encryption-bucket-key-enabled": "true",
    } == dict(scoped.headers)


def test_binding_rejects_non_aws_or_unbounded_configuration():
    base = dict(bucket=BUCKET, prefix=PREFIX, region_name=REGION)
    for config, ttl in (
            (S3Config(**{**base, "prefix": ""}), 60),
            (S3Config(**{**base, "region_name": None}), 60),
            (S3Config(**{**base,
                       "endpoint_url": "https://r2.example"}), 60),
            (S3Config(**base), 61)):
        with pytest.raises(ValueError, match="pack binding"):
            S3PackBinding(config, ttl)


def test_lambda_pack_open_returns_only_bounded_scoped_metadata(monkeypatch):
    store, signer = issuer()
    secret = b"s" * 32
    gate = HttpGate(
        object(), WORKSPACE, secret, lambda: NOW,
        pack_open=signer.open)
    app._gateway_cache = gate
    token = make_token(
        secret, MEMBER, WORKSPACE,
        capability=peer_capability.FULL,
        issued_at=NOW, ttl_ms=60_000)
    opened = PackOpen("PUT", OID, len(BODY))
    result = app.handler({
        "version": "2.0",
        "rawPath": "/pack/open",
        "rawQueryString": f"ws={WORKSPACE}",
        "headers": {"authorization": "Bearer " + token},
        "requestContext": {"http": {"method": "POST"}},
        "body": base64.b64encode(encode_pack_open(opened)).decode(),
        "isBase64Encoded": True,
    }, None)

    assert result["statusCode"] == 200
    raw = base64.b64decode(result["body"])
    scoped = decode_scoped_request(raw)
    assert scoped == signer.open(MEMBER, opened, NOW)
    assert len(raw) < 16 * 1024
    assert BODY not in raw
    assert store.data == {}


def test_lambda_gateway_composes_one_store_namespace_with_pack_issuer(
        monkeypatch):
    config = S3Config(
        BUCKET, PREFIX, region_name=REGION,
        expected_bucket_owner=OWNER)
    issued = []

    class PackIssuer:
        def open(self, *_args):
            pass

    pack_issuer = PackIssuer()
    monkeypatch.setattr(app, "_s3_config", lambda: config)
    monkeypatch.setattr(app, "_store", lambda value: object())
    monkeypatch.setattr(app, "_secret", lambda: b"s" * 32)
    monkeypatch.setattr(app, "_pack_issuer", lambda value: (
        issued.append(value) or pack_issuer))
    monkeypatch.setenv("TINYP2P_WORKSPACE_ID", WORKSPACE)
    app._gateway_cache = None

    gate = app._gateway()
    assert issued == [config]
    assert gate.pack_open == pack_issuer.open
    assert app._gateway_cache is gate
