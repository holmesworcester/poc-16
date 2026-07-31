"""Deterministic SigV4 refinement for direct isolated-ingress R2 PUTs."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urlencode,
    urlsplit,
    urlunsplit,
)
from unittest.mock import patch

import pytest

from core.limits import MAX_PILE_BYTES
from core.ingress import ingress_key
from deploy.cloudflare_upload.boundary import Deployment
from deploy.cloudflare_upload.signer import (
    ALGORITHM,
    PAYLOAD,
    R2UploadSigner,
)
from deploy.upload_broker import AuthorizedPilePut
from deploy.upload_session import valid_provider_binding
from deploy.upload_wire import UploadCapability


FIXED = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)
FIXED_MS = int(FIXED.timestamp() * 1000)
WORKSPACE = "b" * 64
MEMBER = "e" * 64
SESSION = "f" * 32
DIGEST = "1" * 64
ACCESS = "2" * 32
SECRET = "3" * 64
SIGNED_HEADERS = (
    "content-length",
    "content-type",
    "host",
    "if-none-match",
)
EXPECTED_SIGNATURE = (
    "87d20707133d0eb05af65c5f71acaf93"
    "eb0a1370499c579431bd9163079043b2"
)


def deployment(**changes):
    values = {
        "account_id": "a" * 32,
        "workspace": WORKSPACE,
        "canonical_bucket": "poc16-canonical",
        "ingress_bucket": "poc16-untrusted-ingress",
        "owner": "production-west",
        "broker_name": "poc16-upload-broker",
        "applier_name": "poc16-repository-applier",
        "read_permission_group_id": "c" * 32,
        "write_permission_group_id": "d" * 32,
        "broker_domain": "uploads.example.com",
        "presign_ttl_seconds": 60,
    }
    values.update(changes)
    return Deployment(**values)


def authorized(
        *, digest=DIGEST, size=42,
        workspace=WORKSPACE, member=MEMBER, session=SESSION,
        not_after_ms=FIXED_MS + 5_500):
    return AuthorizedPilePut(
        workspace,
        member,
        session,
        digest,
        size,
        not_after_ms,
    )


def signer(candidate=None, *, access=ACCESS, secret=SECRET, now=FIXED_MS):
    return R2UploadSigner(
        deployment() if candidate is None else candidate,
        access,
        secret,
        clock=lambda: now,
    )


def _query(pairs):
    return urlencode(
        sorted(pairs),
        doseq=False,
        safe="-_.~",
        quote_via=quote,
    )


def _mac(key, value):
    return hmac.new(key, value, hashlib.sha256).digest()


def _signing_key(secret, date, region, service):
    key = _mac(
        ("AWS4" + secret).encode("ascii"), date.encode("ascii"))
    key = _mac(key, region.encode("ascii"))
    key = _mac(key, service.encode("ascii"))
    return _mac(key, b"aws4_request")


def _signature_valid(
        capability, secret, now_ms, body, *, access_key=ACCESS,
        method=None, url=None, headers=None):
    """Independent strict verifier for the request surface under test."""
    method = "PUT" if method is None else method
    url = capability.url if url is None else url
    headers = dict(capability.headers) \
        if headers is None else dict(headers)
    try:
        parsed = urlsplit(url)
        pairs = parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True)
        if len({name for name, _ in pairs}) != len(pairs):
            return False
        query = dict(pairs)
        signature = query.pop("X-Amz-Signature")
        if set(query) != {
                "X-Amz-Algorithm",
                "X-Amz-Content-Sha256",
                "X-Amz-Credential",
                "X-Amz-Date",
                "X-Amz-Expires",
                "X-Amz-SignedHeaders"}:
            return False
        credential = query["X-Amz-Credential"].split("/")
        if len(credential) != 5 \
                or credential[-1] != "aws4_request":
            return False
        access, date, region, service, _ = credential
        timestamp = query["X-Amz-Date"]
        issued = datetime.strptime(
            timestamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        ttl = int(query["X-Amz-Expires"])
        issued_ms = int(issued.timestamp()) * 1000
        signed = tuple(query["X-Amz-SignedHeaders"].split(";"))
        request_headers = {
            str(name).lower(): str(value)
            for name, value in headers.items()
        }
        request_headers["host"] = parsed.netloc
        if query["X-Amz-Algorithm"] != ALGORITHM \
                or query["X-Amz-Content-Sha256"] != PAYLOAD \
                or not 1 <= ttl <= 604_800 \
                or not issued_ms <= now_ms < issued_ms + ttl * 1000 \
                or date != timestamp[:8] \
                or signed != SIGNED_HEADERS \
                or any(name not in request_headers for name in signed) \
                or int(request_headers["content-length"]) != len(body) \
                or parsed.scheme != "https" or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None \
                or parsed.port is not None or parsed.fragment:
            return False
        canonical_headers = "".join(
            f"{name}:{request_headers[name].strip()}\n"
            for name in signed
        )
        canonical_uri = quote(
            unquote(parsed.path), safe="/-_.~")
        canonical_request = "\n".join((
            method,
            canonical_uri,
            _query(query.items()),
            canonical_headers,
            ";".join(signed),
            PAYLOAD,
        ))
        scope = "/".join(credential[1:])
        string_to_sign = "\n".join((
            ALGORITHM,
            timestamp,
            scope,
            hashlib.sha256(
                canonical_request.encode("utf-8")).hexdigest(),
        ))
        expected = hmac.new(
            _signing_key(secret, date, region, service),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False
    return access == access_key and hmac.compare_digest(signature, expected)


def _mutate_query(url, name, value):
    parsed = urlsplit(url)
    pairs = [
        (key, value if key == name else current)
        for key, current in parse_qsl(
            parsed.query, keep_blank_values=True)
    ]
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        _query(pairs),
        parsed.fragment,
    ))


class Staging:
    """Create-only staging refinement; it makes no body-digest claim."""

    def __init__(self):
        self.data = {}

    def execute(
            self, capability, body, *,
            method=None, url=None, headers=None, now_ms=FIXED_MS):
        url = capability.url if url is None else url
        if not _signature_valid(
                capability, SECRET, now_ms, body,
                method=method, url=url, headers=headers):
            return 403
        key = unquote(urlsplit(url).path).removeprefix("/")
        if key in self.data:
            return 412
        self.data[key] = body
        return 200


def test_frozen_vector_matches_exact_path_style_r2_sigv4():
    capability = signer().sign(authorized())
    expected_key = ingress_key(
        WORKSPACE, SESSION, MEMBER, DIGEST)
    expected_url = (
        "https://" + "a" * 32 + ".r2.cloudflarestorage.com/"
        "poc16-untrusted-ingress/" + expected_key
        + "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD"
        "&X-Amz-Credential=" + "2" * 32
        + "%2F20260729%2Fauto%2Fs3%2Faws4_request"
        "&X-Amz-Date=20260729T120000Z"
        "&X-Amz-Expires=5"
        "&X-Amz-SignedHeaders="
        "content-length%3Bcontent-type%3Bhost%3Bif-none-match"
        "&X-Amz-Signature=" + EXPECTED_SIGNATURE
    )

    assert capability == UploadCapability(
        expected_url,
        (
            ("content-length", "42"),
            ("content-type", "application/octet-stream"),
            ("if-none-match", "*"),
        ),
        FIXED_MS + 5_000,
    )
    assert _signature_valid(
        capability, SECRET, FIXED_MS, b"x" * 42)


def test_frozen_vector_cross_checks_botocore_sigv4_when_available():
    pytest.importorskip("boto3")
    pytest.importorskip("botocore")
    from botocore.auth import S3SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    capability = signer().sign(authorized())
    parsed = urlsplit(capability.url)
    unsigned_url = urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        "X-Amz-Content-Sha256=UNSIGNED-PAYLOAD",
        "",
    ))
    request = AWSRequest(
        method="PUT",
        url=unsigned_url,
        headers=dict(capability.headers),
    )
    with patch(
            "botocore.auth.get_current_datetime",
            return_value=FIXED):
        S3SigV4QueryAuth(
            Credentials(ACCESS, SECRET),
            "s3",
            "auto",
            expires=5,
        ).add_auth(request)

    assert dict(parse_qsl(
        urlsplit(request.url).query)) == dict(parse_qsl(parsed.query))
    assert dict(parse_qsl(parsed.query))[
        "X-Amz-Signature"] == EXPECTED_SIGNATURE


def test_method_endpoint_bucket_key_headers_query_and_expiry_are_bound():
    capability = signer().sign(authorized())
    headers = dict(capability.headers)
    foreign_account = capability.url.replace(
        "a" * 32 + ".r2.", "9" * 32 + ".r2.")
    foreign_bucket = capability.url.replace(
        "/poc16-untrusted-ingress/", "/poc16-canonical/")
    foreign_key = capability.url.replace(
        f"/{DIGEST}?", f"/{'9' * 64}?")
    root = capability.url.replace(
        urlsplit(capability.url).path, "/poc16-canonical/root")
    cases = (
        {"method": "GET"},
        {"method": "DELETE"},
        {"url": foreign_account},
        {"url": foreign_bucket},
        {"url": foreign_key},
        {"url": root},
        {"url": _mutate_query(
            capability.url, "X-Amz-Expires", "6")},
        {"url": _mutate_query(
            capability.url, "X-Amz-Content-Sha256", "0" * 64)},
        {"url": _mutate_query(
            capability.url, "X-Amz-Credential",
            "9" * 32 + "/20260729/auto/s3/aws4_request")},
        {"url": _mutate_query(
            capability.url, "X-Amz-Signature", "0" * 64)},
        {"headers": {
            key: value for key, value in headers.items()
            if key != "content-type"}},
        {"headers": {**headers, "content-type": "text/plain"}},
        {"headers": {**headers, "content-length": "43"}},
        {"headers": {**headers, "if-none-match": "\"etag\""}},
        {"now_ms": capability.expires_at_ms},
    )

    for changes in cases:
        now_ms = changes.get("now_ms", FIXED_MS)
        request = {
            name: value
            for name, value in changes.items()
            if name != "now_ms"
        }
        assert not _signature_valid(
            capability,
            SECRET,
            now_ms,
            b"x" * 42,
            **request,
        )


def test_create_only_replay_and_length_mutation_never_clobber_staging():
    capability = signer().sign(authorized())
    store = Staging()
    key = unquote(urlsplit(capability.url).path).removeprefix("/")

    assert store.execute(capability, b"x" * 42) == 200
    assert store.execute(capability, b"x" * 42) == 412
    assert store.execute(capability, b"short") == 403
    assert store.data == {key: b"x" * 42}


def test_unsigned_payload_is_explicit_and_requires_applier_verification():
    capability = signer().sign(authorized())
    query = dict(parse_qsl(urlsplit(capability.url).query))
    store = Staging()
    wrong_same_length = b"not-the-declared-digest".ljust(42, b"!")

    assert query["X-Amz-Content-Sha256"] == "UNSIGNED-PAYLOAD"
    assert all(
        "sha256" not in name for name, _ in capability.headers)
    assert hashlib.sha256(wrong_same_length).hexdigest() != DIGEST
    assert store.execute(capability, wrong_same_length) == 200
    assert all(
        key.startswith("poc16-untrusted-ingress/ingress/v1/")
        for key in store.data
    )
    assert all("/poc16-canonical/" not in key for key in store.data)


def test_deadline_rounds_down_and_subsecond_authority_fails_closed():
    rounded = signer(now=FIXED_MS + 499).sign(authorized(
        not_after_ms=FIXED_MS + 5_500))

    assert dict(parse_qsl(urlsplit(rounded.url).query))[
        "X-Amz-Expires"] == "5"
    assert rounded.expires_at_ms == FIXED_MS + 5_000
    with pytest.raises(RuntimeError, match="no signed second"):
        signer().sign(authorized(
            not_after_ms=FIXED_MS + 999))


def test_pile_metadata_accepts_n_and_rejects_n_plus_one():
    accepted = signer().sign(authorized(size=MAX_PILE_BYTES))

    assert dict(accepted.headers)["content-length"] == str(MAX_PILE_BYTES)
    expected = ingress_key(
        WORKSPACE, SESSION, MEMBER, DIGEST)
    assert urlsplit(accepted.url).path.endswith("/" + expected)
    with pytest.raises(ValueError, match="size"):
        signer().sign(authorized(size=MAX_PILE_BYTES + 1))


@pytest.mark.parametrize(
    "change",
    (
        lambda value: replace(value, workspace="9" * 64),
        lambda value: replace(value, member="E" * 64),
        lambda value: replace(value, session="F" * 32),
        lambda value: replace(value, digest="9" * 63),
        lambda value: replace(value, size=-1),
        lambda value: replace(value, not_after_ms="later"),
    ),
)
def test_signer_rejects_forged_semantic_grants(change):
    with pytest.raises(ValueError):
        signer().sign(change(authorized()))


def test_provider_binding_pins_account_bucket_jurisdiction_and_parent():
    base = signer()
    same = signer(secret="4" * 64)
    other_parent = signer(access="9" * 32)
    other_bucket = signer(deployment(ingress_bucket="other-ingress"))
    european = signer(deployment(jurisdiction="eu"))

    assert base.provider_binding == same.provider_binding
    assert base.provider_binding != other_parent.provider_binding
    assert base.provider_binding != other_bucket.provider_binding
    assert base.provider_binding != european.provider_binding
    assert len(base.provider_binding.rsplit(":", 1)[1]) == 64
    assert valid_provider_binding(base.provider_binding)
    assert european.sign(authorized()).url.startswith(
        "https://" + "a" * 32 + ".eu.r2.cloudflarestorage.com/"
        "poc16-untrusted-ingress/"
    )
    assert ACCESS not in base.provider_binding
    assert SECRET not in repr(base)


def test_reserved_credential_bytes_are_encoded_and_signed_canonically():
    reserved_access = "ACCESS+key=value~"
    reserved_secret = "secret/with+reserved=characters"
    capability = signer(
        access=reserved_access, secret=reserved_secret).sign(authorized())
    query = dict(parse_qsl(urlsplit(capability.url).query))

    assert "%2F" in capability.url \
        and "%2B" in capability.url and "%3D" in capability.url
    assert query["X-Amz-Credential"].startswith(
        reserved_access + "/20260729/auto/s3/aws4_request")
    assert _signature_valid(
        capability,
        reserved_secret,
        FIXED_MS,
        b"x" * 42,
        access_key=reserved_access,
    )


@pytest.mark.parametrize(
    "access,secret",
    (
        ("short", SECRET),
        ("contains space", SECRET),
        ("access/with/slash", SECRET),
        ("é" * 32, SECRET),
        (ACCESS, "short"),
        (ACCESS, "contains space"),
        (ACCESS, "é" * 64),
    ),
)
def test_parent_credentials_are_bounded_ascii_but_never_returned(
        access, secret):
    with pytest.raises(ValueError):
        signer(access=access, secret=secret)
