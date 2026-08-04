"""R2 object capabilities attenuate operations and keep bytes on R2."""
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from core.crypto import h
from core.limits import MAX_DIRECT_OBJECT_BYTES, MAX_SEMANTIC_PILE_BYTES
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_SCOPED_TTL_MS,
    ObjectOpen,
    PackOpen,
    confine_object_request,
    confine_scoped_request,
    object_key,
    pack_key,
)
from deploy.cloudflare_pack.contract import (
    PACK_TICKET_SECRET_BYTES,
    R2PackTarget,
)
from deploy.cloudflare_pack.issuer import R2PackIssuer
from deploy.cloudflare_pack.put import R2ImmutablePut


NOW = 1_800_000_000_000
MEMBER = h(b"member")
OID = h(b"pack payload")
OTHER = h(b"other pack")
ACCESS = "a" * 32
SECRET = "b" * 64
TICKET_SECRET = b"t" * PACK_TICKET_SECRET_BYTES
PREFIX = "repositories/" + h(b"workspace")
TICKET_DOMAIN = b"poc16-r2-immutable-put-v1\0"


def target(**changes):
    values = {
        "endpoint": "https://" + "c" * 32 + ".r2.cloudflarestorage.com",
        "bucket": "poc16-packs",
        "prefix": PREFIX,
        "put_endpoint": "https://packs.example.com",
        "ttl_seconds": 30,
    }
    values.update(changes)
    return R2PackTarget(**values)


def issuer(candidate=None, *, clock=None):
    return R2PackIssuer(
        target() if candidate is None else candidate,
        ACCESS,
        SECRET,
        TICKET_SECRET,
        clock=(lambda: NOW) if clock is None else clock,
    )


def _direct_ticket_url(logical_key, body_bytes, expires_at_ms):
    message = TICKET_DOMAIN + b"\0".join((
        logical_key.encode("ascii"),
        str(body_bytes).encode("ascii"),
        str(expires_at_ms).encode("ascii"),
    ))
    signature = hmac.new(
        TICKET_SECRET, message, hashlib.sha256).hexdigest()
    return (
        f"{target().put_endpoint}/{logical_key}"
        f"?body_bytes={body_bytes}&expires_at_ms={expires_at_ms}"
        f"&signature={signature}"
    )


def _ticket_url(oid, pack_bytes, expires_at_ms):
    return _direct_ticket_url(
        pack_key(oid), pack_bytes, expires_at_ms)


class ProviderFailure(Exception):
    def __init__(self, status):
        super().__init__(f"provider status {status}")
        self.status = status


class SentinelStream:
    """Virtual body: tests can model 95 MiB without allocating or reading it."""

    def __init__(self, size, digest=OID, failure=None):
        self.size = size
        self.digest = digest
        self.failure = failure

    async def arrayBuffer(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack route buffered request.body")

    def getReader(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack route read request.body")

    def __iter__(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack route iterated request.body")

    def __bytes__(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack route copied request.body")


@dataclass
class FakeRequest:
    method: str
    url: str
    headers: object
    body: object

    async def arrayBuffer(self):  # pragma: no cover - failure is the assertion
        raise AssertionError("pack route buffered Request")


class FakeR2:
    """The native binding consumes the stream outside the Python route."""

    def __init__(self):
        self.objects = {}
        self.calls = []

    async def put(self, key, value, **options):
        self.calls.append((key, value, options))
        assert options["onlyIf"] == {"If-None-Match": "*"}
        if key in self.objects:
            return None
        if value.failure is not None:
            raise value.failure
        if options["sha256"] != value.digest:
            raise ProviderFailure(400)
        self.objects[key] = (value.size, value.digest)
        return SimpleNamespace(key=key)


def request_for(scoped, body, **changes):
    values = {
        "method": scoped.method,
        "url": scoped.url,
        "headers": dict(scoped.headers),
        "body": body,
    }
    values.update(changes)
    return FakeRequest(**values)


def run(route, request):
    return asyncio.run(route.handle(request))


def test_whole_and_exact_range_gets_are_direct_presigned_r2_requests():
    whole = PackOpen("GET", OID, MAX_PACK_BYTES)
    ranged = PackOpen(
        "GET",
        OID,
        MAX_PACK_BYTES,
        MAX_PACK_BYTES - MAX_SEMANTIC_PILE_BYTES,
        MAX_SEMANTIC_PILE_BYTES,
    )
    issued = issuer()

    whole_request = issued.open_pack(MEMBER, whole, NOW)
    range_request = issued.open_pack(MEMBER, ranged, NOW)

    assert confine_scoped_request(whole, whole_request, NOW) is whole_request
    assert confine_scoped_request(ranged, range_request, NOW) is range_request
    expected_path = f"/poc16-packs/{PREFIX}/pack/{OID}"
    assert urlsplit(whole_request.url).path == expected_path
    assert urlsplit(range_request.url).path == expected_path
    assert whole_request.headers == ()
    assert range_request.headers == ((
        "range",
        f"bytes={MAX_PACK_BYTES - MAX_SEMANTIC_PILE_BYTES}-"
        f"{MAX_PACK_BYTES - 1}",
    ),)
    assert parse_qs(urlsplit(whole_request.url).query)[
        "X-Amz-SignedHeaders"] == ["host"]
    assert parse_qs(urlsplit(range_request.url).query)[
        "X-Amz-SignedHeaders"] == ["host;range"]
    assert NOW < whole_request.expires_at_ms <= NOW + 30_000
    assert NOW < range_request.expires_at_ms <= NOW + 30_000


def test_object_get_is_one_exact_bounded_direct_r2_request():
    opened = ObjectOpen("GET", OID, MAX_DIRECT_OBJECT_BYTES)

    scoped = issuer().open_object(MEMBER, opened, NOW)

    assert confine_object_request(opened, scoped, NOW) is scoped
    assert scoped.method == "GET"
    assert scoped.headers == ()
    assert urlsplit(scoped.url).path == f"/poc16-packs/{PREFIX}/obj/{OID}"
    assert parse_qs(urlsplit(scoped.url).query)[
        "X-Amz-SignedHeaders"] == ["host"]
    assert scoped.expires_at_ms == NOW + target().ttl_seconds * 1000


def test_object_issuer_fails_closed_on_identity_type_time_and_deadline():
    opened = ObjectOpen("GET", OID, MAX_DIRECT_OBJECT_BYTES)
    issued = issuer()

    for member, candidate, trusted_now in (
            ("not-a-member", opened, NOW),
            (MEMBER, PackOpen("GET", OID, MAX_PACK_BYTES), NOW),
            (MEMBER, opened, True)):
        with pytest.raises(ValueError):
            issued.open_object(member, candidate, trusted_now)

    deadline = NOW + target().ttl_seconds * 1000
    late = issuer(clock=lambda: deadline)
    with pytest.raises(RuntimeError, match="deadline"):
        late.open_object(MEMBER, opened, NOW)


@pytest.mark.parametrize("pack_bytes", (1, MAX_PACK_BYTES))
def test_exact_put_boundaries_stream_one_body_identity_to_native_r2(pack_bytes):
    opened = PackOpen("PUT", OID, pack_bytes)
    scoped = issuer().open_pack(MEMBER, opened, NOW)
    assert confine_scoped_request(opened, scoped, NOW) is scoped
    body = SentinelStream(pack_bytes)
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    response = run(route, request_for(scoped, body))

    assert response.status == 201
    assert response.body == b""
    assert dict(response.headers) == {
        "cache-control": "no-store",
        "content-length": "0",
    }
    assert bucket.calls == [(
        f"{PREFIX}/pack/{OID}",
        body,
        {"onlyIf": {"If-None-Match": "*"}, "sha256": OID},
    )]
    assert bucket.objects == {
        f"{PREFIX}/pack/{OID}": (pack_bytes, OID)}


@pytest.mark.parametrize("object_bytes", (1, MAX_DIRECT_OBJECT_BYTES))
def test_exact_object_put_boundaries_use_the_same_native_r2_route(
        object_bytes):
    opened = ObjectOpen("PUT", OID, object_bytes)
    scoped = issuer().open_object(MEMBER, opened, NOW)
    assert confine_object_request(opened, scoped, NOW) is scoped
    body = SentinelStream(object_bytes)
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    response = run(route, request_for(scoped, body))

    assert response.status == 201
    assert bucket.calls == [(
        f"{PREFIX}/obj/{OID}",
        body,
        {"onlyIf": {"If-None-Match": "*"}, "sha256": OID},
    )]
    assert bucket.objects == {
        f"{PREFIX}/obj/{OID}": (object_bytes, OID)}


def test_one_over_object_put_is_rejected_before_r2_sees_the_stream():
    oversized = MAX_DIRECT_OBJECT_BYTES + 1
    request = FakeRequest(
        "PUT",
        _direct_ticket_url(
            object_key(OID), oversized, NOW + 30_000),
        {"content-length": str(oversized), "if-none-match": "*"},
        SentinelStream(oversized),
    )
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    assert run(route, request).status == 413
    assert bucket.calls == []


def test_one_over_is_rejected_before_r2_sees_the_stream():
    oversized = MAX_PACK_BYTES + 1
    request = FakeRequest(
        "PUT",
        _ticket_url(OID, oversized, NOW + 30_000),
        {"content-length": str(oversized), "if-none-match": "*"},
        SentinelStream(oversized),
    )
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    assert run(route, request).status == 413
    assert bucket.calls == []
    assert bucket.objects == {}


def test_create_collision_does_not_consume_or_replace_existing_pack():
    scoped = issuer().open_pack(MEMBER, PackOpen("PUT", OID, 7), NOW)
    existing = (7, OID)
    bucket = FakeR2()
    bucket.objects[f"{PREFIX}/pack/{OID}"] = existing
    body = SentinelStream(7, failure=AssertionError(
        "conditional failure must precede stream consumption"))
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    assert run(route, request_for(scoped, body)).status == 412
    assert bucket.objects[f"{PREFIX}/pack/{OID}"] is existing
    assert bucket.calls[0][1] is body


@pytest.mark.parametrize(("body", "expected"), (
    (SentinelStream(7, OTHER), 400),
    (SentinelStream(7, failure=RuntimeError("interrupted stream")), 503),
    (SentinelStream(7, failure=ProviderFailure(422)), 400),
    (SentinelStream(7, failure=ProviderFailure(412)), 412),
))
def test_checksum_interruption_and_provider_errors_never_create_a_pack(
        body, expected):
    scoped = issuer().open_pack(MEMBER, PackOpen("PUT", OID, 7), NOW)
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    assert run(route, request_for(scoped, body)).status == expected
    assert bucket.objects == {}
    assert bucket.calls[0][1] is body


def test_ticket_expiry_and_excess_lifetime_fail_before_body_or_r2():
    opened = PackOpen("PUT", OID, 7)
    scoped = issuer().open_pack(MEMBER, opened, NOW)
    body = SentinelStream(7)
    bucket = FakeR2()

    expired = R2ImmutablePut(
        target(), bucket, TICKET_SECRET,
        clock=lambda: scoped.expires_at_ms,
    )
    assert run(expired, request_for(scoped, body)).status == 403

    too_long = FakeRequest(
        "PUT",
        _ticket_url(OID, 7, NOW + MAX_SCOPED_TTL_MS + 1),
        {"content-length": "7", "if-none-match": "*"},
        body,
    )
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)
    assert run(route, too_long).status == 403
    assert bucket.calls == []


@pytest.mark.parametrize("mutate", (
    lambda url: url + "&extra=1",
    lambda url: url.replace("expires_at_ms=", "body_bytes=7&expires_at_ms="),
    lambda url: url.replace("body_bytes=7", "body_bytes=8"),
    lambda url: url.replace("signature=", "signature=0"),
    lambda url: url.replace(f"/pack/{OID}", f"/pack/{OTHER}"),
    lambda url: url.replace(f"/pack/{OID}", f"/obj/{OID}"),
    lambda url: url.replace(
        "https://packs.example.com", "https://other.example.com"),
))
def test_ticket_cannot_widen_key_size_origin_or_query(mutate):
    scoped = issuer().open_pack(MEMBER, PackOpen("PUT", OID, 7), NOW)
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)
    request = request_for(scoped, SentinelStream(7), url=mutate(scoped.url))

    assert run(route, request).status == 403
    assert bucket.calls == []


@pytest.mark.parametrize("headers", (
    {"content-length": "6", "if-none-match": "*"},
    {"content-length": "07", "if-none-match": "*"},
    {"content-length": "7"},
    {"content-length": "7", "if-none-match": "anything"},
    {"content-length": "7", "if-none-match": "*", "range": "bytes=0-6"},
    {"content-length": "7", "if-none-match": "*", "content-range": "bytes 0-6/7"},
))
def test_native_route_rejects_every_header_widening(headers):
    scoped = issuer().open_pack(MEMBER, PackOpen("PUT", OID, 7), NOW)
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    request = request_for(scoped, SentinelStream(7), headers=headers)
    assert run(route, request).status == 400
    assert bucket.calls == []


def test_native_route_rejects_wrong_method_missing_body_and_bad_clock():
    scoped = issuer().open_pack(MEMBER, PackOpen("PUT", OID, 7), NOW)
    bucket = FakeR2()
    route = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: NOW)

    assert run(route, request_for(
        scoped, SentinelStream(7), method="GET")).status == 405
    assert run(route, request_for(scoped, None)).status == 400
    bad_clock = R2ImmutablePut(
        target(), bucket, TICKET_SECRET, clock=lambda: True)
    assert run(bad_clock, request_for(scoped, SentinelStream(7))).status == 503
    assert bucket.calls == []


@pytest.mark.parametrize("changes", (
    {"endpoint": "http://example.com"},
    {"put_endpoint": "https://packs.example.com/path"},
    {"bucket": "Bad_Bucket"},
    {"prefix": "/absolute"},
    {"ttl_seconds": 0},
    {"ttl_seconds": MAX_SCOPED_TTL_MS // 1000 + 1},
))
def test_target_rejects_ambiguous_or_wider_provider_scope(changes):
    with pytest.raises(ValueError):
        target(**changes)


def test_issuer_rejects_wrong_member_and_preserves_url_fragment_rule():
    opened = PackOpen("GET", OID, 7)
    with pytest.raises(ValueError):
        issuer().open_pack("not-a-member", opened, NOW)
    with pytest.raises(ValueError):
        R2PackIssuer(target(), ACCESS, SECRET, b"short", clock=lambda: NOW)

    scoped = issuer().open_pack(MEMBER, opened, NOW)
    parsed = urlsplit(scoped.url)
    assert parsed.fragment == ""


def test_native_worker_import_does_not_load_sigv4_or_upload_broker():
    script = """
import json
import sys
import deploy.cloudflare_pack.put
print(json.dumps(sorted(name for name in sys.modules if name.startswith(
    (\"deploy.cloudflare_upload\", \"deploy.upload_broker\")))))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout) == []
