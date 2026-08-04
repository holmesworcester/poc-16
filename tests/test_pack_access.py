"""Pack transfer control stays bounded while bytes use ordinary HTTP."""
import asyncio
from dataclasses import replace
import json

import pytest

from core import pack_access, peer_capability
from core.crypto import h
from core.fact import canon
from core.grants import make_token
from core.http import HttpGate
from core.limits import (
    MAX_DIRECT_OBJECT_BYTES,
    MAX_SEMANTIC_PILE_BYTES,
    PayloadTooLarge,
)
from core.pack_access import (
    MAX_OBJECT_OPEN_BYTES,
    MAX_PACK_BYTES,
    MAX_PACK_OPEN_BYTES,
    MAX_SCOPED_HEADER_VALUE_BYTES,
    MAX_SCOPED_HEADERS,
    MAX_SCOPED_REQUEST_BYTES,
    MAX_SCOPED_TTL_MS,
    MAX_SCOPED_URL_BYTES,
    InvalidPackAccess,
    ObjectOpen,
    PackOpen,
    ScopedRequest,
    confine_object_request,
    confine_scoped_request,
    copy_object_get,
    copy_pack_get,
    decode_object_open,
    decode_pack_open,
    decode_scoped_request,
    encode_object_open,
    encode_pack_open,
    encode_scoped_request,
    object_key,
    pack_key,
)
from core.writer_layout import MAX_LAYOUT_PACK_BYTES


WORKSPACE = h(b"workspace")
MEMBER = h(b"member")
OID = h(b"pack")
SECRET = b"s" * 32
NOW = 1_800_000_000_000


def bearer(capability):
    return {"Authorization": "Bearer " + make_token(
        SECRET,
        MEMBER,
        WORKSPACE,
        capability=capability,
        issued_at=NOW,
        ttl_ms=60_000,
    )}


def call(gate, method="POST", body=b"", headers=None, workspace=WORKSPACE):
    return asyncio.run(gate.handle(
        method,
        "/pack/open",
        {"ws": workspace},
        headers or {},
        body,
    ))


def call_object(
        gate, method="POST", body=b"", headers=None, workspace=WORKSPACE):
    return asyncio.run(gate.handle(
        method,
        "/obj/open",
        {"ws": workspace},
        headers or {},
        body,
    ))


def scoped_for(opened, *, expires_at_ms=NOW + 10_000):
    if opened.method == "PUT":
        headers = (
            ("content-length", str(opened.pack_bytes)),
            ("if-none-match", "*"),
        )
    elif opened.offset is not None:
        headers = ((
            "range",
            f"bytes={opened.offset}-{opened.offset + opened.length - 1}",
        ),)
    else:
        headers = ()
    return ScopedRequest(
        opened.method,
        f"https://bucket.example/prefix/{pack_key(opened.oid)}?signature=x",
        headers,
        expires_at_ms,
    )


def object_scoped(opened, *, expires_at_ms=NOW + 10_000):
    headers = () if opened.method == "GET" else (
        ("content-length", str(opened.object_bytes)),
        ("if-none-match", "*"),
    )
    return ScopedRequest(
        opened.method,
        f"https://bucket.example/prefix/{object_key(opened.oid)}?signature=x",
        headers,
        expires_at_ms,
    )


def test_object_open_codec_has_one_method_and_named_repository_bound():
    opened = ObjectOpen("PUT", OID, MAX_DIRECT_OBJECT_BYTES)
    raw = encode_object_open(opened)

    assert object_key(OID) == "obj/" + OID
    assert decode_object_open(raw) == opened
    assert json.loads(raw) == {
        "format": "poc16-object-open-v2",
        "method": "PUT",
        "object_bytes": MAX_DIRECT_OBJECT_BYTES,
        "oid": OID,
    }
    for method, oid, maximum in (
            ("POST", OID, MAX_DIRECT_OBJECT_BYTES),
            ("GET", OID.upper(), MAX_DIRECT_OBJECT_BYTES),
            ("GET", OID, 0),
            ("GET", OID, MAX_DIRECT_OBJECT_BYTES + 1),
            ("GET", OID, True)):
        with pytest.raises(InvalidPackAccess):
            ObjectOpen(method, oid, maximum)
    with pytest.raises(PayloadTooLarge):
        decode_object_open(b" " * (MAX_OBJECT_OPEN_BYTES + 1))


def test_object_get_request_and_stream_are_bounded_and_hashed():
    body = b"content-addressed object"
    opened = ObjectOpen("GET", h(body), len(body))
    scoped = object_scoped(opened)
    assert confine_object_request(opened, scoped, NOW) is scoped

    written = []
    assert copy_object_get(
        opened,
        200,
        {"Content-Length": str(len(body))},
        (body[:5], body[5:]),
        written.append,
    ) == len(body)
    assert b"".join(written) == body

    bad_scopes = (
        replace(scoped, method="PUT"),
        replace(scoped, url=(
            "https://bucket.example/prefix/obj/" + h(b"wrong"))),
        replace(scoped, headers=(("range", "bytes=0-1"),)),
        replace(scoped, expires_at_ms=NOW),
    )
    for candidate in bad_scopes:
        with pytest.raises(InvalidPackAccess):
            confine_object_request(opened, candidate, NOW)

    bad_responses = (
        (206, {"Content-Length": str(len(body))}, (body,)),
        (200, {"Content-Length": str(len(body) + 1)}, (body,)),
        (200, {"Content-Length": "01"}, (b"x",)),
        (200, {
            "Content-Length": str(len(body)),
            "Content-Range": f"bytes 0-{len(body) - 1}/{len(body)}",
        }, (body,)),
        (200, {"Content-Length": str(len(body))}, (body[:-1],)),
        (200, {"Content-Length": str(len(body))}, (body[:-1] + b"!",)),
    )
    for status, headers, chunks in bad_responses:
        with pytest.raises(InvalidPackAccess):
            copy_object_get(
                opened, status, headers, chunks, lambda _part: None)


def test_object_put_confinement_requires_exact_create_only_headers():
    opened = ObjectOpen("PUT", OID, 100)
    scoped = object_scoped(opened)
    assert confine_object_request(opened, scoped, NOW) is scoped

    for headers in (
            (("content-length", "99"), ("if-none-match", "*")),
            (("content-length", "100"),),
            (("content-length", "100"), ("if-none-match", "present")),
            (("content-length", "100"), ("if-none-match", "*"),
             ("range", "bytes=0-99"))):
        with pytest.raises(InvalidPackAccess):
            confine_object_request(
                opened, replace(scoped, headers=headers), NOW)


def gate(issuer, **limits):
    return HttpGate(
        object(), WORKSPACE, SECRET, lambda: NOW,
        pack_open=issuer, **limits)


def object_gate(issuer, **limits):
    return HttpGate(
        object(), WORKSPACE, SECRET, lambda: NOW,
        object_open=issuer, **limits)


def test_gate_requires_push_only_for_object_put_and_never_buffers_body():
    get = ObjectOpen("GET", OID, MAX_DIRECT_OBJECT_BYTES)
    put = ObjectOpen("PUT", OID, MAX_DIRECT_OBJECT_BYTES)
    calls = []

    def issuer(member, request, trusted_now):
        calls.append((member, request, trusted_now))
        return object_scoped(request)

    service = object_gate(issuer)
    get_body = encode_object_open(get)
    put_body = encode_object_open(put)
    response = call_object(service, body=get_body, headers=bearer(
        peer_capability.READ_ONLY))
    assert response.status == 200
    assert decode_scoped_request(response.body) == object_scoped(get)
    assert calls == [(MEMBER, get, NOW)]
    assert call_object(
        service, body=put_body,
        headers=bearer(peer_capability.READ_ONLY)).status == 401
    put_response = call_object(
        service, body=put_body, headers=bearer(peer_capability.OWNER))
    assert put_response.status == 200
    assert decode_scoped_request(put_response.body) == object_scoped(put)
    assert calls[-1] == (MEMBER, put, NOW)
    assert call_object(service, body=get_body).status == 401
    assert call_object(
        service, method="GET", headers=bearer(
            peer_capability.READ_ONLY)).status == 405
    assert call_object(
        object_gate(None), body=get_body,
        headers=bearer(peer_capability.READ_ONLY)).status == 405
    assert HttpGate.request_limit("POST", "/obj/open") \
        == MAX_OBJECT_OPEN_BYTES
    assert call_object(
        service,
        body=b" " * (MAX_OBJECT_OPEN_BYTES + 1),
        headers=bearer(peer_capability.READ_ONLY),
    ).status == 413


def test_pack_open_codec_has_one_portable_exact_bound():
    assert MAX_PACK_BYTES == MAX_LAYOUT_PACK_BYTES
    assert pack_key(OID) == "pack/" + OID

    whole_put = PackOpen("PUT", OID, MAX_PACK_BYTES)
    whole_get = PackOpen("GET", OID, MAX_PACK_BYTES)
    ranged = PackOpen(
        "GET", OID, MAX_PACK_BYTES,
        MAX_PACK_BYTES - MAX_SEMANTIC_PILE_BYTES,
        MAX_SEMANTIC_PILE_BYTES)
    for opened in (whole_put, whole_get, ranged):
        raw = encode_pack_open(opened)
        assert decode_pack_open(raw) == opened
        assert json.loads(raw)["format"] == "poc16-pack-open-v1"

    assert set(json.loads(encode_pack_open(whole_get))) == {
        "format", "method", "oid", "pack_bytes"}
    assert set(json.loads(encode_pack_open(ranged))) == {
        "format", "length", "method", "offset", "oid", "pack_bytes"}


@pytest.mark.parametrize("arguments", (
    ("PUT", OID, MAX_PACK_BYTES + 1, None, None),
    ("PUT", OID, 1, 0, 1),
    ("GET", OID, 1, 0, MAX_SEMANTIC_PILE_BYTES + 1),
    ("GET", OID, MAX_SEMANTIC_PILE_BYTES,
     1, MAX_SEMANTIC_PILE_BYTES),
    ("GET", OID, 1, 0, 0),
    ("GET", OID, 1, 0, None),
    ("get", OID, 1, None, None),
    ("GET", OID.upper(), 1, None, None),
    ("GET", OID, True, None, None),
))
def test_pack_open_rejects_every_method_size_and_range_widening(arguments):
    with pytest.raises(InvalidPackAccess):
        PackOpen(*arguments)


def test_pack_open_decoder_rejects_noncanonical_and_malformed_documents():
    opened = PackOpen("GET", OID, 10, 2, 3)
    raw = encode_pack_open(opened)
    value = json.loads(raw)
    bad = [
        b" " + raw,
        canon({**value, "extra": 1}),
        canon({key: item for key, item in value.items() if key != "length"}),
        canon({**value, "method": "get"}),
        raw[:-1] + b',"method":"GET"}',
    ]
    for candidate in bad:
        with pytest.raises(InvalidPackAccess):
            decode_pack_open(candidate)

    with pytest.raises(InvalidPackAccess):
        decode_pack_open(b" " * MAX_PACK_OPEN_BYTES)
    with pytest.raises(PayloadTooLarge):
        decode_pack_open(b" " * (MAX_PACK_OPEN_BYTES + 1))


def test_scoped_request_codec_bounds_url_headers_and_total_bytes():
    opened = PackOpen("GET", OID, 10, 2, 3)
    scoped = scoped_for(opened)
    assert decode_scoped_request(encode_scoped_request(scoped)) == scoped

    suffix = "/" + pack_key(OID)
    exact_url = "https://x/" + "a" * (
        MAX_SCOPED_URL_BYTES - len("https://x/") - len(suffix)) + suffix
    assert len(exact_url) == MAX_SCOPED_URL_BYTES
    ScopedRequest("GET", exact_url, (), NOW)
    with pytest.raises(InvalidPackAccess):
        ScopedRequest("GET", exact_url + "x", (), NOW)

    headers = tuple((f"x-{index:02d}", "v")
                    for index in range(MAX_SCOPED_HEADERS))
    ScopedRequest("GET", "https://x/" + pack_key(OID), headers, NOW)
    with pytest.raises(InvalidPackAccess):
        ScopedRequest(
            "GET", "https://x/" + pack_key(OID),
            headers + (("z", "v"),), NOW)
    ScopedRequest(
        "GET", "https://x/" + pack_key(OID),
        (("x", "v" * MAX_SCOPED_HEADER_VALUE_BYTES),), NOW)
    with pytest.raises(InvalidPackAccess):
        ScopedRequest(
            "GET", "https://x/" + pack_key(OID),
            (("x", "v" * (MAX_SCOPED_HEADER_VALUE_BYTES + 1)),), NOW)

    oversized = ScopedRequest(
        "GET", "https://x/" + pack_key(OID),
        tuple((f"x-{index}", "v" * MAX_SCOPED_HEADER_VALUE_BYTES)
              for index in range(4)), NOW)
    with pytest.raises(PayloadTooLarge):
        encode_scoped_request(oversized)


@pytest.mark.parametrize("kwargs", (
    {"method": "get"},
    {"url": "ftp://bucket.example/pack/x"},
    {"url": "https://user@bucket.example/pack/x"},
    {"url": "https://bucket.example/pack/x#fragment"},
    {"headers": (("Range", "bytes=0-1"),)},
    {"headers": (("x-b", "v"), ("x-a", "v"))},
    {"headers": (("x", "bad\r\nheader"),)},
    {"expires_at_ms": True},
))
def test_scoped_request_rejects_ambiguous_http_metadata(kwargs):
    values = {
        "method": "GET",
        "url": "https://bucket.example/" + pack_key(OID),
        "headers": (),
        "expires_at_ms": NOW,
    }
    values.update(kwargs)
    with pytest.raises(InvalidPackAccess):
        ScopedRequest(**values)


def test_scoped_decoder_rejects_noncanonical_shape_and_one_over():
    raw = encode_scoped_request(scoped_for(PackOpen("GET", OID, 10)))
    value = json.loads(raw)
    for candidate in (
            b" " + raw,
            canon({**value, "extra": 1}),
            canon({**value, "headers": {}}),
            raw[:-1] + b',"method":"GET"}'):
        with pytest.raises(InvalidPackAccess):
            decode_scoped_request(candidate)
    with pytest.raises(InvalidPackAccess):
        decode_scoped_request(b" " * MAX_SCOPED_REQUEST_BYTES)
    with pytest.raises(PayloadTooLarge):
        decode_scoped_request(b" " * (MAX_SCOPED_REQUEST_BYTES + 1))


def test_confinement_accepts_only_the_exact_method_key_range_and_expiry():
    ranged = PackOpen("GET", OID, 100, 10, 20)
    good = scoped_for(ranged)
    assert confine_scoped_request(ranged, good, NOW) is good
    exact_expiry = replace(
        good,
        headers=(("authorization", "signed"), *good.headers),
        expires_at_ms=NOW + MAX_SCOPED_TTL_MS,
    )
    assert confine_scoped_request(ranged, exact_expiry, NOW) is exact_expiry

    bad = (
        replace(good, method="PUT"),
        replace(good, url="https://bucket.example/pack/" + h(b"other")),
        replace(good, headers=(("range", "bytes=10-30"),)),
        replace(good, headers=()),
        replace(good, expires_at_ms=NOW),
        replace(good, expires_at_ms=NOW + MAX_SCOPED_TTL_MS + 1),
    )
    for scoped in bad:
        with pytest.raises(InvalidPackAccess):
            confine_scoped_request(ranged, scoped, NOW)

    whole = PackOpen("GET", OID, 100)
    with pytest.raises(InvalidPackAccess):
        confine_scoped_request(
            whole,
            replace(scoped_for(whole), headers=(("range", "bytes=0-99"),)),
            NOW,
        )


def test_put_confinement_requires_whole_create_only_request():
    opened = PackOpen("PUT", OID, 100)
    good = scoped_for(opened)
    assert confine_scoped_request(opened, good, NOW) == good

    for headers in (
            (("content-length", "99"), ("if-none-match", "*")),
            (("content-length", "100"),),
            (("content-length", "100"), ("if-none-match", "present")),
            (("content-length", "100"), ("if-none-match", "*"),
             ("range", "bytes=0-99"))):
        with pytest.raises(InvalidPackAccess):
            confine_scoped_request(
                opened, replace(good, headers=headers), NOW)


def test_whole_pack_get_streams_to_sink_and_verifies_hash_and_length():
    body = b"one" + b"two" + b"three"
    opened = PackOpen("GET", h(body), len(body))
    written = []

    class Chunks:
        def __iter__(self):
            yield b"one"
            yield b"two"
            yield b"three"

        def read(self, *_args):
            raise AssertionError("stream must not be read without a bound")

    assert copy_pack_get(
        opened,
        200,
        {"Content-Length": str(len(body))},
        Chunks(),
        written.append,
    ) == len(body)
    assert b"".join(written) == body

    corrupt = []
    with pytest.raises(InvalidPackAccess, match="integrity"):
        copy_pack_get(
            opened, 200, {"content-length": str(len(body))},
            (body[:-1] + b"!",), corrupt.append)
    # A caller must use a temporary sink: bad bytes are never publication.
    assert b"".join(corrupt) == body[:-1] + b"!"


def test_ranged_pack_get_requires_exact_206_metadata_and_stays_bounded():
    opened = PackOpen("GET", OID, 100, 10, 4)
    expected_headers = {
        "Content-Length": "4",
        "Content-Range": "bytes 10-13/100",
    }
    written = []
    assert copy_pack_get(
        opened, 206, expected_headers, (b"ab", b"cd"),
        written.append) == 4
    assert written == [b"ab", b"cd"]

    cases = (
        (200, expected_headers, (b"abcd",)),
        (206, {**expected_headers, "Content-Length": "5"}, (b"abcd",)),
        (206, {**expected_headers,
               "Content-Range": "bytes 10-14/100"}, (b"abcd",)),
        (206, {"Content-Length": "4"}, (b"abcd",)),
        (206, expected_headers, (b"abc",)),
        (206, expected_headers, (b"abcde",)),
        (206, expected_headers, (b"", b"abcd")),
        (206, expected_headers, ("abcd",)),
    )
    for status, headers, chunks in cases:
        with pytest.raises(InvalidPackAccess):
            copy_pack_get(opened, status, headers, chunks, lambda _part: None)


def test_pack_get_rejects_duplicate_headers_and_excess_fragmentation(
        monkeypatch):
    body = b"abc"
    opened = PackOpen("GET", h(body), len(body))

    class DuplicateHeaders:
        @staticmethod
        def items():
            return (("Content-Length", "3"), ("content-length", "3"))

    with pytest.raises(InvalidPackAccess, match="headers"):
        copy_pack_get(
            opened, 200, DuplicateHeaders(), (body,), lambda _part: None)

    monkeypatch.setattr(pack_access, "MAX_DIRECT_STREAM_CHUNKS", 2)
    with pytest.raises(InvalidPackAccess, match="stream"):
        copy_pack_get(
            opened, 200, {"Content-Length": "3"},
            (b"a", b"b", b"c"), lambda _part: None)


def test_gate_uses_normal_grants_and_requires_push_only_for_put():
    calls = []

    def issuer(member, opened, trusted_now):
        calls.append((member, opened, trusted_now))
        return scoped_for(opened)

    service = gate(issuer)
    get = PackOpen("GET", OID, 100, 10, 20)
    put = PackOpen("PUT", OID, 100)
    readonly = bearer(peer_capability.READ_ONLY)
    owner = bearer(peer_capability.OWNER)
    full = bearer(peer_capability.FULL)

    response = call(service, body=encode_pack_open(get), headers=readonly)
    assert response.status == 200
    assert response.headers == {
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
    }
    assert decode_scoped_request(response.body) == scoped_for(get)
    assert calls == [(MEMBER, get, NOW)]

    assert call(
        service, body=encode_pack_open(put), headers=readonly).status == 401
    assert calls == [(MEMBER, get, NOW)]
    assert call(
        service, body=encode_pack_open(put), headers=owner).status == 200
    assert calls[-1] == (MEMBER, put, NOW)
    assert call(
        service, body=encode_pack_open(put), headers=full).status == 200

    assert call(service, body=encode_pack_open(get)).status == 401
    assert call(
        service, body=encode_pack_open(get), headers=readonly,
        workspace=h(b"other workspace")).status == 404
    assert call(service, method="GET", headers=readonly).status == 405
    assert call(gate(None), body=encode_pack_open(get), headers=readonly) \
        .status == 405


def test_gate_accepts_async_issuer_and_fails_closed_on_issuer_faults():
    opened = PackOpen("GET", OID, 100, 10, 20)
    body, headers = encode_pack_open(opened), bearer(peer_capability.READ_ONLY)
    calls = []

    async def asynchronous(member, request, trusted_now):
        calls.append((member, request, trusted_now))
        return scoped_for(request)

    assert call(gate(asynchronous), body=body, headers=headers).status == 200
    assert calls == [(MEMBER, opened, NOW)]

    good = scoped_for(opened)

    def raises(*_args):
        raise OSError("provider signer unavailable")

    bad_issuers = (
        lambda *_args: object(),
        lambda *_args: replace(good, method="PUT"),
        lambda *_args: replace(
            good, url="https://bucket.example/pack/" + h(b"wrong")),
        lambda *_args: replace(good, headers=()),
        lambda *_args: replace(good, expires_at_ms=NOW),
        raises,
    )
    assert [call(gate(issuer), body=body, headers=headers).status
            for issuer in bad_issuers] == [503] * len(bad_issuers)


def test_gate_and_transport_enforce_the_pack_open_request_limit():
    opened = PackOpen("GET", OID, 100)
    body = encode_pack_open(opened)
    headers = bearer(peer_capability.READ_ONLY)
    issuer = lambda _member, request, _now: scoped_for(request)

    assert HttpGate.request_limit("POST", "/pack/open") \
        == MAX_PACK_OPEN_BYTES
    assert HttpGate.request_limit("GET", "/pack/open") == 0
    assert call(
        gate(issuer, max_request_bytes=len(body)),
        body=body, headers=headers).status == 200
    assert call(
        gate(issuer, max_request_bytes=len(body) - 1),
        body=body, headers=headers).status == 413
    assert call(
        gate(issuer), body=b" " * MAX_PACK_OPEN_BYTES,
        headers=headers).status == 400
    assert call(
        gate(issuer), body=b" " * (MAX_PACK_OPEN_BYTES + 1),
        headers=headers).status == 413


def test_gate_rejects_noncallable_issuer_at_composition_time():
    with pytest.raises(ValueError, match="pack OPEN issuer"):
        gate(object())
