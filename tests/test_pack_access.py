"""Pack transfer control stays bounded while bytes use ordinary HTTP."""
import asyncio
from dataclasses import replace
import json

import pytest

from core import peer_capability
from core.crypto import h
from core.fact import canon
from core.grants import make_token
from core.http import HttpGate
from core.limits import MAX_PILE_BYTES, PayloadTooLarge
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_PACK_OPEN_BYTES,
    MAX_SCOPED_HEADER_VALUE_BYTES,
    MAX_SCOPED_HEADERS,
    MAX_SCOPED_REQUEST_BYTES,
    MAX_SCOPED_TTL_MS,
    MAX_SCOPED_URL_BYTES,
    InvalidPackAccess,
    PackOpen,
    ScopedRequest,
    confine_scoped_request,
    decode_pack_open,
    decode_scoped_request,
    encode_pack_open,
    encode_scoped_request,
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


def gate(issuer, **limits):
    return HttpGate(
        object(), WORKSPACE, SECRET, lambda: NOW,
        pack_open=issuer, **limits)


def test_pack_open_codec_has_one_portable_exact_bound():
    assert MAX_PACK_BYTES == MAX_LAYOUT_PACK_BYTES
    assert pack_key(OID) == "pack/" + OID

    whole_put = PackOpen("PUT", OID, MAX_PACK_BYTES)
    whole_get = PackOpen("GET", OID, MAX_PACK_BYTES)
    ranged = PackOpen(
        "GET", OID, MAX_PACK_BYTES,
        MAX_PACK_BYTES - MAX_PILE_BYTES, MAX_PILE_BYTES)
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
    ("GET", OID, 1, 0, MAX_PILE_BYTES + 1),
    ("GET", OID, MAX_PILE_BYTES, 1, MAX_PILE_BYTES),
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


def test_gate_uses_normal_grants_and_requires_push_only_for_put():
    calls = []

    def issuer(member, opened, trusted_now):
        calls.append((member, opened, trusted_now))
        return scoped_for(opened)

    service = gate(issuer)
    get = PackOpen("GET", OID, 100, 10, 20)
    put = PackOpen("PUT", OID, 100)
    readonly = bearer(peer_capability.READ_ONLY)
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
        service, body=encode_pack_open(put), headers=full).status == 200
    assert calls[-1] == (MEMBER, put, NOW)

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
