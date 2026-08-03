"""Bounded control metadata for immutable pack HTTP transfer.

Pack bodies never pass through these codecs.  A caller names one exact pack
operation and a provider-specific issuer returns only the ordinary HTTP
request needed to perform it.  :func:`confine_scoped_request` keeps issuer
mistakes from widening method, object, range, create-only, or lifetime scope.
"""
from dataclasses import dataclass
import re
from urllib.parse import urlsplit

from .fact import canon
from .limits import MAX_PILE_BYTES, MIB, PayloadTooLarge, decode_json
from .shape import valid_fid


PACK_OPEN_FORMAT = "poc16-pack-open-v1"
SCOPED_REQUEST_FORMAT = "poc16-scoped-request-v1"
PACK_PREFIX = "pack"

MAX_PACK_BYTES = 95 * MIB
MAX_PACK_OPEN_BYTES = 1024
MAX_SCOPED_REQUEST_BYTES = 16 * 1024
MAX_SCOPED_URL_BYTES = 8 * 1024
MAX_SCOPED_HEADERS = 32
MAX_SCOPED_HEADER_NAME_BYTES = 128
MAX_SCOPED_HEADER_VALUE_BYTES = 4 * 1024
MAX_SCOPED_TTL_MS = 60_000
MAX_SAFE_INTEGER = (1 << 53) - 1

_METHODS = frozenset(("GET", "PUT"))
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")


class InvalidPackAccess(ValueError):
    """Pack control bytes or an issued request exceed their exact scope."""


def _bounded_ascii(value, maximum, *, allow_empty=False, allow_space=True):
    return isinstance(value, str) \
        and (allow_empty or value) \
        and len(value) <= maximum \
        and all(
            (32 if allow_space else 33) <= ord(character) < 127
            for character in value)


@dataclass(frozen=True, slots=True)
class PackOpen:
    """One exact whole-pack or single-pile-range operation."""

    method: str
    oid: str
    pack_bytes: int
    offset: int | None = None
    length: int | None = None

    def __post_init__(self):
        ranged = self.offset is not None or self.length is not None
        if self.method not in _METHODS or not valid_fid(self.oid) \
                or type(self.pack_bytes) is not int \
                or not 1 <= self.pack_bytes <= MAX_PACK_BYTES \
                or self.method == "PUT" and ranged \
                or ranged and (
                    type(self.offset) is not int
                    or type(self.length) is not int
                    or self.offset < 0
                    or not 1 <= self.length <= MAX_PILE_BYTES
                    or self.offset + self.length > self.pack_bytes
                ):
            raise InvalidPackAccess("pack OPEN")


@dataclass(frozen=True, slots=True)
class ScopedRequest:
    """One provider-issued ordinary HTTP request, without body bytes."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    expires_at_ms: int

    def __post_init__(self):
        if not _bounded_ascii(
                    self.url, MAX_SCOPED_URL_BYTES, allow_space=False) \
                or not isinstance(self.headers, tuple) \
                or len(self.headers) > MAX_SCOPED_HEADERS:
            raise InvalidPackAccess("scoped request")
        try:
            parsed = urlsplit(self.url)
        except (TypeError, ValueError) as error:
            raise InvalidPackAccess("scoped request URL") from error
        names = []
        for pair in self.headers:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise InvalidPackAccess("scoped request headers")
            name, value = pair
            if not isinstance(name, str) or not isinstance(value, str) \
                    or name != name.lower() \
                    or _HEADER_NAME.fullmatch(name) is None \
                    or not _bounded_ascii(
                        name, MAX_SCOPED_HEADER_NAME_BYTES) \
                    or not _bounded_ascii(
                        value, MAX_SCOPED_HEADER_VALUE_BYTES,
                        allow_empty=True):
                raise InvalidPackAccess("scoped request headers")
            names.append(name)
        if self.method not in _METHODS \
                or parsed.scheme not in {"http", "https"} \
                or not parsed.netloc or parsed.username is not None \
                or parsed.password is not None or parsed.fragment \
                or names != sorted(names) \
                or len(set(names)) != len(names) \
                or type(self.expires_at_ms) is not int \
                or not 1 <= self.expires_at_ms <= MAX_SAFE_INTEGER:
            raise InvalidPackAccess("scoped request")


def pack_key(oid):
    if not valid_fid(oid):
        raise InvalidPackAccess("pack OID")
    return f"{PACK_PREFIX}/{oid}"


def pack_open_document(value):
    if not isinstance(value, PackOpen):
        raise InvalidPackAccess("pack OPEN")
    document = {
        "format": PACK_OPEN_FORMAT,
        "method": value.method,
        "oid": value.oid,
        "pack_bytes": value.pack_bytes,
    }
    if value.offset is not None:
        document.update(offset=value.offset, length=value.length)
    return document


def scoped_request_document(value):
    if not isinstance(value, ScopedRequest):
        raise InvalidPackAccess("scoped request")
    return {
        "expires_at_ms": value.expires_at_ms,
        "format": SCOPED_REQUEST_FORMAT,
        "headers": [list(pair) for pair in value.headers],
        "method": value.method,
        "url": value.url,
    }


def _encode(document, maximum, label):
    try:
        raw = canon(document)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidPackAccess(label) from error
    if len(raw) > maximum:
        raise PayloadTooLarge(f"{label} too large")
    return raw


def _decode(raw, maximum, label):
    try:
        value = decode_json(raw, maximum, label)
        if canon(value) != raw:
            raise ValueError("noncanonical")
        return value
    except PayloadTooLarge:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise InvalidPackAccess(label) from error


def encode_pack_open(value):
    return _encode(
        pack_open_document(value), MAX_PACK_OPEN_BYTES, "pack OPEN")


def decode_pack_open(raw):
    value = _decode(raw, MAX_PACK_OPEN_BYTES, "pack OPEN")
    try:
        if not isinstance(value, dict) \
                or value.get("format") != PACK_OPEN_FORMAT \
                or set(value) not in (
                    {"format", "method", "oid", "pack_bytes"},
                    {"format", "method", "oid", "pack_bytes",
                     "offset", "length"},
                ):
            raise ValueError("pack OPEN shape")
        result = PackOpen(
            value["method"], value["oid"], value["pack_bytes"],
            value.get("offset"), value.get("length"))
        if pack_open_document(result) != value:
            raise ValueError("pack OPEN shape")
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise InvalidPackAccess("pack OPEN") from error


def encode_scoped_request(value):
    return _encode(
        scoped_request_document(value),
        MAX_SCOPED_REQUEST_BYTES,
        "scoped request",
    )


def decode_scoped_request(raw):
    value = _decode(
        raw, MAX_SCOPED_REQUEST_BYTES, "scoped request")
    try:
        if not isinstance(value, dict) or set(value) != {
                "expires_at_ms", "format", "headers", "method", "url"} \
                or value.get("format") != SCOPED_REQUEST_FORMAT \
                or not isinstance(value["headers"], list):
            raise ValueError("scoped request shape")
        result = ScopedRequest(
            value["method"], value["url"],
            tuple(
                tuple(pair) if isinstance(pair, list) else pair
                for pair in value["headers"]
            ),
            value["expires_at_ms"],
        )
        if scoped_request_document(result) != value:
            raise ValueError("scoped request shape")
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise InvalidPackAccess("scoped request") from error


def confine_scoped_request(
        opened, scoped, trusted_now, *, max_ttl_ms=MAX_SCOPED_TTL_MS):
    """Return ``scoped`` only when it cannot exceed ``opened`` authority."""
    if not isinstance(opened, PackOpen) \
            or not isinstance(scoped, ScopedRequest) \
            or type(trusted_now) is not int \
            or type(max_ttl_ms) is not int or max_ttl_ms <= 0 \
            or scoped.method != opened.method \
            or not trusted_now < scoped.expires_at_ms \
            <= trusted_now + max_ttl_ms:
        raise InvalidPackAccess("scoped request binding")
    try:
        path = urlsplit(scoped.url).path
    except ValueError as error:
        raise InvalidPackAccess("scoped request binding") from error
    if not path.endswith("/" + pack_key(opened.oid)):
        raise InvalidPackAccess("scoped request pack key")
    headers = dict(scoped.headers)
    expected_range = None if opened.offset is None else (
        f"bytes={opened.offset}-{opened.offset + opened.length - 1}")
    if opened.method == "PUT":
        if headers.get("content-length") != str(opened.pack_bytes) \
                or headers.get("if-none-match") != "*" \
                or "range" in headers:
            raise InvalidPackAccess("scoped create-only PUT")
    elif headers.get("range") != expected_range \
            or expected_range is None and "range" in headers:
        raise InvalidPackAccess("scoped GET range")
    return scoped


__all__ = (
    "MAX_PACK_BYTES",
    "MAX_PACK_OPEN_BYTES",
    "MAX_SCOPED_HEADERS",
    "MAX_SCOPED_REQUEST_BYTES",
    "MAX_SCOPED_TTL_MS",
    "InvalidPackAccess",
    "PackOpen",
    "ScopedRequest",
    "confine_scoped_request",
    "decode_pack_open",
    "decode_scoped_request",
    "encode_pack_open",
    "encode_scoped_request",
    "pack_key",
    "pack_open_document",
    "scoped_request_document",
)
