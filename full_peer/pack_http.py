"""FullPeer's streaming implementation of immutable-object HTTP transfer.

The shared :class:`core.http.HttpGate` authenticates ``/obj/open`` and
``/pack/open`` and confines the returned metadata. This host-only module owns
short-lived exact tickets and streams ``obj/`` or ``pack/`` files; no large
body enters a core ``Response`` or ``ObjectStore.get_bounded``.
"""
import asyncio
import base64
from dataclasses import dataclass
import hashlib
import hmac
import os
import tempfile
import time
from urllib.parse import urlencode, urlsplit

from core import peer_capability
from core.fact import canon
from core.http import AsyncFromSyncReader, HttpGate, Response
from core.http_stdlib import handler_for as core_handler_for
from core.limits import DIRECT_STREAM_CHUNK_BYTES, PayloadTooLarge, decode_json
from core.pack_access import (
    MAX_PACK_BYTES,
    MAX_SCOPED_TTL_MS,
    ObjectOpen,
    PackOpen,
    ScopedRequest,
    object_key,
    pack_key,
)
from core.shape import valid_fid


STREAM_CHUNK_BYTES = DIRECT_STREAM_CHUNK_BYTES
DEFAULT_TICKET_TTL_MS = 30_000
MAX_TICKET_BYTES = 1024
_TICKET_DOMAIN = b"poc16-full-peer-pack-ticket-v1\0"
_OBJECT_TICKET_DOMAIN = b"poc16-full-peer-object-ticket-v1\0"
_TEMP_PREFIX = ".pack-upload-"
_TEMP_SUFFIX = ".tmp"


def now_ms():
    return int(time.time() * 1000)


@dataclass(frozen=True, slots=True)
class _Ticket:
    workspace: str
    member: str
    opened: ObjectOpen | PackOpen
    expires_at_ms: int


class FullPeerPackService:
    """Issue exact tickets and stream immutable objects from local disk."""

    def __init__(
            self, peer, ticket_secret, *, clock=now_ms,
            ttl_ms=DEFAULT_TICKET_TTL_MS,
            read_opener=open):
        if not isinstance(ticket_secret, bytes) or len(ticket_secret) < 32 \
                or not callable(clock) or not callable(read_opener) \
                or type(ttl_ms) is not int \
                or not 0 < ttl_ms <= MAX_SCOPED_TTL_MS:
            raise ValueError("FullPeer object service options")
        self.peer = peer
        self.ticket_secret = ticket_secret
        self.clock = clock
        self.ttl_ms = ttl_ms
        self.read_opener = read_opener

    def _root(self, workspace):
        store = self.peer.store(workspace)
        root = getattr(store, "root", None)
        if not isinstance(root, str) or not root:
            raise ValueError("FullPeer streaming needs filesystem storage")
        return root

    def _directory(self, workspace):
        directory = os.path.join(self._root(workspace), "pack")
        os.makedirs(directory, exist_ok=True)
        return directory

    def _path(self, workspace, oid):
        return os.path.join(self._directory(workspace), pack_key(oid)[5:])

    def _object_path(self, workspace, oid):
        return os.path.join(
            self._root(workspace), *object_key(oid).split("/"))

    def _encode_payload(self, value, domain):
        payload = canon(value)
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
        mac = hmac.new(
            self.ticket_secret, domain + payload,
            hashlib.sha256).hexdigest()
        return encoded.decode("ascii") + "." + mac

    def _decode_payload(self, token, domain):
        try:
            if not isinstance(token, str) \
                    or len(token) > 2 * MAX_TICKET_BYTES:
                raise ValueError
            encoded, mac = token.split(".", 1)
            padded = encoded + "=" * (-len(encoded) % 4)
            payload = base64.b64decode(
                padded, altchars=b"-_", validate=True)
            expected = hmac.new(
                self.ticket_secret, domain + payload,
                hashlib.sha256).hexdigest()
            value = decode_json(payload, MAX_TICKET_BYTES, "pack ticket")
            if not hmac.compare_digest(expected, mac) \
                    or base64.urlsafe_b64encode(payload).rstrip(
                        b"=").decode("ascii") != encoded \
                    or canon(value) != payload \
                    or not isinstance(value, list):
                raise ValueError
            return value
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("stream ticket") from error

    def _encode_ticket(self, ticket):
        return self._encode_payload([
            ticket.workspace,
            ticket.member,
            ticket.expires_at_ms,
            ticket.opened.method,
            ticket.opened.oid,
            ticket.opened.pack_bytes,
            ticket.opened.offset,
            ticket.opened.length,
        ], _TICKET_DOMAIN)

    def _decode_ticket(self, token):
        try:
            value = self._decode_payload(token, _TICKET_DOMAIN)
            if len(value) != 8:
                raise ValueError
            return _Ticket(
                value[0], value[1],
                PackOpen(value[3], value[4], value[5], value[6], value[7]),
                value[2],
            )
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("pack ticket") from error

    def _encode_object_ticket(self, ticket):
        return self._encode_payload([
            ticket.workspace,
            ticket.member,
            ticket.expires_at_ms,
            ticket.opened.oid,
            ticket.opened.max_bytes,
        ], _OBJECT_TICKET_DOMAIN)

    def _decode_object_ticket(self, token):
        try:
            value = self._decode_payload(token, _OBJECT_TICKET_DOMAIN)
            if len(value) != 5:
                raise ValueError
            return _Ticket(
                value[0], value[1], ObjectOpen(value[3], value[4]), value[2])
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("object ticket") from error

    @staticmethod
    def _validated_origin(origin):
        parsed = urlsplit(origin)
        if parsed.scheme != "http" or not parsed.netloc \
                or parsed.path or parsed.query or parsed.fragment \
                or parsed.username is not None or parsed.password is not None:
            raise ValueError("FullPeer pack origin")
        return origin

    def issue(self, workspace, member, opened, trusted_now, origin):
        """Issue one exact pack operation after the common gate authorizes."""
        if not self.peer.has_workspace(workspace) \
                or not valid_fid(member) \
                or not isinstance(opened, PackOpen) \
                or type(trusted_now) is not int:
            raise ValueError("FullPeer pack ticket binding")
        self._directory(workspace)
        origin = self._validated_origin(origin)
        expires = trusted_now + self.ttl_ms
        token = self._encode_ticket(_Ticket(
            workspace, member, opened, expires))
        if opened.method == "PUT":
            headers = (
                ("content-length", str(opened.pack_bytes)),
                ("if-none-match", "*"),
            )
        elif opened.offset is None:
            headers = ()
        else:
            headers = ((
                "range",
                f"bytes={opened.offset}-{opened.offset + opened.length - 1}",
            ),)
        return ScopedRequest(
            opened.method,
            f"{origin}/{pack_key(opened.oid)}?{urlencode({'ticket': token})}",
            headers,
            expires,
        )

    def issue_object(
            self, workspace, member, opened, trusted_now, origin):
        """Issue one read-only content-addressed object operation."""
        if not self.peer.has_workspace(workspace) \
                or not valid_fid(member) \
                or not isinstance(opened, ObjectOpen) \
                or type(trusted_now) is not int:
            raise ValueError("FullPeer object ticket binding")
        self._object_path(workspace, opened.oid)
        origin = self._validated_origin(origin)
        expires = trusted_now + self.ttl_ms
        token = self._encode_object_ticket(_Ticket(
            workspace, member, opened, expires))
        return ScopedRequest(
            "GET",
            f"{origin}/{object_key(opened.oid)}?"
            f"{urlencode({'ticket': token})}",
            (),
            expires,
        )

    def _resolve(self, token, method, oid, trusted_now):
        ticket = self._decode_ticket(token)
        if ticket.expires_at_ms <= trusted_now \
                or ticket.opened.method != method \
                or ticket.opened.oid != oid:
            raise ValueError("pack ticket scope")
        return ticket

    def _resolve_object(self, token, method, oid, trusted_now):
        ticket = self._decode_object_ticket(token)
        if ticket.expires_at_ms <= trusted_now \
                or method != "GET" or ticket.opened.oid != oid:
            raise ValueError("object ticket scope")
        return ticket

    @staticmethod
    def _send(handler, status, *, length=0, headers=()):
        handler.send_response(status)
        values = {
            "Cache-Control": "no-store",
            "Content-Length": str(length),
            **dict(headers),
        }
        for name, value in values.items():
            handler.send_header(name, value)
        handler.end_headers()

    @classmethod
    def _error(cls, handler, status):
        handler.close_connection = True
        return cls._finish(handler, status)

    @classmethod
    def _finish(cls, handler, status, *, length=0, headers=()):
        try:
            return cls._send(
                handler, status, length=length, headers=headers)
        except (BrokenPipeError, ConnectionResetError, OSError):
            handler.close_connection = True

    def _stream(self, handler, source, status, offset, length, headers):
        try:
            source.seek(offset)
            self._send(handler, status, length=length, headers=headers)
            remaining = length
            while remaining:
                maximum = min(STREAM_CHUNK_BYTES, remaining)
                chunk = source.read(maximum)
                if not chunk or len(chunk) > maximum:
                    handler.close_connection = True
                    return
                handler.wfile.write(chunk)
                remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            handler.close_connection = True
        finally:
            source.close()

    def _matches(self, path, opened):
        try:
            if os.stat(path).st_size != opened.pack_bytes:
                return False
            digest = hashlib.sha256()
            with self.read_opener(path, "rb") as source:
                while True:
                    chunk = source.read(STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    if len(chunk) > STREAM_CHUNK_BYTES:
                        raise ValueError("pack reader exceeded chunk bound")
                    digest.update(chunk)
            return digest.hexdigest() == opened.oid
        except FileNotFoundError:
            return False

    def _put(self, handler, ticket):
        opened = ticket.opened
        if handler.headers.get("Transfer-Encoding") \
                or handler.headers.get("Range") is not None \
                or handler.headers.get("If-None-Match") != "*" \
                or handler.headers.get("Content-Length") \
                != str(opened.pack_bytes):
            return self._error(handler, 403)
        handler.close_connection = True
        directory = self._directory(ticket.workspace)
        final = self._path(ticket.workspace, opened.oid)
        fd, temporary = tempfile.mkstemp(
            dir=directory, prefix=_TEMP_PREFIX, suffix=_TEMP_SUFFIX)
        status = 503
        try:
            digest = hashlib.sha256()
            remaining = opened.pack_bytes
            with os.fdopen(fd, "wb") as target:
                while remaining:
                    chunk = handler.rfile.read(
                        min(STREAM_CHUNK_BYTES, remaining))
                    if not chunk:
                        status = 400
                        break
                    if len(chunk) > min(STREAM_CHUNK_BYTES, remaining):
                        raise ValueError("pack request exceeded chunk bound")
                    target.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                target.flush()
                os.fsync(target.fileno())
            if remaining == 0:
                if digest.hexdigest() != opened.oid:
                    status = 400
                else:
                    try:
                        os.link(temporary, final)
                        status = 201
                    except FileExistsError:
                        status = 204 if self._matches(
                            final, opened) else 409
        except (OSError, ValueError):
            status = 503
        finally:
            try:
                os.remove(temporary)
            except FileNotFoundError:
                pass
        return self._finish(handler, status)

    def _get(self, handler, ticket):
        opened = ticket.opened
        expected_range = None if opened.offset is None else (
            f"bytes={opened.offset}-{opened.offset + opened.length - 1}")
        if handler.headers.get("Range") != expected_range \
                or expected_range is None \
                and handler.headers.get("Range") is not None:
            return self._error(handler, 403)
        path = self._path(ticket.workspace, opened.oid)
        try:
            if os.stat(path).st_size != opened.pack_bytes:
                return self._error(handler, 409)
            source = self.read_opener(path, "rb")
        except FileNotFoundError:
            return self._error(handler, 404)
        except OSError:
            return self._error(handler, 503)
        offset = 0 if opened.offset is None else opened.offset
        length = opened.pack_bytes if opened.length is None else opened.length
        status = 200 if opened.offset is None else 206
        headers = [
            ("Accept-Ranges", "bytes"),
            ("Content-Type", "application/octet-stream"),
        ]
        if status == 206:
            headers.append((
                "Content-Range",
                f"bytes {offset}-{offset + length - 1}/{opened.pack_bytes}",
            ))
        return self._stream(
            handler, source, status, offset, length, headers)

    def _get_object(self, handler, ticket):
        opened = ticket.opened
        if handler.headers.get("Range") is not None \
                or handler.headers.get("Transfer-Encoding"):
            return self._error(handler, 403)
        path = self._object_path(ticket.workspace, opened.oid)
        try:
            size = os.stat(path).st_size
            if size > opened.max_bytes:
                return self._error(handler, 413)
            source = self.read_opener(path, "rb")
        except FileNotFoundError:
            return self._error(handler, 404)
        except OSError:
            return self._error(handler, 503)
        return self._stream(
            handler,
            source,
            200,
            0,
            size,
            (("Content-Type", "application/octet-stream"),),
        )

    def dispatch(self, handler, method, path, query):
        parts = path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "pack" \
                or not valid_fid(parts[1]):
            return self._error(handler, 404)
        if set(query) != {"ticket"}:
            return self._error(handler, 403)
        try:
            ticket = self._resolve(
                query["ticket"], method, parts[1], self.clock())
        except (TypeError, ValueError):
            return self._error(handler, 403)
        if method == "PUT":
            return self._put(handler, ticket)
        if method == "GET":
            return self._get(handler, ticket)
        return self._error(handler, 405)

    def dispatch_object(self, handler, method, path, query):
        parts = path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "obj" \
                or not valid_fid(parts[1]):
            return self._error(handler, 404)
        if set(query) != {"ticket"}:
            return self._error(handler, 403)
        try:
            ticket = self._resolve_object(
                query["ticket"], method, parts[1], self.clock())
        except (TypeError, ValueError):
            return self._error(handler, 403)
        return self._get_object(handler, ticket)


class _PackHandlerMixin:
    """Add streaming bytes without duplicating ordinary gate routes."""

    pack_service = None

    def _origin(self):
        host = self.headers.get("Host", "")
        parsed = urlsplit("http://" + host)
        if not host or parsed.netloc != host or parsed.hostname is None \
                or parsed.username is not None or parsed.password is not None:
            raise ValueError("HTTP Host")
        return "http://" + host

    def _open(self, method, path, query):
        try:
            body = self._body(method, path)
        except PayloadTooLarge:
            return self._send(Response(413))
        except ValueError:
            return self._send(Response(400))
        workspace = query.get("ws", "")
        if not self.peer.has_workspace(workspace):
            return self._send(Response(404))
        try:
            origin = self._origin()
            gate = HttpGate(
                AsyncFromSyncReader(self.peer.store(workspace)),
                workspace,
                self.secret,
                self.pack_service.clock,
                sync_profile=self.sync_profile,
                object_open=lambda member, opened, trusted_now:
                    self.pack_service.issue_object(
                        workspace, member, opened, trusted_now, origin),
                pack_open=lambda member, opened, trusted_now:
                    self.pack_service.issue(
                        workspace, member, opened, trusted_now, origin),
            )
            response = asyncio.run(gate.handle(
                method, path, query, dict(self.headers), body))
        except Exception:
            response = Response(503)
        return self._send(response)

    def _dispatch(self, method):
        path, query = self._request()
        if path in {"/obj/open", "/pack/open"}:
            return self._open(method, path, query)
        if path.startswith("/obj/") and "ticket" in query:
            return self.pack_service.dispatch_object(
                self, method, path, query)
        if path.startswith("/pack/"):
            return self.pack_service.dispatch(
                self, method, path, query)
        return super()._dispatch(method)


def handler_for(
        peer, secret, sync_profile=peer_capability.FULL, *,
        gate_options=None, pack_service=None):
    """Bind the ordinary FullPeer gate plus its streaming pack data plane."""
    base = core_handler_for(
        peer, secret, sync_profile, gate_options=gate_options)
    service = FullPeerPackService(peer, secret) \
        if pack_service is None else pack_service
    if not isinstance(service, FullPeerPackService):
        raise TypeError("FullPeer pack service")
    return type(
        "BoundFullPeerPackHandler",
        (_PackHandlerMixin, base),
        {"pack_service": service},
    )


__all__ = (
    "DEFAULT_TICKET_TTL_MS",
    "MAX_TICKET_BYTES",
    "STREAM_CHUNK_BYTES",
    "FullPeerPackService",
    "handler_for",
)
