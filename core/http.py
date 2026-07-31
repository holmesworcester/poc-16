"""The one database-free HTTP peer-data gate.

``HttpGate`` owns every route and authorization decision. Provider runtimes
call it directly; :mod:`core.http_stdlib` binds the same gate to ordinary HTTP
bytes for a full peer. Iroh may wrap those bytes later, but it must not
acquire another route table.
"""
import base64
from dataclasses import dataclass, field
import json
import re

from . import peer_capability
from .crypto import h, seal_to
from .grants import check_token, make_token
from .ingress import PermanentIngressRejection
from .limits import (
    MAX_INVITE_BYTES,
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_PAGE_REQUEST_BYTES,
    MAX_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    MAX_ROOT_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)
from .repository_reader import RepositoryReader, RepositoryRootError
from .object_store import MAX_INVITE_ID_BYTES

OID_RE = re.compile(r"^[0-9a-f]{64}$")
INVITE_RE = re.compile(
    rf"^[a-z0-9._-]{{1,{MAX_INVITE_ID_BYTES}}}$")


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""
    headers: dict = field(default_factory=dict)


class AsyncFromSyncReader:
    """Expose a blocking reader to the one async gate used by Lambda."""

    def __init__(self, reader):
        self.reader = reader

    async def get_bounded(self, key, max_bytes):
        return self.reader.get_bounded(key, max_bytes)


class HttpGate:
    """One-workspace peer authorization and immutable-object service.

    The gate is async because a Cloudflare R2 binding is async. Lambda wraps
    its synchronous SDK adapter with :class:`AsyncFromSyncReader`, so both
    deployments execute this same route and authorization implementation.
    Supplying a receiver enables writes through ``RepositoryApplier``;
    omitting it yields the hosted read-only capability.
    """

    def __init__(
            self, store, workspace, secret, now, receiver=None,
            *, sync_profile=peer_capability.READ_ONLY,
            max_request_bytes=MAX_MINT_REQUEST_BYTES,
            max_root_bytes=MAX_ROOT_BYTES,
            max_object_bytes=MAX_OBJECT_BYTES,
            max_batch_count=PAGE_BATCH,
            max_batch_bytes=MAX_PAGE_BATCH_BYTES,
            max_mint_fetches=MAX_MINT_FETCHES,
            max_mint_fetch_bytes=MAX_MINT_FETCH_BYTES,
            grant_ttl_ms=60_000,
            seal=seal_to):
        if not isinstance(workspace, str) or not workspace:
            raise ValueError("workspace")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("grant secret")
        if not callable(seal):
            raise ValueError("grant sealer")
        self.store, self.workspace = store, workspace
        self.receiver = receiver
        self.secret, self.now = secret, now
        if sync_profile is not None \
                and not peer_capability.known(sync_profile):
            raise ValueError("sync profile")
        bounded = (
            ("request bytes", max_request_bytes, MAX_MINT_REQUEST_BYTES),
            ("root bytes", max_root_bytes, MAX_ROOT_BYTES),
            ("object bytes", max_object_bytes, MAX_OBJECT_BYTES),
            ("batch count", max_batch_count, PAGE_BATCH),
            ("batch bytes", max_batch_bytes, MAX_PAGE_BATCH_BYTES),
        )
        if any(
                type(value) is not int or not 0 < value <= ceiling
                for _, value, ceiling in bounded) or any(
                type(value) is not int or not 0 <= value <= ceiling
                for value, ceiling in (
                    (max_mint_fetches, MAX_MINT_FETCHES),
                    (max_mint_fetch_bytes, MAX_MINT_FETCH_BYTES),
                )):
            raise ValueError("HTTP gate limits")
        if max_object_bytes < MAX_REPOSITORY_OBJECT_BYTES:
            raise ValueError("HTTP gate cannot serve canonical facts")
        self.sync_profile = sync_profile
        self.max_request_bytes = max_request_bytes
        self.max_root_bytes = max_root_bytes
        self.max_object_bytes = max_object_bytes
        self.max_batch_count = max_batch_count
        self.max_batch_bytes = max_batch_bytes
        self.max_mint_fetches = max_mint_fetches
        self.max_mint_fetch_bytes = max_mint_fetch_bytes
        self.grant_ttl_ms = grant_ttl_ms
        self.seal = seal

    @staticmethod
    def _header(headers, name):
        name = name.lower()
        return next(
            (value for key, value in headers.items()
             if key.lower() == name),
            "",
        )

    @staticmethod
    def _json(status, value, headers=None):
        body = json.dumps(
            value, sort_keys=True, separators=(",", ":")).encode()
        return Response(
            status, body,
            {"Content-Type": "application/json", **(headers or {})},
        )

    def _workspace(self, query):
        value = query.get("ws")
        if isinstance(value, (list, tuple)):
            value = value[0] if len(value) == 1 else None
        return value == self.workspace

    def _member(self, headers, trusted_now, *, require_push=False):
        return check_token(
            self.secret,
            self._header(headers, "Authorization"),
            self.workspace,
            trusted_now=trusted_now,
            require_push=require_push,
        )

    async def _get(self, key, max_bytes):
        """Fetch one exact transport key without interpreting repository state."""
        value = await self.store.get_bounded(key, max_bytes)
        if value is not None and len(value) > max_bytes:
            raise PayloadTooLarge("object read exceeds byte limit")
        return value

    async def _root(self):
        return await self._get("root", self.max_root_bytes)

    async def _reader(self):
        """Open one root-only Reader for readiness or root presentation."""
        root = await self._root()
        return RepositoryReader(
            self.workspace, root, lambda _oid: None,
        ) if root else None

    @staticmethod
    def _decode_mint(body, workspace):
        request = decode_json(
            body, MAX_MINT_REQUEST_BYTES, "mint request")
        if not isinstance(request, dict) \
                or set(request) != {"ws", "pile"} \
                or request["ws"] != workspace \
                or not isinstance(request["pile"], str):
            raise ValueError("mint request")
        return base64.b64decode(request["pile"], validate=True)

    async def _mint(self, body, trusted_now):
        if not isinstance(body, bytes) or len(body) > self.max_request_bytes:
            return Response(413)
        try:
            pile = self._decode_mint(body, self.workspace)
        except (TypeError, ValueError, json.JSONDecodeError):
            return Response(400)
        try:
            root = await self._root()
            if not root:
                return Response(503)
        except Exception:
            return Response(503)
        fetch_error = None

        async def fetch(oid):
            nonlocal fetch_error
            try:
                return await self._get(
                    "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)
            except Exception as error:
                fetch_error = error
                return None

        try:
            grant = await RepositoryReader.mint_awaited(
                self.workspace,
                root,
                fetch,
                pile,
                trusted_now,
                max_unique_fetches=self.max_mint_fetches,
                max_fetch_bytes=self.max_mint_fetch_bytes,
            )
        except RepositoryRootError:
            return Response(503)
        except Exception:
            return Response(503 if fetch_error is not None else 403)
        if fetch_error is not None:
            return Response(503)
        if grant is None:
            return Response(403)
        public, verb = grant
        token = make_token(
            self.secret, public, self.workspace, verb,
            capability=self.sync_profile,
            issued_at=trusted_now, ttl_ms=self.grant_ttl_ms)
        response = {
            "etag": h(root),
            "grant": base64.b64encode(
                self.seal(public, token.encode())).decode(),
            "root": base64.b64encode(root).decode(),
        }
        if self.sync_profile is not None:
            response["cap"] = self.sync_profile
        return self._json(200, response)

    @staticmethod
    def _decode_batch(body):
        oids = decode_json(
            body, MAX_MINT_REQUEST_BYTES, "page request")
        if not isinstance(oids, list) or not all(
                isinstance(oid, str) and OID_RE.fullmatch(oid)
                for oid in oids):
            raise ValueError("object batch")
        return oids

    async def _batch(self, body):
        if not isinstance(body, bytes) or len(body) > min(
                self.max_request_bytes, MAX_PAGE_REQUEST_BYTES):
            return Response(413)
        try:
            oids = self._decode_batch(body)
            if len(oids) > self.max_batch_count:
                return Response(413)
        except (TypeError, ValueError, json.JSONDecodeError):
            return Response(400)
        values, encoded_bytes, fetched = [], 2, {}
        try:
            for index, oid in enumerate(oids):
                if oid not in fetched:
                    fetched[oid] = await self._get(
                        "obj/" + oid, self.max_object_bytes)
                raw = fetched[oid]
                if raw is not None and h(raw) != oid:
                    return Response(503)
                item_bytes = 4 if raw is None \
                    else 2 + 4 * ((len(raw) + 2) // 3)
                encoded_bytes += item_bytes + (1 if index else 0)
                if encoded_bytes > self.max_batch_bytes:
                    return Response(413)
                values.append(
                    base64.b64encode(raw).decode()
                    if raw is not None else None)
        except PayloadTooLarge:
            return Response(413)
        except Exception:
            return Response(503)
        return self._json(200, values)

    @staticmethod
    def _read_only_path(path):
        return any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in ("/pile", "/ctl")
        )

    @staticmethod
    def public_response(method, path):
        """Return a workspace-independent peer response, if one exists."""
        if method.upper() == "GET" and "/" + path.strip("/") == "/healthz":
            return HttpGate._json(200, {"ok": True})
        return None

    @staticmethod
    def request_limit(method, path):
        """Maximum request bytes before any transport reads the body."""
        method = method.upper()
        path = "/" + path.strip("/")
        if method == "PUT" and path.startswith("/pile/"):
            return MAX_PILE_BYTES
        if method == "POST" and path == "/mint":
            return MAX_MINT_REQUEST_BYTES
        if method == "POST" and path == "/page":
            return MAX_PAGE_REQUEST_BYTES
        return 0

    async def handle(self, method, path, query=None, headers=None, body=b""):
        """Return one transport-neutral response; provider failures fail shut."""
        method, query, headers = method.upper(), query or {}, headers or {}
        path = "/" + path.strip("/")
        public = self.public_response(method, path)
        if public is not None:
            return public
        if path == "/readyz" and method == "GET":
            try:
                if await self._reader() is None:
                    raise ValueError("root readiness")
            except Exception:
                return self._json(503, {"ok": False})
            return self._json(200, {"ok": True})
        if not self._workspace(query):
            return Response(404)
        trusted_now = self.now()
        if path == "/mint" and method == "POST":
            return await self._mint(body, trusted_now)
        if path.startswith("/invite/") and method == "GET":
            invite = path.removeprefix("/invite/")
            if not INVITE_RE.fullmatch(invite):
                return Response(404)
            try:
                raw = await self._get(
                    "invite/" + invite, MAX_INVITE_BYTES)
            except PayloadTooLarge:
                return Response(413)
            except Exception:
                return Response(503)
            if raw is None:
                return Response(404)
            return Response(
                200, raw, {
                    "Cache-Control": "no-store",
                    "Content-Type": "application/octet-stream",
                })
        if path.startswith("/ctl"):
            return Response(405)
        if method == "PUT" and path.startswith("/pile/"):
            if self.receiver is None:
                return Response(405)
            member = self._member(
                headers, trusted_now, require_push=True)
            if not member:
                return Response(401)
            parts = path.strip("/").split("/")
            if len(parts) != 3 or parts[:2] != ["pile", member] \
                    or not OID_RE.fullmatch(parts[2]):
                return Response(403)
            if not isinstance(body, bytes) or len(body) > MAX_PILE_BYTES \
                    or h(body) != parts[2]:
                return Response(400)
            try:
                result = await self.receiver.receive_pile(member, body)
            except PermanentIngressRejection:
                return Response(400)
            except Exception:
                return Response(503)
            status = getattr(result, "status", None)
            if status in {"applied", "noop"}:
                return Response(204)
            if status == "rejected":
                return Response(400)
            return Response(503)
        if self.receiver is None and self._read_only_path(path):
            return Response(405)
        if not self._member(headers, trusted_now):
            return Response(401)
        if path == "/root" and method == "GET":
            try:
                reader = await self._reader()
                root = reader.root_bytes if reader is not None else b""
            except Exception:
                return Response(503)
            etag = reader.etag if reader is not None else h(root)
            if self._header(headers, "If-None-Match") == etag:
                return Response(304)
            return Response(
                200, root, {
                    "Cache-Control": "no-store",
                    "Content-Type": "application/octet-stream",
                    "ETag": etag,
                })
        if path == "/page" and method == "POST":
            return await self._batch(body)
        if path.startswith("/page/") and method == "GET":
            oid = path.removeprefix("/page/")
            if not OID_RE.fullmatch(oid):
                return Response(404)
            try:
                raw = await self._get(
                    "obj/" + oid, self.max_object_bytes)
            except PayloadTooLarge:
                return Response(413)
            except Exception:
                return Response(503)
            if raw is None:
                return Response(404)
            if h(raw) != oid:
                return Response(503)
            return Response(
                200, raw, {
                    "Cache-Control": "no-store",
                    "Content-Type": "application/octet-stream",
                })
        return Response(404)
