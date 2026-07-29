"""Database-free protocol gateway shared by Lambda and Cloudflare Workers."""
import base64
from dataclasses import dataclass, field
import json
import re

from core import manifest, mint, peer_capability
from core.crypto import h, seal_to
from core.grants import check_token, make_token

OID_RE = re.compile(r"^[0-9a-f]{64}$")
INVITE_RE = re.compile(r"^[a-zA-Z0-9._~-]{1,256}$")


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""
    headers: dict = field(default_factory=dict)


class AsyncFromSyncReader:
    """Expose a blocking reader to the one async gateway used by Lambda."""

    def __init__(self, reader):
        self.reader = reader

    async def get(self, key):
        return self.reader.get(key)

    async def has(self, key):
        return self.reader.has(key)


class Gateway:
    """One-workspace, read-only authorization and immutable-object service.

    The gateway is async because a Cloudflare R2 binding is async. Lambda wraps
    its synchronous SDK adapter with :class:`AsyncFromSyncReader`, so both
    deployments execute this same route and authorization implementation.
    """

    def __init__(
            self, store, workspace, secret, now,
            *, sync_profile=peer_capability.READ_ONLY,
            max_request_bytes=512 * 1024,
            max_root_bytes=1024 * 1024,
            max_object_bytes=8 * 1024 * 1024,
            max_batch_count=256,
            max_batch_bytes=4 * 1024 * 1024,
            max_mint_fetches=128,
            max_mint_fetch_bytes=4 * 1024 * 1024,
            grant_ttl_ms=60_000):
        if not isinstance(workspace, str) or not workspace:
            raise ValueError("workspace")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("grant secret")
        self.store, self.workspace = store, workspace
        self.secret, self.now = secret, now
        if not peer_capability.known(sync_profile):
            raise ValueError("sync profile")
        self.sync_profile = sync_profile
        self.max_request_bytes = max_request_bytes
        self.max_root_bytes = max_root_bytes
        self.max_object_bytes = max_object_bytes
        self.max_batch_count = max_batch_count
        self.max_batch_bytes = max_batch_bytes
        self.max_mint_fetches = max_mint_fetches
        self.max_mint_fetch_bytes = max_mint_fetch_bytes
        self.grant_ttl_ms = grant_ttl_ms

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

    def _member(self, headers, trusted_now):
        return check_token(
            self.secret,
            self._header(headers, "Authorization"),
            self.workspace,
            trusted_now=trusted_now,
        )

    async def _root(self):
        root = await self.store.get("root")
        if root is not None and len(root) > self.max_root_bytes:
            raise ValueError("root size")
        return root

    @staticmethod
    def _decode_mint(body, workspace):
        request = json.loads(body)
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
            if not root or manifest.decode_root(root).anchor != self.workspace:
                return Response(403)
            grant = await mint.async_stateless(
                pile, root,
                lambda oid: self.store.get("obj/" + oid),
                trusted_now,
                max_unique_fetches=self.max_mint_fetches,
                max_fetch_bytes=self.max_mint_fetch_bytes,
            )
        except Exception:
            return Response(403)
        if grant is None:
            return Response(403)
        public, verb = grant
        token = make_token(
            self.secret, public[:16], self.workspace, verb,
            capability=self.sync_profile,
            issued_at=trusted_now, ttl_ms=self.grant_ttl_ms)
        return self._json(200, {
            "cap": self.sync_profile,
            "etag": h(root),
            "grant": base64.b64encode(
                seal_to(public, token.encode())).decode(),
            "root": base64.b64encode(root).decode(),
        })

    @staticmethod
    def _decode_batch(body):
        oids = json.loads(body)
        if not isinstance(oids, list) or not all(
                isinstance(oid, str) and OID_RE.fullmatch(oid)
                for oid in oids):
            raise ValueError("object batch")
        return oids

    async def _batch(self, body):
        if not isinstance(body, bytes) or len(body) > self.max_request_bytes:
            return Response(413)
        try:
            oids = self._decode_batch(body)
            if len(oids) > self.max_batch_count:
                return Response(413)
        except (TypeError, ValueError, json.JSONDecodeError):
            return Response(400)
        values, encoded_bytes = [], 2
        try:
            for oid in oids:
                raw = await self.store.get("obj/" + oid)
                if raw is not None and (
                        len(raw) > self.max_object_bytes or h(raw) != oid):
                    return Response(503)
                value = base64.b64encode(raw).decode() \
                    if raw is not None else None
                encoded_bytes += 4 if value is None else len(value) + 2
                if encoded_bytes > self.max_batch_bytes:
                    return Response(413)
                values.append(value)
        except Exception:
            return Response(503)
        return self._json(200, values)

    @staticmethod
    def _read_only_path(path):
        return any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in ("/pile", "/poke", "/ctl")
        )

    async def handle(self, method, path, query=None, headers=None, body=b""):
        """Return one transport-neutral response; provider failures fail shut."""
        method, query, headers = method.upper(), query or {}, headers or {}
        path = "/" + path.strip("/")
        if path == "/healthz" and method == "GET":
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
                raw = await self.store.get("invite/" + invite)
            except Exception:
                return Response(503)
            if raw is None:
                return Response(404)
            if len(raw) > self.max_object_bytes:
                return Response(413)
            return Response(
                200, raw, {
                    "Cache-Control": "no-store",
                    "Content-Type": "application/octet-stream",
                })
        if self._read_only_path(path):
            return Response(405)
        if not self._member(headers, trusted_now):
            return Response(401)
        if path == "/root" and method == "GET":
            try:
                root = await self._root() or b""
                if root:
                    snapshot = manifest.decode_root(root)
                    if snapshot.anchor != self.workspace:
                        raise ValueError("root anchor")
            except Exception:
                return Response(503)
            etag = h(root)
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
                raw = await self.store.get("obj/" + oid)
            except Exception:
                return Response(503)
            if raw is None:
                return Response(404)
            if len(raw) > self.max_object_bytes:
                return Response(413)
            if h(raw) != oid:
                return Response(503)
            return Response(
                200, raw, {
                    "Cache-Control": "no-store",
                    "Content-Type": "application/octet-stream",
                })
        return Response(404)
