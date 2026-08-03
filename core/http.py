"""The one database-free HTTP peer-data gate.

``HttpGate`` owns every route and authorization decision. Provider runtimes
call it directly; :mod:`core.http_stdlib` binds the same gate to ordinary HTTP
bytes for a full peer. Iroh may wrap those bytes later, but it must not
acquire another route table.
"""
import base64
import asyncio
from dataclasses import dataclass, field
import inspect
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
from .object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    MAX_INVITE_ID_BYTES,
    STALE,
    Versioned,
    ensure_object_async,
)
from .pack_access import (
    MAX_PACK_OPEN_BYTES,
    confine_scoped_request,
    decode_pack_open,
    encode_scoped_request,
)
from .writer_head import (
    MAX_HEAD_SLOT_BYTES,
    decode_slot,
    head_slot_key,
    head_slot_prefix,
)

OID_RE = re.compile(r"^[0-9a-f]{64}$")
INVITE_RE = re.compile(
    rf"^[a-z0-9._-]{{1,{MAX_INVITE_ID_BYTES}}}$")


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""
    headers: dict = field(default_factory=dict)


class AsyncFromSyncReader:
    """Expose one blocking ObjectStore to the shared awaited HTTP gate."""

    def __init__(self, reader):
        self.reader = reader

    async def get_bounded(self, key, max_bytes):
        return await asyncio.to_thread(
            self.reader.get_bounded, key, max_bytes)

    async def read_versioned(self, key):
        return await asyncio.to_thread(self.reader.read_versioned, key)

    async def put_if_absent(self, key, value):
        return await asyncio.to_thread(
            self.reader.put_if_absent, key, value)

    async def cas(self, key, token, value):
        return await asyncio.to_thread(self.reader.cas, key, token, value)

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        return await asyncio.to_thread(
            self.reader.list_page, prefix, cursor, limit)


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
            mirror=None,
            mint_authorize=None,
            pack_open=None,
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
        self.mirror = mirror
        self.mint_authorize = mint_authorize
        if pack_open is not None and not callable(pack_open):
            raise ValueError("pack OPEN issuer")
        self.pack_open = pack_open
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
        if self.mint_authorize is not None:
            try:
                if inspect.iscoroutinefunction(self.mint_authorize):
                    grant = await self.mint_authorize(pile, "sync")
                else:
                    grant = await asyncio.to_thread(
                        self.mint_authorize, pile, "sync")
                    if inspect.isawaitable(grant):
                        grant = await grant
            except Exception:
                return Response(403)
            if grant is None:
                return Response(403)
            public, verb = grant
            token = make_token(
                self.secret, public, self.workspace, verb,
                capability=self.sync_profile,
                issued_at=trusted_now, ttl_ms=self.grant_ttl_ms)
            response = {
                "grant": base64.b64encode(
                    self.seal(public, token.encode())).decode(),
            }
            if self.sync_profile is not None:
                response["cap"] = self.sync_profile
            return self._json(200, response)
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

    async def _open_pack(self, body, headers, trusted_now):
        """Authorize one bounded pack request; body bytes bypass this gate."""
        if self.pack_open is None:
            return Response(405)
        if not isinstance(body, bytes) or len(body) > min(
                self.max_request_bytes, MAX_PACK_OPEN_BYTES):
            return Response(413)
        try:
            opened = decode_pack_open(body)
        except PayloadTooLarge:
            return Response(413)
        except ValueError:
            return Response(400)
        member = self._member(
            headers, trusted_now, require_push=opened.method == "PUT")
        if not member:
            return Response(401)
        try:
            if inspect.iscoroutinefunction(self.pack_open):
                scoped = await self.pack_open(member, opened, trusted_now)
            else:
                scoped = await asyncio.to_thread(
                    self.pack_open, member, opened, trusted_now)
                if inspect.isawaitable(scoped):
                    scoped = await scoped
            scoped = confine_scoped_request(opened, scoped, trusted_now)
            response = encode_scoped_request(scoped)
        except Exception:
            return Response(503)
        return Response(200, response, {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
        })

    async def _heads(self, query):
        """Return one bounded page of atomically opened writer slots.

        The page is not a workspace snapshot and does not pretend to be one:
        each independent slot may have linearized at a different instant.
        Returning the small tops with their directory page removes one
        network round per writer while preserving per-writer CAS authority.
        The returned digest authenticates this HTTP response value; it is not
        the provider's opaque CAS token and cannot mutate the source slot.
        """
        cursor = query.get("cursor") or None
        try:
            limit = int(query.get("limit", PAGE_BATCH))
        except (TypeError, ValueError):
            return Response(400)
        if not 0 < limit <= PAGE_BATCH:
            return Response(400)
        try:
            page = await self.store.list_page(
                head_slot_prefix(self.workspace), cursor, limit)
            opened = await asyncio.gather(*(
                self.store.get_bounded(key, MAX_HEAD_SLOT_BYTES)
                for key in page.keys), return_exceptions=True)
        except Exception:
            return Response(503)
        if not isinstance(opened, (tuple, list)) \
                or len(opened) != len(page.keys):
            return Response(503)
        normalized = []
        for value in opened:
            if isinstance(value, ValueError) or value is None:
                normalized.append(None)
            elif isinstance(value, BaseException) \
                    or not isinstance(value, bytes) \
                    or len(value) > MAX_HEAD_SLOT_BYTES:
                return Response(503)
            else:
                normalized.append(value)
        return self._json(200, {
            "cursor": page.cursor,
            "heads": [
                [key, None, None]
                if value is None else [
                    key, base64.b64encode(value).decode(), h(value)]
                for key, value in zip(page.keys, normalized)
            ],
        })

    async def _head(self, device, headers):
        try:
            key = head_slot_key(self.workspace, device)
            opened = await self.store.read_versioned(key)
        except ValueError:
            return Response(404)
        except Exception:
            return Response(503)
        if opened is ABSENT:
            return Response(404)
        if not isinstance(opened, Versioned):
            return Response(503)
        etag = opened.token.value
        if self._header(headers, "If-None-Match") == etag:
            return Response(304)
        return Response(200, opened.value, {
            "Cache-Control": "no-store",
            "Content-Type": "application/octet-stream",
            "ETag": etag,
        })

    async def _object(self, oid):
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
        return Response(200, raw, {
            "Cache-Control": "no-store",
            "Content-Type": "application/octet-stream",
        })

    async def _put_object(self, oid, body):
        if not OID_RE.fullmatch(oid) or not isinstance(body, bytes) \
                or len(body) > self.max_object_bytes or h(body) != oid:
            return Response(400)
        try:
            result = await ensure_object_async(self.store, oid, body)
        except PayloadTooLarge:
            return Response(413)
        except ValueError:
            return Response(409)
        except Exception:
            return Response(503)
        if result is CREATED:
            return Response(201)
        if result is EXISTS:
            return Response(204)
        return Response(503)

    async def _accept_mirror(self, device, body):
        if self.mirror is None:
            return Response(405)
        try:
            slot = decode_slot(
                body, workspace=self.workspace, device=device)
            result = self.mirror.accept_slot(body)
            if inspect.isawaitable(result):
                result = await result
        except ValueError as error:
            return Response(
                409 if "concurrent" in str(error) else 400)
        except Exception:
            return Response(503)
        if result.errors:
            return Response(400)
        # A cached directory observation may be stale by the time a reverse
        # sync reaches this receiver.  ``changed == 0`` can mean either exact
        # no-op or "receiver is already newer"; only the exact installed slot
        # is CAS success for the caller's proposed value.
        try:
            current = await self.store.get_bounded(
                head_slot_key(slot.workspace, slot.device),
                MAX_HEAD_SLOT_BYTES,
            )
        except Exception:
            return Response(503)
        if current != body:
            return Response(409)
        return Response(204 if not result.changed else 201, headers={
            "ETag": h(current),
        })

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
        if method == "POST" and path == "/obj":
            return MAX_PAGE_REQUEST_BYTES
        if method == "POST" and path == "/pack/open":
            return MAX_PACK_OPEN_BYTES
        if method == "PUT" and path.startswith("/obj/"):
            return MAX_OBJECT_BYTES
        if method == "PUT" and path.startswith("/mirror/"):
            return MAX_HEAD_SLOT_BYTES
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
                if self.mirror is not None or self.mint_authorize is not None:
                    await self.store.list_page(
                        head_slot_prefix(self.workspace), None, 1)
                elif await self._reader() is None:
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
        if path == "/pack/open":
            if method != "POST":
                return Response(405)
            return await self._open_pack(body, headers, trusted_now)
        if path.startswith("/ctl"):
            return Response(405)
        if method == "PUT" and (
                path.startswith("/obj/")
                or path.startswith("/mirror/")):
            if not self._member(
                    headers, trusted_now, require_push=True):
                return Response(401)
            if path.startswith("/obj/"):
                return await self._put_object(
                    path.removeprefix("/obj/"), body)
            device = path.removeprefix("/mirror/")
            return await self._accept_mirror(device, body)
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
        if path == "/heads" and method == "GET":
            return await self._heads(query)
        if path.startswith("/head/") and method == "GET":
            return await self._head(
                path.removeprefix("/head/"), headers)
        if path == "/obj" and method == "POST":
            return await self._batch(body)
        if path.startswith("/obj/") and method == "GET":
            return await self._object(path.removeprefix("/obj/"))
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
