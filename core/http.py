"""The one database-free HTTP peer-data gate.

``HttpGate`` owns every route and authorization decision. Provider runtimes
call it directly; :mod:`core.http_stdlib` binds the same gate to ordinary HTTP
bytes for a full peer. Iroh may wrap those bytes later, but it must not
acquire another route table.
"""
import base64
from dataclasses import dataclass, field
import inspect
import json
import re

from . import peer_capability
from .crypto import h, seal_to
from .grants import check_token, make_token
from .limits import (
    MAX_INVITE_BYTES,
    MAX_CONTROL_PILE_BYTES,
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_PAGE_REQUEST_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)
from .object_store import (
    ABSENT,
    MAX_INVITE_ID_BYTES,
    StoreError,
    Versioned,
    mutable_key,
)
from .pack_access import (
    MAX_OBJECT_OPEN_BYTES,
    MAX_PACK_OPEN_BYTES,
    confine_object_request,
    confine_scoped_request,
    decode_object_open,
    decode_pack_open,
    encode_scoped_request,
)
from .removal_path import ProofRefreshRequired, RemovalDenied
from .shape import valid_fid
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


async def _to_thread(function, *args, **kwargs):
    """Load host thread support only when a blocking adapter actually uses it."""
    from asyncio import to_thread

    return await to_thread(function, *args, **kwargs)


class AsyncFromSyncReader:
    """Expose one blocking ObjectStore to the shared awaited HTTP gate."""

    def __init__(self, reader):
        self.reader = reader

    async def get_bounded(self, key, max_bytes):
        return await _to_thread(
            self.reader.get_bounded, key, max_bytes)

    async def copy_pile_object(self, oid, max_bytes, write):
        return await _to_thread(
            self.reader.copy_pile_object, oid, max_bytes, write)

    async def read_versioned(self, key):
        return await _to_thread(self.reader.read_versioned, key)

    async def has(self, key):
        return await _to_thread(self.reader.has, key)

    async def put_if_absent(self, key, value):
        return await _to_thread(
            self.reader.put_if_absent, key, value)

    async def cas(self, key, token, value):
        return await _to_thread(self.reader.cas, key, token, value)

    async def list_page(self, prefix, cursor=None, limit=PAGE_BATCH):
        return await _to_thread(
            self.reader.list_page, prefix, cursor, limit)


class HttpGate:
    """One-workspace peer authorization and immutable-object service.

    The gate is async because a Cloudflare R2 binding is async. Lambda wraps
    its synchronous SDK adapter with :class:`AsyncFromSyncReader`, so both
    deployments execute this same route and authorization implementation.
    Writer publication enters through the per-device object and mirror routes;
    this gate does not expose the retired workspace-global pile applier.
    """

    def __init__(
            self, store, workspace, secret, now,
            *, sync_profile=peer_capability.READ_ONLY,
            mirror=None,
            head_advance=None,
            mint_authorize=None,
            path_authorize=None,
            removal_bootstrap=None,
            removal_apply=None,
            object_open=None,
            pack_open=None,
            max_request_bytes=MAX_MINT_REQUEST_BYTES,
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
        self.mirror = mirror
        if head_advance is not None and not callable(head_advance):
            raise ValueError("head advancer")
        self.head_advance = head_advance
        self.mint_authorize = mint_authorize
        callbacks = (
            ("path authorizer", path_authorize),
            ("removal bootstrap", removal_bootstrap),
            ("removal control applier", removal_apply),
        )
        if any(value is not None and not callable(value)
               for _label, value in callbacks):
            raise ValueError(next(
                label for label, value in callbacks
                if value is not None and not callable(value)))
        self.path_authorize = path_authorize
        self.removal_bootstrap = removal_bootstrap
        self.removal_apply = removal_apply
        if object_open is not None and not callable(object_open):
            raise ValueError("object OPEN issuer")
        if pack_open is not None and not callable(pack_open):
            raise ValueError("pack OPEN issuer")
        self.object_open = object_open
        self.pack_open = pack_open
        self.secret, self.now = secret, now
        if not peer_capability.known(sync_profile):
            raise ValueError("sync profile")
        bounded = (
            ("request bytes", max_request_bytes, MAX_MINT_REQUEST_BYTES),
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

    def _member(
            self, headers, trusted_now, *, require_push=False,
            require_object_put=False):
        return check_token(
            self.secret,
            self._header(headers, "Authorization"),
            self.workspace,
            trusted_now=trusted_now,
            require_push=require_push,
            require_object_put=require_object_put,
        )

    async def _get(self, key, max_bytes):
        """Fetch one exact transport key without interpreting repository state."""
        value = await self.store.get_bounded(key, max_bytes)
        if value is not None and len(value) > max_bytes:
            raise PayloadTooLarge("object read exceeds byte limit")
        return value

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
                    grant = await self.mint_authorize(
                        pile, trusted_now, purpose="sync")
                else:
                    grant = await _to_thread(
                        self.mint_authorize,
                        pile,
                        trusted_now,
                        purpose="sync",
                    )
                    if inspect.isawaitable(grant):
                        grant = await grant
            except ProofRefreshRequired:
                return self._json(409, {"error": "proof_refresh_required"})
            except RemovalDenied:
                return Response(403)
            except (PayloadTooLarge, StoreError):
                return Response(503)
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
            response["cap"] = self.sync_profile
            return self._json(200, response)
        return Response(503)

    async def _removal_path(self, body, trusted_now):
        """Evaluate historical membership and return only caller points."""
        if self.path_authorize is None:
            return Response(405)
        if not isinstance(body, bytes) or len(body) > self.max_request_bytes:
            return Response(413)
        try:
            pile = self._decode_mint(body, self.workspace)
            if inspect.iscoroutinefunction(self.path_authorize):
                result = await self.path_authorize(pile, trusted_now)
            else:
                result = await _to_thread(
                    self.path_authorize, pile, trusted_now)
                if inspect.isawaitable(result):
                    result = await result
        except (PayloadTooLarge, StoreError):
            return Response(503)
        except (TypeError, ValueError, json.JSONDecodeError):
            return Response(403)
        if not isinstance(result, bytes) or len(result) > MAX_MINT_REQUEST_BYTES:
            return Response(403 if result is None else 503)
        return Response(200, result, {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
        })

    async def _bootstrap_removal(self, body):
        """Evaluate one original direct-member control closure, then discard."""
        if self.removal_bootstrap is None:
            return Response(405)
        if not isinstance(body, bytes) or len(body) > MAX_CONTROL_PILE_BYTES:
            return Response(413)
        try:
            if inspect.iscoroutinefunction(self.removal_bootstrap):
                result = await self.removal_bootstrap(body)
            else:
                result = await _to_thread(self.removal_bootstrap, body)
                if inspect.isawaitable(result):
                    result = await result
        except (PayloadTooLarge, StoreError):
            return Response(503)
        except Exception:
            return Response(403)
        return self._removal_result(result)

    async def _apply_removal(self, body, writer):
        """Evaluate one exact authenticated control pile, then discard it."""
        if self.removal_apply is None:
            return Response(405)
        if not isinstance(body, bytes) or len(body) > MAX_CONTROL_PILE_BYTES:
            return Response(413)
        try:
            if inspect.iscoroutinefunction(self.removal_apply):
                result = await self.removal_apply(body, writer=writer)
            else:
                result = await _to_thread(
                    self.removal_apply, body, writer=writer)
                if inspect.isawaitable(result):
                    result = await result
        except (PayloadTooLarge, StoreError):
            return Response(503)
        except Exception:
            return Response(403)
        return self._removal_result(result)

    @staticmethod
    def _removal_result(result):
        status = getattr(result, "status", None)
        if status == "applied":
            return Response(201)
        if status == "noop":
            return Response(204)
        if status == "retryable":
            return Response(409)
        if status == "rejected":
            return Response(403)
        return Response(503)

    async def _advance_head(self, proposed_head, body, trusted_now):
        """Evaluate one owner proof, then CAS only its bound writer slot."""
        if self.head_advance is None:
            return Response(405)
        if not OID_RE.fullmatch(proposed_head) \
                or not isinstance(body, bytes) \
                or len(body) > self.max_request_bytes:
            return Response(400)
        try:
            if inspect.iscoroutinefunction(self.head_advance):
                result = await self.head_advance(
                    body, proposed_head, trusted_now)
            else:
                result = await _to_thread(
                    self.head_advance, body, proposed_head, trusted_now)
                if inspect.isawaitable(result):
                    result = await result
        except ProofRefreshRequired:
            return self._json(409, {"error": "proof_refresh_required"})
        except RemovalDenied:
            return Response(403)
        except (PayloadTooLarge, StoreError):
            return Response(503)
        except ValueError:
            return Response(403)
        except Exception:
            return Response(503)
        status = getattr(result, "status", None)
        if status == "applied":
            return Response(201)
        if status == "noop":
            return Response(204)
        if status == "retryable":
            return Response(409)
        return Response(503)

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
            headers, trusted_now,
            require_object_put=opened.method == "PUT")
        if not member:
            return Response(401)
        try:
            if inspect.iscoroutinefunction(self.pack_open):
                scoped = await self.pack_open(member, opened, trusted_now)
            else:
                scoped = await _to_thread(
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

    async def _open_object(self, body, headers, trusted_now):
        """Authorize one direct object GET/PUT; bytes bypass this gate."""
        if self.object_open is None:
            return Response(405)
        if not isinstance(body, bytes) or len(body) > min(
                self.max_request_bytes, MAX_OBJECT_OPEN_BYTES):
            return Response(413)
        try:
            opened = decode_object_open(body)
        except PayloadTooLarge:
            return Response(413)
        except ValueError:
            return Response(400)
        member = self._member(
            headers, trusted_now,
            require_object_put=opened.method == "PUT")
        if not member:
            return Response(401)
        try:
            if inspect.iscoroutinefunction(self.object_open):
                scoped = await self.object_open(
                    member, opened, trusted_now)
            else:
                scoped = await _to_thread(
                    self.object_open, member, opened, trusted_now)
                if inspect.isawaitable(scoped):
                    scoped = await scoped
            scoped = confine_object_request(
                opened, scoped, trusted_now)
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
            from asyncio import gather

            page = await self.store.list_page(
                head_slot_prefix(self.workspace), cursor, limit)
            opened = await gather(*(
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
        }, {"Cache-Control": "no-store"})

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

    async def _layout(self, device, encoded_start):
        """Return one bounded source-local locator page, never a pack body."""
        try:
            key = (
                f"layouts/{self.workspace}/{device}/{encoded_start}"
            )
            if not mutable_key(key):
                raise ValueError
            raw = await self._get(key, MAX_OBJECT_BYTES)
        except ValueError:
            return Response(404)
        except PayloadTooLarge:
            return Response(413)
        except Exception:
            return Response(503)
        if raw is None:
            return Response(404)
        return Response(200, raw, {
            "Cache-Control": "no-store",
            "Content-Type": "application/octet-stream",
        })

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
        if method == "POST" and path == "/mint":
            return MAX_MINT_REQUEST_BYTES
        if method == "POST" and path == "/removal/path":
            return MAX_MINT_REQUEST_BYTES
        if method == "POST" and path == "/removal/bootstrap":
            return MAX_CONTROL_PILE_BYTES
        if method == "POST" and path == "/removal/apply":
            return MAX_CONTROL_PILE_BYTES
        if method == "POST" and path.startswith("/head/"):
            return MAX_MINT_REQUEST_BYTES
        if method == "POST" and path == "/obj":
            return MAX_PAGE_REQUEST_BYTES
        if method == "POST" and path == "/pack/open":
            return MAX_PACK_OPEN_BYTES
        if method == "POST" and path == "/obj/open":
            return MAX_OBJECT_OPEN_BYTES
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
                await self.store.list_page(
                    head_slot_prefix(self.workspace), None, 1)
            except Exception:
                return self._json(503, {"ok": False})
            return self._json(200, {"ok": True})
        if not self._workspace(query):
            return Response(404)
        trusted_now = self.now()
        if path == "/mint" and method == "POST":
            return await self._mint(body, trusted_now)
        if path == "/removal/path" and method == "POST":
            return await self._removal_path(body, trusted_now)
        if path == "/removal/bootstrap" and method == "POST":
            return await self._bootstrap_removal(body)
        if path.startswith("/head/") and method == "POST":
            return await self._advance_head(
                path.removeprefix("/head/"), body, trusted_now)
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
        if path == "/obj/open":
            if method != "POST":
                return Response(405)
            return await self._open_object(body, headers, trusted_now)
        if path.startswith("/ctl"):
            return Response(405)
        if path == "/removal/apply" and method == "POST":
            writer = self._member(
                headers, trusted_now, require_push=True)
            if writer is None:
                return Response(401)
            return await self._apply_removal(body, writer)
        if method == "PUT" and path.startswith("/mirror/"):
            if not self._member(
                    headers, trusted_now, require_push=True):
                return Response(401)
            device = path.removeprefix("/mirror/")
            return await self._accept_mirror(device, body)
        if not self._member(headers, trusted_now):
            return Response(401)
        if path == "/heads" and method == "GET":
            return await self._heads(query)
        if path.startswith("/head/") and method == "GET":
            return await self._head(
                path.removeprefix("/head/"), headers)
        if path.startswith("/layout/") and method == "GET":
            parts = path.strip("/").split("/")
            if len(parts) != 3:
                return Response(404)
            return await self._layout(parts[1], parts[2])
        if path == "/obj" and method == "POST":
            return await self._batch(body)
        if path.startswith("/obj/") and method == "GET":
            return await self._object(path.removeprefix("/obj/"))
        return Response(404)
