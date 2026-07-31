"""HTTP peer and pile-transfer helpers for the sync dial."""
import base64
import json
import urllib.error
import urllib.request

import facts as families

from core import peer_capability
from core.crypto import h, unseal
from core.http_body import read_bounded
from core.limits import (
    MAX_CONTROL_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_PILE_BYTES,
    MAX_ROOT_BYTES,
    decode_json,
)
from .node import now_ms


class PushUnsupported(RuntimeError):
    """The authenticated peer profile does not accept pile delivery."""


class Peer:
    """HTTP client for one (workspace, responder) pair.

    Bearer authority stays opaque.  The sole decoded field is the fail-closed
    sync profile repeated by mint; both are replaced together on a 401.
    """

    def __init__(self, node, ws, url):
        self.node, self.ws, self.url = node, ws, url
        self.cache = node.sync_state(ws, url)

    @property
    def accepts_push(self):
        return "sync_profile" not in self.cache or peer_capability.allows_push(
            self.cache["sync_profile"])

    def _http(
            self, method, path, data=None, etag=None, auth=True, retry=True,
            require_push=False, response_limit=MAX_CONTROL_BYTES):
        req = urllib.request.Request(f"{self.url}{path}?ws={self.ws}", data=data, method=method)
        if auth:
            if "token" not in self.cache:
                self.mint()
            if require_push and not self.accepts_push:
                raise PushUnsupported("peer advertises pull-only sync")
            req.add_header("Authorization", "Bearer " + self.cache["token"])
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                body = read_bounded(
                    r, response_limit, "peer response")
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, b"", {}
            if e.code == 401 and auth and retry:
                self.cache.pop("token", None)
                self.cache.pop("sync_profile", None)
                return self._http(
                    method, path, data, etag, auth, retry=False,
                    require_push=require_push,
                    response_limit=response_limit)
            raise

    def mint(self):
        """The handshake: a small closed pile — request fact + its auth
        closure — judged by the responder's kernel; the grant comes back
        encrypted to our key."""
        n = self.node
        with n.lock:
            ts = now_ms()
            facts = families.proof_payload(
                n, self.ws, "sync", ts + 120_000, ts)
        body = json.dumps({
            "ws": self.ws,
            "pile": base64.b64encode(
                n.sender(self.ws).pack(facts)).decode(),
        }).encode()
        if len(body) > MAX_MINT_REQUEST_BYTES:
            raise ValueError("mint request too large")
        _, resp, _ = self._http(
            "POST", "/mint", body, auth=False,
            response_limit=MAX_CONTROL_BYTES)
        o = decode_json(resp, MAX_CONTROL_BYTES, "mint response")
        secret, _ = self.node.identity(self.ws)
        token = unseal(secret, base64.b64decode(o["grant"])).decode()
        self.cache.update({
            "token": token,
            "sync_profile": peer_capability.negotiate(token, o),
        })

    def root(self, etag=None, *, response_limit):
        if type(response_limit) is not int \
                or not 0 < response_limit <= MAX_ROOT_BYTES:
            raise ValueError("peer root response limit")
        status, b, hdr = self._http(
            "GET", "/root", etag=etag, response_limit=response_limit)
        response_etag = next(
            (value for name, value in hdr.items()
             if name.lower() == "etag"),
            None,
        )
        return None if status == 304 else (b, response_etag)

    def obj(self, oh, *, response_limit):
        if type(response_limit) is not int \
                or not 0 < response_limit <= MAX_OBJECT_BYTES:
            raise ValueError("peer object response limit")
        _, b, _ = self._http(
            "GET", f"/page/{oh}", response_limit=response_limit)
        return b

    def objs(self, oids):
        """Fetch an ordered object batch, splitting a provider-sized 413."""
        oids = tuple(oids)
        if not oids:
            return ()
        try:
            _, raw, _ = self._http(
                "POST", "/page", json.dumps(oids).encode(),
                response_limit=MAX_PAGE_BATCH_BYTES)
        except urllib.error.HTTPError as error:
            if error.code != 413:
                raise
            if len(oids) == 1:
                # Batch responses are capped below the valid single-object
                # limit. Fall back to the hash-addressed GET instead of making
                # a large-but-valid canonical fact impossible to reconcile.
                return (self.obj(
                    oids[0], response_limit=MAX_OBJECT_BYTES),)
            middle = len(oids) // 2
            return self.objs(oids[:middle]) + self.objs(oids[middle:])
        values = decode_json(
            raw, MAX_PAGE_BATCH_BYTES, "page batch response")
        if not isinstance(values, list) or len(values) != len(oids):
            raise ValueError("page batch")
        try:
            return tuple(
                base64.b64decode(value, validate=True)
                if value is not None else None
                for value in values
            )
        except (TypeError, ValueError) as error:
            raise ValueError("page batch encoding") from error

    def put_pile(self, b):
        if not isinstance(b, bytes) or len(b) > MAX_PILE_BYTES:
            raise ValueError("pile too large")
        self._http(
            "PUT", f"/pile/{self.node.member_for(self.ws)}/{h(b)}", data=b,
            require_push=True, response_limit=MAX_CONTROL_BYTES)

    def poke(self):
        self._http("POST", "/poke", data=b"", auth=False)
