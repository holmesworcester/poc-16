"""HTTP peer and pile-transfer helpers for the sync dial."""
import base64
import json
import urllib.error
import urllib.parse
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
    decode_json,
)
from core.object_store import ABSENT, ListPage, Versioned, VersionToken
from core.writer_head import (
    MAX_HEAD_SLOT_BYTES,
    head_slot_key,
    head_slot_prefix,
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
        self._opened_head_page = None
        self._observed_heads = {}
        self._head_directory_complete = False

    @property
    def accepts_push(self):
        return "sync_profile" not in self.cache or peer_capability.allows_push(
            self.cache["sync_profile"])

    def _http(
            self, method, path, data=None, etag=None, auth=True, retry=True,
            require_push=False, response_limit=MAX_CONTROL_BYTES,
            query=None):
        encoded_query = urllib.parse.urlencode({
            "ws": self.ws,
            **(query or {}),
        })
        req = urllib.request.Request(
            f"{self.url}{path}?{encoded_query}",
            data=data,
            method=method,
        )
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
                    response_limit=response_limit, query=query)
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

    def heads(self, cursor=None, limit=256):
        query = {"limit": limit}
        if cursor is not None:
            query["cursor"] = cursor
        _, raw, _ = self._http(
            "GET", "/heads", query=query,
            response_limit=MAX_CONTROL_BYTES)
        value = decode_json(raw, MAX_CONTROL_BYTES, "head directory")
        if not isinstance(value, dict) or set(value) != {"cursor", "heads"} \
                or value["cursor"] is not None and not isinstance(
                    value["cursor"], str) \
                or not isinstance(value["heads"], list):
            raise ValueError("head directory")
        entries = []
        try:
            for entry in value["heads"]:
                if not isinstance(entry, list) or len(entry) != 3:
                    raise ValueError
                key, encoded, digest = entry
                if not isinstance(key, str):
                    raise ValueError
                if encoded is None and digest is None:
                    entries.append((key, ABSENT))
                    continue
                if not isinstance(encoded, str) \
                        or not isinstance(digest, str):
                    raise ValueError
                raw_slot = base64.b64decode(encoded, validate=True)
                if h(raw_slot) != digest:
                    raise ValueError
                entries.append((
                    key,
                    # RemoteStore uses this only as the atomic-read identity
                    # carried into local mirror validation. Source mutation
                    # still goes through /mirror and its receiver-owned CAS.
                    Versioned(raw_slot, VersionToken(digest)),
                ))
        except (TypeError, ValueError) as error:
            raise ValueError("head directory") from error
        page = ListPage(
            tuple(key for key, _opened in entries), value["cursor"])
        prefix = head_slot_prefix(self.ws)
        if any(not key.startswith(prefix) for key in page.keys):
            raise ValueError("foreign head directory key")
        self._opened_head_page = (
            page.keys,
            tuple(opened for _key, opened in entries),
        )
        self._observed_heads.update(entries)
        if page.cursor is None:
            self._head_directory_complete = True
        return page

    def opened_heads(self, keys):
        """Return the exact slots bundled with the latest directory page."""
        keys = tuple(keys)
        if self._opened_head_page is None \
                or self._opened_head_page[0] != keys:
            raise ValueError("head directory page is no longer current")
        return self._opened_head_page[1]

    def observed_head(self, key):
        """Return a disposable result from this turn's complete scan.

        A stale observation cannot authorize a push: `/mirror` opens the
        receiver's current slot again and owns its CAS.  This cache only
        avoids rereading every unchanged remote top during the reverse half
        of one two-way sync turn.
        """
        if key in self._observed_heads:
            return True, self._observed_heads[key]
        return self._head_directory_complete, ABSENT

    def head(self, device, etag=None):
        key = head_slot_key(self.ws, device)
        status, b, hdr = self._http(
            "GET", f"/head/{device}", etag=etag,
            response_limit=MAX_HEAD_SLOT_BYTES)
        response_etag = next(
            (value for name, value in hdr.items()
             if name.lower() == "etag"),
            None,
        )
        if status == 304:
            return None
        if not response_etag:
            raise ValueError(f"head slot has no version: {key}")
        opened = Versioned(b, VersionToken(response_etag))
        self._observed_heads[key] = opened
        return opened.value, opened.token

    def obj(self, oh, *, response_limit):
        if type(response_limit) is not int \
                or not 0 < response_limit <= MAX_OBJECT_BYTES:
            raise ValueError("peer object response limit")
        _, b, _ = self._http(
            "GET", f"/obj/{oh}", response_limit=response_limit)
        return b

    def objs(self, oids):
        """Fetch an ordered object batch, splitting a provider-sized 413."""
        oids = tuple(oids)
        if not oids:
            return ()
        try:
            _, raw, _ = self._http(
                "POST", "/obj", json.dumps(oids).encode(),
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

    def put_obj(self, oid, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES \
                or h(raw) != oid:
            raise ValueError("peer immutable object")
        status, _, _ = self._http(
            "PUT", f"/obj/{oid}", data=raw, require_push=True,
            response_limit=MAX_CONTROL_BYTES)
        return status

    def accept_slot(self, device, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_HEAD_SLOT_BYTES:
            raise ValueError("peer head slot")
        try:
            status, _, headers = self._http(
                "PUT", f"/mirror/{device}", data=raw,
                require_push=True, response_limit=MAX_CONTROL_BYTES)
        except urllib.error.HTTPError as error:
            if error.code == 409:
                return False, None
            raise
        token = next(
            (value for name, value in headers.items()
             if name.lower() == "etag"),
            None,
        )
        return status in {201, 204}, (
            None if token is None else VersionToken(token))
