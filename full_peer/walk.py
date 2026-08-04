"""HTTP peer and pile-transfer helpers for the sync dial."""
import base64
import hashlib
import http.client
import io
import json
import urllib.error
import urllib.parse
import urllib.request

import facts as families

from core import peer_capability
from core.crypto import h, unseal
from core.http import (
    encode_head_commit_request,
    encode_head_permit_request,
)
from core.http_body import read_bounded
from core.limits import (
    MAX_CONTROL_BYTES,
    MAX_DIRECT_OBJECT_BYTES,
    MAX_HEAD_PERMIT_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    DIRECT_STREAM_CHUNK_BYTES,
    decode_json,
)
from core.object_store import (
    ABSENT,
    ListPage,
    OutcomeUnknown,
    Versioned,
    VersionToken,
)
from core.pack_access import (
    MAX_SCOPED_REQUEST_BYTES,
    ObjectOpen,
    PackOpen,
    confine_object_request,
    confine_scoped_request,
    copy_object_get,
    copy_pack_get,
    decode_scoped_request,
    encode_object_open,
    encode_pack_open,
)
from core.writer_head import (
    MAX_HEAD_SLOT_BYTES,
    head_slot_key,
    head_slot_prefix,
)
from core.writer_layout import (
    MAX_LAYOUT_PAGE_BYTES,
    parse_layout_page_key,
)
from .node import ACCESS_PROOF_TTL_MS, now_ms


class PushUnsupported(RuntimeError):
    """The authenticated peer profile does not accept pile delivery."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """A scoped provider request cannot delegate its capability by redirect."""

    def redirect_request(self, *_args, **_kwargs):
        return None


_DIRECT_OPENER = urllib.request.build_opener(_RejectRedirects)


def _origin(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise ValueError("scoped request origin") from error
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("scoped request origin")
    return (
        parsed.scheme,
        parsed.hostname.lower(),
        port if port is not None else (443 if parsed.scheme == "https" else 80),
    )


class Peer:
    """HTTP client for one (workspace, responder) pair.

    Bearer authority stays opaque.  The sole decoded field is the fail-closed
    sync profile repeated by mint; both are replaced together on a 401.
    """

    def __init__(self, node, ws, url):
        self.node, self.ws, self.url = node, ws, url
        # A grant describes this one exchange with this one responder.  It is
        # deliberately not node state: a later sync proves current authority
        # again and receives a fresh profile.
        self._token = None
        self._sync_profile = None
        self._opened_head_page = None
        self._observed_heads = {}
        self._head_directory_complete = False

    @property
    def accepts_push(self):
        """Whether this peer accepts validate-first all-writer gossip."""
        return peer_capability.allows_push(
            self._sync_profile)

    @property
    def accepts_owner_publish(self):
        """Whether this peer accepts immutable owner-log publication."""
        return peer_capability.allows_object_put(
            self._sync_profile)

    def _http(
            self, method, path, data=None, etag=None, auth=True, retry=True,
            require_push=False, require_object_put=False,
            response_limit=MAX_CONTROL_BYTES,
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
            if self._token is None:
                self.mint()
            if require_push and not self.accepts_push:
                raise PushUnsupported("peer advertises pull-only sync")
            if require_object_put and not self.accepts_owner_publish:
                raise PushUnsupported(
                    "peer does not accept immutable publication")
            req.add_header("Authorization", "Bearer " + self._token)
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with _DIRECT_OPENER.open(req, timeout=15) as r:
                body = read_bounded(
                    r, response_limit, "peer response")
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, b"", {}
            if e.code == 401 and auth and retry:
                self._token = None
                self._sync_profile = None
                return self._http(
                    method, path, data, etag, auth, retry=False,
                    require_push=require_push,
                    require_object_put=require_object_put,
                    response_limit=response_limit, query=query)
            raise

    def _confine_direct_origin(self, scoped):
        """Bind direct bytes to the authenticated peer's deployment class."""
        target = _origin(scoped.url)
        gate = _origin(self.url)
        profile = self._sync_profile
        if profile == peer_capability.FULL:
            if target != gate:
                raise ValueError("FullPeer scoped request changed origin")
        elif profile in {peer_capability.OWNER, peer_capability.READ_ONLY}:
            # Pull-only is a capability, not proof that this is a hosted
            # deployment. A same-origin FullPeer route may remain on its local
            # or Iroh-carried HTTP dial; an origin-changing S3/R2 capability
            # must be protected by TLS.
            if target != gate and target[0] != "https":
                raise ValueError("hosted scoped request requires HTTPS")
        else:
            raise ValueError("unknown scoped request peer profile")
        return scoped

    def _proof_body(self, pile):
        if not isinstance(pile, bytes):
            raise TypeError("access proof pile")
        body = json.dumps({
            "ws": self.ws,
            "pile": base64.b64encode(pile).decode(),
        }).encode()
        if len(body) > MAX_MINT_REQUEST_BYTES:
            raise ValueError("access proof request too large")
        return body

    def removal_path(self):
        """Fetch only this device/member's path after historical proof."""
        with self.node.lock:
            proof = self.node.removal_path_proof(self.ws)
        body = self._proof_body(proof)
        try:
            _, path, _ = self._http(
                "POST",
                "/removal/path",
                body,
                auth=False,
                response_limit=MAX_MINT_REQUEST_BYTES,
            )
        except urllib.error.HTTPError as error:
            if error.code != 403:
                raise
            # A new recipient may not know this member yet. Reuse only the
            # writer's original signed clear-only control leaf; the gate
            # evaluates and discards it, then owns all subsequent state.
            bootstrap = self.node.removal_bootstrap_pile(self.ws)
            self._http(
                "POST",
                "/removal/bootstrap",
                bootstrap,
                auth=False,
                response_limit=MAX_CONTROL_BYTES,
            )
            _, path, _ = self._http(
                "POST",
                "/removal/path",
                body,
                auth=False,
                response_limit=MAX_MINT_REQUEST_BYTES,
            )
        return path

    def mint(self):
        """Run historical-path then current-membership proof phases."""
        n = self.node
        for attempt in range(2):
            path = self.removal_path()
            with n.lock:
                ts = now_ms()
                closed = families.proof_payload(
                    n,
                    self.ws,
                    "sync",
                    ts + ACCESS_PROOF_TTL_MS,
                    ts,
                    removal_path=path,
                )
                proof = n.sender(self.ws).pack(closed)
            try:
                _, resp, _ = self._http(
                    "POST",
                    "/mint",
                    self._proof_body(proof),
                    auth=False,
                    response_limit=MAX_CONTROL_BYTES,
                )
                break
            except urllib.error.HTTPError as error:
                if error.code != 409 or attempt:
                    raise
        else:  # pragma: no cover - the bounded loop either breaks or raises.
            raise RuntimeError("mint proof refresh")
        o = decode_json(resp, MAX_CONTROL_BYTES, "mint response")
        secret, _ = self.node.identity(self.ws)
        token = unseal(secret, base64.b64decode(o["grant"])).decode()
        self._token = token
        self._sync_profile = peer_capability.negotiate(token, o)

    def issue_head_permit(self, proof, proposed_head, control_piles):
        """Obtain one exact non-expiring permit before control takes effect."""
        body = encode_head_permit_request(proof, control_piles)
        status, permit, _ = self._http(
            "POST",
            f"/head/{proposed_head}/permit",
            body,
            auth=False,
            response_limit=MAX_HEAD_PERMIT_BYTES,
        )
        if status != 200 or not permit:
            raise ValueError("control-head permit issuance")
        return permit

    def commit_head_permit(self, permit, proposed_head, control_piles):
        """Hold and replay one permit until its removal-first CAS completes."""
        body = encode_head_commit_request(permit, control_piles)
        try:
            status, _, _ = self._http(
                "POST",
                f"/head/{proposed_head}/commit",
                body,
                auth=False,
                response_limit=MAX_CONTROL_BYTES,
            )
        except urllib.error.HTTPError as error:
            if error.code == 412:
                return "conflict"
            if error.code == 409 or 500 <= error.code < 600:
                return "retryable"
            raise
        except (
                urllib.error.URLError,
                http.client.IncompleteRead,
                http.client.RemoteDisconnected,
                TimeoutError,
                ConnectionError):
            # The server may have completed either removal CAS, head CAS, or
            # both before the response disappeared. The caller still holds
            # the same exact permit/body, so replay is the sole safe action.
            return "retryable"
        if status == 201:
            return "applied"
        if status == 204:
            return "noop"
        raise ValueError("control-head permit commit")

    def advance_head(self, proof, proposed_head):
        """Submit one exact owner proof to the public mechanical CAS route."""
        if not isinstance(proof, bytes) or not isinstance(
                proposed_head, str):
            raise ValueError("owner head publication")
        try:
            status, _, _ = self._http(
                "POST", "/head/" + proposed_head, proof, auth=False,
                response_limit=MAX_CONTROL_BYTES)
        except urllib.error.HTTPError as error:
            if error.code == 412:
                return "conflict"
            if error.code == 409:
                return "retryable"
            raise
        if status == 201:
            return "applied"
        if status == 204:
            return "noop"
        raise ValueError("owner head publication")

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
        value = bytearray()
        copied = self.copy_obj(
            oh, response_limit=response_limit, write=value.extend)
        return None if copied is None else bytes(value)

    def copy_obj(self, oh, *, response_limit, write):
        """Copy one object through its size-appropriate HTTP data plane."""
        if type(response_limit) is not int \
                or not 0 < response_limit <= MAX_DIRECT_OBJECT_BYTES \
                or not callable(write):
            raise ValueError("peer object response limit")
        if response_limit <= MAX_OBJECT_BYTES:
            _, raw, _ = self._http(
                "GET", f"/obj/{oh}", response_limit=response_limit)
            write(raw)
            return len(raw)

        opened = ObjectOpen("GET", oh, response_limit)
        _, raw, _ = self._http(
            "POST", "/obj/open",
            data=encode_object_open(opened),
            response_limit=MAX_SCOPED_REQUEST_BYTES)
        scoped = confine_object_request(
            opened, decode_scoped_request(raw), now_ms())
        self._confine_direct_origin(scoped)
        request = urllib.request.Request(
            scoped.url,
            method="GET",
            headers=dict(scoped.headers),
        )
        with _DIRECT_OPENER.open(request, timeout=60) as response:
            def chunks():
                while True:
                    chunk = response.read(DIRECT_STREAM_CHUNK_BYTES)
                    if not chunk:
                        return
                    yield chunk

            return copy_object_get(
                opened,
                response.status,
                response.headers,
                chunks(),
                write,
            )

    def layout(self, key, *, response_limit=MAX_LAYOUT_PAGE_BYTES):
        """Open one directly addressed, bounded source-local layout page."""
        workspace, device, start = parse_layout_page_key(key)
        if workspace != self.ws \
                or type(response_limit) is not int \
                or not 0 < response_limit <= MAX_LAYOUT_PAGE_BYTES:
            raise ValueError("peer writer layout")
        try:
            _, body, _ = self._http(
                "GET", f"/layout/{device}/{start:016d}",
                response_limit=response_limit)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise
        return body

    def copy_pack(self, opened, write):
        """Open, then verify and stream one exact ordinary-HTTP pack GET."""
        if not isinstance(opened, PackOpen) or opened.method != "GET" \
                or not callable(write):
            raise ValueError("peer pack GET")
        _, raw, _ = self._http(
            "POST", "/pack/open", data=encode_pack_open(opened),
            response_limit=MAX_SCOPED_REQUEST_BYTES)
        scoped = confine_scoped_request(
            opened, decode_scoped_request(raw), now_ms())
        self._confine_direct_origin(scoped)
        request = urllib.request.Request(
            scoped.url,
            method="GET",
            headers=dict(scoped.headers),
        )
        with _DIRECT_OPENER.open(request, timeout=60) as response:
            def chunks():
                while True:
                    chunk = response.read(DIRECT_STREAM_CHUNK_BYTES)
                    if not chunk:
                        return
                    yield chunk

            return copy_pack_get(
                opened,
                response.status,
                response.headers,
                chunks(),
                write,
            )

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
        if not isinstance(raw, bytes) \
                or not 0 < len(raw) <= MAX_DIRECT_OBJECT_BYTES \
                or h(raw) != oid:
            raise ValueError("peer immutable object")
        opened = ObjectOpen("PUT", oid, len(raw))
        _, encoded, _ = self._http(
            "POST", "/obj/open", data=encode_object_open(opened),
            require_object_put=True,
            response_limit=MAX_SCOPED_REQUEST_BYTES)
        scoped = confine_object_request(
            opened, decode_scoped_request(encoded), now_ms())
        self._confine_direct_origin(scoped)
        parsed = urllib.parse.urlsplit(scoped.url)
        connection_type = http.client.HTTPSConnection \
            if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(
            parsed.hostname, parsed.port, timeout=60)
        path = parsed.path + (
            "?" + parsed.query if parsed.query else "")
        try:
            connection.request(
                "PUT",
                path,
                body=io.BytesIO(raw),
                headers=dict(scoped.headers),
            )
            response = connection.getresponse()
            response_body = response.read(MAX_CONTROL_BYTES + 1)
            status = response.status
        except (OSError, http.client.HTTPException) as error:
            raise OutcomeUnknown(
                "direct immutable PUT outcome unknown") from error
        finally:
            connection.close()
        if len(response_body) > MAX_CONTROL_BYTES:
            raise ValueError("direct immutable PUT response too large")
        if status in {200, 201}:
            return 201
        if status == 204:
            return 204
        if status in {409, 412}:
            digest = hashlib.sha256()
            try:
                copied = self.copy_obj(
                    oid, response_limit=len(raw), write=digest.update)
            except Exception as error:
                raise ValueError("remote immutable create conflict") \
                    from error
            if copied == len(raw) and digest.hexdigest() == oid:
                return 204
            raise ValueError("remote immutable create conflict")
        if status in {408, 425, 429} or status >= 500:
            raise OutcomeUnknown(
                f"direct immutable PUT returned HTTP {status}")
        raise ValueError(
            f"direct immutable PUT returned HTTP {status}")

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
