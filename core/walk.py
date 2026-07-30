"""HTTP peer and pile-transfer helpers for the sync dial."""
import base64
import json
import urllib.error
import urllib.request

import facts as families
from facts.auth import request as auth_request

from . import peer_capability
from .close import close, encode_pile
from .crypto import h, unseal
from .kernel import resolve_deps
from .limits import (
    MAX_CONTROL_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_PILE_BYTES,
    MAX_ROOT_BYTES,
    decode_json,
)
from .node import now_ms
from .object_store import ensure_object


class PushUnsupported(RuntimeError):
    """The authenticated peer profile does not accept pile delivery."""


class Peer:
    """HTTP client for one (workspace, responder) pair.

    Bearer authority stays opaque.  The sole decoded field is the fail-closed
    sync profile repeated by mint; both are replaced together on a 401.
    """

    def __init__(self, node, ws, url):
        self.node, self.ws, self.url = node, ws, url
        self.cache = node.sync_cache.setdefault((ws, url), {})

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
                claimed = r.headers.get("Content-Length")
                if claimed is not None:
                    try:
                        length = int(claimed)
                    except (TypeError, ValueError) as error:
                        raise ValueError("peer content length") from error
                    if length < 0 or length > response_limit:
                        raise ValueError("peer response too large")
                body = r.read(response_limit + 1)
                if len(body) > response_limit:
                    raise ValueError("peer response too large")
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
            facts = auth_request.payload(n, self.ws, "sync", ts + 120_000, ts)
        body = json.dumps({
            "ws": self.ws,
            "pile": base64.b64encode(
                encode_pile(facts, workspace=self.ws)).decode(),
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

    def root(self, etag=None):
        status, b, hdr = self._http(
            "GET", "/root", etag=etag, response_limit=MAX_ROOT_BYTES)
        response_etag = next(
            (value for name, value in hdr.items()
             if name.lower() == "etag"),
            None,
        )
        return None if status == 304 else (b, response_etag)

    def obj(self, oh):
        _, b, _ = self._http(
            "GET", f"/page/{oh}", response_limit=MAX_OBJECT_BYTES)
        return b

    def put_obj(self, oid, value):
        """Deliver one immutable object before facts that may name it."""
        if not isinstance(value, bytes) or len(value) > MAX_OBJECT_BYTES \
                or h(value) != oid:
            raise ValueError("immutable object address")
        self._http(
            "PUT", f"/page/{oid}", data=value, require_push=True,
            response_limit=MAX_CONTROL_BYTES)

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
                return (self.obj(oids[0]),)
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


def _push(node, ws, peer, push_fids):
    """Close one dial's push set into a pile and PUT it — the mirror of a
    pull. Available blob proofs travel as independently verified immutable
    objects before the fact-only pile: if an upload fails, the peer cannot
    publish a fact difference that only a one-way sender could satisfy.
    Replicas that do not yet hold a proof still relay its fact, allowing a
    receiver with another source to complete it. The responder drains the
    pile on receipt, so there is no poke."""
    with node.lock:
        idx = node.idx(ws)
        facts = close([node.fact_of(ws, fid) for fid in push_fids],
                      lambda fid: resolve_deps(node.fact_of(ws, fid), idx) or [],
                      lambda fid: node.fact_of(ws, fid))
        blob_oids = sorted({
            oid for fact in facts for oid in families.blob_refs(fact)
        })
        b = encode_pile(facts, workspace=ws)
        st = node.store(ws)
    for oid in blob_oids:
        value = st.get("obj/" + oid)
        if value is None:
            continue
        if h(value) != oid:
            raise ValueError("local immutable object integrity")
        peer.put_obj(oid, value)
    peer.put_pile(b)
    return tuple(fact.fid for fact in facts)


def _fetch_blobs(node, ws, peer):
    """Fetch missing spilled objects.

    Return ``(landed_fids, complete)`` so a caller stamps an ETag only after
    every live reference is present; a transient bad/missing proof must retry
    on the next unchanged-root dial.
    """
    st = node.store(ws)
    with node.lock:
        pending = []
        for (fid,) in node.idx(ws).execute("SELECT fid FROM proofs"):
            fact = node.fact_of(ws, fid)
            if node.suppressed(ws, fact):
                continue
            refs = families.blob_refs(fact)
            if refs:
                pending.append((fid, refs))
    landed, complete = [], True
    for fid, refs in pending:
        fetched = False
        whole = True
        for oid in refs:
            if st.has("obj/" + oid):
                continue
            blob = peer.obj(oid)
            if blob and h(blob) == oid:
                ensure_object(st, oid, blob)
                fetched = True
            else:
                whole = False
                complete = False
        if whole and fetched:
            landed.append(fid)
    return landed, complete
