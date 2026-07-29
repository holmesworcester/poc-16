"""HTTP peer and pile-transfer helpers for the sync dial."""
import base64
import json
import urllib.error
import urllib.request

import facts as families
from .close import close, encode_pile
from .crypto import h, unseal
from facts.auth import request as auth_request
from .kernel import resolve_deps
from .node import now_ms
from .pump import pump

ARRIVAL_BATCH = 16


class Peer:
    """HTTP client for one (workspace, responder) pair; grants are opaque
    request decorators, re-minted on 401."""

    def __init__(self, node, ws, url):
        self.node, self.ws, self.url = node, ws, url
        self.cache = node.sync_cache.setdefault((ws, url), {})

    def _http(self, method, path, data=None, etag=None, auth=True, retry=True):
        req = urllib.request.Request(f"{self.url}{path}?ws={self.ws}", data=data, method=method)
        if auth:
            if "token" not in self.cache:
                self.mint()
            req.add_header("Authorization", "Bearer " + self.cache["token"])
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, b"", {}
            if e.code == 401 and auth and retry:
                self.cache.pop("token", None)
                return self._http(method, path, data, etag, auth, retry=False)
            raise

    def mint(self):
        """The handshake: a small closed pile — request fact + its auth
        closure — judged by the responder's kernel; the grant comes back
        encrypted to our key."""
        n = self.node
        with n.lock:
            ts = now_ms()
            facts = auth_request.payload(n, self.ws, "sync", ts + 120_000, ts)
        body = json.dumps({"ws": self.ws,
                           "pile": base64.b64encode(encode_pile(facts)).decode()}).encode()
        _, resp, _ = self._http("POST", "/mint", body, auth=False)
        o = json.loads(resp)
        secret, _ = self.node.identity(self.ws)
        self.cache["token"] = unseal(
            secret, base64.b64decode(o["grant"])).decode()

    def root(self, etag=None):
        status, b, hdr = self._http("GET", "/root", etag=etag)
        return None if status == 304 else (b, hdr.get("ETag"))

    def obj(self, oh):
        _, b, _ = self._http("GET", f"/page/{oh}")
        return b

    def objs(self, oids):
        """Fetch an ordered object batch in one authenticated request."""
        oids = tuple(oids)
        _, raw, _ = self._http(
            "POST", "/page", json.dumps(oids).encode())
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) != len(oids):
            raise ValueError("page batch")
        return tuple(
            base64.b64decode(value, validate=True)
            if value is not None else None
            for value in values
        )

    def put_pile(self, b):
        self._http(
            "PUT", f"/pile/{self.node.member_for(self.ws)}/{h(b)}", data=b)

    def poke(self):
        self._http("POST", "/poke", data=b"", auth=False)


def _push(node, ws, peer, push_fids):
    """Close one dial's push set into a pile and PUT it — the mirror of a
    pull. The responder drains on receipt, so there is no poke."""
    with node.lock:
        idx = node.idx(ws)
        facts = close([node.fact_of(ws, fid) for fid in push_fids],
                      lambda fid: resolve_deps(node.fact_of(ws, fid), idx) or [],
                      lambda fid: node.fact_of(ws, fid))
        st, blobs = node.store(ws), {}
        for f in facts:
            for bh in families.blob_refs(f):
                if st.has("obj/" + bh):
                    blobs[bh] = st.get("obj/" + bh)
        b = encode_pile(facts, blobs)
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
        notified = {
            fid for (fid,) in node.idx(ws).execute(
                "SELECT DISTINCT fid FROM log WHERE op='*'")
        }
        pending = []
        for (fid,) in node.idx(ws).execute("SELECT fid FROM proofs"):
            fact = node.fact_of(ws, fid)
            if node.suppressed(ws, fact):
                continue
            refs = families.blob_refs(fact)
            if refs:
                pending.append((fid, refs))
    landed, batch, complete = [], [], True
    for fid, refs in pending:
        fetched = False
        whole = True
        for oid in refs:
            if st.has("obj/" + oid):
                continue
            blob = peer.obj(oid)
            if blob and h(blob) == oid:
                st.put("obj/" + oid, blob)
                fetched = True
            else:
                whole = False
                complete = False
        if whole and (fetched or fid not in notified):
            batch.append(fid)
        if len(batch) >= ARRIVAL_BATCH:
            landed += _land(node, ws, batch)
            batch = []
    landed += _land(node, ws, batch)
    return landed, complete


def _land(node, ws, fids):
    fids = node.log_arrivals(ws, fids, repeat=True)
    if fids:
        pump(node, ws)
    return fids
