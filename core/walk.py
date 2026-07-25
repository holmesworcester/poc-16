"""HTTP peer and pile-transfer helpers for the engine sync driver."""
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

    def put_pile(self, b):
        self._http(
            "PUT", f"/pile/{self.node.member_for(self.ws)}/{h(b)}", data=b)

    def poke(self):
        self._http("POST", "/poke", data=b"", auth=False)


def walk(node, ws, url):
    """Compatibility name for the shared engine diff driver."""
    from .sync import sync
    return sync(node, ws, url)


def _push(node, ws, peer, push_fids):
    """Close one range's push set into a pile and PUT it — the mirror of a
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


def _fetch_blobs(node, ws, peer):
    """Spilled bodies ride blob/ (served by the same page route): fetch what
    accepted file facts reference and we lack."""
    st = node.store(ws)
    with node.lock:
        refs = {blob for (fid,) in node.idx(ws).execute("SELECT fid FROM facts")
                for blob in families.blob_refs(node.fact_of(ws, fid))}
    for bh in refs:
        if not st.has("obj/" + bh):
            b = peer.obj(bh)
            if b and h(b) == bh:
                st.put("obj/" + bh, b)
