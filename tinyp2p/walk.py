"""The walk: one-sided reconciliation against a passive responder.

Decide with hashes, converge with piles. The initiator fetches the manifest
(one conditional GET in steady state), prunes ranges whose fingerprints
match, pulls differing ranges as closed units into its own ingress pile,
and at walk end pushes the symmetric difference — collect-then-close, one
pile, PUT + poke. The responder runs zero sync logic.
"""
import base64
import json
import urllib.error
import urllib.request

from . import fact as F
from .close import close, decode_pile, encode_pile
from .crypto import h, unseal
from .kernel import resolve_deps
from .layout import fingerprint
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
            rq = F.req(n.pk, "sync", ts + 120_000, ts)
            sg = F.sig_for(n.sk, n.pk, rq, ts)
            src = n.member_src(self.ws)
            newmap = {rq.fid: rq, sg.fid: sg}
            deps = {rq.fid: [sg.fid] + ([src] if src else []), sg.fid: []}
            facts = close([sg, rq],
                          lambda fid: deps.get(fid) if fid in deps else
                          (resolve_deps(n.fact_of(self.ws, fid), n.idx(self.ws)) or []),
                          lambda fid: newmap.get(fid) or n.fact_of(self.ws, fid))
        body = json.dumps({"ws": self.ws,
                           "pile": base64.b64encode(encode_pile(facts)).decode()}).encode()
        _, resp, _ = self._http("POST", "/mint", body, auth=False)
        o = json.loads(resp)
        self.cache["token"] = unseal(self.node.sk, base64.b64decode(o["grant"])).decode()

    def root(self, etag=None):
        status, b, hdr = self._http("GET", "/root", etag=etag)
        return None if status == 304 else (b, hdr.get("ETag"))

    def obj(self, oh):
        _, b, _ = self._http("GET", f"/page/{oh}")
        return b

    def put_pile(self, b):
        self._http("PUT", f"/pile/{self.node.member}/{h(b)}", data=b)

    def poke(self):
        self._http("POST", "/poke", data=b"", auth=False)


EMPTY = {"fences": [], "tail": {"fp": fingerprint([]), "n": 0, "page": None, "annex": None}}


def walk(node, ws, url):
    """One dial converges both sides. Returns (pulled_units, pushed_facts)."""
    peer = Peer(node, ws, url)
    cache = peer.cache
    got = peer.root(cache.get("etag"))
    if got is None:  # 304: nothing remote changed
        if node.store(ws).etag("root") == cache.get("local"):
            return 0, 0  # steady state costs one conditional GET
        man_bytes, retag = cache.get("man"), cache.get("etag")
    else:
        man_bytes, retag = got
    m = json.loads(man_bytes) if man_bytes else EMPTY

    ranges, lo = [], ""
    for fen in m["fences"]:
        ranges.append((lo, fen["hi"], fen))
        lo = fen["hi"]
    ranges.append((lo, "~", m["tail"]))  # ranges partition the whole keyspace

    with node.lock:
        lkeys = node.keys(ws)
    lfids = {k.split(":", 1)[1] for k in lkeys}
    pulled, push_fids = 0, []
    for lo, hi, fen in ranges:
        mine = [k for k in lkeys if lo < k <= hi]
        if fen["fp"] == fingerprint(mine):
            continue  # prune: equal fingerprint, equal range
        page = decode_pile(peer.obj(fen["page"]))[0] if fen.get("page") else []
        rfids = {f.fid for f in page}  # the responder's full in-range entries
        if any(fid not in lfids for fid in rfids):
            annex = decode_pile(peer.obj(fen["annex"]))[0] if fen.get("annex") else []
            b = encode_pile(annex + page)  # already a closed unit
            node.store(ws).put(f"pile/{node.member}/{h(b)}", b)
            pulled += 1
        push_fids += [k.split(":", 1)[1] for k in mine if k.split(":", 1)[1] not in rfids]

    if pulled:
        node.turn(ws)
        _fetch_blobs(node, ws, peer)

    if push_fids:  # the push tail: collect-then-close, one pile
        with node.lock:
            idx = node.idx(ws)
            news = [node.fact_of(ws, fid) for fid in push_fids]
            facts = close(news, lambda fid: resolve_deps(node.fact_of(ws, fid), idx) or [],
                          lambda fid: node.fact_of(ws, fid))
            st, blobs = node.store(ws), {}
            for f in facts:
                bh = f.body.get("blob")
                if bh and st.has("obj/" + bh):
                    blobs[bh] = st.get("obj/" + bh)
            b = encode_pile(facts, blobs)
        peer.put_pile(b)
        peer.poke()
        retag = None  # remote root moved; re-read next walk

    cache.update({"etag": retag, "man": man_bytes, "local": node.store(ws).etag("root")})
    return pulled, len(push_fids)


def _fetch_blobs(node, ws, peer):
    """Spilled bodies ride blob/ (served by the same page route): fetch what
    accepted file facts reference and we lack."""
    st = node.store(ws)
    with node.lock:
        rows = node.app.execute("SELECT blob FROM files WHERE ws=?", (ws,)).fetchall()
    for (bh,) in rows:
        if not st.has("obj/" + bh):
            b = peer.obj(bh)
            if b and h(b) == bh:
                st.put("obj/" + bh, b)
