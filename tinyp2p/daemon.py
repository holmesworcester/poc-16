"""The daemon: a responder half (seven verbs, zero sync logic) plus an
initiator half (cadence walks round-robin over the keyring, kicked on news).

The gate is a parameter supplier: mint currys the workspace anchor and the
removal set into the one kernel; every other verb just checks the grant at
the door. Invite blobs are the one ungated read; LIST on them is denied
absolutely (there is no route).
"""
import base64
import hashlib
import hmac as hmaclib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import cmds
from .close import decode_pile
from .crypto import h, seal_to
from .facts.auth import request
from .kernel import evaluate
from .node import Node, now_ms
from .walk import walk

GRANT_TTL = int(os.environ.get("TINYP2P_GRANT_TTL", 60_000))


class Syncer(threading.Thread):
    """The initiator half: walk every (workspace, peer) each cadence; kick()
    for eager delivery after local news."""

    def __init__(self, node, cadence):
        super().__init__(daemon=True)
        self.node, self.cadence, self.wake = node, cadence, threading.Event()

    def kick(self):
        self.wake.set()

    def run(self):
        while True:
            self.wake.wait(self.cadence)
            self.wake.clear()
            for ws in self.node.workspaces():
                for url in self.node.keyring["workspaces"][ws]["peers"]:
                    try:
                        walk(self.node, ws, url)
                    except Exception:
                        if os.environ.get("TINYP2P_DEBUG"):
                            import traceback
                            traceback.print_exc()
                        # peer down or refused: the next cadence retries


def make_token(secret, member, ws):
    pj = json.dumps({"m": member, "ws": ws, "exp": now_ms() + GRANT_TTL}, sort_keys=True)
    mac = hmaclib.new(secret, pj.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(pj.encode()).decode() + "." + mac


def check_token(secret, auth, ws):
    try:
        body, mac = auth.split(" ", 1)[1].split(".")
        pj = base64.urlsafe_b64decode(body)
        if not hmaclib.compare_digest(
                hmaclib.new(secret, pj, hashlib.sha256).hexdigest(), mac):
            return None
        g = json.loads(pj)
        return g["m"] if g["ws"] == ws and g["exp"] > now_ms() else None
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    node = secret = syncer = None
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---- plumbing ----
    def _q(self):
        u = urlparse(self.path)
        return u.path.strip("/").split("/"), \
            {k: v[0] for k, v in parse_qs(u.query).items()}

    def _body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def _send(self, code, b=b"", ctype="application/json", etag=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(b)

    def _json(self, code, o):
        self._send(code, json.dumps(o).encode())

    def _member(self, ws):
        return check_token(self.secret, self.headers.get("Authorization", ""), ws)

    def _known(self, ws):
        return ws in self.node.keyring["workspaces"]

    # ---- the verbs ----
    def do_GET(self):
        parts, q = self._q()
        ws = q.get("ws", "")
        if parts[0] == "ctl":
            return self.ctl_get(parts, q)
        if parts[0] == "invite" and len(parts) == 2:  # the one ungated read
            b = self.node.store(ws).get("invite/" + parts[1]) if self._known(ws) else None
            return self._send(200, b, "application/octet-stream") if b else self._send(404)
        if not self._known(ws) or not self._member(ws):
            return self._send(401 if self._known(ws) else 404)
        if parts[0] == "root":
            self.node.turn(ws)  # a peer drains before serving its root
            b = self.node.store(ws).get("root") or b""
            etag = h(b)
            if self.headers.get("If-None-Match") == etag:
                return self._send(304)
            return self._send(200, b, etag=etag)
        if parts[0] == "page" and len(parts) == 2:  # leaf piles and blobs alike
            b = self.node.store(ws).get("obj/" + parts[1])
            return self._send(200, b, "application/octet-stream") if b else self._send(404)
        if parts[0] == "pile":
            return self._json(200, self.node.store(ws).list("pile/"))
        self._send(404)

    def do_PUT(self):
        parts, q = self._q()
        ws = q.get("ws", "")
        m = self._member(ws)
        if not self._known(ws) or not m:
            return self._send(401 if self._known(ws) else 404)
        if parts[0] == "pile" and len(parts) == 3 and parts[1] == m:
            b = self._body()
            if h(b) != parts[2]:
                return self._send(400)
            self.node.store(ws).put(f"pile/{m}/{parts[2]}", b)
            self.node.turn(ws)  # drain on receipt — a pushed pile needs no poke
            return self._send(204)  # delivery receipt; acceptance is the treap
        self._send(403)

    def do_POST(self):
        parts, q = self._q()
        if parts[0] == "ctl":
            return self.ctl_post(parts, self._body())
        ws = q.get("ws", "")
        if not self._known(ws):
            return self._send(404)
        if parts[0] == "poke":
            self.node.turn(ws)
            return self._send(204)
        if parts[0] == "mint":
            return self.mint(json.loads(self._body()))
        self._send(404)

    def mint(self, o):
        """Evaluate mode: the payload proves itself; no drain, no writes."""
        ws = o["ws"]
        if not self._known(ws):
            return self._send(404)
        try:
            facts, _ = decode_pile(base64.b64decode(o["pile"]))
        except Exception:
            return self._send(400)
        with self.node.lock:
            globals_ = self.node.globals(ws)
        ok = evaluate(facts, ws, globals_)
        rq = [fact for fact in facts if fact.t == request.TAG]
        if not ok or len(rq) != 1 or rq[0].body["exp"] < now_ms():
            return self._send(403)
        token = make_token(self.secret, rq[0].body["pk"][:16], ws)
        root = self.node.store(ws).get("root")
        return self._json(200, {
            "grant": base64.b64encode(seal_to(rq[0].body["pk"], token.encode())).decode(),
            "root": base64.b64encode(root).decode() if root else None,
            "etag": h(root) if root else None})

    # ---- node-local control plane (not part of the protocol) ----
    def ctl_get(self, parts, q):
        n, ws = self.node, self._resolve(q.get("ws", ""))
        if parts[1] == "status":
            return self._json(200, cmds.status(n))
        if parts[1] == "msgs":
            return self._json(200, cmds.msgs(n, ws, q.get("chan")))
        if parts[1] == "members":
            return self._json(200, cmds.members(n, ws))
        if parts[1] == "files":
            return self._json(200, cmds.files(n, ws))
        if parts[1] == "file":
            got = cmds.file_bytes(n, ws, q["fid"])
            if not got or got[1] is None:
                return self._send(404)
            return self._json(200, {"name": got[0],
                                    "data": base64.b64encode(got[1]).decode()})
        self._send(404)

    def ctl_post(self, parts, body):
        n, o = self.node, json.loads(body or b"{}")
        ws = self._resolve(o.get("ws", ""))
        try:
            if parts[1] == "create":
                return self._json(200, {"ws": cmds.create(n, o["name"])})
            if parts[1] == "invite":
                return self._json(200, {"link": cmds.make_invite(n, ws)})
            if parts[1] == "join":
                r = {"ws": cmds.join(n, o["link"], o["name"])}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "post":
                r = {"fid": cmds.post(n, ws, o.get("chan", "general"), o["text"], o.get("ts"))}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "send":
                r = {"fid": cmds.send_file(n, ws, o.get("chan", "general"), o["name"],
                                           base64.b64decode(o["data"]))}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "evict":
                r = {"fid": cmds.evict(n, ws, o["member"])}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "sync":
                for w in ([ws] if ws else n.workspaces()):
                    for url in n.keyring["workspaces"][w]["peers"]:
                        walk(n, w, url)
                return self._json(200, {"ok": True})
            if parts[1] == "rebuild":
                n.rebuild(ws)
                return self._json(200, {"ok": True})
        except Exception as e:
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(404)

    def _resolve(self, ws):
        """Accept a unique workspace-id prefix on the control plane."""
        hits = [w for w in self.node.workspaces() if w.startswith(ws)]
        return hits[0] if len(hits) == 1 and ws else ws


def serve(dir, port, host="127.0.0.1", cadence=1.0, url=None):
    node = Node(dir)
    node.url = url or f"http://{host}:{port}"
    syncer = Syncer(node, cadence)
    syncer.start()
    Handler.node, Handler.secret, Handler.syncer = node, os.urandom(32), syncer
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"tinyp2p daemon {node.member} on {node.url} ({dir})", flush=True)
    srv.serve_forever()
