"""The daemon: a responder half (seven verbs, zero sync logic) plus an
initiator half (cadence walks round-robin over the keyring, kicked on news).

The gate opens a root-stamped WorkerView and performs exact authority and
suppression reads; every other remote verb checks the resulting grant at the
door. Invite blobs are the one ungated read; LIST on them is denied absolutely
(there is no route).
"""
import base64
import hashlib
import hmac as hmaclib
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import actions, cmds, manifest, mint as gate
from .crypto import h, seal_to
from .node import Node, now_ms
from .store import PAGE_BATCH
from .sync import sync

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
                        sync(self.node, ws, url)
                    except Exception as error:
                        self.node.record_sync_failure(ws, url, error)
                        if os.environ.get("TINYP2P_DEBUG"):
                            import traceback
                            traceback.print_exc()
                        # peer down or refused: the next cadence retries
                    else:
                        self.node.record_sync_success(ws, url)


def make_token(secret, member, ws, verb="sync"):
    pj = json.dumps({
        "exp": now_ms() + GRANT_TTL, "m": member, "v": verb, "ws": ws,
    }, sort_keys=True)
    mac = hmaclib.new(secret, pj.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(pj.encode()).decode() + "." + mac


def check_token(secret, auth, ws, verb="sync"):
    try:
        body, mac = auth.split(" ", 1)[1].split(".")
        pj = base64.urlsafe_b64decode(body)
        if not hmaclib.compare_digest(
                hmaclib.new(secret, pj, hashlib.sha256).hexdigest(), mac):
            return None
        g = json.loads(pj)
        return g["m"] if g["ws"] == ws and g["v"] == verb \
            and g["exp"] > now_ms() else None
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
        if parts[0] == "page" and len(parts) == 2:  # store objects and blobs alike
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
            return self._send(204)  # delivery receipt; acceptance is the judge
        self._send(403)

    def do_POST(self):
        parts, q = self._q()
        if parts[0] == "ctl":
            return self.ctl_post(parts, self._body())
        ws = q.get("ws", "")
        if not self._known(ws):
            return self._send(404)
        if parts[0] == "page":
            if not self._member(ws):
                return self._send(401)
            try:
                oids = json.loads(self._body())
                if not isinstance(oids, list) or len(oids) > PAGE_BATCH \
                        or not all(
                        isinstance(oid, str) and len(oid) == 64
                        and all(c in "0123456789abcdef" for c in oid)
                        for oid in oids):
                    raise ValueError
            except (TypeError, ValueError):
                return self._send(400)
            store = self.node.store(ws)
            return self._json(200, [
                base64.b64encode(raw).decode() if raw is not None else None
                for raw in (store.get("obj/" + oid) for oid in oids)
            ])
        if parts[0] == "poke":
            self.node.turn(ws)
            return self._send(204)
        if parts[0] == "mint":
            try:
                return self.mint(json.loads(self._body()))
            except (TypeError, ValueError):
                return self._send(400)
        self._send(404)

    def mint(self, o):
        """Evaluate mode: the payload proves itself; no drain, no writes."""
        try:
            if not isinstance(o, dict):
                raise TypeError
            ws, encoded = o["ws"], o["pile"]
            if not isinstance(ws, str) or not isinstance(encoded, str):
                raise TypeError
            pile = base64.b64decode(encoded, validate=True)
        except (KeyError, TypeError, ValueError):
            return self._send(400)
        if not self._known(ws):
            return self._send(404)
        with self.node.lock:
            try:
                root = self.node.store(ws).get("root")
                if not root:
                    return self._send(403)
                anchor = manifest.decode_root(root)[0]
            except Exception:
                return self._send(403)
            if anchor != ws:
                return self._send(403)
            store = self.node.store(ws)
            grant = gate.stateless(
                pile, root, lambda oid: store.get("obj/" + oid), now_ms())
        if grant is None:
            return self._send(403)
        public, verb = grant
        token = make_token(self.secret, public[:16], ws, verb)
        return self._json(200, {
            "grant": base64.b64encode(
                seal_to(public, token.encode())).decode(),
            "root": base64.b64encode(root).decode(),
            "etag": h(root)})

    # ---- node-local control plane (not part of the protocol) ----
    def ctl_get(self, parts, q):
        n = self.node
        try:
            if len(parts) != 2:
                return self._send(404)
            if parts[1] == "status":
                return self._json(200, cmds.status(n))
            ws = self._resolve(q.get("ws", ""))
            if not self._known(ws):
                return self._send(404)
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
                return self._json(
                    200, {"name": got[0],
                          "data": base64.b64encode(got[1]).decode()})
            return self._send(404)
        except (KeyError, TypeError, ValueError):
            return self._send(400)

    def ctl_post(self, parts, body):
        try:
            if len(parts) != 2:
                return self._send(404)
            o = json.loads(body or b"{}")
            if not isinstance(o, dict):
                raise TypeError
        except (json.JSONDecodeError, TypeError):
            return self._send(400)
        n = self.node
        try:
            if parts[1] == "create":
                return self._json(200, {"ws": cmds.create(n, o["name"])})
            if parts[1] == "join":
                r = {"ws": cmds.join(n, o["link"], o["name"])}
                self.syncer.kick()
                return self._json(200, r)
            ws = self._resolve(o.get("ws", ""))
            if not self._known(ws):
                return self._send(404)
            if parts[1] == "invite":
                return self._json(200, {"link": cmds.make_invite(n, ws)})
            if parts[1] == "post":
                r = {"fid": cmds.post(n, ws, o.get("chan", "general"), o["text"], o.get("ts"))}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "send":
                r = {"fid": self.send_file(n, ws, o)}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "save":
                return self._json(
                    200, cmds.save_file(n, ws, o["fid"], o["out"]))
            if parts[1] == "evict":
                r = {"fid": cmds.evict(n, ws, o["member"])}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "remove":
                r = {"fid": cmds.remove(n, ws, o["fid"])}
                self.syncer.kick()
                return self._json(200, r)
            if parts[1] == "sync":
                for w in [ws]:
                    for url in n.keyring["workspaces"][w]["peers"]:
                        try:
                            sync(n, w, url)
                        except Exception as error:
                            n.record_sync_failure(w, url, error)
                            raise
                        else:
                            n.record_sync_success(w, url)
                return self._json(200, {"ok": True})
            if parts[1] == "rebuild":
                n.rebuild(ws)
                return self._json(200, {"ok": True})
        except actions.ScreenRejected as e:
            return self._json(403, {"error": f"{type(e).__name__}: {e}"})
        except (KeyError, TypeError, ValueError) as e:
            return self._json(400, {"error": f"{type(e).__name__}: {e}"})
        except Exception as e:
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(404)

    def send_file(self, node, ws, request):
        """Use daemon-local paths for large files; spool inline control data."""
        if request.get("path"):
            return cmds.send_file(
                node, ws, request.get("chan", "general"),
                request["path"], request.get("name"))
        handle, path = tempfile.mkstemp(prefix="poc-16-ctl-")
        try:
            with os.fdopen(handle, "wb") as spool:
                spool.write(base64.b64decode(request["data"]))
            return cmds.send_file(
                node, ws, request.get("chan", "general"), path,
                request.get("name") or "attachment")
        finally:
            os.unlink(path)

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
    print(f"core daemon {node.member} on {node.url} ({dir})", flush=True)
    srv.serve_forever()
