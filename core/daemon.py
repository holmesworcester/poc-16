"""The daemon: a responder half (seven verbs, zero sync logic) plus an
initiator half (cadence walks round-robin over the keyring, kicked on news).

The gate opens a root-stamped WorkerView and performs exact authority and
suppression reads; every other remote verb checks the resulting grant at the
door. Invite blobs are the one ungated read; LIST on them is denied absolutely
(there is no route).
"""
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import facts

from . import cmds, manifest, mint as gate, peer_capability
from .crypto import h, seal_to
from .fetch_budget import BudgetedFetch
from .grants import check_token as _check_token
from .grants import make_token as _make_token
from .node import Node, now_ms
from .runtime import AuthorityRejected
from .store import PAGE_BATCH
from .sync import sync

GRANT_TTL = int(os.environ.get("TINYP2P_GRANT_TTL", 60_000))
MINT_MAX_FETCHES = int(os.environ.get("TINYP2P_MINT_MAX_FETCHES", 128))
MINT_MAX_FETCH_BYTES = int(
    os.environ.get("TINYP2P_MINT_MAX_FETCH_BYTES", 4 * 1024 * 1024))
CORE_COMMANDS = {
    "core.rebuild": "_command_rebuild",
    "core.status": "_command_status",
    "core.sync": "_command_sync",
}


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


def make_token(
        secret, member, ws, verb="sync",
        capability=peer_capability.FULL):
    return _make_token(
        secret, member, ws, verb,
        capability=capability, issued_at=now_ms(), ttl_ms=GRANT_TTL)


def check_token(secret, auth, ws, verb="sync", *, require_push=False):
    return _check_token(
        secret, auth, ws, verb,
        trusted_now=now_ms(), require_push=require_push)


class Handler(BaseHTTPRequestHandler):
    node = secret = syncer = None
    sync_profile = peer_capability.FULL
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

    def _member(self, ws, *, require_push=False):
        return check_token(
            self.secret, self.headers.get("Authorization", ""), ws,
            require_push=require_push)

    def _known(self, ws):
        return ws in self.node.keyring["workspaces"]

    # ---- the verbs ----
    def do_GET(self):
        parts, q = self._q()
        ws = q.get("ws", "")
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
        m = self._member(ws, require_push=True)
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
        """Read-only gate: judge the bounded proof without admitting it."""
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
                anchor = manifest.decode_root(root).anchor
            except Exception:
                return self._send(403)
            if anchor != ws:
                return self._send(403)
            store = self.node.store(ws)
            fetch = BudgetedFetch(
                lambda oid: store.get("obj/" + oid),
                max_fetches=MINT_MAX_FETCHES,
                max_bytes=MINT_MAX_FETCH_BYTES,
            )
            grant = gate.stateless(
                pile, root, fetch, now_ms())
        if grant is None:
            return self._send(403)
        public, verb = grant
        token = make_token(
            self.secret, public[:16], ws, verb, self.sync_profile)
        response = {
            "grant": base64.b64encode(
                seal_to(public, token.encode())).decode(),
            "root": base64.b64encode(root).decode(),
            "etag": h(root)}
        if self.sync_profile is not None:
            response["cap"] = self.sync_profile
        return self._json(200, response)

    # ---- node-local control plane (not part of the protocol) ----
    def ctl_post(self, parts, body):
        try:
            if parts != ["ctl", "command"]:
                return self._send(404)
            request = json.loads(body or b"{}")
            if not isinstance(request, dict) \
                    or set(request) != {"path", "argv"} \
                    or not isinstance(request["path"], str) \
                    or not isinstance(request["argv"], list) \
                    or not all(
                        isinstance(token, str) for token in request["argv"]):
                raise TypeError
        except (json.JSONDecodeError, TypeError):
            return self._send(400)

        path, argv = request["path"], request["argv"]
        core_method = CORE_COMMANDS.get(path)
        application = facts.COMMANDS.get(path)
        if core_method is None and application is None:
            return self._json(404, {"error": f"unknown command: {path}"})
        try:
            if core_method is not None:
                result = getattr(self, core_method)(argv)
            else:
                result = facts.invoke_command(self.node, path, argv)
                self.syncer.kick()
            return self._json(200, result)
        except AuthorityRejected as e:
            return self._json(403, {"error": f"{type(e).__name__}: {e}"})
        except facts.WorkspaceNotFound as e:
            return self._json(404, {"error": f"{type(e).__name__}: {e}"})
        except (KeyError, TypeError, ValueError) as e:
            return self._json(400, {"error": f"{type(e).__name__}: {e}"})
        except Exception as e:
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _core_workspace(self, argv, usage):
        if len(argv) != 1:
            raise ValueError(f"usage: {usage}")
        return facts.workspace_for(self.node, argv[0])

    def _command_status(self, argv):
        if argv:
            raise ValueError("usage: core.status")
        return cmds.status(self.node)

    def _command_sync(self, argv):
        ws = self._core_workspace(argv, "core.sync <workspace>")
        for url in self.node.keyring["workspaces"][ws]["peers"]:
            try:
                sync(self.node, ws, url)
            except Exception as error:
                self.node.record_sync_failure(ws, url, error)
                raise
            else:
                self.node.record_sync_success(ws, url)
        return {"ok": True}

    def _command_rebuild(self, argv):
        ws = self._core_workspace(argv, "core.rebuild <workspace>")
        self.node.rebuild(ws)
        return {"ok": True}


def serve(dir, port, host="127.0.0.1", cadence=1.0, url=None):
    node = Node(dir)
    node.url = url or f"http://{host}:{port}"
    syncer = Syncer(node, cadence)
    syncer.start()
    Handler.node, Handler.secret, Handler.syncer = node, os.urandom(32), syncer
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"core daemon {node.member} on {node.url} ({dir})", flush=True)
    srv.serve_forever()
