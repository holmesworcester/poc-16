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

from . import cmds, manifest, mint as gate, peer_capability, shape
from .crypto import h, seal_to
from .fetch_budget import BudgetedFetch
from .grants import check_token as _check_token
from .grants import make_token as _make_token
from .limits import (
    MAX_CONTROL_BYTES,
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_REQUEST_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PAGE_BATCH_BYTES,
    MAX_PAGE_REQUEST_BYTES,
    MAX_PILE_BYTES,
    MAX_ROOT_BYTES,
    PAGE_BATCH,
    PayloadTooLarge,
    decode_json,
)
from .node import Node, now_ms
from .object_store import ensure_object
from .runtime import AuthorityRejected
from .sync import sync

GRANT_TTL = int(os.environ.get("TINYP2P_GRANT_TTL", 60_000))


def _env_budget(name, ceiling):
    try:
        value = int(os.environ.get(name, ceiling))
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"invalid {name}") from error
    if not 0 <= value <= ceiling:
        raise RuntimeError(f"invalid {name}")
    return value


MINT_MAX_FETCHES = _env_budget(
    "TINYP2P_MINT_MAX_FETCHES", MAX_MINT_FETCHES)
MINT_MAX_FETCH_BYTES = _env_budget(
    "TINYP2P_MINT_MAX_FETCH_BYTES", MAX_MINT_FETCH_BYTES)
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

    def _body(self, limit):
        """Read exactly one bounded, non-chunked request body."""
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("unsupported transfer encoding")
        claimed = self.headers.get("Content-Length")
        try:
            length = 0 if claimed is None else int(claimed)
        except (TypeError, ValueError) as error:
            raise ValueError("content length") from error
        if length < 0:
            raise ValueError("content length")
        if length > limit:
            raise PayloadTooLarge("request body too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("short request body")
        return body

    def _send(self, code, b=b"", ctype="application/json", etag=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(b)

    def _json(self, code, o):
        body = json.dumps(o, separators=(",", ":")).encode()
        return self._send(code, body)

    def _json_limited(self, code, o, limit):
        body = json.dumps(o, separators=(",", ":")).encode()
        if len(body) > limit:
            return self._send(413)
        return self._send(code, body)

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
            if b is None:
                return self._send(404)
            if len(b) > MAX_OBJECT_BYTES:
                return self._send(503)
            return self._send(200, b, "application/octet-stream")
        if not self._known(ws) or not self._member(ws):
            return self._send(401 if self._known(ws) else 404)
        if parts[0] == "root":
            self.node.turn(ws)  # a peer drains before serving its root
            b = self.node.store(ws).get("root") or b""
            if len(b) > MAX_ROOT_BYTES:
                return self._send(503)
            etag = h(b)
            if self.headers.get("If-None-Match") == etag:
                return self._send(304)
            return self._send(200, b, etag=etag)
        if parts[0] == "page" and len(parts) == 2:  # store objects and blobs alike
            if not shape.valid_fid(parts[1]):
                return self._send(404)
            b = self.node.store(ws).get("obj/" + parts[1])
            if b is None:
                return self._send(404)
            if len(b) > MAX_OBJECT_BYTES or h(b) != parts[1]:
                return self._send(503)
            return self._send(200, b, "application/octet-stream")
        if parts[0] == "pile":
            return self._json_limited(
                200, self.node.store(ws).list("pile/"), MAX_CONTROL_BYTES)
        self._send(404)

    def do_PUT(self):
        parts, q = self._q()
        ws = q.get("ws", "")
        if not self._known(ws):
            return self._send(404)
        m = self._member(ws, require_push=True)
        if not m:
            return self._send(401)
        if parts[0] == "page" and len(parts) == 2:
            if not shape.valid_fid(parts[1]):
                return self._send(404)
            try:
                raw = self._body(MAX_OBJECT_BYTES)
                ensure_object(self.node.store(ws), parts[1], raw)
            except PayloadTooLarge:
                return self._send(413)
            except ValueError:
                return self._send(400)
            return self._send(204)
        if parts[0] == "pile" and len(parts) == 3 and parts[1] == m:
            try:
                b = self._body(MAX_PILE_BYTES)
            except PayloadTooLarge:
                return self._send(413)
            except ValueError:
                return self._send(400)
            if h(b) != parts[2]:
                return self._send(400)
            self.node.store(ws).put(f"pile/{m}/{parts[2]}", b)
            self.node.turn(ws)  # drain on receipt — a pushed pile needs no poke
            return self._send(204)  # delivery receipt; acceptance is the judge
        self._send(403)

    def do_POST(self):
        parts, q = self._q()
        if parts[0] == "ctl":
            try:
                body = self._body(MAX_CONTROL_BYTES)
            except PayloadTooLarge:
                return self._send(413)
            except ValueError:
                return self._send(400)
            return self.ctl_post(parts, body)
        ws = q.get("ws", "")
        if not self._known(ws):
            return self._send(404)
        if parts[0] == "page":
            if not self._member(ws):
                return self._send(401)
            try:
                oids = decode_json(
                    self._body(MAX_PAGE_REQUEST_BYTES),
                    MAX_PAGE_REQUEST_BYTES, "page request")
                if not isinstance(oids, list) or not all(
                        shape.valid_fid(oid)
                        for oid in oids):
                    raise ValueError
                if len(oids) > PAGE_BATCH:
                    return self._send(413)
            except PayloadTooLarge:
                return self._send(413)
            except (TypeError, ValueError):
                return self._send(400)
            store = self.node.store(ws)
            values, encoded_size = [], 2
            for index, oid in enumerate(oids):
                raw = store.get("obj/" + oid)
                if raw is not None and (
                        len(raw) > MAX_OBJECT_BYTES or h(raw) != oid):
                    return self._send(503)
                item_size = 4 if raw is None \
                    else 2 + 4 * ((len(raw) + 2) // 3)
                encoded_size += item_size + (1 if index else 0)
                if encoded_size > MAX_PAGE_BATCH_BYTES:
                    return self._send(413)
                values.append(
                    base64.b64encode(raw).decode()
                    if raw is not None else None)
            return self._json(200, values)
        if parts[0] == "poke":
            try:
                if self._body(MAX_CONTROL_BYTES):
                    return self._send(400)
            except PayloadTooLarge:
                return self._send(413)
            except ValueError:
                return self._send(400)
            self.node.turn(ws)
            return self._send(204)
        if parts[0] == "mint":
            try:
                body = self._body(MAX_MINT_REQUEST_BYTES)
                return self.mint(decode_json(
                    body, MAX_MINT_REQUEST_BYTES, "mint request"))
            except PayloadTooLarge:
                return self._send(413)
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
            request = decode_json(
                body or b"{}", MAX_CONTROL_BYTES, "control request")
            if not isinstance(request, dict) \
                    or set(request) != {"path", "argv"} \
                    or not isinstance(request["path"], str) \
                    or not isinstance(request["argv"], list) \
                    or not all(
                        isinstance(token, str) for token in request["argv"]):
                raise TypeError
        except (TypeError, ValueError):
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


def serve(
        dir, port, host="127.0.0.1", cadence=1.0, url=None, *,
        store_factory=None):
    node = Node(dir, store_factory=store_factory)
    node.url = url or f"http://{host}:{port}"
    syncer = Syncer(node, cadence)
    syncer.start()
    Handler.node, Handler.secret, Handler.syncer = node, os.urandom(32), syncer
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"core daemon {node.member} on {node.url} ({dir})", flush=True)
    srv.serve_forever()
