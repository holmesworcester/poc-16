"""Full-peer process composition with physically separate listeners.

Peer traffic is translated by :mod:`core.http_stdlib` into the shared,
database-free :class:`core.http.HttpGate`. This module owns only local sync
scheduling and an unconditionally loopback control listener.
"""

import ipaddress
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import facts

from core.limits import MAX_CONTROL_BYTES, PayloadTooLarge, decode_json
from core.http_stdlib import handler_for as peer_handler_for

from . import status
from .node import FullPeer, now_ms
from .sync import sync

LOCAL_COMMANDS = {
    "peer.rebuild": "_command_rebuild",
    "peer.status": "_command_status",
    "peer.sync": "_command_sync",
}


class Syncer(threading.Thread):
    """Walk every configured peer on cadence and after local authoring."""

    def __init__(self, node, cadence):
        super().__init__(daemon=True)
        self.node, self.cadence, self.wake = node, cadence, threading.Event()

    def kick(self):
        self.wake.set()

    def run(self):
        while True:
            self.wake.wait(self.cadence)
            self.wake.clear()
            for workspace in self.node.workspaces():
                for url in self.node.keyring["workspaces"][workspace]["peers"]:
                    try:
                        sync(self.node, workspace, url)
                    except Exception as error:
                        self.node.record_sync_failure(workspace, url, error)
                        if os.environ.get("TINYP2P_DEBUG"):
                            import traceback
                            traceback.print_exc()
                    else:
                        self.node.record_sync_success(workspace, url)


class ControlHandler(BaseHTTPRequestHandler):
    """The one local command envelope; it contains no peer-data routes."""

    node = syncer = None
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, value):
        return self._send(
            code, json.dumps(value, separators=(",", ":")).encode())

    def _body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("unsupported transfer encoding")
        claimed = self.headers.get("Content-Length")
        try:
            length = 0 if claimed is None else int(claimed)
        except (TypeError, ValueError) as error:
            raise ValueError("content length") from error
        if length < 0:
            raise ValueError("content length")
        if length > MAX_CONTROL_BYTES:
            raise PayloadTooLarge("control request too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("short control request")
        return body

    def do_POST(self):
        if urlparse(self.path).path != "/ctl/command":
            return self._send(404)
        try:
            body = self._body()
        except PayloadTooLarge:
            return self._send(413)
        except ValueError:
            return self._send(400)
        return self.dispatch(body)

    def dispatch(self, body):
        try:
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
        local_method = LOCAL_COMMANDS.get(path)
        application = facts.COMMANDS.get(path)
        if local_method is None and application is None:
            return self._json(404, {"error": f"unknown command: {path}"})
        try:
            if local_method is not None:
                result = getattr(self, local_method)(argv)
            else:
                result = facts.invoke_command(self.node, path, argv)
                self.syncer.kick()
            return self._json(200, result)
        except facts.WorkspaceNotFound as error:
            return self._json(
                404, {"error": f"{type(error).__name__}: {error}"})
        except (KeyError, TypeError, ValueError) as error:
            return self._json(
                400, {"error": f"{type(error).__name__}: {error}"})
        except Exception as error:
            return self._json(
                500, {"error": f"{type(error).__name__}: {error}"})

    def _workspace(self, argv, usage):
        if len(argv) != 1:
            raise ValueError(f"usage: {usage}")
        return facts.workspace_for(self.node, argv[0])

    def _command_status(self, argv):
        if argv:
            raise ValueError("usage: peer.status")
        return status.describe(self.node)

    def _command_sync(self, argv):
        workspace = self._workspace(argv, "peer.sync <workspace>")
        for url in self.node.keyring["workspaces"][workspace]["peers"]:
            try:
                sync(self.node, workspace, url)
            except Exception as error:
                self.node.record_sync_failure(workspace, url, error)
                raise
            else:
                self.node.record_sync_success(workspace, url)
        return {"ok": True}

    def _command_rebuild(self, argv):
        self.node.rebuild(self._workspace(
            argv, "peer.rebuild <workspace>"))
        return {"ok": True}


def control_handler_for(node, syncer):
    return type(
        "BoundControlHandler",
        (ControlHandler,),
        {"node": node, "syncer": syncer},
    )


def _control_server(node, syncer, host, port):
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError as error:
        raise ValueError("control listener must use a loopback IP") from error
    if not loopback:
        raise ValueError("control listener must use a loopback IP")
    return ThreadingHTTPServer(
        (host, port), control_handler_for(node, syncer))


def serve(
        directory, port, host="127.0.0.1", cadence=1.0, url=None, *,
        control_port=7101, store_factory=None):
    """Run peer data on the requested interface and control on loopback."""
    if port == control_port:
        raise ValueError("peer and control ports must differ")
    node = FullPeer(directory, store_factory=store_factory)
    syncer = Syncer(node, cadence)
    secret = os.urandom(32)
    peer_server = ThreadingHTTPServer(
        (host, port), peer_handler_for(node, secret))
    try:
        control_server = _control_server(
            node, syncer, "127.0.0.1", control_port)
    except BaseException:
        peer_server.server_close()
        raise
    actual_port = peer_server.server_address[1]
    node.url = url or f"http://{host}:{actual_port}"
    syncer.start()
    peer_thread = threading.Thread(
        target=peer_server.serve_forever, daemon=True)
    peer_thread.start()
    print(
        f"full peer {node.member}: data {node.url}; "
        f"control http://127.0.0.1:{control_server.server_address[1]} "
        f"({directory})",
        flush=True,
    )
    try:
        control_server.serve_forever()
    finally:
        peer_server.shutdown()
        peer_server.server_close()
        control_server.server_close()
        peer_thread.join()
