"""Full-peer process composition with physically separate listeners.

Peer traffic is translated by :mod:`core.http_stdlib` into the shared,
database-free :class:`core.http.HttpGate`. This module owns only local sync
scheduling and an unconditionally loopback control listener.
"""

import ipaddress
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import facts

from core.limits import MAX_CONTROL_BYTES, PayloadTooLarge, decode_json
from core.http_stdlib import HttpGateOptions
from core.http_stdlib import handler_for as peer_handler_for

from . import status
from .iroh_forwarders import IrohForwarders
from .iroh_process import IrohProcess, STOP_SECONDS
from .keychain import iroh_peer
from .node import FullPeer
from .sync import sync

LOCAL_COMMANDS = {
    "peer.iroh.remove": "_command_iroh_remove",
    "peer.iroh.set": "_command_iroh_set",
    "peer.rebuild": "_command_rebuild",
    "peer.status": "_command_status",
    "peer.sync": "_command_sync",
}


class Syncer(threading.Thread):
    """Walk every configured peer on cadence and after local authoring."""

    def __init__(self, node, cadence):
        super().__init__(daemon=True)
        self.node, self.cadence = node, cadence
        self.wake, self.stopping = threading.Event(), threading.Event()

    def kick(self):
        self.wake.set()

    def stop(self):
        self.stopping.set()
        self.wake.set()

    @staticmethod
    def _peer_name(peer):
        return peer if isinstance(peer, str) \
            else f"iroh:{peer['endpoint']}"

    def sync_workspace(self, workspace, *, fail=False):
        for peer in self.node.keyring["workspaces"][workspace]["peers"]:
            name = self._peer_name(peer)
            try:
                url = self.node.resolve_peer(workspace, peer)
                sync(self.node, workspace, url)
            except Exception as error:
                self.node.record_sync_failure(workspace, name, error)
                if fail:
                    raise
                if os.environ.get("TINYP2P_DEBUG"):
                    import traceback
                    traceback.print_exc()
            else:
                self.node.record_sync_success(workspace, name)

    def run(self):
        while not self.stopping.is_set():
            self.wake.wait(self.cadence)
            self.wake.clear()
            if self.stopping.is_set():
                return
            for workspace in self.node.workspaces():
                self.sync_workspace(workspace)


def _loopback(host, label):
    try:
        allowed = ipaddress.ip_address(host).is_loopback
    except ValueError as error:
        raise ValueError(f"{label} must use a loopback IP") from error
    if not allowed:
        raise ValueError(f"{label} must use a loopback IP")


def _http_address(host, port):
    return f"http://[{host}]:{port}" if ":" in host \
        else f"http://{host}:{port}"


def _socket_address(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


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
        self.syncer.sync_workspace(workspace, fail=True)
        return {"ok": True}

    def _command_iroh_set(self, argv):
        if len(argv) != 3:
            raise ValueError(
                "usage: peer.iroh.set <workspace> <endpoint> <ticket>")
        workspace = facts.workspace_for(self.node, argv[0])
        self.node.set_iroh_peer(workspace, argv[1], argv[2])
        self.syncer.kick()
        return {"ok": True}

    def _command_iroh_remove(self, argv):
        if len(argv) != 2:
            raise ValueError(
                "usage: peer.iroh.remove <workspace> <endpoint>")
        workspace = facts.workspace_for(self.node, argv[0])
        self.node.remove_iroh_peer(workspace, argv[1])
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
    _loopback(host, "control listener")
    server = ThreadingHTTPServer(
        (host, port), control_handler_for(node, syncer))
    server.daemon_threads = True
    return server


class FullPeerService:
    """Supervise the data gate, local control, scheduler, and Iroh wrapper."""

    def __init__(
            self, directory, port, host="127.0.0.1", cadence=1.0,
            url=None, *, control_port=7101, store_factory=None,
            gate_options=None, iroh_binary=None, iroh_key_file=None,
            iroh_loopback=False):
        if port == control_port and port != 0:
            raise ValueError("peer and control ports must differ")
        if iroh_binary is not None:
            _loopback(host, "Iroh peer-data listener")
            if url is not None:
                raise ValueError(
                    "Iroh mode cannot advertise a plain HTTP peer URL")

        self.directory = directory
        self.node = FullPeer(directory, store_factory=store_factory)
        self.syncer = Syncer(self.node, cadence)
        gate_options = HttpGateOptions() \
            if gate_options is None else gate_options
        self.peer_server = ThreadingHTTPServer(
            (host, port), peer_handler_for(
                self.node,
                os.urandom(32),
                gate_options=gate_options,
            ))
        self.peer_server.daemon_threads = True
        try:
            self.control_server = _control_server(
                self.node, self.syncer, "127.0.0.1", control_port)
        except BaseException:
            self.peer_server.server_close()
            raise

        data_host, actual_port = self.peer_server.server_address[:2]
        self.data_address = _http_address(data_host, actual_port)
        self.control_address = _http_address(
            "127.0.0.1", self.control_server.server_address[1])
        # Never serialize the accepting peer's private loopback seam.
        self.node.peer_address = None if iroh_binary is not None \
            else url or self.data_address
        self.iroh_binary = iroh_binary
        self.iroh_key_file = Path(
            iroh_key_file
            or Path(directory) / "iroh" / "endpoint.key")
        self.iroh_loopback = iroh_loopback
        self.iroh = None
        self.forwarders = None if iroh_binary is None else IrohForwarders(
            iroh_binary, loopback=iroh_loopback)
        self.peer_thread = self.monitor_thread = None
        self._control_thread = None
        self._control_active = threading.Event()
        self._closing = threading.Event()
        self._started = False
        self._failure = None
        self._failure_lock = threading.Lock()

    @property
    def failure(self):
        with self._failure_lock:
            return self._failure

    def _fail(self, message):
        if self._closing.is_set():
            return
        with self._failure_lock:
            if self._failure is not None:
                return
            self._failure = message
        # The control loop is the main wait point. Its shutdown unblocks run();
        # Stop peer data immediately when the supervised acceptor disappears.
        if threading.current_thread() is not self.peer_thread:
            self.peer_server.shutdown()
        if self._control_active.is_set():
            self.control_server.shutdown()

    def _serve_peer_data(self):
        try:
            self.peer_server.serve_forever()
        except BaseException as error:
            self._fail(
                f"peer-data listener failed: {type(error).__name__}: {error}")
        else:
            self._fail("peer-data listener stopped unexpectedly")

    def _monitor(self):
        while not self._closing.wait(.05):
            if self.peer_thread is not None \
                    and not self.peer_thread.is_alive():
                self._fail("peer-data listener died")
                return
            if self.iroh is not None:
                code = self.iroh.process.poll()
                if code is not None:
                    self._fail(f"Iroh child exited unexpectedly ({code})")
                    return
            if self.forwarders is not None:
                self.forwarders.maintain()

    def start(self):
        if self._started:
            raise RuntimeError("full peer service already started")
        try:
            self.peer_thread = threading.Thread(
                target=self._serve_peer_data,
                name="full-peer-data",
                daemon=True,
            )
            self.peer_thread.start()
            self._started = True
            if self.iroh_binary is not None:
                host, port = self.peer_server.server_address[:2]
                self.iroh = IrohProcess.start(
                    self.iroh_binary,
                    _socket_address(host, port),
                    self.iroh_key_file,
                    loopback=self.iroh_loopback,
                )
                advertised = iroh_peer(
                    self.iroh.ready.endpoint_id, self.iroh.ready.peer)
                self.node.use_iroh(advertised, self.forwarders)
            self.syncer.start()
            self.monitor_thread = threading.Thread(
                target=self._monitor,
                name="full-peer-supervisor",
                daemon=True,
            )
            self.monitor_thread.start()
        except BaseException:
            self.close()
            raise
        return self

    def report(self):
        print(
            f"full peer {self.node.member}: data {self.data_address}; "
            f"control {self.control_address} ({self.directory})",
            flush=True,
        )
        if self.iroh is not None:
            print(
                f"IROH endpoint_id={self.iroh.ready.endpoint_id} "
                f"peer={self.iroh.ready.peer} pid={self.iroh.process.pid}",
                flush=True,
            )

    def run(self):
        self.start()
        if self.failure is not None:
            self.close()
            raise RuntimeError(self.failure)
        self.report()
        self._control_thread = threading.current_thread()
        self._control_active.set()
        try:
            if self.failure is not None:
                raise RuntimeError(self.failure)
            self.control_server.serve_forever()
            if not self._closing.is_set() and self.failure is None:
                self._fail("control listener stopped unexpectedly")
        finally:
            self._control_active.clear()
            self.close()
        if self.failure is not None:
            raise RuntimeError(self.failure)

    def close(self):
        if self._closing.is_set():
            return
        self._closing.set()
        self.syncer.stop()
        if self._started:
            self.peer_server.shutdown()
        if self._control_active.is_set() \
                and threading.current_thread() is not self._control_thread:
            self.control_server.shutdown()
        self.peer_server.server_close()
        self.control_server.server_close()
        if self.forwarders is not None:
            self.forwarders.close()
        if self.iroh is not None:
            self.iroh.stop()
        if self.peer_thread is not None:
            self.peer_thread.join(STOP_SECONDS)
        if self.monitor_thread is not None:
            self.monitor_thread.join(STOP_SECONDS)
        if self.syncer.is_alive():
            self.syncer.join(STOP_SECONDS)


def _run_service(service):
    """Give SIGTERM the same bounded cleanup path as Ctrl-C."""
    handlers = {}
    main_thread = threading.current_thread() is threading.main_thread()

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    if main_thread:
        for name in ("SIGINT", "SIGTERM"):
            number = getattr(signal, name, None)
            if number is not None:
                handlers[number] = signal.getsignal(number)
                signal.signal(number, interrupt)
    try:
        service.run()
    except KeyboardInterrupt:
        service.close()
    finally:
        if main_thread:
            for number, handler in handlers.items():
                signal.signal(number, handler)


def serve(
        directory, port, host="127.0.0.1", cadence=1.0, url=None, *,
        control_port=7101, store_factory=None, gate_options=None,
        iroh_binary=None, iroh_key_file=None, iroh_loopback=False):
    """Run one full peer; optionally expose peer data only through Iroh."""
    service = FullPeerService(
        directory,
        port,
        host,
        cadence,
        url,
        control_port=control_port,
        store_factory=store_factory,
        gate_options=gate_options,
        iroh_binary=iroh_binary,
        iroh_key_file=iroh_key_file,
        iroh_loopback=iroh_loopback,
    )
    return _run_service(service)
