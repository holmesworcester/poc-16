"""Real-link FullPeer catch-up over a shaped Linux namespace pair.

The default ``run`` mode creates two isolated network stacks joined by a veth
pair, applies kernel rate and delay controls, measures the useful TCP line rate,
and then times production FullPeer HTTP catch-up through that same link.  It
requires passwordless sudo only for the temporary namespace setup; peer state
and benchmark results remain owned by the invoking user.
"""
import argparse
import asyncio
from collections import Counter
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import facts

from bench.writer_p2p_cost import MeteredPeer
from core.limits import (
    DIRECT_STREAM_CHUNK_BYTES,
    MAX_DIRECT_OBJECT_BYTES,
    MAX_OBJECT_BYTES,
)
from core.pack_access import (
    MAX_SCOPED_REQUEST_BYTES,
    ObjectOpen,
    confine_object_request,
    copy_object_get,
    decode_scoped_request,
    encode_object_open,
)
from core.store import RemoteStore
from full_peer.node import FullPeer
from full_peer import walk as walk_module


DEFAULT_BANDWIDTH_MBIT = 5
DEFAULT_RTT_MS = 20
DEFAULT_PILES = 16
DEFAULT_TEXT_BYTES = 2 * 1024 * 1024
DEFAULT_LINE_BYTES = 8 * 1024 * 1024
DEFAULT_RATE_FRACTION = .70
SOURCE_ADDRESS = "10.247.16.1"
TARGET_ADDRESS = "10.247.16.2"
PEER_PORT = 17816
LINE_PORT = 17817


@dataclass(frozen=True, slots=True)
class RequestEvent:
    method: str
    path: str
    started: float
    stopped: float
    request_bytes: int
    response_bytes: int


def request_waves(events):
    """Count observed sequential/overlapping request phases."""
    ordered = sorted(events, key=lambda event: event.started)
    if not ordered:
        return 0
    waves = 1
    wave_stop = ordered[0].stopped
    for event in ordered[1:]:
        if event.started >= wave_stop:
            waves += 1
            wave_stop = event.stopped
        else:
            wave_stop = max(wave_stop, event.stopped)
    return waves


class NetworkMeteredPeer(MeteredPeer):
    """Production HTTP peer with actual request timing and path accounting."""

    def __init__(self, node, workspace, url):
        super().__init__(node, workspace, url)
        self.events = []
        self._events_lock = threading.Lock()

    def _http(self, method, path, data=None, *args, **kwargs):
        started = time.perf_counter()
        try:
            response = super()._http(method, path, data, *args, **kwargs)
            response_bytes = len(response[1])
            return response
        finally:
            stopped = time.perf_counter()
            with self._events_lock:
                self.events.append(RequestEvent(
                    method,
                    path,
                    started,
                    stopped,
                    len(data or b""),
                    locals().get("response_bytes", 0),
                ))

    def copy_obj(self, oh, *, response_limit, write):
        """Instrument the literal streaming GET omitted by control framing."""
        if response_limit <= MAX_OBJECT_BYTES:
            return super().copy_obj(
                oh, response_limit=response_limit, write=write)
        if type(response_limit) is not int \
                or not 0 < response_limit <= MAX_DIRECT_OBJECT_BYTES \
                or not callable(write):
            raise ValueError("peer object response limit")
        opened = ObjectOpen("GET", oh, response_limit)
        _, raw, _ = self._http(
            "POST", "/obj/open",
            data=encode_object_open(opened),
            response_limit=MAX_SCOPED_REQUEST_BYTES,
        )
        scoped = confine_object_request(
            opened,
            decode_scoped_request(raw),
            walk_module.now_ms(),
        )
        self._confine_direct_origin(scoped)
        request = urllib.request.Request(
            scoped.url,
            method="GET",
            headers=dict(scoped.headers),
        )
        response_bytes = 0
        started = time.perf_counter()
        try:
            with walk_module._DIRECT_OPENER.open(
                    request, timeout=60) as response:
                def chunks():
                    nonlocal response_bytes
                    while True:
                        chunk = response.read(DIRECT_STREAM_CHUNK_BYTES)
                        if not chunk:
                            return
                        response_bytes += len(chunk)
                        yield chunk

                return copy_object_get(
                    opened,
                    response.status,
                    response.headers,
                    chunks(),
                    write,
                )
        finally:
            with self._events_lock:
                self.events.append(RequestEvent(
                    "GET", "/obj/stream", started, time.perf_counter(),
                    0, response_bytes,
                ))


@dataclass(frozen=True, slots=True)
class CatchupMeasurement:
    elapsed_seconds: float
    facts: int
    piles: int
    durable_bytes: int
    http_requests: int
    http_gets: int
    logical_gets: int
    request_waves: int
    request_bytes: int
    response_bytes: int
    request_breakdown: tuple[tuple[str, int], ...]


def _store_sizes(node, workspace):
    store = node.store(workspace)
    return {
        key: os.path.getsize(store._p(key))
        for key in store.list("")
    }


def measure_catchup(node, workspace, url):
    """Pull one production HTTP forest through validation into durable state."""
    peer = NetworkMeteredPeer(node, workspace, url)
    remote = RemoteStore(peer)
    before_facts = set(node.sql(workspace).fact_ids())
    before_sizes = _store_sizes(node, workspace)
    started = time.perf_counter()
    result = asyncio.run(node.mirror(workspace).sync_from(remote))
    elapsed = time.perf_counter() - started
    if result.errors:
        raise ValueError("network catch-up mirror error") from ValueError(
            result.errors[0][1])
    after_facts = set(node.sql(workspace).fact_ids())
    after_sizes = _store_sizes(node, workspace)
    durable_bytes = sum(
        size for key, size in after_sizes.items()
        if key not in before_sizes
    )
    # POST /obj is a bounded logical batch GET. POST /obj/open and /pack/open
    # authorize a following literal GET and therefore count as read setup.
    logical_gets = sum(
        event.method == "GET" or event.path in {
            "/obj", "/obj/open", "/pack/open"}
        for event in peer.events
    )
    breakdown = tuple(sorted(Counter(
        f"{event.method} {event.path}" for event in peer.events
    ).items()))
    return CatchupMeasurement(
        elapsed,
        len(after_facts - before_facts),
        result.piles,
        durable_bytes,
        len(peer.events),
        sum(event.method == "GET" for event in peer.events),
        logical_gets,
        request_waves(peer.events),
        sum(event.request_bytes for event in peer.events),
        sum(event.response_bytes for event in peer.events),
        breakdown,
    )


def _rate_mbps(byte_count, elapsed_seconds):
    if byte_count < 0 or elapsed_seconds <= 0:
        raise ValueError("network rate inputs")
    return byte_count * 8 / elapsed_seconds / 1_000_000


def final_report(
        measurement, *, bandwidth_mbit, rtt_ms, line_bytes,
        line_elapsed_seconds, wire_rx_bytes, minimum_fraction):
    """Join independently measured link and verified-catch-up evidence."""
    line_rate = _rate_mbps(line_bytes, line_elapsed_seconds)
    wire_rate = _rate_mbps(wire_rx_bytes, measurement.elapsed_seconds)
    fraction = wire_rate / line_rate
    value = {
        "topology": "two Linux network namespaces over shaped veth",
        "configured_bandwidth_mbps": bandwidth_mbit,
        "configured_rtt_ms": rtt_ms,
        "measured_line_bytes": line_bytes,
        "measured_line_seconds": line_elapsed_seconds,
        "measured_line_rate_mbps": line_rate,
        "catchup_seconds": measurement.elapsed_seconds,
        "catchup_wire_rx_bytes": wire_rx_bytes,
        "catchup_wire_rate_mbps": wire_rate,
        "line_rate_fraction": fraction,
        "minimum_line_rate_fraction": minimum_fraction,
        **asdict(measurement),
    }
    value["network_bound"] = fraction >= minimum_fraction
    return value


def _fixture(root, url, piles, text_bytes):
    source = FullPeer(str(root / "source"))
    source.peer_address = url
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    link = facts.auth.user_invite.make(source, workspace)
    target = FullPeer(str(root / "target"))
    facts.auth.user.accept(target, link, "target")
    text = "x" * text_bytes
    for ordinal in range(piles):
        facts.content.message.post(
            source,
            workspace,
            "network-bound",
            f"{ordinal:08d}:{text}",
            ts=10_000 + ordinal,
        )
    return workspace


def _run(command, *, check=True, capture_output=True, env=None):
    return subprocess.run(
        command,
        check=check,
        capture_output=capture_output,
        text=True,
        env=env,
    )


def _sudo(*command, **kwargs):
    return _run(("sudo", "-n", *command), **kwargs)


def _as_user_namespace(namespace, command, environment):
    uid, gid = os.getuid(), os.getgid()
    exports = tuple(
        f"{key}={value}" for key, value in environment.items())
    return (
        "sudo", "-n", "ip", "netns", "exec", namespace,
        "sudo", "-n", f"--user=#{uid}", f"--group=#{gid}",
        "env", *exports, *command,
    )


def _wait_port(namespace, address, port, environment, timeout=15):
    code = (
        "import socket; "
        f"s=socket.create_connection(({address!r},{port}),1); s.close()"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _run(
            _as_user_namespace(
                namespace, (sys.executable, "-c", code), environment),
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(.05)
    raise TimeoutError(f"{address}:{port} did not become ready")


def _counter(namespace, name):
    result = _sudo(
        "ip", "netns", "exec", namespace,
        "cat", f"/sys/class/net/eth0/statistics/{name}",
    )
    return int(result.stdout.strip())


def _line_server(host, port, byte_count):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        print("READY", flush=True)
        connection, _address = listener.accept()
        with connection:
            chunk = b"l" * (64 * 1024)
            remaining = byte_count
            while remaining:
                part = chunk[:min(len(chunk), remaining)]
                connection.sendall(part)
                remaining -= len(part)


def _line_client(host, port, expected):
    received = 0
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=10) as connection:
        while True:
            chunk = connection.recv(64 * 1024)
            if not chunk:
                break
            received += len(chunk)
    elapsed = time.perf_counter() - started
    if received != expected:
        raise ValueError("line measurement truncated")
    return {"bytes": received, "elapsed_seconds": elapsed}


def _namespace_run(args):
    if sys.platform != "linux" or not shutil.which("ip") \
            or not shutil.which("tc"):
        raise RuntimeError("network-bound run requires Linux iproute2")
    if min(
            args.bandwidth_mbit, args.rtt_ms, args.piles,
            args.text_bytes, args.line_bytes) <= 0 \
            or not 0 < args.minimum_fraction <= 1:
        raise ValueError("network-bound options")
    _sudo("true")
    suffix = uuid.uuid4().hex[:6]
    source_ns, target_ns = f"p16s{suffix}", f"p16t{suffix}"
    first_link, second_link = f"p16a{suffix}", f"p16b{suffix}"
    root = Path(tempfile.mkdtemp(prefix="poc16-network-bound-"))
    repo = Path(__file__).resolve().parents[1]
    environment = {
        "NO_PROXY": f"{SOURCE_ADDRESS},{TARGET_ADDRESS}",
        "PYTHONPATH": str(repo),
        "no_proxy": f"{SOURCE_ADDRESS},{TARGET_ADDRESS}",
    }
    server = line_server = server_log = None
    try:
        workspace = _fixture(
            root,
            f"http://{SOURCE_ADDRESS}:{PEER_PORT}",
            args.piles,
            args.text_bytes,
        )
        _sudo("ip", "netns", "add", source_ns)
        _sudo("ip", "netns", "add", target_ns)
        _sudo(
            "ip", "link", "add", first_link,
            "type", "veth", "peer", "name", second_link)
        _sudo("ip", "link", "set", first_link, "netns", source_ns)
        _sudo("ip", "link", "set", second_link, "netns", target_ns)
        for namespace, link, address in (
                (source_ns, first_link, SOURCE_ADDRESS),
                (target_ns, second_link, TARGET_ADDRESS)):
            _sudo("ip", "-n", namespace, "link", "set", "lo", "up")
            _sudo(
                "ip", "-n", namespace, "link", "set", link,
                "name", "eth0")
            _sudo("ip", "-n", namespace, "link", "set", "eth0", "up")
            _sudo(
                "ip", "-n", namespace, "addr", "add",
                f"{address}/30", "dev", "eth0")
            _sudo(
                "ip", "netns", "exec", namespace,
                "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
                "delay", f"{args.rtt_ms / 2:g}ms",
                "rate", f"{args.bandwidth_mbit}mbit",
                "limit", "10000")

        server_log = open(root / "server.log", "w")
        server = subprocess.Popen(
            _as_user_namespace(source_ns, (
                sys.executable, "-m", "full_peer", "daemon",
                str(root / "source"),
                "--host", "0.0.0.0",
                "--port", str(PEER_PORT),
                "--control-port", "0",
                "--url", f"http://{SOURCE_ADDRESS}:{PEER_PORT}",
            ), environment),
            stdout=server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_port(
            target_ns, SOURCE_ADDRESS, PEER_PORT, environment)

        line_server = subprocess.Popen(
            _as_user_namespace(source_ns, (
                sys.executable, str(Path(__file__).resolve()),
                "line-server", "--host", "0.0.0.0",
                "--port", str(LINE_PORT),
                "--bytes", str(args.line_bytes),
            ), environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if line_server.stdout.readline().strip() != "READY":
            raise RuntimeError("line-rate server failed")
        line = _run(_as_user_namespace(target_ns, (
            sys.executable, str(Path(__file__).resolve()),
            "line-client", "--host", SOURCE_ADDRESS,
            "--port", str(LINE_PORT), "--bytes", str(args.line_bytes),
        ), environment))
        line_result = json.loads(line.stdout)
        if line_server.wait(10) != 0:
            raise RuntimeError(line_server.stderr.read())
        line_server = None

        before_rx = _counter(target_ns, "rx_bytes")
        catchup = _run(_as_user_namespace(target_ns, (
            sys.executable, str(Path(__file__).resolve()),
            "catchup", "--state", str(root / "target"),
            "--workspace", workspace,
            "--url", f"http://{SOURCE_ADDRESS}:{PEER_PORT}",
        ), environment))
        after_rx = _counter(target_ns, "rx_bytes")
        measurement = CatchupMeasurement(**json.loads(catchup.stdout))
        report = final_report(
            measurement,
            bandwidth_mbit=args.bandwidth_mbit,
            rtt_ms=args.rtt_ms,
            line_bytes=line_result["bytes"],
            line_elapsed_seconds=line_result["elapsed_seconds"],
            wire_rx_bytes=after_rx - before_rx,
            minimum_fraction=args.minimum_fraction,
        )
        if not report["network_bound"]:
            raise AssertionError(json.dumps(report, sort_keys=True))
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        for process in (line_server, server):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
        if server_log is not None:
            server_log.close()
        for namespace in (source_ns, target_ns):
            _sudo(
                "ip", "netns", "delete", namespace,
                check=False,
            )
        shutil.rmtree(root)


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--bandwidth-mbit", type=int, default=DEFAULT_BANDWIDTH_MBIT)
    run.add_argument("--rtt-ms", type=int, default=DEFAULT_RTT_MS)
    run.add_argument("--piles", type=int, default=DEFAULT_PILES)
    run.add_argument("--text-bytes", type=int, default=DEFAULT_TEXT_BYTES)
    run.add_argument("--line-bytes", type=int, default=DEFAULT_LINE_BYTES)
    run.add_argument(
        "--minimum-fraction", type=float, default=DEFAULT_RATE_FRACTION)
    line_server = sub.add_parser("line-server")
    line_server.add_argument("--host", required=True)
    line_server.add_argument("--port", type=int, required=True)
    line_server.add_argument("--bytes", type=int, required=True)
    line_client = sub.add_parser("line-client")
    line_client.add_argument("--host", required=True)
    line_client.add_argument("--port", type=int, required=True)
    line_client.add_argument("--bytes", type=int, required=True)
    catchup = sub.add_parser("catchup")
    catchup.add_argument("--state", required=True)
    catchup.add_argument("--workspace", required=True)
    catchup.add_argument("--url", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "run":
        _namespace_run(args)
    elif args.command == "line-server":
        _line_server(args.host, args.port, args.bytes)
    elif args.command == "line-client":
        print(json.dumps(_line_client(args.host, args.port, args.bytes)))
    else:
        measurement = measure_catchup(
            FullPeer(args.state), args.workspace, args.url)
        print(json.dumps(asdict(measurement)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
