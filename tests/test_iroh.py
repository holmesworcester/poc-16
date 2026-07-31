"""Real Iroh loopback around the one core HTTP grant gate."""
import base64
import http.client
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

import pytest

import facts
from core.close import encode_pile
from core.crypto import h, unseal
from core.limits import MAX_OBJECT_BYTES
from core.node import Node, now_ms
from facts.auth import request


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "full_peer" / "iroh" / "Cargo.toml"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_port(port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f"port {port} did not open")


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5)


def ready_process(command):
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    readable, _, _ = select.select([process.stdout], [], [], 30)
    if not readable:
        stop(process)
        raise AssertionError("Iroh process did not report readiness")
    line = process.stdout.readline().strip()
    if not line.startswith("READY "):
        error = process.stderr.read() if process.poll() is not None else ""
        stop(process)
        raise AssertionError(f"bad Iroh readiness: {line!r} {error!r}")
    return process, dict(field.split("=", 1) for field in line.split()[1:])


@pytest.fixture(scope="module")
def iroh_binary(tmp_path_factory):
    configured = os.environ.get("POC16_IROH_CARGO_TARGET")
    target = Path(configured) if configured \
        else tmp_path_factory.mktemp("iroh-cargo-target")
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--manifest-path",
            str(MANIFEST),
        ],
        cwd=ROOT,
        env={**os.environ, "CARGO_TARGET_DIR": str(target)},
        check=True,
        timeout=300,
    )
    return target / "debug" / "poc16-iroh"


def start_gate(node_dir, port, *, read_only=False):
    command = [
        sys.executable,
        "-m",
        "core",
        "daemon",
        str(node_dir),
        "--port",
        str(port),
        "--cadence",
        "3600",
        "--peer-data-only",
    ]
    if read_only:
        command.append("--read-only")
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={**os.environ, "TINYP2P_GRANT_TTL": "3000"},
    )
    wait_port(port)
    return process


def call(address, method, path, *, body=b"", token=None, headers=None):
    host, port = address
    request_headers = {"Connection": "close", **(headers or {})}
    if token is not None:
        request_headers["Authorization"] = "Bearer " + token
    connection = http.client.HTTPConnection(host, port, timeout=15)
    connection.request(
        method,
        path,
        body=body,
        headers=request_headers,
    )
    response = connection.getresponse()
    result = response.status, response.read(), {
        name.lower(): value for name, value in response.getheaders()
        if name.lower() in {"content-type", "etag"}
    }
    connection.close()
    return result


def raw_call(address, raw):
    with socket.create_connection(address, timeout=15) as stream:
        stream.settimeout(15)
        stream.sendall(raw)
        reader = stream.makefile("rb")
        status_line = reader.readline(4096)
        assert status_line.startswith(b"HTTP/1.1 ")
        status = int(status_line.split()[1])
        headers = {}
        while True:
            line = reader.readline(16 * 1024)
            if line == b"\r\n":
                break
            name, value = line.decode("ascii").split(":", 1)
            headers[name.lower()] = value.strip()
        size = int(headers.get("content-length", "0"))
        return status, reader.read(size), {
            name: value for name, value in headers.items()
            if name in {"content-type", "etag"}
        }


def repository_bytes(node_dir, workspace):
    root = Path(node_dir) / "ws" / workspace
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != ".root.lock"
        and not path.name.endswith(".idx.db")
    }


def mint(address, workspace, pile, identity_secret):
    response = call(
        address,
        "POST",
        f"/mint?ws={workspace}",
        body=json.dumps({
            "ws": workspace,
            "pile": base64.b64encode(pile).decode(),
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert response[0] == 200
    value = json.loads(response[1])
    return unseal(
        identity_secret,
        base64.b64decode(value["grant"]),
    ).decode(), value["cap"]


def test_core_http_is_unchanged_across_real_iroh_identities(
        tmp_path, iroh_binary):
    node_dir = tmp_path / "peer"
    node = Node(str(node_dir))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    member = node.member_for(workspace)
    identity_secret = node.identity(workspace)[0]
    issued = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", issued + 120_000, issued))
    node.store(workspace).put("invite/not-remote", b"local bootstrap")
    node.idx(workspace).close()

    gate_port = free_port()
    gate_address = ("127.0.0.1", gate_port)
    gate = start_gate(node_dir, gate_port)
    processes = [gate]
    try:
        accepting, accepting_ready = ready_process([
            str(iroh_binary),
            "serve",
            "--upstream",
            f"127.0.0.1:{gate_port}",
            "--loopback",
            "--session-seconds",
            "30",
        ])
        processes.append(accepting)
        forwarders = []
        for _ in range(2):
            process, ready = ready_process([
                str(iroh_binary),
                "forward",
                "--peer",
                accepting_ready["peer"],
                "--loopback",
                "--session-seconds",
                "30",
            ])
            processes.append(process)
            forwarders.append((
                ready["endpoint_id"],
                ("127.0.0.1", int(ready["listen"].rsplit(":", 1)[1])),
            ))
        assert len({
            accepting_ready["endpoint_id"],
            *(identity for identity, _ in forwarders),
        }) == 3
        paths = [gate_address, *(address for _, address in forwarders)]

        def parity(method, path, **kwargs):
            results = [call(address, method, path, **kwargs) for address in paths]
            assert results[1:] == results[:1] * (len(results) - 1)
            return results[0]

        raw = b"ordinary object bytes over unchanged core HTTP"
        oid = h(raw)
        token, capability = mint(
            gate_address, workspace, pile, identity_secret)
        assert capability == "sync-v1/full"
        assert parity(
            "PUT", f"/page/{oid}?ws={workspace}",
            body=raw, token=token,
        )[0] == 204
        token, _ = mint(gate_address, workspace, pile, identity_secret)
        assert parity(
            "GET", f"/page/{oid}?ws={workspace}", token=token,
        )[:2] == (200, raw)

        baseline = repository_bytes(node_dir, workspace)
        token, _ = mint(gate_address, workspace, pile, identity_secret)
        assert parity(
            "GET", f"/root?ws={workspace}",
        )[0] == 401
        tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
        assert parity(
            "GET", f"/root?ws={workspace}", token=tampered,
        )[0] == 401
        assert parity(
            "GET", "/root?ws=" + "0" * 64, token=token,
        )[0] == 404

        wrong_oid = "f" * 64
        assert h(b"does not match") != wrong_oid
        token, _ = mint(gate_address, workspace, pile, identity_secret)
        assert parity(
            "PUT", f"/page/{wrong_oid}?ws={workspace}",
            body=b"does not match", token=token,
        )[0] == 400
        token, _ = mint(gate_address, workspace, pile, identity_secret)
        assert parity(
            "PUT",
            f"/pile/not-{member}/{h(b'pile')}?ws={workspace}",
            body=b"pile",
            token=token,
        )[0] == 403

        ctl = json.dumps({
            "path": "content.message.post",
            "argv": [workspace, "general", "must-not-land"],
        }).encode()
        for method, path, body in (
                ("POST", "/ctl/command", ctl),
                ("GET", f"/invite/not-remote?ws={workspace}", b""),
                ("POST", f"/poke?ws={workspace}", b""),
                ("GET", f"/unknown?ws={workspace}", b"")):
            route_token, _ = mint(
                gate_address, workspace, pile, identity_secret)
            assert parity(
                method, path, body=body, token=route_token,
            )[0] == 404

        token, _ = mint(gate_address, workspace, pile, identity_secret)
        oversized = (
            f"PUT /page/{h(b'never lands')}?ws={workspace} HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Length: {MAX_OBJECT_BYTES + 1}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        oversize_results = [
            raw_call(address, oversized) for address in paths
        ]
        assert oversize_results[1:] == \
            oversize_results[:1] * (len(oversize_results) - 1)
        assert oversize_results[0][0] == 413

        token, _ = mint(gate_address, workspace, pile, identity_secret)
        malformed = (
            f"PUT /page/{h(b'malformed never lands')}?ws={workspace} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Content-Length: nope\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        malformed_results = [
            raw_call(address, malformed) for address in paths
        ]
        assert malformed_results[1:] == \
            malformed_results[:1] * (len(malformed_results) - 1)
        assert malformed_results[0][0] == 400
        assert repository_bytes(node_dir, workspace) == baseline

        expired, _ = mint(gate_address, workspace, pile, identity_secret)
        time.sleep(3.1)
        assert parity(
            "GET", f"/root?ws={workspace}", token=expired,
        )[0] == 401
        assert repository_bytes(node_dir, workspace) == baseline

        stop(gate)
        gate = start_gate(node_dir, gate_port, read_only=True)
        processes[0] = gate
        read_only, capability = mint(
            gate_address, workspace, pile, identity_secret)
        assert capability == "sync-v1/read"
        assert parity(
            "PUT",
            f"/page/{h(b'read only denial')}?ws={workspace}",
            body=b"read only denial",
            token=read_only,
        )[0] == 401
        assert repository_bytes(node_dir, workspace) == baseline
    finally:
        for process in reversed(processes):
            stop(process)
