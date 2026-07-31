"""Real Iroh transport around the one ordinary full-peer HTTP grant gate."""
import asyncio
import base64
import http.client
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

import pytest

import facts
from core.close import encode_pile
from core.crypto import h, unseal
from core.limits import MAX_MINT_FETCHES, MAX_MINT_FETCH_BYTES
from core.repository_reader import RepositoryReader
from facts.auth import request
from full_peer.daemon import FullPeerService
from full_peer.node import FullPeer, now_ms


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "full_peer" / "iroh" / "Cargo.toml"


def wait_until(predicate, timeout=15, message="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except OSError:
            pass
        time.sleep(.05)
    raise AssertionError(f"timed out waiting for {message}")


def port_open(port):
    with socket.create_connection(("127.0.0.1", port), timeout=.2):
        return True


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        return process.wait(10)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(5)


def next_line(process, timeout=30):
    result = queue.Queue(maxsize=1)

    def read():
        result.put(process.stdout.readline())

    threading.Thread(target=read, daemon=True).start()
    try:
        line = result.get(timeout=timeout).strip()
    except queue.Empty:
        stop(process)
        raise AssertionError("process did not report readiness") from None
    if not line:
        error = process.stderr.read() if process.poll() is not None else ""
        stop(process)
        raise AssertionError(f"process exited before readiness: {error}")
    return line


def parse_fields(line, marker):
    assert line.startswith(marker + " "), line
    return dict(field.split("=", 1) for field in line.split()[1:])


def ready_process(command):
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return process, parse_fields(next_line(process), "READY")


def start_full_peer(state, binary, environment=None):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "full_peer",
            "daemon",
            str(state),
            "--port", "0",
            "--control-port", "0",
            "--cadence", "3600",
            "--iroh",
            "--iroh-binary", str(binary),
            "--iroh-loopback",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env={**os.environ, **(environment or {})},
    )
    service = next_line(process)
    match = re.fullmatch(
        r"full peer [^:]+: data (http://[^;]+); "
        r"control (http://[^ ]+) \(.*\)",
        service,
    )
    if match is None:
        stop(process)
        raise AssertionError(f"bad full-peer readiness: {service!r}")
    iroh = parse_fields(next_line(process), "IROH")
    return process, {
        "data": match.group(1),
        "control": match.group(2),
        **iroh,
    }


def start_plain_full_peer(state, environment):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "full_peer",
            "daemon",
            str(state),
            "--port", "0",
            "--control-port", "0",
            "--cadence", "3600",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env={**os.environ, **environment},
    )
    service = next_line(process)
    match = re.fullmatch(
        r"full peer [^:]+: data (http://[^;]+); "
        r"control (http://[^ ]+) \(.*\)",
        service,
    )
    if match is None:
        stop(process)
        raise AssertionError(f"bad full-peer readiness: {service!r}")
    return process, {
        "data": match.group(1),
        "control": match.group(2),
    }


def address(url):
    parsed = urlparse(url)
    return parsed.hostname, parsed.port


def call(target, method, path, *, body=b"", token=None, headers=None):
    request_headers = {"Connection": "close", **(headers or {})}
    if token is not None:
        request_headers["Authorization"] = "Bearer " + token
    connection = http.client.HTTPConnection(*target, timeout=15)
    connection.request(method, path, body=body, headers=request_headers)
    response = connection.getresponse()
    result = response.status, response.read(), {
        name.lower(): value for name, value in response.getheaders()
        if name.lower() in {"content-type", "etag"}
    }
    connection.close()
    return result


def repository_bytes(node_dir, workspace):
    root = Path(node_dir) / "ws" / workspace
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != ".root.lock"
        and not path.name.endswith((".idx.db", ".idx.db-shm", ".idx.db-wal"))
    }


def mint(target, workspace, pile, identity_secret):
    status, body, _ = call(
        target,
        "POST",
        f"/mint?ws={workspace}",
        body=json.dumps({
            "ws": workspace,
            "pile": base64.b64encode(pile).decode(),
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    value = json.loads(body)
    return (
        unseal(
            identity_secret,
            base64.b64decode(value["grant"]),
        ).decode(),
        value["cap"],
    )


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


def test_supervised_iroh_is_the_same_authorized_http_gate_and_restarts(
        tmp_path, iroh_binary):
    state = tmp_path / "peer"
    bootstrap = FullPeer(str(state))
    workspace = facts.auth.workspace.create(bootstrap, "alice", ts=1)
    identity_secret = bootstrap.identity(workspace)[0]
    issued = now_ms()
    pile = encode_pile(request.payload(
        bootstrap, workspace, "sync", issued + 300_000, issued))
    bootstrap.sql(workspace).db.close()

    daemon, ready = start_full_peer(
        state,
        iroh_binary,
        {"TINYP2P_GRANT_TTL": "1000"},
    )
    children = [daemon]
    first_endpoint = ready["endpoint_id"]
    first_child_pid = int(ready["pid"])
    try:
        forwarders = []
        for _ in range(2):
            forwarder, forwarded = ready_process([
                str(iroh_binary),
                "forward",
                "--peer", ready["peer"],
                "--loopback",
            ])
            children.append(forwarder)
            forwarders.append((
                forwarded["endpoint_id"],
                address("http://" + forwarded["listen"]),
            ))
        assert len({
            first_endpoint,
            *(identity for identity, _ in forwarders),
        }) == 3

        direct = address(ready["data"])
        through_iroh = [target for _, target in forwarders]
        assert call(direct, "GET", "/healthz")[0] == 200
        assert all(
            call(target, "GET", "/healthz")[0] == 200
            for target in through_iroh
        )

        token, capability = mint(
            through_iroh[0], workspace, pile, identity_secret)
        assert capability == "sync-v1/full"
        raw = b"ordinary object bytes through Iroh"
        oid = h(raw)
        assert call(
            through_iroh[0],
            "PUT",
            f"/page/{oid}?ws={workspace}",
            body=raw,
            token=token,
        )[0] == 204

        token, _ = mint(
            through_iroh[1], workspace, pile, identity_secret)
        assert call(
            through_iroh[1],
            "GET",
            f"/page/{oid}?ws={workspace}",
            token=token,
        )[:2] == (200, raw)

        baseline = repository_bytes(state, workspace)
        time.sleep(1.2)
        assert call(
            through_iroh[1],
            "GET",
            f"/page/{oid}?ws={workspace}",
            token=token,
        )[0] == 401
        assert repository_bytes(state, workspace) == baseline
        assert call(
            through_iroh[0],
            "GET",
            f"/root?ws={workspace}",
        )[0] == 401
        token, _ = mint(
            through_iroh[0], workspace, pile, identity_secret)
        assert call(
            through_iroh[0],
            "PUT",
            f"/page/{'f' * 64}?ws={workspace}",
            body=b"wrong digest",
            token=token,
        )[0] == 400
        control_request = b'{"path":"peer.status","argv":[]}'
        peer_control = call(
            direct,
            "POST",
            f"/ctl/command?ws={workspace}",
            body=control_request,
        )
        tunneled_control = call(
            through_iroh[0],
            "POST",
            f"/ctl/command?ws={workspace}",
            body=control_request,
        )
        assert peer_control[0] == 405
        assert tunneled_control == peer_control
        assert repository_bytes(state, workspace) == baseline

        status, body, _ = call(
            address(ready["control"]),
            "POST",
            f"/ctl/command?ws={workspace}",
            body=control_request,
        )
        assert status == 200
        assert workspace in json.loads(body)["workspaces"]

        for forwarder in children[1:]:
            stop(forwarder)
        children[:] = [daemon]
        assert stop(daemon) == 0
        children.clear()
        wait_until(
            lambda: _pid_absent(first_child_pid),
            message="supervised Iroh child cleanup",
        )

        daemon, ready = start_full_peer(
            state,
            iroh_binary,
            {"TINYP2P_GRANT_TTL": "1000"},
        )
        children.append(daemon)
        assert ready["endpoint_id"] == first_endpoint
        second_child_pid = int(ready["pid"])
        os.kill(second_child_pid, signal.SIGTERM)
        assert daemon.wait(15) != 0
        children.clear()
        wait_until(
            lambda: _pid_absent(second_child_pid),
            message="failed Iroh child reaping",
        )
        for url in (ready["data"], ready["control"]):
            wait_until(
                lambda url=url: not _address_open(address(url)),
                message=f"{url} fail-shut",
            )
    finally:
        for process in reversed(children):
            stop(process)


def test_full_peer_mint_fails_at_exactly_one_under_each_fetch_budget(tmp_path):
    state = tmp_path / "peer"
    bootstrap = FullPeer(str(state))
    workspace = facts.auth.workspace.create(bootstrap, "alice", ts=1)
    issued = now_ms()
    pile = encode_pile(request.payload(
        bootstrap, workspace, "sync", issued + 300_000, issued))
    store = bootstrap.store(workspace)
    root = store.get("root")

    async def measure():
        fetched = {}

        async def fetch(oid):
            raw = store.get("obj/" + oid)
            fetched.setdefault(oid, raw)
            return raw

        decision = await RepositoryReader.mint_awaited(
            workspace,
            root,
            fetch,
            pile,
            issued,
            max_unique_fetches=MAX_MINT_FETCHES,
            max_fetch_bytes=MAX_MINT_FETCH_BYTES,
        )
        assert decision is not None
        return len(fetched), sum(len(raw) for raw in fetched.values())

    fetches, fetched_bytes = asyncio.run(measure())
    assert fetches > 0
    assert fetched_bytes > 0
    bootstrap.sql(workspace).db.close()
    body = json.dumps({
        "ws": workspace,
        "pile": base64.b64encode(pile).decode(),
    }).encode()

    configurations = (
        {
            "TINYP2P_MINT_MAX_FETCHES": str(fetches - 1),
            "TINYP2P_MINT_MAX_FETCH_BYTES": str(MAX_MINT_FETCH_BYTES),
        },
        {
            "TINYP2P_MINT_MAX_FETCHES": str(MAX_MINT_FETCHES),
            "TINYP2P_MINT_MAX_FETCH_BYTES": str(fetched_bytes - 1),
        },
    )
    for environment in configurations:
        daemon, ready = start_plain_full_peer(state, environment)
        try:
            assert call(
                address(ready["data"]),
                "POST",
                f"/mint?ws={workspace}",
                body=body,
                headers={"Content-Type": "application/json"},
            )[0] == 403
            assert store.get("root") == root
        finally:
            assert stop(daemon) == 0


def _pid_absent(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _address_open(target):
    try:
        with socket.create_connection(target, timeout=.2):
            return True
    except OSError:
        return False


def test_peer_data_listener_death_fails_the_whole_service(tmp_path):
    service = FullPeerService(
        str(tmp_path / "peer"),
        0,
        cadence=3600,
        control_port=0,
    )
    errors = []

    def run():
        try:
            service.run()
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    wait_until(
        lambda: port_open(service.peer_server.server_address[1]),
        message="peer-data listener",
    )
    service.peer_server.shutdown()
    thread.join(10)

    assert not thread.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert "peer-data listener" in str(errors[0])
    assert not _address_open(service.control_server.server_address)


def test_iroh_mode_refuses_an_externally_bound_plain_http_seam(tmp_path):
    with pytest.raises(
            ValueError, match="Iroh peer-data listener must use a loopback IP"):
        FullPeerService(
            str(tmp_path),
            0,
            host="0.0.0.0",
            control_port=0,
            iroh_binary="poc16-iroh",
        )
    with pytest.raises(
            ValueError, match="cannot advertise a plain HTTP peer URL"):
        FullPeerService(
            str(tmp_path / "url"),
            0,
            url="https://peer.example",
            control_port=0,
            iroh_binary="poc16-iroh",
        )


def test_iroh_startup_failure_closes_both_bound_listeners(tmp_path):
    service = FullPeerService(
        str(tmp_path),
        0,
        cadence=3600,
        control_port=0,
        iroh_binary=tmp_path / "missing-poc16-iroh",
    )
    addresses = (
        service.peer_server.server_address,
        service.control_server.server_address,
    )

    with pytest.raises(FileNotFoundError):
        service.start()

    assert all(not _address_open(target) for target in addresses)
