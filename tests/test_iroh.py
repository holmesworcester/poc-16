"""Real Iroh connections around the one ordinary full-peer HTTP grant gate."""
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
from core.crypto import h
from core.pack_access import MAX_OBJECT_OPEN_BYTES
from full_peer.daemon import FullPeerService
from full_peer.iroh_forwarders import IrohForwarders
from full_peer.iroh_process import STOP_SECONDS
from full_peer.keychain import iroh_peer
from full_peer.node import FullPeer
from full_peer.walk import Peer


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


def _capture_error(errors, function, *args):
    try:
        function(*args)
    except BaseException as error:
        errors.append(error)


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


def start_full_peer(state, binary, environment=None, *, cadence="3600"):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "full_peer",
            "daemon",
            str(state),
            "--port", "0",
            "--control-port", "0",
            "--cadence", str(cadence),
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


def control_command(ready, path, *argv):
    status, body, _ = call(
        address(ready["control"]),
        "POST",
        "/ctl/command",
        body=json.dumps({
            "path": path,
            "argv": [str(value) for value in argv],
        }).encode(),
    )
    value = json.loads(body) if body else None
    assert status == 200, value
    return value


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


def raw_call(target, raw):
    with socket.create_connection(target, timeout=15) as stream:
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
        and path.name != ".cas.lock"
        and not path.name.endswith((".idx.db", ".idx.db-shm", ".idx.db-wal"))
    }


def http_request_threads():
    return {
        thread.ident for thread in threading.enumerate()
        if thread.is_alive()
        and thread.ident is not None
        and "(process_request_thread)" in thread.name
    }


def mint(target, node, workspace):
    """Exercise the production historical-path and current-proof handshake."""
    peer = Peer(node, workspace, f"http://{target[0]}:{target[1]}")
    peer.mint()
    return peer._token, peer._sync_profile


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


@pytest.mark.parametrize(
    "ticket",
    (
        "not-valid-base64!",
        base64.urlsafe_b64encode(b"\xff").decode().rstrip("="),
        "A" * ((((4096 + 2) // 3) * 4) + 1),
    ),
    ids=("base64", "postcard", "oversized"),
)
def test_malformed_ticket_exits_before_binding_a_forwarder(
        iroh_binary, ticket):
    completed = subprocess.run(
        [
            str(iroh_binary),
            "forward",
            f"--peer={ticket}",
            "--loopback",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode != 0
    assert "READY " not in completed.stdout
    assert "ticket" in completed.stderr.lower()


def test_saturated_real_iroh_sessions_recover_without_repository_mutation(
        tmp_path, iroh_binary):
    state = tmp_path / "peer"
    bootstrap = FullPeer(str(state))
    workspace = facts.auth.workspace.create(bootstrap, "alice", ts=1)

    service = FullPeerService(
        str(state),
        0,
        cadence=3600,
        control_port=0,
    )
    children = []
    hostile_sockets = []
    try:
        service.start()
        direct = address(service.data_address)
        token, capability = mint(direct, bootstrap, workspace)
        assert capability == "sync-v1/full"
        expected = call(
            direct,
            "GET",
            f"/heads?ws={workspace}",
            token=token,
        )
        assert expected[0] == 200
        baseline = repository_bytes(state, workspace)
        wait_until(
            lambda: not http_request_threads(),
            message="direct HTTP request thread cleanup",
        )
        baseline_threads = http_request_threads()

        acceptor, accepting = ready_process([
            str(iroh_binary),
            "serve",
            "--upstream", f"{direct[0]}:{direct[1]}",
            "--loopback",
            "--max-connections", "2",
            "--setup-seconds", "1",
            "--session-seconds", "2",
        ])
        children.append(acceptor)
        forward_targets = []
        for _ in range(3):
            forwarder, forwarded = ready_process([
                str(iroh_binary),
                "forward",
                f"--peer={accepting['peer']}",
                "--loopback",
                "--setup-seconds", "5",
                "--session-seconds", "5",
            ])
            children.append(forwarder)
            forward_targets.append(address("http://" + forwarded["listen"]))

        for target in forward_targets[:2]:
            stream = socket.create_connection(target, timeout=5)
            stream.sendall(b"G")
            hostile_sockets.append(stream)

        wait_until(
            lambda: len(http_request_threads() - baseline_threads) == 2,
            message="both admitted Iroh streams to reach core HTTP",
        )
        admitted_threads = http_request_threads() - baseline_threads
        assert len(admitted_threads) == 2

        overflow_results = []
        overflow_errors = []
        overflow = threading.Thread(
            target=lambda: _capture_error(
                overflow_errors,
                lambda: overflow_results.append(call(
                    forward_targets[2],
                    "GET",
                    f"/heads?ws={workspace}",
                    token=token,
                )),
            ),
        )
        overflow.start()
        overflow.join(2)
        assert not overflow.is_alive()
        assert overflow_results == []
        assert len(overflow_errors) == 1
        assert isinstance(
            overflow_errors[0],
            (OSError, http.client.HTTPException),
        )
        assert http_request_threads() - baseline_threads == admitted_threads
        assert repository_bytes(state, workspace) == baseline

        for stream in hostile_sockets:
            stream.settimeout(5)
            try:
                closed = stream.recv(1)
            except (ConnectionResetError, BrokenPipeError):
                closed = b""
            assert closed == b""
        wait_until(
            lambda: http_request_threads() == baseline_threads,
            message="expired hostile core HTTP handlers to exit",
        )

        recovered_at = time.monotonic()
        recovered = call(
            forward_targets[2],
            "GET",
            f"/heads?ws={workspace}",
            token=token,
        )
        assert time.monotonic() - recovered_at < 2
        assert recovered == expected
        assert repository_bytes(state, workspace) == baseline
    finally:
        for stream in hostile_sockets:
            stream.close()
        for process in reversed(children):
            stop(process)
        service.close()


def test_supervised_iroh_is_the_same_authorized_http_gate_and_restarts(
        tmp_path, iroh_binary):
    state = tmp_path / "peer"
    bootstrap = FullPeer(str(state))
    workspace = facts.auth.workspace.create(bootstrap, "alice", ts=1)
    member = bootstrap.member_for(workspace)
    published = repository_bytes(state, workspace)
    object_key, raw = next(
        (key, value) for key, value in published.items()
        if key.startswith("obj/"))
    oid = object_key.removeprefix("obj/")

    daemon, ready = start_full_peer(
        state,
        iroh_binary,
        {"TINYP2P_GRANT_TTL": "2000"},
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
                f"--peer={ready['peer']}",
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
        paths = [direct, *through_iroh]

        def parity(method, path, **kwargs):
            results = [
                call(target, method, path, **kwargs)
                for target in paths
            ]
            assert results[1:] == results[:1] * (len(results) - 1)
            return results[0]

        assert call(direct, "GET", "/healthz")[0] == 200
        assert all(
            call(target, "GET", "/healthz")[0] == 200
            for target in through_iroh
        )

        token, capability = mint(through_iroh[0], bootstrap, workspace)
        assert capability == "sync-v1/full"
        baseline = repository_bytes(state, workspace)
        # An unknown route cannot mutate repository state through either
        # direct TCP or Iroh's opaque byte forwarding.
        assert parity(
            "PUT",
            f"/retired/{oid}?ws={workspace}",
            body=raw,
            token=token,
        )[0] == 404
        assert repository_bytes(state, workspace) == baseline

        token, _ = mint(through_iroh[1], bootstrap, workspace)
        assert parity(
            "GET",
            f"/obj/{oid}?ws={workspace}",
            token=token,
        )[:2] == (200, raw)

        time.sleep(2.2)
        assert parity(
            "GET",
            f"/obj/{oid}?ws={workspace}",
            token=token,
        )[0] == 401
        assert repository_bytes(state, workspace) == baseline

        assert parity(
            "GET",
            f"/heads?ws={workspace}",
        )[0] == 401
        token, _ = mint(through_iroh[0], bootstrap, workspace)
        tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
        assert parity(
            "GET",
            f"/heads?ws={workspace}",
            token=tampered,
        )[0] == 401

        token, _ = mint(direct, bootstrap, workspace)
        assert parity(
            "GET",
            "/heads?ws=" + "0" * 64,
            token=token,
        )[0] == 404

        for method, path in (
                ("POST", f"/heads?ws={workspace}"),
                ("GET", f"/unknown?ws={workspace}")):
            route_token, _ = mint(
                through_iroh[0], bootstrap, workspace)
            assert parity(
                method,
                path,
                token=route_token,
            )[0] == 404

        control_request = b'{"path":"peer.status","argv":[]}'
        token, _ = mint(through_iroh[0], bootstrap, workspace)
        peer_control = parity(
            "POST",
            f"/ctl/command?ws={workspace}",
            body=control_request,
            token=token,
        )
        assert peer_control[0] == 405

        token, _ = mint(direct, bootstrap, workspace)
        retired_put = (
            f"PUT /obj/{h(b'never lands')}?"
            f"ws={workspace} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        retired_results = [
            raw_call(target, retired_put) for target in paths
        ]
        assert retired_results[1:] == \
            retired_results[:1] * (len(retired_results) - 1)
        assert retired_results[0][0] == 404

        oversized = (
            "POST /obj/open?"
            f"ws={workspace} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Length: {MAX_OBJECT_OPEN_BYTES + 1}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        oversized_results = [
            raw_call(target, oversized) for target in paths
        ]
        assert oversized_results[1:] == \
            oversized_results[:1] * (len(oversized_results) - 1)
        assert oversized_results[0][0] == 413

        token, _ = mint(through_iroh[0], bootstrap, workspace)
        malformed = (
            "POST /obj/open?"
            f"ws={workspace} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Content-Length: nope\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        malformed_results = [
            raw_call(target, malformed) for target in paths
        ]
        assert malformed_results[1:] == \
            malformed_results[:1] * (len(malformed_results) - 1)
        assert malformed_results[0][0] == 400
        assert repository_bytes(state, workspace) == baseline

        status, body, _ = call(
            address(ready["control"]),
            "POST",
            f"/ctl/command?ws={workspace}",
            body=control_request,
        )
        assert status == 200
        assert workspace in json.loads(body)["workspaces"]
        status, body, _ = call(
            address(ready["control"]),
            "POST",
            f"/ctl/command?ws={workspace}",
            body=json.dumps({
                "path": "auth.user_invite.create",
                "argv": [workspace],
            }).encode(),
        )
        assert status == 200
        link = json.loads(body)
        invite = json.loads(base64.urlsafe_b64decode(link))
        assert set(invite) == {"b", "p", "s", "ws"}
        assert invite["p"] == {
            "kind": "iroh",
            "endpoint": ready["endpoint_id"],
            "ticket": ready["peer"],
        }
        assert "u" not in invite
        after_invite = repository_bytes(state, workspace)
        assert after_invite == baseline

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
            {"TINYP2P_GRANT_TTL": "2000"},
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


def test_two_supervised_full_peers_schedule_only_through_iroh_and_reap(
        tmp_path, iroh_binary):
    """Invite, cadence, restart, refresh, child death, and removal are real."""
    alice_state = tmp_path / "alice"
    bob_state = tmp_path / "bob"
    stranger_state = tmp_path / "stranger"
    alice = bob = stranger = None
    descendants = set()

    def remember(ready):
        descendants.add(int(ready["pid"]))

    def workspace_row(ready, workspace):
        return control_command(
            ready, "peer.status")["workspaces"][workspace]

    def connection(ready, workspace):
        rows = workspace_row(ready, workspace)["iroh_connections"]
        return rows[0] if len(rows) == 1 else None

    try:
        alice, alice_ready = start_full_peer(
            alice_state, iroh_binary, cadence=".1")
        bob, bob_ready = start_full_peer(
            bob_state, iroh_binary, cadence=".1")
        remember(alice_ready)
        remember(bob_ready)
        workspace = control_command(
            alice_ready, "auth.workspace.create", "alice")
        link = control_command(
            alice_ready, "auth.user_invite.create", workspace)
        invitation = json.loads(base64.urlsafe_b64decode(link))
        assert invitation["p"] == {
            "kind": "iroh",
            "endpoint": alice_ready["endpoint_id"],
            "ticket": alice_ready["peer"],
        }
        assert control_command(
            bob_ready, "auth.user.join", link, "bob") == workspace

        alice_message = control_command(
            alice_ready,
            "content.message.post",
            workspace,
            "general",
            "from alice through scheduled Iroh",
        )
        bob_message = control_command(
            bob_ready,
            "content.message.post",
            workspace,
            "general",
            "from bob through scheduled Iroh",
        )

        def converged():
            forests = {
                workspace_row(alice_ready, workspace)[
                    "forest_fingerprint"],
                workspace_row(bob_ready, workspace)[
                    "forest_fingerprint"],
            }
            fids = {
                row["fid"]
                for row in control_command(
                    bob_ready, "content.message.list", workspace)
            }
            return len(forests) == 1 \
                and {alice_message, bob_message}.issubset(fids)

        wait_until(
            converged,
            timeout=30,
            message="two full peers to converge through scheduled Iroh",
        )
        persisted = json.loads(
            (bob_state / "keyring.json").read_text())
        assert persisted["workspaces"][workspace]["peers"] == [
            invitation["p"]]
        assert urlparse(alice_ready["data"]).hostname == "127.0.0.1"
        assert urlparse(bob_ready["data"]).hostname == "127.0.0.1"
        first = connection(bob_ready, workspace)
        assert first is not None
        assert first["endpoint"] == alice_ready["endpoint_id"]
        assert first["state"] == "ready"
        assert urlparse(first["loopback_url"]).hostname == "127.0.0.1"
        descendants.add(first["pid"])

        # Restart recreates the private forwarder solely from the durable
        # locator. No private loopback URL is persisted.
        first_pid, first_url = first["pid"], first["loopback_url"]
        assert stop(bob) == 0
        bob = None
        wait_until(
            lambda: _pid_absent(first_pid),
            message="restart to reap old outbound forwarder",
        )
        assert not _address_open(address(first_url))
        bob, bob_ready = start_full_peer(
            bob_state, iroh_binary, cadence=".1")
        remember(bob_ready)
        recreated = connection(bob_ready, workspace)
        assert recreated is not None
        assert recreated["pid"] != first_pid
        assert recreated["generation"] == 1
        descendants.add(recreated["pid"])
        after_restart = control_command(
            alice_ready,
            "content.message.post",
            workspace,
            "general",
            "after bob restart",
        )
        wait_until(
            lambda: any(
                row["fid"] == after_restart
                for row in control_command(
                    bob_ready, "content.message.list", workspace)
            ),
            timeout=30,
            message="recreated forwarder to sync",
        )

        # Restart the accepting peer until its reachable address changes, then
        # refresh the same endpoint's ticket. The old child and private URL are
        # replaced without changing sync or authorization code.
        old_ticket = alice_ready["peer"]
        old_endpoint = alice_ready["endpoint_id"]
        for _ in range(4):
            assert stop(alice) == 0
            alice = None
            alice, alice_ready = start_full_peer(
                alice_state, iroh_binary, cadence=".1")
            remember(alice_ready)
            assert alice_ready["endpoint_id"] == old_endpoint
            if alice_ready["peer"] != old_ticket:
                break
        assert alice_ready["peer"] != old_ticket
        before_refresh = connection(bob_ready, workspace)
        assert control_command(
            bob_ready,
            "peer.iroh.set",
            workspace,
            old_endpoint,
            alice_ready["peer"],
        ) == {"ok": True}
        refreshed = connection(bob_ready, workspace)
        assert refreshed is not None
        assert refreshed["pid"] != before_refresh["pid"]
        assert refreshed["generation"] > before_refresh["generation"]
        descendants.add(refreshed["pid"])
        wait_until(
            lambda: _pid_absent(before_refresh["pid"]),
            message="ticket refresh to reap superseded forwarder",
        )
        assert not _address_open(address(before_refresh["loopback_url"]))
        persisted = json.loads(
            (bob_state / "keyring.json").read_text())
        assert persisted["workspaces"][workspace]["peers"] == [{
            **invitation["p"],
            "ticket": alice_ready["peer"],
        }]

        after_refresh = control_command(
            alice_ready,
            "content.message.post",
            workspace,
            "general",
            "after ticket refresh",
        )
        wait_until(
            lambda: any(
                row["fid"] == after_refresh
                for row in control_command(
                    bob_ready, "content.message.list", workspace)
            ),
            timeout=30,
            message="refreshed ticket to sync",
        )

        # Unexpected child death closes the old dial, remains visible in local
        # status, and is recreated with bounded backoff.
        observed = connection(bob_ready, workspace)
        for expected_failures in (1, 2):
            killed = dict(observed)
            os.kill(killed["pid"], signal.SIGKILL)
            wait_until(
                lambda: not _address_open(address(killed["loopback_url"])),
                message="killed forwarder to fail its old dial closed",
            )
            observed = {}

            def recreated_after_death():
                row = connection(bob_ready, workspace)
                if row is None or row["generation"] <= killed["generation"]:
                    return False
                observed.update(row)
                return row["state"] == "ready" \
                    and row["failures"] >= expected_failures \
                    and "exited unexpectedly" in row["last_error"]

            wait_until(
                recreated_after_death,
                timeout=20,
                message="dead forwarder to be observed and recreated",
            )
            assert observed["pid"] != killed["pid"]
            descendants.add(observed["pid"])

        # Removal is durable and immediately reaps the child. Restart cannot
        # resurrect reachability absent from configuration.
        removed_pid = observed["pid"]
        removed_url = observed["loopback_url"]
        assert control_command(
            bob_ready,
            "peer.iroh.remove",
            workspace,
            old_endpoint,
        ) == {"ok": True}
        wait_until(
            lambda: _pid_absent(removed_pid),
            message="removed forwarder to be reaped",
        )
        assert not _address_open(address(removed_url))
        assert workspace_row(
            bob_ready, workspace)["iroh_connections"] == []
        assert json.loads(
            (bob_state / "keyring.json").read_text()
        )["workspaces"][workspace]["peers"] == []

        # Endpoint IDs only make reachability records self-consistent. A
        # mismatched ticket starts no usable dial and grants nothing.
        wrong_endpoint = "0" * 64
        assert wrong_endpoint != old_endpoint
        assert control_command(
            bob_ready,
            "peer.iroh.set",
            workspace,
            wrong_endpoint,
            alice_ready["peer"],
        ) == {"ok": True}
        mismatch = connection(bob_ready, workspace)
        assert mismatch["state"] == "retry"
        assert mismatch["pid"] is None
        assert "ticket endpoint mismatch" in mismatch["last_error"]
        assert control_command(
            bob_ready,
            "peer.iroh.remove",
            workspace,
            wrong_endpoint,
        ) == {"ok": True}

        # A live, internally consistent Iroh connection is still powerless
        # without the ordinary workspace grant. The scheduled sync path gets
        # the gate's denial and cannot create or mutate remote repository data.
        stranger, stranger_ready = start_full_peer(
            stranger_state, iroh_binary, cadence=".1")
        remember(stranger_ready)
        untouched = repository_bytes(stranger_state, workspace)
        assert control_command(
            bob_ready,
            "peer.iroh.set",
            workspace,
            stranger_ready["endpoint_id"],
            stranger_ready["peer"],
        ) == {"ok": True}

        def scheduled_denial_visible():
            return any(
                row["peer"]
                == f"iroh:{stranger_ready['endpoint_id']}"
                and "HTTP Error 404" in row["error"]
                for row in workspace_row(
                    bob_ready, workspace)["sync_failures"]
            )

        wait_until(
            scheduled_denial_visible,
            timeout=20,
            message="scheduled unauthorized Iroh peer denial",
        )
        denied = connection(bob_ready, workspace)
        assert denied is not None
        assert denied["state"] == "ready"
        descendants.add(denied["pid"])
        assert repository_bytes(stranger_state, workspace) == untouched == {}
        assert control_command(
            bob_ready,
            "peer.iroh.remove",
            workspace,
            stranger_ready["endpoint_id"],
        ) == {"ok": True}
        wait_until(
            lambda: _pid_absent(denied["pid"]),
            message="denied peer forwarder cleanup",
        )

        assert stop(bob) == 0
        bob = None
        bob, bob_ready = start_full_peer(
            bob_state, iroh_binary, cadence=".1")
        remember(bob_ready)
        assert workspace_row(
            bob_ready, workspace)["iroh_connections"] == []
    finally:
        for process in (bob, alice, stranger):
            if process is not None:
                stop(process)
        for pid in descendants:
            wait_until(
                lambda pid=pid: _pid_absent(pid),
                timeout=20,
                message=f"Iroh child {pid} cleanup",
            )


def test_four_supervised_full_peers_gossip_independent_writers_over_iroh(
        tmp_path, iroh_binary):
    """A line topology relays four writer trees without a direct HTTP peer."""
    names = ("alice", "bob", "carol", "dave")
    states = {name: tmp_path / name for name in names}
    processes, ready = {}, {}
    descendants = set()

    def start(name):
        process, service = start_full_peer(
            states[name], iroh_binary, cadence=".1")
        processes[name], ready[name] = process, service
        descendants.add(int(service["pid"]))

    def status(name):
        return control_command(ready[name], "peer.status")

    def workspace_row(name, workspace):
        return status(name)["workspaces"][workspace]

    def peer_endpoints(name, workspace):
        return {
            peer["endpoint"]
            for peer in workspace_row(name, workspace)["peers"]
        }

    def remember_forwarders(workspace):
        for name in names:
            for connection in workspace_row(
                    name, workspace)["iroh_connections"]:
                if connection["pid"] is not None:
                    descendants.add(connection["pid"])

    try:
        for name in names:
            start(name)

        workspace = control_command(
            ready["alice"], "auth.workspace.create", "alice")
        for name in names[1:]:
            link = control_command(
                ready["alice"], "auth.user_invite.create", workspace)
            assert control_command(
                ready[name], "auth.user.join", link, name) == workspace

        expected_devices = {
            status(name)["pk"]
            for name in names
        }

        def bootstrap_converged():
            rows = [workspace_row(name, workspace) for name in names]
            return len({row["forest_fingerprint"] for row in rows}) == 1 \
                and all(len(row["writers"]) == len(names) for row in rows) \
                and all(
                    {writer["device"] for writer in row["writers"]}
                    == expected_devices
                    for row in rows
                )

        wait_until(
            bootstrap_converged,
            timeout=45,
            message="four invitees to converge through the bootstrap star",
        )

        # Invitations initially give every joiner Alice's locator. Rewire to
        # one directed line. Each dial still reconciles in both directions:
        # Bob <-> Alice, Carol <-> Bob, and Dave <-> Carol.
        for name, upstream in (("carol", "bob"), ("dave", "carol")):
            assert control_command(
                ready[name],
                "peer.iroh.set",
                workspace,
                ready[upstream]["endpoint_id"],
                ready[upstream]["peer"],
            ) == {"ok": True}
            assert control_command(
                ready[name],
                "peer.iroh.remove",
                workspace,
                ready["alice"]["endpoint_id"],
            ) == {"ok": True}

        assert peer_endpoints("alice", workspace) == set()
        assert peer_endpoints("bob", workspace) == {
            ready["alice"]["endpoint_id"]}
        assert peer_endpoints("carol", workspace) == {
            ready["bob"]["endpoint_id"]}
        assert peer_endpoints("dave", workspace) == {
            ready["carol"]["endpoint_id"]}

        # Restart the tail after rewiring. Its only durable remote locator is
        # an Iroh endpoint/ticket; the private HTTP loopback and child process
        # must be replaced rather than persisted.
        def dave_forwarder_ready():
            rows = workspace_row(
                "dave", workspace)["iroh_connections"]
            return len(rows) == 1 \
                and rows[0]["state"] == "ready" \
                and rows[0]["pid"] is not None

        wait_until(
            dave_forwarder_ready,
            timeout=20,
            message="Dave's line forwarder",
        )
        old_server_pid = int(ready["dave"]["pid"])
        old_endpoint = ready["dave"]["endpoint_id"]
        old_forwarder = workspace_row(
            "dave", workspace)["iroh_connections"][0]
        descendants.add(old_forwarder["pid"])
        assert stop(processes.pop("dave")) == 0
        wait_until(
            lambda: _pid_absent(old_server_pid)
            and _pid_absent(old_forwarder["pid"]),
            timeout=20,
            message="Dave's pre-restart Iroh children to exit",
        )
        start("dave")
        assert ready["dave"]["endpoint_id"] == old_endpoint
        assert peer_endpoints("dave", workspace) == {
            ready["carol"]["endpoint_id"]}
        wait_until(
            dave_forwarder_ready,
            timeout=20,
            message="Dave's restarted line forwarder",
        )
        restarted_forwarder = workspace_row(
            "dave", workspace)["iroh_connections"][0]
        assert restarted_forwarder["pid"] != old_forwarder["pid"]
        descendants.add(restarted_forwarder["pid"])

        authored = {
            control_command(
                ready[name],
                "content.message.post",
                workspace,
                "general",
                f"independent writer: {name}",
            )
            for name in names
        }
        assert len(authored) == len(names)

        def line_converged():
            snapshots = {name: status(name) for name in names}
            rows = {
                name: snapshots[name]["workspaces"][workspace]
                for name in names
            }
            if len({
                    row["forest_fingerprint"]
                    for row in rows.values()}) != 1:
                return False
            if any(
                    len(row["writers"]) != len(names)
                    or any(
                        writer["head"] != writer["projected_head"]
                        for writer in row["writers"])
                    for row in rows.values()):
                return False
            return all(
                authored <= {
                    message["fid"]
                    for message in control_command(
                        ready[name],
                        "content.message.list",
                        workspace,
                    )
                }
                for name in names
            )

        wait_until(
            line_converged,
            timeout=45,
            message="four writers to converge across the Iroh line",
        )
        remember_forwarders(workspace)

        # The local control ports drove authoring and observation. Inter-peer
        # configuration contains only Iroh locators, so every scheduled pull,
        # reverse mirror, grant, and multi-hop relay above crossed real Iroh.
        for name in names:
            row = workspace_row(name, workspace)
            assert all(peer["kind"] == "iroh" for peer in row["peers"])
            configured = {
                f"iroh:{peer['endpoint']}" for peer in row["peers"]
            }
            assert configured.isdisjoint({
                failure["peer"] for failure in row["sync_failures"]
            })
    finally:
        for process in tuple(processes.values()):
            stop(process)
        for pid in descendants:
            wait_until(
                lambda pid=pid: _pid_absent(pid),
                timeout=20,
                message=f"four-peer Iroh child {pid} cleanup",
            )


def test_changed_private_iroh_urls_need_no_retained_sync_walk(tmp_path):
    class CyclingForwarders:
        def __init__(self):
            self.urls = iter([
                "http://127.0.0.1:41001",
                "http://127.0.0.1:41002",
                "http://127.0.0.1:41003",
            ])

        def refresh(self, configured):
            assert len(configured) == 1

        def resolve(self, workspace, peer):
            return next(self.urls)

    node = FullPeer(str(tmp_path / "peer"))
    workspace = "a" * 64
    peer = iroh_peer("b" * 64, "B")
    node.add_workspace(workspace, "workspace", [peer])
    node.use_iroh(iroh_peer("c" * 64, "C"), CyclingForwarders())
    assert [node.resolve_peer(workspace, peer) for _ in range(3)] == [
        "http://127.0.0.1:41001",
        "http://127.0.0.1:41002",
        "http://127.0.0.1:41003",
    ]
    assert not hasattr(node, "sync_cache")


def test_set_and_remove_leave_only_an_inflight_peers_turn_state(tmp_path):
    private_url = "http://127.0.0.1:41001"

    class StaticForwarders:
        def refresh(self, configured):
            self.configured = tuple(configured)

        def resolve(self, workspace, peer):
            return private_url

    node = FullPeer(str(tmp_path / "peer"))
    workspace = "a" * 64
    endpoint = "b" * 64
    peer = iroh_peer(endpoint, "A")
    node.add_workspace(workspace, "workspace", [peer])
    node.use_iroh(iroh_peer("c" * 64, "C"), StaticForwarders())
    url = node.resolve_peer(workspace, peer)
    client = Peer(node, workspace, url)
    client._token = "ordinary-grant"
    client._sync_profile = "sync-v1/full"

    node.set_iroh_peer(workspace, endpoint, "B")
    assert (client._token, client._sync_profile) == (
        "ordinary-grant", "sync-v1/full")
    replacement = node.keyring["workspaces"][workspace]["peers"][0]
    fresh = Peer(node, workspace, node.resolve_peer(workspace, replacement))
    assert fresh._token is fresh._sync_profile is None

    node.remove_iroh_peer(workspace, endpoint)
    assert (client._token, client._sync_profile) == (
        "ordinary-grant", "sync-v1/full")


def test_outbound_startup_is_bounded_cancelled_and_reaped_on_close(tmp_path):
    pid_path = tmp_path / "hung.pid"
    binary = tmp_path / "hung-iroh"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import time\n"
        f"open({str(pid_path)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    binary.chmod(0o700)
    forwarders = IrohForwarders(binary)
    peer = iroh_peer("a" * 64, "A")
    errors = []

    thread = threading.Thread(
        target=lambda: _capture_error(
            errors, forwarders.resolve, "b" * 64, peer))
    thread.start()
    wait_until(pid_path.exists, message="hung outbound child to start")
    pid = int(pid_path.read_text())
    started = time.monotonic()
    forwarders.close()
    elapsed = time.monotonic() - started
    thread.join(STOP_SECONDS)

    assert elapsed < STOP_SECONDS
    assert not thread.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], TimeoutError)
    wait_until(lambda: _pid_absent(pid), message="hung outbound child cleanup")


def test_forwarder_maintenance_attempts_only_one_due_start_per_turn(
        monkeypatch):
    forwarders = IrohForwarders("unused")
    starts = []
    monkeypatch.setattr(
        forwarders, "_start", lambda slot: starts.append(slot.peer["endpoint"]))
    configured = [
        ("f" * 64, iroh_peer(f"{index:064x}", "A"))
        for index in range(8)
    ]

    forwarders.refresh(configured)
    assert len(starts) == 1
    forwarders.maintain()
    assert len(starts) == 2
    forwarders.close()


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


def test_iroh_mode_rejects_persisted_plain_peer_configuration(
        tmp_path, iroh_binary):
    state = tmp_path / "peer"
    node = FullPeer(str(state))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    node.keyring["workspaces"][workspace]["peers"] = [
        "http://peer.example"]
    node.save_keyring()
    service = FullPeerService(
        str(state),
        0,
        cadence=3600,
        control_port=0,
        iroh_binary=iroh_binary,
        iroh_loopback=True,
    )
    addresses = (
        service.peer_server.server_address,
        service.control_server.server_address,
    )

    with pytest.raises(
            ValueError, match="Iroh mode requires Iroh peer locators"):
        service.start()

    assert service.iroh.process.poll() is not None
    assert all(not _address_open(target) for target in addresses)


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
