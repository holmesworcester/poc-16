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
from core.close import encode_pile
from core.crypto import h, unseal
from core.limits import (
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
    MAX_OBJECT_BYTES,
    MAX_ROOT_BYTES,
)
from core.repository_reader import RepositoryReader
from facts.auth import request
from full_peer import walk as walk_module
from full_peer.daemon import FullPeerService
from full_peer.iroh_forwarders import IrohForwarders
from full_peer.iroh_process import STOP_SECONDS
from full_peer.keychain import iroh_peer
from full_peer.node import FullPeer, now_ms
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
        and path.name != ".root.lock"
        and not path.name.endswith((".idx.db", ".idx.db-shm", ".idx.db-wal"))
    }


def http_request_threads():
    return {
        thread.ident for thread in threading.enumerate()
        if thread.is_alive()
        and thread.ident is not None
        and "(process_request_thread)" in thread.name
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
    identity_secret = bootstrap.identity(workspace)[0]
    issued = now_ms()
    pile = encode_pile(request.payload(
        bootstrap, workspace, "sync", issued + 300_000, issued))
    bootstrap.sql(workspace).db.close()

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
        token, capability = mint(
            direct, workspace, pile, identity_secret)
        assert capability == "sync-v1/full"
        expected = call(
            direct,
            "GET",
            f"/root?ws={workspace}",
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
                    f"/root?ws={workspace}",
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
            f"/root?ws={workspace}",
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
    identity_secret = bootstrap.identity(workspace)[0]
    issued = now_ms()
    pile = encode_pile(request.payload(
        bootstrap, workspace, "sync", issued + 300_000, issued))
    bootstrap.sql(workspace).db.close()

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

        token, capability = mint(
            through_iroh[0], workspace, pile, identity_secret)
        assert capability == "sync-v1/full"
        raw = b"ordinary object bytes through Iroh"
        oid = h(raw)
        assert parity(
            "PUT",
            f"/page/{oid}?ws={workspace}",
            body=raw,
            token=token,
        )[0] == 204

        token, _ = mint(
            through_iroh[1], workspace, pile, identity_secret)
        assert parity(
            "GET",
            f"/page/{oid}?ws={workspace}",
            token=token,
        )[:2] == (200, raw)

        baseline = repository_bytes(state, workspace)
        time.sleep(2.2)
        assert parity(
            "GET",
            f"/page/{oid}?ws={workspace}",
            token=token,
        )[0] == 401
        assert repository_bytes(state, workspace) == baseline

        assert parity(
            "GET",
            f"/root?ws={workspace}",
        )[0] == 401
        token, _ = mint(
            through_iroh[0], workspace, pile, identity_secret)
        tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
        assert parity(
            "GET",
            f"/root?ws={workspace}",
            token=tampered,
        )[0] == 401

        token, _ = mint(
            direct, workspace, pile, identity_secret)
        assert parity(
            "GET",
            "/root?ws=" + "0" * 64,
            token=token,
        )[0] == 404

        token, _ = mint(
            through_iroh[0], workspace, pile, identity_secret)
        assert parity(
            "PUT",
            f"/page/{'f' * 64}?ws={workspace}",
            body=b"wrong digest",
            token=token,
        )[0] == 400

        token, _ = mint(
            through_iroh[1], workspace, pile, identity_secret)
        assert parity(
            "PUT",
            f"/pile/not-{member}/{h(b'pile')}?ws={workspace}",
            body=b"pile",
            token=token,
        )[0] == 403

        for method, path in (
                ("POST", f"/root?ws={workspace}"),
                ("GET", f"/unknown?ws={workspace}")):
            route_token, _ = mint(
                through_iroh[0], workspace, pile, identity_secret)
            assert parity(
                method,
                path,
                token=route_token,
            )[0] == 404

        control_request = b'{"path":"peer.status","argv":[]}'
        token, _ = mint(
            through_iroh[0], workspace, pile, identity_secret)
        peer_control = parity(
            "POST",
            f"/ctl/command?ws={workspace}",
            body=control_request,
            token=token,
        )
        assert peer_control[0] == 405

        token, _ = mint(
            direct, workspace, pile, identity_secret)
        oversized = (
            f"PUT /page/{h(b'never lands')}?ws={workspace} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Length: {MAX_OBJECT_BYTES + 1}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        oversized_results = [
            raw_call(target, oversized) for target in paths
        ]
        assert oversized_results[1:] == \
            oversized_results[:1] * (len(oversized_results) - 1)
        assert oversized_results[0][0] == 413

        token, _ = mint(
            through_iroh[0], workspace, pile, identity_secret)
        malformed = (
            f"PUT /page/{h(b'malformed never lands')}?"
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
        assert invite["p"] == {
            "kind": "iroh",
            "endpoint": ready["endpoint_id"],
            "ticket": ready["peer"],
        }
        assert "u" not in invite
        after_invite = repository_bytes(state, workspace)
        assert {
            key: value for key, value in after_invite.items()
            if not key.startswith("invite/")
        } == baseline
        assert len([
            key for key in after_invite if key.startswith("invite/")
        ]) == 1

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
            roots = {
                workspace_row(alice_ready, workspace)["root"],
                workspace_row(bob_ready, workspace)["root"],
            }
            fids = {
                row["fid"]
                for row in control_command(
                    bob_ready, "content.message.list", workspace)
            }
            return len(roots) == 1 and None not in roots \
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


def test_changed_private_iroh_urls_discard_each_superseded_sync_walk(tmp_path):
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
    url = node.resolve_peer(workspace, peer)
    unrelated = {"keep": True}
    node.sync_cache[("d" * 64, "http://127.0.0.1:49999")] = unrelated

    for expected in (
            "http://127.0.0.1:41002",
            "http://127.0.0.1:41003"):
        superseded = {"walk": object()}
        node.sync_cache[(workspace, url)] = superseded
        url = node.resolve_peer(workspace, peer)
        assert url == expected
        assert "walk" in superseded
        assert (workspace, url) not in node.sync_cache

    current = {"current": True}
    node.sync_cache[(workspace, url)] = current
    assert [
        key for key in node.sync_cache if key[0] == workspace
    ] == [(workspace, "http://127.0.0.1:41003")]
    assert node.sync_cache == {
        (workspace, "http://127.0.0.1:41003"): current,
        ("d" * 64, "http://127.0.0.1:49999"): unrelated,
    }


def test_set_and_remove_detach_cache_without_mutating_an_active_http_walk(
        tmp_path, monkeypatch):
    private_url = "http://127.0.0.1:41001"

    class StaticForwarders:
        def refresh(self, configured):
            self.configured = tuple(configured)

        def resolve(self, workspace, peer):
            return private_url

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _maximum):
            return b"root"

    class BarrierCache(dict):
        def __init__(self):
            super().__init__(token="ordinary-grant")
            self.entered = threading.Event()
            self.resume = threading.Event()

        def __contains__(self, key):
            present = super().__contains__(key)
            if key == "token":
                self.entered.set()
                if not self.resume.wait(5):
                    raise TimeoutError("cache race barrier")
            return present

    monkeypatch.setattr(
        walk_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(),
    )
    node = FullPeer(str(tmp_path / "peer"))
    workspace = "a" * 64
    endpoint = "b" * 64
    peer = iroh_peer(endpoint, "A")
    node.add_workspace(workspace, "workspace", [peer])
    node.use_iroh(iroh_peer("c" * 64, "C"), StaticForwarders())

    def race(configured_peer, edit):
        url = node.resolve_peer(workspace, configured_peer)
        cache = BarrierCache()
        with node.lock:
            node.sync_cache[(workspace, url)] = cache
        client = Peer(node, workspace, url)
        errors = []
        thread = threading.Thread(
            target=lambda: _capture_error(
                errors,
                lambda: client.root(response_limit=MAX_ROOT_BYTES),
            ),
        )
        thread.start()
        assert cache.entered.wait(5)
        try:
            edit()
        finally:
            cache.resume.set()
        thread.join(5)

        assert not thread.is_alive()
        assert errors == []
        assert cache == {"token": "ordinary-grant"}
        assert (workspace, url) not in node.sync_cache
        assert Peer(node, workspace, url).cache is not cache
        node._evict_sync_cache(workspace, url)

    race(peer, lambda: node.set_iroh_peer(workspace, endpoint, "B"))
    replacement = node.keyring["workspaces"][workspace]["peers"][0]
    race(replacement, lambda: node.remove_iroh_peer(workspace, endpoint))


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
