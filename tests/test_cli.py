"""The process CLI and daemon are transports for family-owned commands."""
import asyncio
from dataclasses import FrozenInstanceError
import io
import json
from types import SimpleNamespace
import urllib.error

import pytest

import facts
from core import http
from core.limits import PayloadTooLarge
from full_peer import cli, daemon
from full_peer.node import FullPeer


EXPECTED = {
    "auth.removal.evict",
    "auth.user.join",
    "auth.user.list",
    "auth.user_invite.create",
    "auth.workspace.create",
    "content.delete.remove",
    "content.file.list",
    "content.file.resume_upload",
    "content.file.save",
    "content.file.send",
    "content.file.upload",
    "content.message.list",
    "content.message.post",
    "content.message.upload",
}


def test_http_gate_host_options_are_immutable_and_fail_closed():
    options = cli._gate_options({
        "TINYP2P_GRANT_TTL": "1234",
        "TINYP2P_MINT_MAX_FETCHES": "7",
        "TINYP2P_MINT_MAX_FETCH_BYTES": "8192",
    })
    assert (
        options.grant_ttl_ms,
        options.max_mint_fetches,
        options.max_mint_fetch_bytes,
    ) == (1234, 7, 8192)
    with pytest.raises(FrozenInstanceError):
        options.grant_ttl_ms = 1

    for invalid in (
            {"TINYP2P_GRANT_TTL": "0"},
            {"TINYP2P_MINT_MAX_FETCHES": "-1"},
            {"TINYP2P_MINT_MAX_FETCH_BYTES": "not-an-integer"}):
        with pytest.raises(RuntimeError, match="invalid"):
            cli._gate_options(invalid)


def test_checked_registry_is_exactly_the_union_of_family_declarations():
    declared = {
        path: command
        for module in facts.MODULES
        for path, command in getattr(module, "CLI", {}).items()
    }
    assert facts.COMMANDS == declared
    assert set(facts.COMMANDS) == EXPECTED
    assert all(path.count(".") >= 2 for path in facts.COMMANDS)


def test_ephemeral_proof_constructors_are_family_owned_and_purpose_keyed():
    declared = {
        purpose: command
        for module in facts.MODULES
        for purpose, command in getattr(module, "PROOF_COMMANDS", {}).items()
    }
    assert facts.PROOF_COMMANDS == declared
    assert set(facts.PROOF_COMMANDS) == {"sync", "upload"}
    assert all(
        command.__module__.startswith("facts.")
        for command in facts.PROOF_COMMANDS.values()
    )


def test_registry_rejects_duplicates_bad_paths_and_noncallables():
    command = lambda node: None
    first = SimpleNamespace(
        __name__="facts.first", CLI={"test.family.run": command})
    duplicate = SimpleNamespace(
        __name__="facts.second", CLI={"test.family.run": command})
    with pytest.raises(ValueError, match="duplicate"):
        facts.compile_commands((first, duplicate))
    for path, handler in (
            ("unqualified", command),
            ("Bad.family.run", command),
            ("test.family.value", 1)):
        module = SimpleNamespace(
            __name__="facts.invalid", CLI={path: handler})
        with pytest.raises(ValueError, match="bad CLI"):
            facts.compile_commands((module,))


def test_one_binder_serves_new_commands_prefixes_and_integer_time(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path))
    workspace = facts.invoke_command(
        node, "auth.workspace.create", ["alice"])
    fid = facts.invoke_command(
        node, "content.message.post",
        [workspace[:12], "general", "zero is a timestamp", "0"],
    )
    assert node.fact_of(workspace, fid).ts == 0

    def echo(host, workspace, value, ts=None):
        return workspace, value, ts

    monkeypatch.setitem(facts.COMMANDS, "test.echo.run", echo)
    assert facts.invoke_command(
        node, "test.echo.run", [workspace[:8], "untouched", "-2"],
    ) == (workspace, "untouched", -2)
    with pytest.raises(ValueError, match="ts must be an integer"):
        facts.invoke_command(
            node, "test.echo.run", [workspace, "value", "tomorrow"])


def test_real_family_commands_take_time_from_the_host_capability(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path))
    ticks = iter((101, 102))
    monkeypatch.setattr(node, "now_ms", lambda: next(ticks))

    workspace = facts.auth.workspace.create(node, "alice")
    fid = facts.content.message.post(
        node, workspace, "general", "host clock")

    assert node.fact_of(workspace, workspace).ts == 101
    assert node.fact_of(workspace, fid).ts == 102


def test_workspace_prefix_must_be_unique():
    node = SimpleNamespace(
        workspaces=lambda: ("a" * 63 + "0", "a" * 63 + "1"))
    with pytest.raises(facts.WorkspaceNotFound, match="ambiguous"):
        facts.workspace_for(node, "a" * 63)
    with pytest.raises(facts.WorkspaceNotFound, match="unknown"):
        facts.workspace_for(node, "b")
    with pytest.raises(facts.WorkspaceNotFound, match="unknown"):
        facts.workspace_for(node, "")


def _handler(node):
    handler = object.__new__(daemon.ControlHandler)
    handler.node = node
    handler.syncer = SimpleNamespace(kicks=0)
    handler.syncer.kick = lambda: setattr(
        handler.syncer, "kicks", handler.syncer.kicks + 1)
    handler._json = lambda code, body: (code, body)
    handler._send = lambda code, *args, **kwargs: (code, None)
    return handler


def _request(handler, path, argv):
    return handler.dispatch(
        json.dumps({"path": path, "argv": argv}).encode())


def test_generic_control_dispatch_maps_failures_and_kicks_only_success(
        tmp_path, monkeypatch):
    handler = _handler(FullPeer(str(tmp_path)))

    code, workspace = _request(
        handler, "auth.workspace.create", ["alice"])
    assert code == 200 and handler.syncer.kicks == 1
    assert _request(
        handler, "content.message.list", ["missing"])[0] == 404
    assert _request(
        handler, "content.message.post", [workspace])[0] == 400
    assert _request(handler, "not.a.command", [])[0] == 404
    assert handler.syncer.kicks == 1

    def denied(node):
        raise ValueError("no")

    def broken(node):
        raise RuntimeError("boom")

    monkeypatch.setitem(facts.COMMANDS, "test.command.denied", denied)
    monkeypatch.setitem(facts.COMMANDS, "test.command.broken", broken)
    assert _request(handler, "test.command.denied", [])[0] == 400
    assert _request(handler, "test.command.broken", [])[0] == 500
    assert handler.syncer.kicks == 1


def test_peer_status_is_local_control_not_a_fact_family_command(tmp_path):
    node = FullPeer(str(tmp_path))
    handler = _handler(node)

    assert _request(handler, "peer.status", []) == (200, {
        "pk": node.pk,
        "member": node.member,
        "workspaces": {},
    })
    assert "peer.status" not in facts.COMMANDS
    assert handler.syncer.kicks == 0


def test_process_cli_forwards_path_and_tokens_without_application_parsing(
        monkeypatch, capsys):
    calls = []

    def control(node_url, path, argv):
        calls.append((node_url, path, argv))
        return {"received": argv}

    monkeypatch.setattr(cli, "ctl", control)
    assert cli.main([
        "--node", "http://node",
        "new.family.command", "name=value", "two words",
    ]) == 0
    assert calls == [(
        "http://node", "new.family.command",
        ["name=value", "two words"],
    )]
    assert json.loads(capsys.readouterr().out) == {
        "received": ["name=value", "two words"]}


@pytest.mark.parametrize("declared", [True, False])
def test_control_success_response_is_bounded_before_json(
        monkeypatch, declared):
    class Response:
        headers = {"Content-Length": "9"} if declared else {}

        def __init__(self):
            self.reads = []
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.closed = True

        def read(self, maximum):
            self.reads.append(maximum)
            return b"x" * maximum

    response = Response()
    monkeypatch.setattr(cli, "MAX_CONTROL_BYTES", 8)
    monkeypatch.setattr(
        cli.urllib.request, "urlopen",
        lambda *_args, **_kwargs: response)

    with pytest.raises(PayloadTooLarge, match="control response"):
        cli.ctl("https://node.invalid", "test.command.run", [])

    assert response.reads == ([] if declared else [9])
    assert response.closed is True


def test_exact_bound_control_response_reaches_json(monkeypatch):
    raw = b"{}" + b" " * 6

    class Response:
        headers = {"Content-Length": str(len(raw))}

        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.closed = True

        @staticmethod
        def read(maximum):
            assert maximum == 9
            return raw

    response = Response()
    monkeypatch.setattr(cli, "MAX_CONTROL_BYTES", 8)
    monkeypatch.setattr(
        cli.urllib.request, "urlopen",
        lambda *_args, **_kwargs: response)

    assert cli.ctl(
        "https://node.invalid", "test.command.run", []) == {}
    assert response.closed is True


def test_control_error_response_is_bounded_and_closed(
        monkeypatch, capsys):
    class Body(io.BytesIO):
        def __init__(self, raw):
            super().__init__(raw)
            self.reads = []

        def read(self, maximum=-1):
            self.reads.append(maximum)
            return super().read(maximum)

    body = Body(b"x" * 9)
    error = urllib.error.HTTPError(
        "https://node.invalid/ctl/command",
        500,
        "hostile endpoint",
        {},
        body,
    )
    monkeypatch.setattr(cli, "MAX_CONTROL_BYTES", 8)
    monkeypatch.setattr(
        cli, "ctl",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error))

    assert cli.main(["test.command.run"]) == 1
    assert body.reads == [9]
    assert body.closed is True
    assert "hostile endpoint" in capsys.readouterr().err


def test_command_discovery_is_sorted_and_needs_no_daemon(capsys):
    assert cli.main(["--commands"]) == 0
    paths = capsys.readouterr().out.splitlines()
    assert paths == sorted(paths)
    assert set(paths) == EXPECTED | set(daemon.LOCAL_COMMANDS)


def test_help_is_local_and_does_not_become_a_command(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "ctl",
        lambda *args: pytest.fail("help reached the daemon"))
    assert cli.main(["--help"]) == 0
    assert "scope.family.verb" in capsys.readouterr().out


def test_peer_gate_cannot_serve_local_control(tmp_path):
    node = FullPeer(str(tmp_path))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    gate = http.HttpGate(
        http.AsyncFromSyncReader(node.store(workspace)),
        workspace,
        b"c" * 32,
        lambda: 100,
        receiver=object(),
    )

    response = asyncio.run(gate.handle(
        "POST", "/ctl/command", {"ws": workspace}, {}, b"{}"))

    assert response.status == 405


def test_control_server_refuses_non_loopback_before_binding(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path))
    syncer = SimpleNamespace()
    monkeypatch.setattr(
        daemon,
        "ThreadingHTTPServer",
        lambda *_args: pytest.fail("non-loopback control address was bound"),
    )

    with pytest.raises(
            ValueError, match="control listener must use a loopback IP"):
        daemon._control_server(node, syncer, "0.0.0.0", 0)
