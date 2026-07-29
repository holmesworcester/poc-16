"""The process CLI and daemon are transports for family-owned commands."""
import json
from types import SimpleNamespace

import pytest

import facts
from core import cli, daemon
from core.node import Node
from core.runtime import AuthorityRejected


EXPECTED = {
    "auth.removal.evict",
    "auth.user.join",
    "auth.user.list",
    "auth.user_invite.create",
    "auth.workspace.create",
    "content.delete.remove",
    "content.file.list",
    "content.file.save",
    "content.file.send",
    "content.message.list",
    "content.message.post",
}


def test_checked_registry_is_exactly_the_union_of_family_declarations():
    declared = {
        path: command
        for module in facts.MODULES
        for path, command in getattr(module, "CLI", {}).items()
    }
    assert facts.COMMANDS == declared
    assert set(facts.COMMANDS) == EXPECTED
    assert all(path.count(".") >= 2 for path in facts.COMMANDS)


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
    node = Node(str(tmp_path))
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
    handler = object.__new__(daemon.Handler)
    handler.node = node
    handler.syncer = SimpleNamespace(kicks=0)
    handler.syncer.kick = lambda: setattr(
        handler.syncer, "kicks", handler.syncer.kicks + 1)
    handler._json = lambda code, body: (code, body)
    handler._send = lambda code, *args, **kwargs: (code, None)
    return handler


def _request(handler, path, argv):
    return handler.ctl_post(
        ["ctl", "command"],
        json.dumps({"path": path, "argv": argv}).encode(),
    )


def test_generic_control_dispatch_maps_failures_and_kicks_only_success(
        tmp_path, monkeypatch):
    handler = _handler(Node(str(tmp_path)))

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
        raise AuthorityRejected("no")

    def broken(node):
        raise RuntimeError("boom")

    monkeypatch.setitem(facts.COMMANDS, "test.command.denied", denied)
    monkeypatch.setitem(facts.COMMANDS, "test.command.broken", broken)
    assert _request(handler, "test.command.denied", [])[0] == 403
    assert _request(handler, "test.command.broken", [])[0] == 500
    assert handler.syncer.kicks == 1


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


def test_command_discovery_is_sorted_and_needs_no_daemon(capsys):
    assert cli.main(["--commands"]) == 0
    paths = capsys.readouterr().out.splitlines()
    assert paths == sorted(paths)
    assert set(paths) == EXPECTED | set(daemon.CORE_COMMANDS)


def test_help_is_local_and_does_not_become_a_command(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "ctl",
        lambda *args: pytest.fail("help reached the daemon"))
    assert cli.main(["--help"]) == 0
    assert "scope.family.verb" in capsys.readouterr().out
