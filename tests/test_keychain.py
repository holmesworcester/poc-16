"""The node-local plural identity holder and workspace bindings."""
import json
import stat

import facts
import pytest

from core.crypto import keypair
from full_peer.keychain import (
    MAX_IROH_TICKET_CHARS,
    MAX_PEERS_PER_WORKSPACE,
    iroh_peer,
)
from full_peer import keychain as keychain_module
from full_peer.node import FullPeer, now_ms
from full_peer.walk import Peer

from .util import add_member


def test_new_keychain_holds_equal_identities_and_workspace_bindings(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    default_secret, default_id = node.keychain.default()
    other_id = node.keychain.add_identity()
    other_secret, other_public = node.keychain.identity(other_id)

    assert default_secret.verify_key.encode().hex() == default_id == node.pk
    assert other_secret.verify_key.encode().hex() == other_public == other_id
    assert set(node.keyring) == {
        "keys", "permit_secret", "workspaces"}
    assert len(bytes.fromhex(node.keyring["permit_secret"])) == 32

    workspace = facts.auth.workspace.create(node, "alice")
    assert node.identity_id(workspace) == default_id
    node.bind_identity(workspace, other_id)
    assert node.identity_id(workspace) == other_id
    fact_count = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    with pytest.raises(ValueError, match="not a workspace member"):
        facts.content.message.post(node, workspace, "general", "must not report success")
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == fact_count

    reopened = FullPeer(node.dir)
    assert reopened.identity_id(workspace) == other_id
    assert set(reopened.keyring["keys"]) == {default_id, other_id}
    with pytest.raises(KeyError, match="unknown identity"):
        reopened.add_workspace(
            "b" * 64, "bad", peers=[], identity="not-a-key")


def test_retired_keyring_schema_is_rejected_instead_of_migrated(tmp_path):
    directory = tmp_path / "retired"
    directory.mkdir()
    secret, _public = keypair()
    workspace = "a" * 64
    (directory / "keyring.json").write_text(json.dumps({
        "sk": secret.encode().hex(),
        "workspaces": {
            workspace: {"name": "old", "peers": ["http://peer"]},
        },
    }))

    with pytest.raises(ValueError, match="keyring schema"):
        FullPeer(str(directory))
    assert json.loads((directory / "keyring.json").read_text())["sk"] \
        == secret.encode().hex()


def test_iroh_peer_reachability_is_bounded_canonical_and_durable(tmp_path):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    peer = iroh_peer("a" * 64, "A_-0")

    node.keyring["workspaces"][workspace]["peers"] = [peer]
    node.save_keyring()
    reopened = FullPeer(str(directory))

    assert reopened.keyring["workspaces"][workspace]["peers"] == [peer]
    assert set(peer) == {"kind", "endpoint", "ticket"}
    assert "url" not in peer

    for bad in (
            {"kind": "iroh", "endpoint": "A" * 64, "ticket": "A"},
            {"kind": "iroh", "endpoint": "a" * 64, "ticket": ""},
            {
                "kind": "iroh",
                "endpoint": "a" * 64,
                "ticket": "A" * (MAX_IROH_TICKET_CHARS + 1),
            },
            {
                "kind": "iroh",
                "endpoint": "a" * 64,
                "ticket": "A",
                "authority": True,
            }):
        with pytest.raises(ValueError):
            reopened.add_workspace(
                "b" * 64, "bad", peers=[bad])

    too_many = [
        iroh_peer(f"{index:064x}", "A")
        for index in range(MAX_PEERS_PER_WORKSPACE + 1)
    ]
    with pytest.raises(ValueError, match="workspace peers"):
        reopened.add_workspace("c" * 64, "too many", peers=too_many)


def test_keyring_save_is_private_atomic_and_cleans_failed_temporary(
        tmp_path, monkeypatch):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    path = directory / "keyring.json"
    original = path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def fail_replace(_source, _destination):
        raise OSError("simulated replace failure")

    with monkeypatch.context() as failed:
        failed.setattr(keychain_module.os, "replace", fail_replace)
        with pytest.raises(OSError, match="simulated"):
            node.add_workspace("a" * 64, "not published", peers=[])

    assert path.read_bytes() == original
    assert list(directory.glob(".keyring.*.tmp")) == []
    assert node.keyring["workspaces"] == {}
    node.keychain.add_identity()
    assert json.loads(path.read_text())["workspaces"] == {}


def test_failed_identity_commit_never_leaks_into_a_later_save(
        tmp_path, monkeypatch):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    path = directory / "keyring.json"
    original = json.loads(path.read_text())
    secret, rejected_id = keypair()

    with monkeypatch.context() as failed:
        failed.setattr(
            keychain_module.os,
            "replace",
            lambda *_args: (_ for _ in ()).throw(
                OSError("simulated replace failure")),
        )
        with pytest.raises(OSError, match="simulated"):
            node.keychain.add_identity(secret)

    assert node.keyring == original
    assert json.loads(path.read_text()) == original
    node.add_workspace("a" * 64, "later", peers=[])
    assert rejected_id not in node.keyring["keys"]
    assert rejected_id not in json.loads(path.read_text())["keys"]


def test_failed_binding_commit_never_leaks_into_a_later_save(
        tmp_path, monkeypatch):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    original_id = node.identity_id(workspace)
    rejected_id = node.keychain.add_identity()
    path = directory / "keyring.json"
    original = json.loads(path.read_text())

    with monkeypatch.context() as failed:
        failed.setattr(
            keychain_module.os,
            "replace",
            lambda *_args: (_ for _ in ()).throw(
                OSError("simulated replace failure")),
        )
        with pytest.raises(OSError, match="simulated"):
            node.bind_identity(workspace, rejected_id)

    assert node.identity_id(workspace) == original_id
    assert json.loads(path.read_text()) == original
    node.add_workspace("b" * 64, "later", peers=[])
    assert node.identity_id(workspace) == original_id
    assert json.loads(path.read_text())["workspaces"][workspace][
        "identity"] == original_id


def test_post_replace_directory_fsync_failure_keeps_disk_and_live_aligned(
        tmp_path, monkeypatch):
    directory = tmp_path / "node"
    node = FullPeer(str(directory))
    path = directory / "keyring.json"
    workspace = "a" * 64
    real_fsync = keychain_module.os.fsync

    def fail_directory_fsync(descriptor):
        if stat.S_ISDIR(keychain_module.os.fstat(descriptor).st_mode):
            raise OSError("simulated directory fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(keychain_module.os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError, match="directory fsync"):
        node.add_workspace(workspace, "visible replacement", peers=[])

    persisted = json.loads(path.read_text())
    assert persisted == node.keyring
    assert persisted["workspaces"][workspace]["name"] == "visible replacement"
    assert list(directory.glob(".keyring.*.tmp")) == []


def test_commands_author_with_the_workspace_bound_identity(tmp_path):
    node = FullPeer(str(tmp_path / "bound"))
    workspace = facts.auth.workspace.create(node, "alice")
    invite_ts = now_ms() + 1
    member_secret, member_public, _ = add_member(
        node, workspace, "bob", ts=invite_ts)
    assert node.keychain.add_identity(member_secret) == member_public
    node.bind_identity(workspace, member_public)

    fid = facts.content.message.post(node, workspace, "general", "from the bound device")
    fact = node.fact_of(workspace, fid)

    assert node.pk != member_public
    assert fact.body["pk"] == member_public
    assert facts.content.message.messages(node, workspace)[-1]["text"] == "from the bound device"


def test_rebinding_a_workspace_has_no_retained_peer_grants(tmp_path):
    node = FullPeer(str(tmp_path / "rebind"))
    workspace = facts.auth.workspace.create(node, "alice")
    replacement = node.keychain.add_identity()
    in_flight = Peer(node, workspace, "http://peer-a")
    in_flight._token = "minted-for-old-identity"
    in_flight._sync_profile = "sync-v1/full"

    node.bind_identity(workspace, replacement)

    assert in_flight._token == "minted-for-old-identity"
    fresh = Peer(node, workspace, "http://peer-a")
    assert fresh._token is fresh._sync_profile is None
    assert not hasattr(node, "sync_cache")


def test_publish_fails_closed_if_workspace_identity_changes_mid_command(tmp_path):
    node = FullPeer(str(tmp_path / "race"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    carol_secret, carol, _ = add_member(node, workspace, "carol", ts=20)
    node.keychain.add_identity(bob_secret)
    node.keychain.add_identity(carol_secret)
    node.bind_identity(workspace, bob)

    original_identity = node.identity
    calls = 0

    def identity(selected_workspace=None):
        nonlocal calls
        calls += 1
        captured = original_identity(selected_workspace)
        if calls == 1:
            node.bind_identity(workspace, carol)
        return captured

    node.identity = identity
    before = tuple(facts.content.message.messages(node, workspace))
    store = node.store(workspace)
    before_heads = {
        key: store.get(key)
        for key in store.list(f"heads/{workspace}/")
    }
    with pytest.raises(
            ValueError, match="publishing identity owner mismatch"):
        facts.content.message.post(
            node, workspace, "general", "captured signer", ts=30)

    assert calls >= 2
    assert node.identity_id(workspace) == carol
    assert tuple(facts.content.message.messages(node, workspace)) == before
    assert {
        key: store.get(key)
        for key in store.list(f"heads/{workspace}/")
    } == before_heads
