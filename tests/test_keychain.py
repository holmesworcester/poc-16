"""The node-local plural identity holder and workspace bindings."""
import json

import pytest

from core import cmds
from core.crypto import keypair
from core.node import Node, now_ms

from .util import add_member


def test_new_keychain_holds_equal_identities_and_workspace_bindings(tmp_path):
    node = Node(str(tmp_path / "node"))
    default_secret, default_id = node.keychain.default()
    other_id = node.keychain.add_identity()
    other_secret, other_public = node.keychain.identity(other_id)

    assert default_secret.verify_key.encode().hex() == default_id == node.pk
    assert other_secret.verify_key.encode().hex() == other_public == other_id
    assert set(node.keyring) == {"keys", "workspaces"}

    workspace = cmds.create(node, "alice")
    assert node.identity_id(workspace) == default_id
    node.bind_identity(workspace, other_id)
    assert node.identity_id(workspace) == other_id
    fact_count = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0]
    with pytest.raises(ValueError, match="not a workspace member"):
        cmds.post(node, workspace, "general", "must not report success")
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts").fetchone()[0] == fact_count

    reopened = Node(node.dir)
    assert reopened.identity_id(workspace) == other_id
    assert set(reopened.keyring["keys"]) == {default_id, other_id}
    with pytest.raises(KeyError, match="unknown identity"):
        reopened.add_workspace(
            "b" * 64, "bad", peers=[], identity="not-a-key")


def test_legacy_single_keyring_migrates_without_changing_identity(tmp_path):
    directory = tmp_path / "legacy"
    directory.mkdir()
    secret, public = keypair()
    workspace = "a" * 64
    (directory / "keyring.json").write_text(json.dumps({
        "sk": secret.encode().hex(),
        "workspaces": {
            workspace: {"name": "old", "peers": ["http://peer"]},
        },
    }))

    node = Node(str(directory))

    assert node.pk == public
    assert node.identity_id(workspace) == public
    assert node.keyring == {
        "keys": {public: secret.encode().hex()},
        "workspaces": {
            workspace: {
                "name": "old",
                "peers": ["http://peer"],
                "identity": public,
            },
        },
    }
    persisted = json.loads((directory / "keyring.json").read_text())
    assert "sk" not in persisted
    assert persisted == node.keyring


def test_commands_author_with_the_workspace_bound_identity(tmp_path):
    node = Node(str(tmp_path / "bound"))
    workspace = cmds.create(node, "alice")
    invite_ts = now_ms() + 1
    member_secret, member_public, _ = add_member(
        node, workspace, "bob", ts=invite_ts)
    assert node.keychain.add_identity(member_secret) == member_public
    node.bind_identity(workspace, member_public)

    fid = cmds.post(node, workspace, "general", "from the bound device")
    fact = node.fact_of(workspace, fid)

    assert node.pk != member_public
    assert fact.body["pk"] == member_public
    assert cmds.msgs(node, workspace)[-1]["text"] == "from the bound device"


def test_rebinding_a_workspace_invalidates_its_cached_peer_grants(tmp_path):
    node = Node(str(tmp_path / "rebind"))
    workspace = cmds.create(node, "alice")
    other_workspace = "f" * 64
    replacement = node.keychain.add_identity()
    stale = {"token": "minted-for-old-identity", "etag": "old"}
    unrelated = {"token": "keep"}
    node.sync_cache[(workspace, "http://peer-a")] = stale
    node.sync_cache[(other_workspace, "http://peer-b")] = unrelated

    node.bind_identity(workspace, replacement)

    assert stale == {}
    assert (workspace, "http://peer-a") not in node.sync_cache
    assert node.sync_cache[(other_workspace, "http://peer-b")] is unrelated


def test_publish_keeps_the_identity_that_signed_during_a_rebind(tmp_path):
    node = Node(str(tmp_path / "race"))
    workspace = cmds.create(node, "alice", ts=1)
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
    fid = cmds.post(node, workspace, "general", "captured signer", ts=30)

    assert calls >= 2  # ingest names its pile with the newly bound identity
    assert node.identity_id(workspace) == carol
    assert node.fact_of(workspace, fid).body["pk"] == bob
    assert cmds.msgs(node, workspace)[-1]["text"] == "captured signer"
