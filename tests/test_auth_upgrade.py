"""Upgrade coverage for workspaces persisted with the pre-rename auth tags."""
from tinyp2p import cmds
from tinyp2p.crypto import keypair
from tinyp2p.facts.auth.legacy_genesis import genesis
from tinyp2p.facts.auth.legacy_invite import invite
from tinyp2p.facts.auth.legacy_join import join
from tinyp2p.facts.auth.legacy_signature import legacy_signature
from tinyp2p.node import INDEX_VERSION, Node


def test_legacy_auth_store_upgrades_rebuilds_and_accepts_new_facts(tmp_path):
    node = Node(str(tmp_path / "legacy"))
    founder_secret, founder = node.identity()
    root = genesis(founder_secret, founder, "alice", 1)
    workspace = root.fid
    node.add_workspace(workspace, "alice", peers=[])
    node.ingest_new(workspace, [root], {root.fid: []})

    invite_secret, invite_public = keypair()
    invitation = invite(founder, invite_public, 2)
    invitation_sig = legacy_signature(
        founder_secret, founder, invitation, 2)
    bob_secret, bob = keypair()
    joined = join(invitation, invite_secret, bob, "bob", 3)
    joined_sig = legacy_signature(bob_secret, bob, joined, 3)
    node.ingest_new(
        workspace,
        [invitation_sig, invitation, joined_sig, joined],
        {
            invitation_sig.fid: [],
            invitation.fid: [invitation_sig.fid, root.fid],
            joined_sig.fid: [],
            joined.fid: [invitation.fid, joined_sig.fid],
        },
    )

    index = node.idx(workspace)
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
        ("family-contract-v1",))
    index.commit()
    index.close()
    node.app.close()

    upgraded = Node(node.dir)
    assert upgraded.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='index-version'").fetchone()[0] \
        == INDEX_VERSION
    assert {row[0] for row in upgraded.idx(workspace).execute(
        "SELECT DISTINCT t FROM facts")} \
        == {"genesis", "sig", "invite", "join"}

    current_message = cmds.post(
        upgraded, workspace, "general", "authored after upgrade")
    assert upgraded.fact_of(workspace, current_message).t == "msg"

    upgraded.app.execute("DELETE FROM members WHERE ws=?", (workspace,))
    upgraded.app.commit()
    upgraded.idx(workspace).executescript(
        "DELETE FROM facts; DELETE FROM offers; DELETE FROM globals; "
        "DELETE FROM meta;")
    upgraded.idx(workspace).commit()
    upgraded.rebuild(workspace)

    assert {member["name"] for member in cmds.members(upgraded, workspace)} \
        == {"alice", "bob"}
    assert {row[0] for row in upgraded.idx(workspace).execute(
        "SELECT DISTINCT t FROM facts")} \
        >= {"genesis", "sig", "invite", "join", "signature", "msg"}
