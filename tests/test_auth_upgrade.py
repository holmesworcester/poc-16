"""Upgrade coverage for workspaces persisted with the pre-rename auth tags."""
import base64

from tinyp2p import cmds, facts
from tinyp2p.crypto import box_encrypt, kdf, keypair
from tinyp2p.fact import canon
from tinyp2p.facts.auth.legacy_genesis import genesis
from tinyp2p.facts.auth.legacy_invite import invite
from tinyp2p.facts.auth.legacy_join import join
from tinyp2p.facts.auth.legacy_signature import legacy_signature
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.layout import layout
from tinyp2p.node import INDEX_VERSION, Node
from tinyp2p.shape import boundary

from .util import (
    add_member,
    all_fids,
    author_msg,
    closed_subset,
    deliver,
    member_src,
)


def _minimum_fid_deps(node, workspace, fact):
    """Resolve needs the way the pre-proof-rank index contract did."""
    index = node.idx(workspace)
    dependencies = [fid for _, fid in fact.refs()]
    handler = facts.handler_for(fact.t)
    assert handler is not None
    for need in handler.needs(fact):
        name, a0, a1 = need[:3]
        query = "SELECT src FROM offers WHERE name=? AND a0=?"
        arguments = [name, a0]
        if a1 is not None:
            query += " AND a1=?"
            arguments.append(a1)
        row = index.execute(
            query + " ORDER BY src LIMIT 1", arguments).fetchone()
        assert row is not None
        source = row[0]
        for required_name, required_a0, required_a1 in (
                need[3] if len(need) == 4 else ()):
            assert index.execute(
                "SELECT 1 FROM offers "
                "WHERE src=? AND name=? AND a0=? AND a1=?",
                (source, required_name, required_a0, required_a1 or ""),
            ).fetchone() is not None
        dependencies.append(source)
    return dependencies


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
    node.app.execute("PRAGMA user_version=0")
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

    facts.clear(upgraded.app, workspace)
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


def test_invite_link_minted_before_upgrade_redeems_after_upgrade(
        tmp_path, monkeypatch):
    founder_secret, founder = keypair()
    root = genesis(founder_secret, founder, "alice", 1)
    invite_secret, invite_public = keypair()
    invitation = invite(founder, invite_public, 2)
    invitation_sig = legacy_signature(
        founder_secret, founder, invitation, 2)
    seed = b"legacy-invite-seed".ljust(32, b"\0")
    blob = canon({
        "pile": [
            root.to_json(),
            invitation_sig.to_json(),
            invitation.to_json(),
        ],
        "isk": invite_secret.encode().hex(),
        "ws": root.fid,
    })
    encrypted = box_encrypt(kdf(seed, "key"), blob)

    class Response:
        def read(self):
            return encrypted

    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *args, **kwargs: Response())
    monkeypatch.setattr("tinyp2p.walk.walk", lambda *args, **kwargs: None)
    link = base64.urlsafe_b64encode(canon({
        "u": "http://legacy-peer",
        "ws": root.fid,
        "s": seed.hex(),
    })).decode()
    joining = Node(str(tmp_path / "joining"))

    workspace = cmds.join(joining, link, "bob")

    assert workspace == root.fid
    assert {row[0] for row in joining.idx(workspace).execute(
        "SELECT DISTINCT t FROM facts")} \
        >= {"genesis", "sig", "invite", "signature", "user"}
    assert {member["name"] for member in cmds.members(joining, workspace)} \
        == {"alice", "bob"}


def test_semantic_index_upgrade_republishes_ranked_authority_closures(
        tmp_path):
    """An old root can fingerprint the same ids but embed different closures.

    Opening it under a proof-ranked index contract must publish a fresh layout,
    not stamp or memoize the old minimum-fid leaf piles.
    """
    node = Node(str(tmp_path / "old-layout"))
    workspace = cmds.create(node, "root", ts=1)
    bob_secret, bob, original = add_member(node, workspace, "bob", ts=10)
    q_secret, q, _ = add_member(node, workspace, "q", ts=20)
    deep_secret, deep, _ = add_member(
        node, workspace, "deep", ts=30, inviter=(q_secret, q))

    for ordinal in range(1000):
        invite_secret, invite_public = keypair()
        invitation = user_invite(
            deep, invite_public, 100 + ordinal * 2)
        rejoined = user(
            invitation, invite_secret, bob, "bob-deep",
            101 + ordinal * 2)
        if rejoined.fid < original.fid:
            break
    else:
        raise AssertionError("could not construct a lower-fid deep rejoin")

    invitation_sig = signature(
        deep_secret, deep, invitation, invitation.ts)
    rejoined_sig = signature(
        bob_secret, bob, rejoined, rejoined.ts)
    node.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined],
        {
            invitation_sig.fid: [],
            invitation.fid: [
                invitation_sig.fid,
                member_src(node, workspace, deep),
            ],
            rejoined_sig.fid: [],
            rejoined.fid: [invitation.fid, rejoined_sig.fid],
        },
    )
    assert member_src(node, workspace, bob) == original.fid

    # Force a promoted range after all membership facts, then author one more
    # Bob message. Its out-of-range membership closure differs between the old
    # minimum-fid rule and the current shortest-proof rule.
    for ordinal in range(200):
        posted = author_msg(
            node, workspace, bob_secret, bob, f"boundary-{ordinal}",
            ts=5000 + ordinal)
        if boundary(posted.fid):
            break
    else:
        raise AssertionError("could not construct a promoted message range")
    final = author_msg(
        node, workspace, bob_secret, bob, "after-boundary", ts=6000)
    assert rejoined.fid in _minimum_fid_deps(
        node, workspace, final)

    canonical_root = node.store(workspace).get("root")
    legacy_root, objects = layout(
        node.keys(workspace),
        lambda fid: node.fact_of(workspace, fid),
        lambda fid: _minimum_fid_deps(
            node, workspace, node.fact_of(workspace, fid)),
        workspace,
        node.globals(workspace),
        None,
    )
    assert legacy_root != canonical_root
    store = node.store(workspace)
    for key, value in objects.items():
        store.put_if_absent(key, value)
    store.put("root", legacy_root)

    index = node.idx(workspace)
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('root', ?)",
        (store.etag("root"),),
    )
    index.execute(
        "INSERT OR REPLACE INTO meta VALUES('index-version', ?)",
        ("family-contract-v4",),
    )
    index.commit()
    index.close()
    node.app.close()

    upgraded = Node(node.dir)
    assert upgraded.store(workspace).get("root") == canonical_root
    assert upgraded.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='index-version'").fetchone() \
        == (INDEX_VERSION,)

    peer = Node(str(tmp_path / "fresh-peer"))
    deliver(
        peer,
        workspace,
        closed_subset(upgraded, workspace, all_fids(upgraded, workspace)),
    )
    peer.turn(workspace)
    assert peer.store(workspace).get("root") == canonical_root
