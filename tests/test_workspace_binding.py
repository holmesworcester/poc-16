"""Canonical workspace identity is proved at every fact and pile door."""
import ast
import base64
import json
import sqlite3
from pathlib import Path

import pytest

import facts
from core import catalog, cmds, daemon
from core.close import decode_pile, encode_pile
from core.crypto import h, keypair
from core.fact import Fact, canon, encode
from core.ingress import InvalidPile, KernelRejected
from core.node import Node
from core.worker import WorkerView
from facts.auth import request
from facts.auth import user as user_family
from facts.auth.signature import signature
from facts.auth.user_invite import user_invite
from facts.content.message import message


def two_workspaces(tmp_path):
    node = Node(str(tmp_path / "node"))
    first = cmds.create(node, "first", ts=1)
    second = cmds.create(node, "second", ts=2)
    assert node.identity_id(first) == node.identity_id(second)
    return node, first, second


def test_same_author_and_form_have_distinct_workspace_bound_ids(tmp_path):
    node, first, second = two_workspaces(tmp_path)
    public = node.identity_id(first)
    first_fact = message(first, public, "general", "same", 10)
    second_fact = message(second, public, "general", "same", 10)
    first_sig = signature(
        node.identity(first)[0], public, first_fact, first_fact.ts)
    second_sig = signature(
        node.identity(second)[0], public, second_fact, second_fact.ts)

    assert first_fact.body == second_fact.body
    assert first_fact.atoms == second_fact.atoms
    assert first_fact.fid != second_fact.fid
    assert first_sig.fid != second_sig.fid
    assert first_fact.env["ws"] == first
    assert second_fact.env["ws"] == second

    for workspace in (first, second):
        genesis = node.fact_of(workspace, workspace)
        assert genesis.fid == workspace
        assert genesis.ws is None
        assert "ws" not in genesis.env


def test_foreign_and_mixed_piles_stop_before_family_dispatch_or_stage(
        tmp_path, monkeypatch):
    node, first, second = two_workspaces(tmp_path)
    public = node.identity_id(first)
    foreign = message(first, public, "general", "foreign", 10)
    foreign_sig = signature(
        node.identity(first)[0], public, foreign, foreign.ts)
    second_genesis = node.fact_of(second, second)
    hostile = canon({
        "ws": second,
        "facts": [
            second_genesis.to_json(),
            foreign_sig.to_json(),
            foreign.to_json(),
        ],
    })

    with pytest.raises(ValueError, match="mixed workspace pile"):
        encode_pile(
            [second_genesis, foreign_sig, foreign], workspace=second)
    with pytest.raises(InvalidPile, match="mixed workspace pile"):
        decode_pile(hostile, second)

    family_calls = []
    admission_calls = []
    real_family_for = facts.family_for
    real_admit = catalog.Catalog._admit_valid

    def observed_family(tag):
        family_calls.append(tag)
        return real_family_for(tag)

    def observed_admit(self, receipt):
        admission_calls.append(receipt.fact.fid)
        return real_admit(self, receipt)

    monkeypatch.setattr(facts, "family_for", observed_family)
    monkeypatch.setattr(catalog.Catalog, "_admit_valid", observed_admit)
    source = f"pile/{node.member_for(second)}/{h(hostile)}"
    node.store(second).put(source, hostile)

    node.turn(second)

    assert family_calls == []
    assert admission_calls == []
    assert node.candidate_of(second, foreign.fid) is None
    assert node.store(second).get(source) is None
    assert node.store(second).get("failed/pile/" + h(hostile)) == hostile
    assert node.ingress_failures(second)[0]["error"] \
        == "InvalidPile: mixed workspace pile"


def test_foreign_pile_and_legacy_pile_have_one_typed_rejection_door(
        tmp_path):
    node, first, second = two_workspaces(tmp_path)
    first_root = node.fact_of(first, first)
    foreign = encode_pile([first_root], workspace=first)

    with pytest.raises(InvalidPile, match="pile workspace"):
        decode_pile(foreign, second)
    with pytest.raises(InvalidPile, match="pile shape"):
        decode_pile(canon({"facts": [first_root.to_json()]}), first)
    with pytest.raises(ValueError, match="pile workspace"):
        encode_pile((), workspace="not-a-workspace")
    with pytest.raises(InvalidPile, match="pile workspace"):
        decode_pile(foreign, None)


def test_uploader_token_workspace_and_pile_path_must_match(tmp_path):
    node, first, second = two_workspaces(tmp_path)
    secret = b"g" * 32
    member = node.member_for(first)
    raw = b"closed pile bytes"
    handler = object.__new__(daemon.Handler)
    handler.node = node
    handler.secret = secret
    sent = []
    handler._send = lambda code, *_args, **_kwargs: sent.append(code) or code
    handler._body = lambda _limit: pytest.fail(
        "workspace/path rejection read the body")

    first_token = daemon.make_token(secret, member, first)
    handler.headers = {"Authorization": "Bearer " + first_token}
    handler._q = lambda: (
        ["pile", member, h(raw)], {"ws": second})
    assert handler.do_PUT() == 401

    second_member = node.member_for(second)
    second_token = daemon.make_token(secret, second_member, second)
    handler.headers = {"Authorization": "Bearer " + second_token}
    handler._q = lambda: (
        ["pile", "not-the-uploader", h(raw)], {"ws": second})
    assert handler.do_PUT() is None
    assert sent[-1] == 403


def test_database_free_mint_and_catalog_enforce_the_same_anchor(tmp_path):
    node, first, second = two_workspaces(tmp_path)
    now = 100
    first_pile = encode_pile(request.payload(
        node, first, "sync", now + 60_000, now), workspace=first)
    second_pile = encode_pile(request.payload(
        node, second, "sync", now + 60_000, now), workspace=second)
    store = node.store(second)
    view = WorkerView.from_root(
        store.get("root"), lambda oid: store.get("obj/" + oid))

    assert view.mint(first_pile, now) is None
    assert view.mint(second_pile, now) \
        == (node.identity_id(second), "sync")

    foreign = message(
        first, node.identity_id(first), "general", "not second", 101)
    with pytest.raises(KernelRejected, match="ingress rejected"):
        node.admit(second, [foreign])
    assert node.candidate_of(second, foreign.fid) is None

    ws_less_ordinary = Fact("msg", 102, [], {}, None)
    db = sqlite3.connect(":memory:")
    db.executescript(catalog.SCHEMA)
    with pytest.raises(ValueError, match="fact workspace"):
        catalog.ScratchCatalog(
            db, ws_less_ordinary.fid).load(ws_less_ordinary)


@pytest.mark.parametrize("case", ("foreign-inner-pile", "incomplete-proof"))
def test_invite_bootstrap_is_workspace_complete_before_keyring_mutation(
        tmp_path, monkeypatch, case):
    node = Node(str(tmp_path / "joiner"))
    before = json.dumps(node.keyring, sort_keys=True)
    expected = "0" * 64
    foreign = "f" * 64
    invite_secret, invite_public = keypair()
    _, inviter = keypair()
    inner_workspace = foreign if case == "foreign-inner-pile" else expected
    invitation = user_invite(
        inner_workspace, inviter, invite_public, 1)
    pile = encode_pile([invitation], workspace=inner_workspace)
    blob = canon({
        "pile": base64.b64encode(pile).decode(),
        "isk": invite_secret.encode().hex(),
        "ws": expected,
    })
    link = base64.urlsafe_b64encode(canon({
        "u": "https://invite.invalid",
        "ws": expected,
        "s": "01" * 32,
    })).decode()

    class Response:
        def read(self):
            return b"encrypted"

    monkeypatch.setattr(
        user_family.urllib.request, "urlopen",
        lambda *_args, **_kwargs: Response())
    monkeypatch.setattr(
        user_family, "box_decrypt",
        lambda *_args, **_kwargs: blob)

    with pytest.raises(ValueError):
        user_family.accept(node, link, "new member")

    assert node.workspaces() == []
    assert json.dumps(node.keyring, sort_keys=True) == before


def test_catalog_reindex_and_reopen_reject_foreign_receipts(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "workspace", ts=1)
    foreign = Fact(
        "sample", 2, [], {"foreign": True}, "f" * 64)
    index = node.idx(workspace)
    index.execute(
        "INSERT INTO facts(fid, blob) VALUES(?,?)",
        (foreign.fid, encode(foreign)),
    )

    with pytest.raises(ValueError, match="fact catalog integrity"):
        node.catalog(workspace).reindex()

    index.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES('index-version', ?)",
        ("force-reindex",),
    )
    index.commit()
    index.close()
    node._idx.clear()

    with pytest.raises(ValueError, match="fact catalog integrity"):
        Node(node.dir)


def test_legacy_catalog_upgrade_rejects_ws_less_ordinary_receipt():
    workspace = "0" * 64
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE facts(
            fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT, admitted INT);
    """)
    ordinary = Fact("sample", 1, [], {"legacy": True}, None)
    db.execute(
        "INSERT INTO facts VALUES(?,?,?,?,1)",
        (
            ordinary.fid,
            ordinary.ts,
            ordinary.t,
            json.dumps(ordinary.to_json()),
        ),
    )
    db.commit()
    db.executescript(catalog.SCHEMA)

    with pytest.raises(ValueError, match="legacy fact catalog integrity"):
        catalog.upgrade_schema(db, workspace)


def test_only_genesis_family_may_construct_a_ws_less_fact():
    """Source ratchet: a new family cannot silently omit the signed anchor."""
    root = Path(__file__).parents[1] / "facts"
    seen = []
    for source in sorted(root.rglob("*.py")):
        tree = ast.parse(source.read_text(), filename=str(source))
        for call in ast.walk(tree):
            if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "Fact"):
                continue
            workspace = next(
                (
                    keyword.value
                    for keyword in call.keywords
                    if keyword.arg == "ws"
                ),
                call.args[4] if len(call.args) >= 5 else None,
            )
            assert workspace is not None, \
                f"{source}: Fact construction omits workspace"
            ws_less = (
                isinstance(workspace, ast.Constant)
                and workspace.value is None
            )
            is_genesis = source.name == "workspace.py"
            assert ws_less == is_genesis, \
                f"{source}: only workspace genesis may pass ws=None"
            seen.append((source, ws_less))

    assert seen
    assert sum(ws_less for _, ws_less in seen) == 2
    assert [
        family.TAG for family in facts.MODULES
        if getattr(family, "GENESIS", False)
    ] == ["workspace"]
