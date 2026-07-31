"""Canonical workspace identity is proved at every fact and pile door."""
import asyncio
import ast
import base64
import json
import sqlite3
from pathlib import Path

import pytest

import facts
from core import http
from core.close import decode_pile, encode_pile
from core.crypto import h, keypair
from core.fact import Fact, canon, encode
from core.grants import make_token
from core.ingress import InvalidPile
from core.limits import MAX_INVITE_BYTES, PayloadTooLarge
from full_peer.node import FullPeer
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from full_peer import sql_store
from facts.auth import request
from facts.auth import user as user_family
from facts.auth import user_invite as user_invite_family
from facts.auth.signature import signature
from facts.auth.user_invite import user_invite
from facts.content.message import message


def two_workspaces(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    first = facts.auth.workspace.create(node, "first", ts=1)
    second = facts.auth.workspace.create(node, "second", ts=2)
    assert node.identity_id(first) == node.identity_id(second)
    return node, first, second


def run(awaitable):
    return asyncio.run(awaitable)


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


def test_foreign_and_mixed_piles_stop_before_family_dispatch_or_root_cas(
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
    real_family_for = facts.family_for

    def observed_family(tag):
        family_calls.append(tag)
        return real_family_for(tag)

    monkeypatch.setattr(facts, "family_for", observed_family)
    store = FsStore(str(tmp_path / "receiver"))
    applier = RepositoryApplier(second, store)
    source = run(applier.stage(node.member_for(second), hostile))

    result = run(applier.apply(source))

    assert family_calls == []
    assert result.status == "rejected"
    assert result.admitted == ()
    assert result.retired is True
    assert store.get("root") is None
    assert store.get(source) is None
    assert store.get("failed/pile/" + h(hostile)) == hostile
    assert json.loads(result.rejection.record)["error"] \
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
    gate = http.HttpGate(
        http.AsyncFromSyncReader(node.store(second)),
        second,
        secret,
        lambda: 100,
        receiver=object(),
    )

    first_token = make_token(
        secret, member, first, issued_at=0, ttl_ms=1_000)
    response = run(gate.handle(
        "PUT",
        f"/pile/{member}/{h(raw)}",
        {"ws": second},
        {"Authorization": "Bearer " + first_token},
        raw,
    ))
    assert response.status == 401

    second_member = node.member_for(second)
    second_token = make_token(
        secret, second_member, second, issued_at=0, ttl_ms=1_000)
    response = run(gate.handle(
        "PUT",
        f"/pile/not-the-uploader/{h(raw)}",
        {"ws": second},
        {"Authorization": "Bearer " + second_token},
        raw,
    ))
    assert response.status == 403


def test_database_free_reader_applier_and_projection_enforce_same_anchor(
        tmp_path):
    node, first, second = two_workspaces(tmp_path)
    now = 100
    first_pile = encode_pile(request.payload(
        node, first, "sync", now + 60_000, now), workspace=first)
    second_pile = encode_pile(request.payload(
        node, second, "sync", now + 60_000, now), workspace=second)
    store = node.store(second)
    reader = node.reader(second)

    assert reader.mint(first_pile, now) is None
    assert reader.mint(second_pile, now) \
        == (node.identity_id(second), "sync")

    foreign = message(
        first, node.identity_id(first), "general", "not second", 101)
    foreign_pile = encode_pile([foreign], workspace=first)
    root = store.get("root")
    source = run(node.applier(second).stage(
        node.member_for(second), foreign_pile))
    result = run(node.applier(second).apply(source))

    assert result.status == "rejected"
    assert result.retired is True
    assert json.loads(result.rejection.record)["error"] \
        == "InvalidPile: pile workspace"
    assert store.get("root") == root
    assert node.fact_of(second, foreign.fid) is None

    ws_less_ordinary = Fact("msg", 102, [], {}, None)
    index = node.idx(second)
    index.execute(
        "INSERT INTO facts VALUES(?,?)",
        (ws_less_ordinary.fid, encode(ws_less_ordinary)),
    )
    index.commit()
    with pytest.raises(ValueError, match="fact projection integrity"):
        node.sql(second).fact(ws_less_ordinary.fid)

    node.rebuild(second)
    assert node.fact_of(second, ws_less_ordinary.fid) is None
    assert store.get("root") == root


@pytest.mark.parametrize("case", ("foreign-inner-pile", "incomplete-proof"))
def test_invite_bootstrap_is_workspace_complete_before_keyring_mutation(
        tmp_path, monkeypatch, case):
    node = FullPeer(str(tmp_path / "joiner"))
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
        headers = {}

        def read(self, maximum):
            assert maximum == MAX_INVITE_BYTES + 1
            return b"encrypted"

        def close(self):
            pass

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


@pytest.mark.parametrize("declared", [True, False])
def test_invite_redemption_bounds_and_closes_untrusted_http_body(
        tmp_path, monkeypatch, declared):
    node = FullPeer(str(tmp_path / "joiner"))
    workspace = "0" * 64
    link = base64.urlsafe_b64encode(canon({
        "u": "https://invite.invalid",
        "ws": workspace,
        "s": "01" * 32,
    })).decode()

    class Response:
        headers = {
            "Content-Length": "9",
        } if declared else {}

        def __init__(self):
            self.reads = []
            self.closed = False

        def read(self, maximum):
            self.reads.append(maximum)
            return b"x" * maximum

        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr(user_family, "MAX_INVITE_BYTES", 8)
    monkeypatch.setattr(
        user_family.urllib.request, "urlopen",
        lambda *_args, **_kwargs: response)

    with pytest.raises(PayloadTooLarge, match="invite response"):
        user_family.accept(node, link, "new member")

    assert response.reads == ([] if declared else [9])
    assert response.closed is True


def test_exact_bound_invite_response_reaches_crypto_and_still_closes(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "joiner"))
    workspace = "0" * 64
    link = base64.urlsafe_b64encode(canon({
        "u": "https://invite.invalid",
        "ws": workspace,
        "s": "01" * 32,
    })).decode()

    class Response:
        headers = {"Content-Length": "8"}

        def __init__(self):
            self.closed = False

        @staticmethod
        def read(maximum):
            assert maximum == 9
            return b"x" * 8

        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr(user_family, "MAX_INVITE_BYTES", 8)
    monkeypatch.setattr(
        user_family.urllib.request, "urlopen",
        lambda *_args, **_kwargs: response)

    def decrypt(_key, encrypted):
        assert encrypted == b"x" * 8
        return b"{}"

    monkeypatch.setattr(user_family, "box_decrypt", decrypt)
    with pytest.raises(ValueError, match="invite workspace"):
        user_family.accept(node, link, "new member")
    assert response.closed is True


def test_invite_creation_checks_encrypted_size_before_store(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "inviter"))
    workspace = facts.auth.workspace.create(node, "inviter", ts=1)
    node.peer_address = "https://invite.example"
    monkeypatch.setattr(user_invite_family, "MAX_INVITE_BYTES", 8)
    monkeypatch.setattr(
        user_invite_family, "box_encrypt",
        lambda _key, _raw: b"x" * 8,
    )

    user_invite_family.make(node, workspace)
    store = node.store(workspace)
    invite_keys = store.list("invite/")
    assert len(invite_keys) == 1
    assert store.get(invite_keys[0]) == b"x" * 8

    monkeypatch.setattr(
        user_invite_family, "box_encrypt",
        lambda _key, _raw: b"x" * 9,
    )
    with pytest.raises(PayloadTooLarge, match="invite too large"):
        user_invite_family.make(node, workspace)
    assert store.list("invite/") == invite_keys


def test_reopen_refresh_discards_foreign_projection_rows(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "workspace", ts=1)
    root = node.store(workspace).get("root")
    foreign = Fact(
        "sample", 2, [], {"foreign": True}, "f" * 64)
    index = node.idx(workspace)
    index.execute(
        "INSERT INTO facts(fid, blob) VALUES(?,?)",
        (foreign.fid, encode(foreign)),
    )

    with pytest.raises(ValueError, match="fact projection integrity"):
        node.sql(workspace).fact(foreign.fid)

    index.execute(
        "DELETE FROM meta WHERE k='root'",
    )
    index.commit()
    index.close()
    node._sql.clear()

    reopened = FullPeer(node.dir)
    assert reopened.fact_of(workspace, foreign.fid) is None
    assert reopened.store(workspace).get("root") == root


def test_incompatible_projection_is_deleted_instead_of_migrated(tmp_path):
    workspace = "0" * 64
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE facts(
            fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT, admitted INT);
        PRAGMA user_version=0;
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
    db.close()

    projection = sql_store.SqlStore.open(str(path), workspace)
    db = projection.db

    assert {
        row[1] for row in db.execute("PRAGMA table_info(facts)")
    } == {"fid", "blob"}
    assert db.execute("SELECT * FROM facts").fetchall() == []


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
