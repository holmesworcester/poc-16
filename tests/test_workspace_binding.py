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
from .util import signed_pile_facts, signed_pile_bytes
from core.crypto import h, keypair
from core.fact import Fact, canon
from core.grants import make_token
from core.close import ClosedPileEvaluator, InvalidPile
from core.limits import MAX_INVITE_BYTES, PayloadTooLarge
from full_peer.node import FullPeer
from full_peer import sql_store
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


def test_foreign_and_mixed_piles_stop_before_family_dispatch(
        tmp_path, monkeypatch):
    node, first, second = two_workspaces(tmp_path)
    public = node.identity_id(first)
    foreign = message(first, public, "general", "foreign", 10)
    foreign_sig = signature(
        node.identity(first)[0], public, foreign, foreign.ts)
    second_genesis = node.fact_of(second, second)
    hostile_value = json.loads(signed_pile_bytes(
        [second_genesis], workspace=second))
    hostile_value["facts"].extend((
        foreign_sig.to_json(),
        foreign.to_json(),
    ))
    hostile = canon(hostile_value)

    with pytest.raises(ValueError, match="signed pile"):
        signed_pile_bytes(
            [second_genesis, foreign_sig, foreign], workspace=second)
    with pytest.raises(InvalidPile, match="signed pile"):
        signed_pile_facts(hostile, second)

    family_calls = []
    real_family_for = facts.family_for

    def observed_family(tag):
        family_calls.append(tag)
        return real_family_for(tag)

    monkeypatch.setattr(facts, "family_for", observed_family)
    with pytest.raises(InvalidPile, match="signed pile"):
        ClosedPileEvaluator(second).evaluate(hostile)
    assert family_calls == []


def test_foreign_signed_pile_has_one_typed_rejection_door(tmp_path):
    node, first, second = two_workspaces(tmp_path)
    first_root = node.fact_of(first, first)
    foreign = signed_pile_bytes([first_root], workspace=first)

    with pytest.raises(InvalidPile, match="signed pile binding"):
        signed_pile_facts(foreign, second)
    with pytest.raises(ValueError, match="signed pile"):
        signed_pile_bytes((), workspace="not-a-workspace")


def test_retired_pile_route_has_no_receiver_even_with_a_valid_token(tmp_path):
    node, first, second = two_workspaces(tmp_path)
    secret = b"g" * 32
    member = node.member_for(first)
    raw = b"closed pile bytes"
    gate = http.HttpGate(
        http.AsyncFromSyncReader(node.store(second)),
        second,
        secret,
        lambda: 100,
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
    assert response.status == 404


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
    pile = signed_pile_bytes([invitation], workspace=inner_workspace)
    blob = canon({
        "pile": base64.b64encode(pile).decode(),
        "isk": invite_secret.encode().hex(),
        "ws": expected,
    })
    link = base64.urlsafe_b64encode(canon({
        "p": "https://invite.invalid",
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

    monkeypatch.setattr(user_family, "_open_invite", lambda _url: Response())
    monkeypatch.setattr(
        user_family, "box_decrypt",
        lambda *_args, **_kwargs: blob)

    with pytest.raises(ValueError):
        user_family.accept(node, link, "new member")

    assert node.workspaces() == []
    assert json.dumps(node.keyring, sort_keys=True) == before


def test_invite_redemption_selects_current_form_but_retains_source_fid(
        tmp_path, monkeypatch):
    """Invite command semantics hydrate after the source pile is judged."""
    from types import SimpleNamespace

    from core.fact import CurrentFact, current_fact, source_fact
    from facts._policy import FamilyPolicy

    node = FullPeer(str(tmp_path / "joiner"))
    workspace, inviter = "0" * 64, "1" * 64
    invite_secret, invite_public = keypair()
    source = Fact(
        "test_user_invite.v0", 1, [],
        {"inviter": inviter, "invitee": invite_public}, workspace)
    current = user_invite(
        workspace, inviter, invite_public, source.ts)

    def reextract(candidate):
        if candidate != source:
            raise ValueError("synthetic invite source")
        return current

    family = SimpleNamespace(
        TAG=user_invite_family.TAG,
        POLICY=FamilyPolicy(),
        DURABLE=True,
        needs=lambda _fact: (),
        validate=lambda fact, _context: current_fact(fact) == current,
        reextract=reextract,
    )
    real_family_for = facts.family_for
    monkeypatch.setattr(
        facts,
        "family_for",
        lambda tag: family if tag in {source.t, current.t}
        else real_family_for(tag),
    )

    pile = signed_pile_bytes((source,), workspace=workspace)
    blob = canon({
        "pile": base64.b64encode(pile).decode(),
        "isk": invite_secret.encode().hex(),
        "ws": workspace,
    })
    link = base64.urlsafe_b64encode(canon({
        "p": "https://invite.invalid",
        "ws": workspace,
        "s": "01" * 32,
    })).decode()

    class Response:
        headers = {}

        @staticmethod
        def read(maximum):
            assert maximum == MAX_INVITE_BYTES + 1
            return b"encrypted"

        @staticmethod
        def close():
            pass

    class SelectedInvite(RuntimeError):
        pass

    observed = []

    def select(invitation, *_args):
        observed.append(invitation)
        raise SelectedInvite

    monkeypatch.setattr(user_family, "_open_invite", lambda _url: Response())
    monkeypatch.setattr(
        user_family, "box_decrypt", lambda *_args, **_kwargs: blob)
    monkeypatch.setattr(user_family, "user", select)

    with pytest.raises(SelectedInvite):
        user_family.accept(node, link, "new member")

    assert len(observed) == 1
    assert isinstance(observed[0], CurrentFact)
    assert source_fact(observed[0]) == source
    assert current_fact(observed[0]) == current
    assert observed[0].fid == source.fid != current.fid
    assert node.workspaces() == []


@pytest.mark.parametrize("declared", [True, False])
def test_invite_redemption_bounds_and_closes_untrusted_http_body(
        tmp_path, monkeypatch, declared):
    node = FullPeer(str(tmp_path / "joiner"))
    workspace = "0" * 64
    link = base64.urlsafe_b64encode(canon({
        "p": "https://invite.invalid",
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
    monkeypatch.setattr(user_family, "_open_invite", lambda _url: response)

    with pytest.raises(PayloadTooLarge, match="invite response"):
        user_family.accept(node, link, "new member")

    assert response.reads == ([] if declared else [9])
    assert response.closed is True


def test_exact_bound_invite_response_reaches_crypto_and_still_closes(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "joiner"))
    workspace = "0" * 64
    link = base64.urlsafe_b64encode(canon({
        "p": "https://invite.invalid",
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
    monkeypatch.setattr(user_family, "_open_invite", lambda _url: response)

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


def test_incompatible_projection_is_deleted_instead_of_migrated(tmp_path):
    workspace = "0" * 64
    path = tmp_path / "obsolete.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE facts(
            fid TEXT PRIMARY KEY, ts INT, t TEXT, j TEXT, admitted INT);
        PRAGMA user_version=0;
    """)
    ordinary = Fact("sample", 1, [], {"obsolete": True}, None)
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
