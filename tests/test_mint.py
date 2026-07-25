"""Acceptance laws for the pure mint (SIMPLIFY.md §4)."""
import base64
import inspect

import pytest
from nacl.exceptions import CryptoError

from tinyp2p import cmds, daemon, mint
from tinyp2p.close import encode_pile
from tinyp2p.crypto import keypair, unseal
from tinyp2p.fact import Fact
from tinyp2p.facts.auth import request
from tinyp2p.facts.auth.signature import signature
from tinyp2p.node import Node, now_ms


@pytest.fixture
def world(tmp_path):
    node = Node(str(tmp_path / "node"))
    now = now_ms()
    workspace = cmds.create(node, "alice", ts=now - 1)
    facts = request.payload(
        node, workspace, "sync", now + 60_000, now)
    return node, workspace, now, facts, encode_pile(facts)


def combine(*streams):
    seen, out = set(), []
    for fact in (fact for stream in streams for fact in stream):
        if fact.fid not in seen:
            seen.add(fact.fid)
            out.append(fact)
    return out


def invoke(node, workspace, pile):
    handler = object.__new__(daemon.Handler)
    handler.node, handler.secret = node, b"mint-test-secret"
    handler._known = lambda candidate: candidate == workspace
    handler._send = lambda code, *args, **kwargs: (code, None)
    handler._json = lambda code, body: (code, body)
    return handler, handler.mint({
        "ws": workspace,
        "pile": base64.b64encode(pile).decode(),
    })


def test_mint_rejects_malformed_requests(world):
    node, workspace, _, _, pile = world
    handler, _ = invoke(node, workspace, pile)

    for body in (
            None, [], {}, {"ws": []}, {"ws": workspace},
            {"ws": workspace, "pile": []}):
        assert handler.mint(body) == (400, None)

    handler._q = lambda: (["mint"], {"ws": workspace})
    handler._body = lambda: b"{"
    assert handler.do_POST() == (400, None)


def test_mint_accepts_exactly_one_ephemeral_fact(world):
    """A mint pile with zero or two DURABLE=False facts is refused; the
    daemon's arity check now lives in the family."""
    node, workspace, now, facts, pile = world
    root = node.store(workspace).get("root")
    anchor, globals_ = mint.root_globals(root)
    second = request.payload(
        node, workspace, "sync", now + 60_001, now + 1)

    assert mint.mint(pile, anchor, globals_, now) \
        == (node.pk, "sync")
    assert mint.mint(
        encode_pile([node.fact_of(workspace, workspace)]),
        anchor, globals_, now,
    ) is None
    assert mint.mint(
        encode_pile(combine(facts, second)),
        anchor, globals_, now,
    ) is None


def test_family_owns_expiry_and_tag(world):
    """Expired request / wrong tag is refused by request.evaluate under
    globals ∪ {("now", ms)} — daemon.mint contains no body parsing."""
    node, workspace, now, _, _ = world
    anchor, globals_ = mint.root_globals(
        node.store(workspace).get("root"))
    expired = encode_pile(request.payload(
        node, workspace, "sync", now - 1, now))
    wrong_verb = encode_pile(request.payload(
        node, workspace, "write", now + 60_000, now))
    wrong = Fact(
        "not-a-request", now, [],
        {"pk": node.pk, "verb": "sync", "exp": now + 60_000},
    )
    wrong_sig = signature(node.sk, node.pk, wrong, now)
    wrong_tag = encode_pile([
        node.fact_of(workspace, workspace), wrong_sig, wrong])

    assert mint.mint(expired, anchor, globals_, now) is None
    assert mint.mint(wrong_verb, anchor, globals_, now) is None
    assert mint.mint(wrong_tag, anchor, globals_, now) is None
    assert ".body" not in inspect.getsource(daemon.Handler.mint)


def test_grant_sealed_to_requester_pk(world):
    """The grant unseals only with the requester's sk; replaying the
    challenge yields nothing to anyone else."""
    node, workspace, _, _, pile = world
    handler, (code, body) = invoke(node, workspace, pile)
    token = unseal(
        node.sk, base64.b64decode(body["grant"])).decode()

    assert code == 200
    assert daemon.check_token(
        handler.secret, "Bearer " + token, workspace) == node.pk[:16]
    other, _ = keypair()
    with pytest.raises(CryptoError):
        unseal(other, base64.b64decode(body["grant"]))


def test_mint_writes_nothing(world):
    """Evaluate mode: no drain, no ingress writes, no idx/app rows — the
    challenge is judged and forgotten."""
    node, workspace, _, _, pile = world
    store = node.store(workspace)
    before = (
        store.list(""),
        tuple(node.idx(workspace).iterdump()),
        tuple(node.app.iterdump()),
    )
    node.globals = lambda _: pytest.fail("mint read the derived index")

    code, _ = invoke(node, workspace, pile)[1]
    after = (
        store.list(""),
        tuple(node.idx(workspace).iterdump()),
        tuple(node.app.iterdump()),
    )

    assert code == 200
    assert after == before


def test_conflict_free_mint_uses_root_metadata_without_app(world):
    """Root metadata is enough only without a committed authority conflict;
    even that path never builds app.db."""
    node, workspace, now, _, pile = world
    root = node.store(workspace).get("root")
    node.idx(workspace).close()
    node.app.close()

    anchor, globals_ = mint.root_globals(root)

    assert anchor == workspace
    assert mint.mint(pile, anchor, globals_, now) \
        == (node.pk, "sync")


@pytest.mark.skip(reason="poc-16-yez.9 decides the gate mask")
def test_gate_mask_screens_whole_closure():
    """gxz seam: a pile whose CLOSURE contains an evicted signer's fact is
    refused at the gate even when the requester is in good standing — enable
    once poc-16-yez.9 confirms the seam."""
    raise NotImplementedError
