"""Black-box and exact-tree contracts for RepositoryReader minting."""
import base64
import asyncio
import inspect
import json
import random

import pytest
from nacl.exceptions import CryptoError

import facts

from core import http, snapshot
from core.close import decode_pile, encode_pile
from core.crypto import h, keypair, unseal
from core.fact import Fact, canon
from full_peer.node import FullPeer, now_ms
from core.repository_reader import RepositoryReader
from facts.auth import request
from facts.auth.device import bind
from facts.auth.signature import signature

from .util import (
    add_member,
    closed_subset,
    inject_device_claim,
    invoke_mint,
    invoke_mint_value,
)


@pytest.fixture
def world(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    now = now_ms()
    workspace = facts.auth.workspace.create(node, "alice", ts=now - 1)
    proof_facts = request.payload(
        node, workspace, "sync", now + 60_000, now)
    return node, workspace, now, proof_facts, encode_pile(proof_facts)


def combine(*streams):
    seen, out = set(), []
    for fact in (fact for stream in streams for fact in stream):
        if fact.fid not in seen:
            seen.add(fact.fid)
            out.append(fact)
    return out


def authorize(node, workspace, pile, now, root=None, fetch=None):
    store = node.store(workspace)
    root = store.get("root") if root is None else root
    fetch = fetch or (lambda oid: store.get("obj/" + oid))
    try:
        return RepositoryReader(
            workspace, root, fetch).mint(pile, now)
    except (TypeError, ValueError):
        return None


def conflict_world(path, seed):
    """A random-depth device chain plus a different explicit affiliation."""
    rng = random.Random(seed)
    node = FullPeer(str(path))
    workspace = facts.auth.workspace.create(node, "root", ts=1)
    founder_secret, founder = node.identity(workspace)
    bind(node, workspace, "root-primary")

    inviter = founder_secret, founder
    for depth in range(rng.randint(1, 4)):
        secret, public, _ = add_member(
            node, workspace, f"member-{seed}-{depth}",
            ts=10 + 10 * depth, inviter=inviter)
        node.keychain.add_identity(secret)
        inviter = secret, public
    inviter_secret, inviter_public = inviter
    node.bind_identity(workspace, inviter_public)
    bind(node, workspace, f"member-primary-{rng.randrange(1_000)}")

    base = now_ms()
    target_secret, target = keypair()
    node.keychain.add_identity(target_secret)
    inject_device_claim(
        node, workspace, inviter_secret, inviter_public, inviter_public,
        target, f"target-{rng.randrange(1_000)}", base + 1)
    node.bind_identity(workspace, target)
    child_secret, child = keypair()
    node.keychain.add_identity(child_secret)
    child_claim = inject_device_claim(
        node, workspace, target_secret, target, inviter_public, child,
        f"child-{rng.randrange(1_000)}", base + 2)

    node.bind_identity(workspace, child)
    now = base + 3
    stale = encode_pile(request.payload(
        node, workspace, "sync", now + 600_000, now))
    stale_root = node.store(workspace).get("root")

    node.bind_identity(workspace, founder)
    inject_device_claim(
        node, workspace, founder_secret, founder, founder, target,
        f"conflict-{rng.randrange(1_000)}", base + 4)
    assert node.fact_of(workspace, child_claim.fid) == child_claim
    fresh = encode_pile(request.payload(
        node, workspace, "sync", now + 600_000, now))
    return node, workspace, now, founder, stale_root, stale, fresh


def test_mint_rejects_malformed_requests(world):
    node, workspace, _, _, pile = world
    for body in (
            None, [], {}, {"ws": []}, {"ws": workspace},
            {"ws": workspace, "pile": []}):
        assert invoke_mint_value(
            node, workspace, body)[1] == (400, None)
    gate, _ = invoke_mint(node, workspace, pile)
    response = asyncio.run(gate.handle(
        "POST", "/mint", {"ws": workspace}, {}, b"{"))
    assert response.status == 400


def test_mint_accepts_exactly_one_ephemeral_request(world):
    node, workspace, now, facts, pile = world
    second = request.payload(
        node, workspace, "sync", now + 60_001, now + 1)
    assert authorize(node, workspace, pile, now) == (node.pk, "sync")
    assert authorize(
        node, workspace,
        encode_pile([node.fact_of(workspace, workspace)]), now) is None
    assert authorize(
        node, workspace, encode_pile(combine(facts, second)), now) is None


def test_http_mint_fails_closed_at_aggregate_fetch_budget(
        world, monkeypatch):
    node, workspace, _, _, pile = world
    monkeypatch.setattr(http, "MAX_MINT_FETCHES", 0)
    handler, (code, body) = invoke_mint(node, workspace, pile)

    assert code == 403
    assert body is None


def test_family_owns_expiry_tag_and_verb(world):
    node, workspace, now, _, _ = world
    expired = encode_pile(request.payload(
        node, workspace, "sync", now - 1, now))
    wrong_verb = encode_pile(request.payload(
        node, workspace, "write", now + 60_000, now))
    wrong = Fact(
        "not-a-request", now, [],
        {"pk": node.pk, "verb": "sync", "exp": now + 60_000},
        workspace)
    wrong_sig = signature(node.sk, node.pk, wrong, now)
    wrong_tag = encode_pile([
        node.fact_of(workspace, workspace), wrong_sig, wrong])

    assert authorize(node, workspace, expired, now) is None
    assert authorize(node, workspace, wrong_verb, now) is None
    assert authorize(node, workspace, wrong_tag, now) is None
    assert ".body" not in inspect.getsource(http.HttpGate._mint)


def test_grant_is_sealed_to_requester(world):
    node, workspace, _, _, pile = world
    handler, (code, body) = invoke_mint(node, workspace, pile)
    token = unseal(
        node.sk, base64.b64decode(body["grant"])).decode()
    assert code == 200
    assert http.check_token(
        handler.secret, "Bearer " + token, workspace) == node.pk[:16]
    other, _ = keypair()
    with pytest.raises(CryptoError):
        unseal(other, base64.b64decode(body["grant"]))


def test_mint_is_read_only_and_does_not_touch_sqlite(world):
    node, workspace, _, _, pile = world
    store = node.store(workspace)
    before = (
        store.list(""),
        tuple(node.idx(workspace).iterdump()),
    )
    node.idx(workspace).close()
    code, _ = invoke_mint(node, workspace, pile)[1]
    assert code == 200

    reopened = FullPeer(node.dir)
    after = (
        reopened.store(workspace).list(""),
        tuple(reopened.idx(workspace).iterdump()),
    )
    assert after == before


def test_missing_composite_trees_fail_closed(world):
    node, workspace, now, _, pile = world
    root = snapshot.encode_root(workspace)
    assert authorize(
        node, workspace, pile, now,
        root=root, fetch=lambda oid: None) is None


def test_obsolete_root_metadata_cannot_override_an_eviction_action(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice")
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob")
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    store = node.store(workspace)
    root = json.loads(store.get("root"))
    root["globals"] = [["removal", bob]]
    forged = canon(root)

    assert authorize(node, workspace, pile, now) is None
    assert authorize(node, workspace, pile, now, root=forged) is None
    store._replace("root", forged)
    assert invoke_mint(node, workspace, pile)[1][0] == 503
    with pytest.raises(ValueError, match="root shape"):
        node.rebuild(workspace)
    assert store.get("root") == forged
    assert authorize(node, workspace, pile, now) is None


def test_repository_reader_remains_pinned_after_a_concurrent_commit(world):
    node, workspace, now, _, pile = world
    store = node.store(workspace)
    old_root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    reader = RepositoryReader(workspace, old_root, fetch)
    assert reader.mint(pile, now) == (node.pk, "sync")

    facts.content.message.post(node, workspace, "general", "changes the root")
    new_root, fetched = store.get("root"), []

    def tracked(oid):
        fetched.append(oid)
        return fetch(oid)

    assert reader.etag != h(new_root)
    assert reader.mint(pile, now) == (node.pk, "sync")
    assert RepositoryReader(
        workspace, new_root, tracked).mint(
            pile, now) == (node.pk, "sync")
    assert fetched


@pytest.mark.parametrize("seed", range(5))
def test_worker_keeps_explicit_authority_stable_across_later_providers(
        tmp_path, seed):
    node, workspace, now, founder, old_root, stale, fresh = \
        conflict_world(tmp_path / f"conflict-{seed}", seed)
    store = node.store(workspace)
    root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    old_reader = RepositoryReader(workspace, old_root, fetch)

    assert old_reader.mint(stale, now)
    for pile, expected in (
            (stale, True),
            (fresh, (founder, "sync"))):
        result = authorize(
            node, workspace, pile, now, root=root, fetch=fetch)
        if expected is True:
            assert result is not None
        else:
            assert result == expected
        assert authorize(
            node, workspace, pile, now, root=root, fetch=fetch) == result
        assert invoke_mint(node, workspace, pile)[1][0] \
            == 200


def test_gate_checks_current_uploader_not_historical_closure_authors(
        tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    bob_message = facts.content.message.post(
        node, workspace, "general", "historical but now inactive", ts=20)
    bob_closure = decode_pile(
        closed_subset(node, workspace, {bob_message}), workspace)
    now = now_ms()
    bob_request = request.payload(
        node, workspace, "sync", now + 60_000, now)

    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    good = request.payload(
        node, workspace, "sync", now + 60_000, now)
    assert authorize(
        node, workspace, encode_pile(good), now) == (node.pk, "sync")
    assert authorize(
        node, workspace, encode_pile(bob_request), now) is None
    assert authorize(
        node, workspace,
        encode_pile(combine(bob_closure, good)), now) \
        == (founder, "sync")
