"""Black-box and exact-tree contracts for the production mint path."""
import base64
import inspect
import json
import random

import pytest
from nacl.exceptions import CryptoError

from core import cmds, daemon, manifest, mint
from core.close import decode_pile, encode_pile
from core.crypto import keypair, unseal
from core.fact import Fact, canon
from core.node import Node, now_ms
from core.worker import WorkerView
from facts.auth import request
from facts.auth.device import bind
from facts.auth.signature import signature

from .util import (
    add_member,
    closed_subset,
    inject_device_claim,
    invoke_mint,
)


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


def authorize(node, workspace, pile, now, root=None, projection=None):
    store = node.store(workspace)
    root = root or store.get("root")
    return mint.stateless(
        pile, root, lambda oid: store.get("obj/" + oid), now, projection)


def conflict_world(path, seed):
    """A random-depth device chain made stale by a shallower winner."""
    rng = random.Random(seed)
    node = Node(str(path))
    workspace = cmds.create(node, "root", ts=1)
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
    assert node.fact_of(workspace, child_claim.fid) is None
    fresh = encode_pile(request.payload(
        node, workspace, "sync", now + 600_000, now))
    return node, workspace, now, founder, stale_root, stale, fresh


def test_mint_rejects_malformed_requests(world):
    node, workspace, _, _, pile = world
    handler, _ = invoke_mint(node, workspace, pile)
    for body in (
            None, [], {}, {"ws": []}, {"ws": workspace},
            {"ws": workspace, "pile": []}):
        assert handler.mint(body) == (400, None)
    handler._q = lambda: (["mint"], {"ws": workspace})
    handler._body = lambda: b"{"
    assert handler.do_POST() == (400, None)


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


def test_family_owns_expiry_tag_and_verb(world):
    node, workspace, now, _, _ = world
    expired = encode_pile(request.payload(
        node, workspace, "sync", now - 1, now))
    wrong_verb = encode_pile(request.payload(
        node, workspace, "write", now + 60_000, now))
    wrong = Fact(
        "not-a-request", now, [],
        {"pk": node.pk, "verb": "sync", "exp": now + 60_000})
    wrong_sig = signature(node.sk, node.pk, wrong, now)
    wrong_tag = encode_pile([
        node.fact_of(workspace, workspace), wrong_sig, wrong])

    assert authorize(node, workspace, expired, now) is None
    assert authorize(node, workspace, wrong_verb, now) is None
    assert authorize(node, workspace, wrong_tag, now) is None
    assert ".body" not in inspect.getsource(daemon.Handler.mint)


def test_grant_is_sealed_to_requester(world):
    node, workspace, _, _, pile = world
    handler, (code, body) = invoke_mint(node, workspace, pile)
    token = unseal(
        node.sk, base64.b64decode(body["grant"])).decode()
    assert code == 200
    assert daemon.check_token(
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
        tuple(node.app.iterdump()),
    )
    node.idx(workspace).close()
    node.app.close()
    code, _ = invoke_mint(node, workspace, pile)[1]
    assert code == 200

    reopened = Node(node.dir)
    after = (
        reopened.store(workspace).list(""),
        tuple(reopened.idx(workspace).iterdump()),
        tuple(reopened.app.iterdump()),
    )
    assert after == before


def test_missing_composite_trees_fail_closed(world):
    node, workspace, now, _, pile = world
    root = manifest.encode_root(workspace, frozenset(), "")
    assert mint.stateless(pile, root, lambda oid: None, now) is None


def test_globals_cannot_override_an_eviction_action(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob")
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    node.bind_identity(workspace, founder)
    cmds.evict(node, workspace, bob)
    store = node.store(workspace)
    root = json.loads(store.get("root"))
    assert root["globals"] == []
    root["globals"] = [["removal", bob]]
    forged = canon(root)

    assert authorize(node, workspace, pile, now) is None
    assert authorize(node, workspace, pile, now, root=forged) is None
    store.put("root", forged)
    assert invoke_mint(node, workspace, pile)[1][0] == 403
    with pytest.raises(ValueError, match="invalid store facts"):
        node.rebuild(workspace)


def test_cached_worker_view_is_root_stamped(world):
    node, workspace, now, _, pile = world
    store = node.store(workspace)
    old_root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    view = WorkerView.from_root(old_root, fetch)
    assert mint.stateless(
        pile, old_root,
        lambda _: pytest.fail("matching view fetched the store"),
        now, view) == (node.pk, "sync")

    cmds.post(node, workspace, "general", "changes the root")
    new_root, fetched = store.get("root"), []

    def tracked(oid):
        fetched.append(oid)
        return fetch(oid)

    assert view.etag != store.etag("root")
    assert mint.stateless(
        pile, new_root, tracked, now, view) == (node.pk, "sync")
    assert fetched


@pytest.mark.parametrize("seed", range(5))
def test_worker_matches_randomized_canonical_authority_conflicts(
        tmp_path, seed):
    node, workspace, now, founder, old_root, stale, fresh = \
        conflict_world(tmp_path / f"conflict-{seed}", seed)
    store = node.store(workspace)
    root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    old_view = WorkerView.from_root(old_root, fetch)

    assert mint.stateless(
        stale, old_root,
        lambda _: pytest.fail("matching view fetched the store"),
        now, old_view)
    assert mint.stateless(stale, root, fetch, now, old_view) is None
    for pile, expected in ((stale, None), (fresh, (founder, "sync"))):
        assert mint.stateless(pile, root, fetch, now) == expected
        assert invoke_mint(node, workspace, pile)[1][0] \
            == (200 if expected else 403)


def test_gate_screens_the_whole_submitted_closure(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    bob_message = cmds.post(
        node, workspace, "general", "historical but now inactive", ts=20)
    bob_closure = decode_pile(
        closed_subset(node, workspace, {bob_message}))[0]

    node.bind_identity(workspace, founder)
    cmds.evict(node, workspace, bob)
    now = now_ms()
    good = request.payload(
        node, workspace, "sync", now + 60_000, now)
    assert authorize(
        node, workspace, encode_pile(good), now) == (node.pk, "sync")
    assert authorize(
        node, workspace,
        encode_pile(combine(bob_closure, good)), now) is None
