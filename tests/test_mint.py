"""Acceptance laws for the pure mint (docs/SIMPLIFY.md §4)."""
import base64
import inspect
import random

import pytest
from nacl.exceptions import CryptoError

from core import cmds, daemon, mint
from core.close import encode_pile
from core.crypto import keypair, unseal
from core.fact import Fact
from facts.auth.device import bind
from facts.auth import request
from facts.auth.signature import signature
from core.node import Node, now_ms

from .util import add_member, inject_device_claim


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
    authority = node.idx(workspace)
    second = request.payload(
        node, workspace, "sync", now + 60_001, now + 1)

    assert mint.mint(
        pile, anchor, globals_, now, canonical_db=authority) \
        == (node.pk, "sync")
    assert mint.mint(
        encode_pile([node.fact_of(workspace, workspace)]),
        anchor, globals_, now, canonical_db=authority,
    ) is None
    assert mint.mint(
        encode_pile(combine(facts, second)),
        anchor, globals_, now, canonical_db=authority,
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
    authority = node.idx(workspace)

    assert mint.mint(
        expired, anchor, globals_, now, canonical_db=authority) is None
    assert mint.mint(
        wrong_verb, anchor, globals_, now, canonical_db=authority) is None
    assert mint.mint(
        wrong_tag, anchor, globals_, now, canonical_db=authority) is None
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


def test_low_level_mint_requires_committed_authority(world):
    node, workspace, now, _, pile = world
    anchor, globals_ = mint.root_globals(
        node.store(workspace).get("root"))

    with pytest.raises(TypeError):
        mint.mint(pile, anchor, globals_, now)
    assert mint.mint(
        pile, anchor, globals_, now, canonical_db=None) is None


def test_stateless_mint_accepts_without_persistent_sqlite(world):
    """A cold tree projection accepts a new request and never reads app.db."""
    node, workspace, now, _, pile = world
    store = node.store(workspace)
    root = store.get("root")
    node.idx(workspace).close()
    node.app.close()

    anchor, _ = mint.root_globals(root)
    fetch = lambda oid: store.get("obj/" + oid)

    assert anchor == workspace
    assert mint.stateless(pile, root, fetch, now) \
        == (node.pk, "sync")


def test_stateless_authority_is_root_stamped_and_reusable(world):
    node, workspace, now, _, pile = world
    store = node.store(workspace)
    old_root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)

    with mint.Authority.from_root(old_root, fetch) as projection:
        assert mint.stateless(
            pile, old_root,
            lambda _: pytest.fail("warm projection fetched the tree"),
            now, projection) == (node.pk, "sync")

        cmds.post(node, workspace, "general", "changes the root")
        new_root, fetched = store.get("root"), []

        def tracked(oid):
            fetched.append(oid)
            return fetch(oid)

        assert projection.etag != store.etag("root")
        assert mint.stateless(
            pile, new_root, tracked, now, projection) == (node.pk, "sync")
        assert fetched


@pytest.mark.parametrize("seed", range(5))
def test_every_mint_path_matches_randomized_canonical_conflicts(
        tmp_path, seed):
    node, workspace, now, founder, old_root, stale, fresh = \
        conflict_world(tmp_path / f"conflict-{seed}", seed)
    store, root = node.store(workspace), node.store(workspace).get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    anchor, globals_ = mint.root_globals(root)
    cases = ((stale, None), (fresh, (founder, "sync")))

    with mint.Authority.from_root(old_root, fetch) as old_projection:
        assert mint.stateless(
            stale, old_root,
            lambda _: pytest.fail("matching old projection fetched the tree"),
            now, old_projection)
        assert mint.stateless(
            stale, root, fetch, now, old_projection) is None

    with mint.Authority.from_root(root, fetch) as projection:
        for pile, expected in cases:
            assert mint.mint(
                pile, anchor, globals_, now,
                canonical_db=node.idx(workspace)) == expected
            assert mint.stateless(pile, root, fetch, now) == expected
            assert mint.stateless(
                pile, root,
                lambda _: pytest.fail("cached mint fetched the tree"),
                now, projection) == expected
            assert invoke(node, workspace, pile)[1][0] \
                == (200 if expected else 403)


@pytest.mark.skip(reason="poc-16-yez.9 decides the gate mask")
def test_gate_mask_screens_whole_closure():
    """gxz seam: a pile whose CLOSURE contains an evicted signer's fact is
    refused at the gate even when the requester is in good standing — enable
    once poc-16-yez.9 confirms the seam."""
    raise NotImplementedError
