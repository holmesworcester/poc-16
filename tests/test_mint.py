"""Acceptance laws for the pure mint (docs/SIMPLIFY.md §4)."""
import base64
import inspect
import json
import random

import pytest
from nacl.exceptions import CryptoError

from core import cmds, daemon, manifest, mint, shape
from core.close import decode_pile, encode_pile
from core.crypto import h, keypair, unseal
from core.fact import Fact, canon
from core.kernel import drain
from facts.auth.device import bind
from facts.auth import request
from facts.auth.signature import signature
from core import node as node_module
from core.node import Node, now_ms

from .util import (
    add_member,
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


def root_with(node, workspace, extra, deps_of=None):
    """Build a self-hashed root over the current facts plus ``extra``,
    optionally under non-canonical closure choices (``deps_of``)."""
    store = node.store(workspace)
    fetch = lambda oid: store.get("obj/" + oid)
    _, _, man, slot = manifest.decode_root(store.get("root"))
    resident = list(node_module.resident(man, fetch))
    unit = combine(resident, extra)
    result = drain(unit, workspace)
    assert result.ok
    by_fid = {fact.fid: fact for fact in unit}
    deps = {valid.fact.fid: list(valid.deps) for valid in result.valids}

    def emit(raw):
        oid = h(raw)
        store.put("obj/" + oid, raw)
        return oid

    _, forged = manifest.build(
        [fact.key for fact in unit], by_fid.__getitem__,
        deps_of or deps.__getitem__, emit)
    return manifest.encode_root(workspace, result.globals, forged, slot)


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
    handler, (code, body) = invoke_mint(node, workspace, pile)
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

    code, _ = invoke_mint(node, workspace, pile)[1]
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
    """A cold store projection accepts a new request and never reads app.db."""
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


def test_stateless_authority_rejects_a_noncanonical_leaf_pile(world):
    """A published leaf pile must be the canonical key-ordered encoding of
    its members; any other bytes fail resident()'s rebuild equality."""
    node, workspace, now, _, pile = world
    for tick in range(3):
        cmds.post(node, workspace, "general", f"m{tick}", ts=now - 9 + tick)
    store = node.store(workspace)
    fetch = lambda oid: store.get("obj/" + oid)

    def emit(raw):
        oid = h(raw)
        store.put("obj/" + oid, raw)
        return oid

    anchor, globals_, man, slot = manifest.decode_root(store.get("root"))
    entries = manifest.decode(fetch(man), fetch)
    members = decode_pile(fetch(entries[0].leaf))[0]
    assert len(members) > 1
    shuffled = entries[0]._replace(
        leaf=emit(encode_pile(list(reversed(members)))))
    corrupt = manifest.encode_root(
        anchor, globals_,
        manifest.encode([shuffled] + list(entries[1:]), emit), slot)

    with pytest.raises(ValueError, match="invalid authority store"):
        mint.Authority.from_root(corrupt, fetch)
    assert mint.stateless(pile, corrupt, fetch, now) is None


def test_stateless_authority_rejects_an_empty_root_without_its_anchor(
        world):
    node, workspace, now, _, pile = world
    objects = {}
    _, empty = manifest.build(
        [], lambda fid: None, lambda fid: (),
        lambda raw: objects.__setitem__(h(raw), raw))
    root = manifest.encode_root(workspace, frozenset(), empty, {})

    with pytest.raises(
            ValueError, match="authority projection does not match root"):
        mint.Authority.from_root(root, objects.get)
    assert mint.stateless(pile, root, objects.get, now) is None


def test_root_metadata_cannot_omit_an_eviction(tmp_path):
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
    honest = store.get("root")
    root = json.loads(honest)
    assert ["removal", bob] in root["globals"]
    root["globals"] = []
    forged = canon(root)
    fetch = lambda oid: store.get("obj/" + oid)

    anchor, globals_ = mint.root_globals(honest)
    assert mint.mint(
        pile, anchor, globals_, now,
        canonical_db=node.idx(workspace)) is None
    store.put("root", forged)

    with pytest.raises(ValueError, match="invalid authority store"):
        mint.Authority.from_root(forged, fetch)
    assert mint.stateless(pile, forged, fetch, now) is None
    assert invoke_mint(node, workspace, pile)[1][0] == 403
    with pytest.raises(ValueError, match="invalid store facts"):
        node.rebuild(workspace)


def test_published_authority_rejects_ephemeral_facts_at_every_boundary(
        world):
    node, workspace, now, request_facts, pile = world
    store = node.store(workspace)
    rogue_bytes = root_with(node, workspace, request_facts)
    fetch = lambda oid: store.get("obj/" + oid)

    with pytest.raises(ValueError, match="invalid authority store"):
        mint.Authority.from_root(rogue_bytes, fetch)

    store.put("root", rogue_bytes)
    assert mint.stateless(pile, rogue_bytes, fetch, now) is None
    assert invoke_mint(node, workspace, pile)[1][0] == 403
    with pytest.raises(ValueError, match="invalid store facts"):
        node.rebuild(workspace)


def test_published_roots_require_canonical_settle_placement(tmp_path):
    """The same fact set under non-canonical closure choices (empty
    siblings) is a different, rejected root: placement is not a publisher
    freedom (was the tree-placement law; now resident()'s rebuild equality)."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    add_member(node, workspace, "bob", ts=10)
    ts, cuts = 100, 0
    while cuts < 2:  # several leaves, so closure siblings really exist
        cuts += shape.boundary(
            cmds.post(node, workspace, "general", f"m{ts}", ts=ts))
        ts += 1
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    honest = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    wrong_bytes = root_with(
        node, workspace, [], deps_of=lambda fid: [])

    assert wrong_bytes != honest  # same facts, different closure bytes
    with pytest.raises(ValueError, match="store placement"):
        mint.Authority.from_root(wrong_bytes, fetch)

    store.put("root", wrong_bytes)
    assert mint.stateless(pile, wrong_bytes, fetch, now) is None
    assert invoke_mint(node, workspace, pile)[1][0] == 403
    with pytest.raises(ValueError, match="store placement"):
        node.rebuild(workspace)


def test_stateless_authority_is_root_stamped_and_reusable(world):
    node, workspace, now, _, pile = world
    store = node.store(workspace)
    old_root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)

    with mint.Authority.from_root(old_root, fetch) as projection:
        assert mint.stateless(
            pile, old_root,
            lambda _: pytest.fail("warm projection fetched the store"),
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
            lambda _: pytest.fail("matching old projection fetched the store"),
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
                lambda _: pytest.fail("cached mint fetched the store"),
                now, projection) == expected
            assert invoke_mint(node, workspace, pile)[1][0] \
                == (200 if expected else 403)


@pytest.mark.skip(reason="poc-16-yez.9 decides the gate mask")
def test_gate_mask_screens_whole_closure():
    """gxz seam: a pile whose CLOSURE contains an evicted signer's fact is
    refused at the gate even when the requester is in good standing — enable
    once poc-16-yez.9 confirms the seam."""
    raise NotImplementedError
