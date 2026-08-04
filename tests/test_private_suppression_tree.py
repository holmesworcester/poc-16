"""Executable privacy, integrity, bound, and CAS contracts for SuppTree."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from core.crypto import h
from core.fact import canon
from core.grants import make_token
from core.http import AsyncFromSyncReader, HttpGate
from core.indexes import principal_sid
from core.limits import (
    MAX_REGISTERED_SUPPRESSION_ROUTES,
    MAX_REMOVAL_UPDATES,
    MAX_REMOVAL_PROOF_STEPS,
    PayloadTooLarge,
)
from core.object_store import (
    OutcomeUnknown,
    REMOVAL_NODE_PREFIX,
    REMOVAL_ROOT_KEY,
)
from core.pack_access import (
    ObjectOpen,
    ScopedRequest,
    decode_scoped_request,
    encode_object_open,
)
from core.store import FsStore
from core.suppression import suppression_slot
from core import suppression_tree as tree

from .shared_bucket import ScriptedBucket


def run(awaitable):
    return asyncio.run(awaitable)


def ids(label):
    return h((label + " workspace").encode()), \
        h((label + " member").encode()), \
        h((label + " device").encode())


def rows():
    workspace, alice, alice_device = ids("alice")
    _other, bob, bob_device = ids("bob")
    return workspace, (
        (principal_sid("member", alice), suppression_slot()),
        (principal_sid("device", alice_device), suppression_slot()),
        (principal_sid("member", bob), suppression_slot(h(b"remove bob"))),
        (principal_sid("device", bob_device), suppression_slot(h(b"remove bob device"))),
    )


def object_map(built):
    return dict(built.nodes)


def proof_for(root, sid, objects):
    async def fetch(oid):
        return objects.get(oid)

    return run(tree._prove(root, sid, fetch))


def update_from(workspace, root, changes, objects):
    async def fetch(oid):
        return objects.get(oid)

    return run(tree._update(workspace, root, changes, fetch))


def lose_response(bucket, actor, operation, key, when):
    gate = bucket.pause(actor, operation, key, when=when)
    gate.error = OutcomeUnknown(
        f"lost {operation} response {when} linearization")
    gate.release.set()


def test_path_reveals_exactly_one_hashed_sid_and_value():
    workspace, source = rows()
    built = tree._build(workspace, source)
    objects = object_map(built)
    target_sid, target_value = source[0]
    hidden_sid, hidden_value = source[2]

    proof = proof_for(built.root, target_sid, objects)
    document = json.loads(proof)

    assert document["key"] == tree.logical_key(workspace, target_sid)
    assert document["value"] == target_value
    assert set(document) == {"format", "key", "path", "root", "value"}
    assert all(
        isinstance(frame, list) and len(frame) == 2
        and type(frame[0]) is int and 0 <= frame[0] < tree.KEY_BITS
        and isinstance(frame[1], str) and len(frame[1]) == 64
        for frame in document["path"])
    assert target_sid.encode() not in proof
    assert hidden_sid.encode() not in proof
    assert hidden_value["action"].encode() not in proof
    assert tree.verify(
        built.root, workspace, target_sid, proof) == target_value

    decoded_nodes = tuple(json.loads(raw) for raw in objects.values())
    leaves = tuple(node for node in decoded_nodes if node["kind"] == "leaf")
    assert len(leaves) == len(source)
    assert all(set(leaf) == {
        "format", "key", "kind", "value", "workspace"
    } for leaf in leaves)
    assert all(
        sid.encode() not in raw
        for sid, _value in source
        for raw in objects.values())


def test_build_update_retries_and_permutations_are_one_aci_join():
    workspace, _member, _device = ids("join")
    sid = principal_sid("member", h(b"joined member"))
    actions = tuple(h(f"action {index}".encode()) for index in range(4))
    events = (
        (sid, suppression_slot()),
        *((sid, suppression_slot(action)) for action in actions),
        (sid, suppression_slot(actions[-1])),
    )
    expected = suppression_slot(min(actions))

    roots = set()
    from itertools import permutations

    for order in permutations(events[:5]):
        built = tree._build(workspace, order)
        proof = proof_for(built.root, sid, object_map(built))
        assert tree.verify(built.root, workspace, sid, proof) == expected
        roots.add(built.root)
    assert len(roots) == 1

    objects = {}
    current = tree._build(workspace, ())
    for event in reversed(events):
        updated = update_from(
            workspace, current.root, (event,), objects)
        objects.update(updated.nodes)
        current = updated
    assert current.root == tree._build(workspace, events[:5]).root
    assert tree.verify(
        current.root,
        workspace,
        sid,
        proof_for(current.root, sid, objects),
    ) == expected


def test_slot_join_is_associative_commutative_idempotent_with_absence():
    values = (
        None,
        suppression_slot(),
        suppression_slot(h(b"action a")),
        suppression_slot(h(b"action b")),
    )
    for left in values:
        assert tree.join_slots(left, left) == left
        for right in values:
            assert tree.join_slots(left, right) == \
                tree.join_slots(right, left)
            for third in values:
                assert tree.join_slots(
                    tree.join_slots(left, right), third
                ) == tree.join_slots(
                    left, tree.join_slots(right, third))
    assert tree.join_slots(None, suppression_slot()) == suppression_slot()
    assert tree.join_slots(
        suppression_slot(), suppression_slot(h(b"active"))) \
        == suppression_slot(h(b"active"))


def test_tiny_batch_exact_bound_prunes_nodes_and_one_over_stops_early():
    assert MAX_REMOVAL_UPDATES == MAX_REGISTERED_SUPPRESSION_ROUTES == 5
    workspace, member, _device = ids("tiny batch")
    initial = (principal_sid("member", member), suppression_slot())
    additions = tuple(
        (principal_sid("member", h(f"member {index}".encode())),
         suppression_slot())
        for index in range(MAX_REMOVAL_UPDATES)
    )
    bucket = ScriptedBucket()
    state = tree.SuppressionTree(workspace, bucket.handle("writer"))
    assert run(state.apply((initial,))).status == "applied"
    before = len(bucket.history)

    assert run(state.apply(iter(additions))).status == "applied"
    mutations = tuple(
        event for event in bucket.history[before:]
        if event.op in {"put_if_absent", "cas"})
    node_puts = tuple(
        event for event in mutations
        if event.op == "put_if_absent"
        and event.key.startswith(REMOVAL_NODE_PREFIX))
    # Five new leaves plus five new branches; superseded path-copy nodes are
    # not sent to the provider.
    assert len(node_puts) == 2 * MAX_REMOVAL_UPDATES
    assert sum(event.op == "cas" for event in mutations) == 1

    consumed = []

    def one_over():
        for index in range(MAX_REMOVAL_UPDATES + 100):
            consumed.append(index)
            yield additions[index % len(additions)]

    before = len(bucket.history)
    with pytest.raises(PayloadTooLarge, match="too many"):
        run(state.apply(one_over()))
    assert consumed == list(range(MAX_REMOVAL_UPDATES + 1))
    assert len(bucket.history) == before

    assert len(tree._build(workspace, iter(additions)).nodes) \
        == 2 * MAX_REMOVAL_UPDATES - 1
    with pytest.raises(PayloadTooLarge, match="too many"):
        tree._build(workspace, iter((*additions, initial)))


def test_missing_forged_duplicate_truncated_stale_and_relabels_fail_closed():
    workspace, source = rows()
    built = tree._build(workspace, source)
    objects = object_map(built)
    sid, _value = source[0]
    proof = proof_for(built.root, sid, objects)
    document = json.loads(proof)
    assert document["path"]

    missing = principal_sid("member", h(b"missing"))
    assert proof_for(built.root, missing, objects) is None
    with pytest.raises(ValueError):
        tree.verify(built.root, workspace, missing, None)

    forged = dict(document)
    forged["value"] = suppression_slot(h(b"forged action"))
    with pytest.raises(ValueError):
        tree.verify(built.root, workspace, sid, canon(forged))

    forged = dict(document)
    forged["path"] = [list(frame) for frame in document["path"]]
    forged["path"][0][1] = h(b"forged sibling")
    with pytest.raises(ValueError):
        tree.verify(built.root, workspace, sid, canon(forged))

    truncated = dict(document)
    truncated["path"] = document["path"][:-1]
    with pytest.raises(ValueError):
        tree.verify(built.root, workspace, sid, canon(truncated))

    duplicate = dict(document)
    duplicate["path"] = [document["path"][0], *document["path"]]
    with pytest.raises(ValueError):
        tree.verify(built.root, workspace, sid, canon(duplicate))

    other_workspace, other_member, other_device = ids("relabel")
    for changed_workspace, changed_sid in (
            (other_workspace, sid),
            (workspace, principal_sid("member", other_member)),
            (workspace, principal_sid("device", other_device))):
        with pytest.raises(ValueError):
            tree.verify(
                built.root, changed_workspace, changed_sid, proof)

    updated = update_from(
        workspace, built.root,
        ((sid, suppression_slot(h(b"later removal"))),), objects)
    objects.update(updated.nodes)
    with pytest.raises(ValueError):
        tree.verify(updated.root, workspace, sid, proof)
    assert tree.verify(built.root, workspace, sid, proof) == \
        suppression_slot()


def test_exact_256_step_proof_verifies_and_one_over_is_rejected():
    workspace, member, _device = ids("proof bound")
    sid = principal_sid("member", member)
    one = tree._build(workspace, ((sid, suppression_slot()),))
    key = tree.logical_key(workspace, sid)
    current = tree.decode_root(one.root).root
    siblings = tuple(
        h(f"opaque sibling {bit}".encode())
        for bit in range(MAX_REMOVAL_PROOF_STEPS))

    for bit in reversed(range(MAX_REMOVAL_PROOF_STEPS)):
        sibling = siblings[bit]
        left, right = (current, sibling) if tree._bit(key, bit) == 0 \
            else (sibling, current)
        current = h(tree._branch_raw(workspace, bit, left, right))

    root = tree.encode_root(
        workspace, current, MAX_REMOVAL_PROOF_STEPS + 1)
    proof = tree._encode_proof(
        h(root), key, suppression_slot(),
        tuple(enumerate(siblings)),
    )
    assert tree.verify(root, workspace, sid, proof) == suppression_slot()

    with pytest.raises(PayloadTooLarge):
        tree._encode_proof(
            h(root), key, suppression_slot(),
            (*tuple(enumerate(siblings)),
             (MAX_REMOVAL_PROOF_STEPS, h(b"one over"))),
        )


def test_private_nodes_and_root_are_not_object_or_grant_addressable(tmp_path):
    workspace, source = rows()
    store = FsStore(tmp_path / "store")
    state = tree.SuppressionTree(workspace, store)
    assert run(state.apply(source)).status == "applied"
    pin = run(state.pin())
    proof = run(pin.proof(source[0][0]))
    assert pin.verify(source[0][0], proof) == source[0][1]

    private_keys = tuple(store.list(REMOVAL_NODE_PREFIX))
    root = tree.decode_root(pin.root_bytes)
    assert private_keys and store.get(REMOVAL_ROOT_KEY) == pin.root_bytes
    assert store.get("obj/" + root.root) is None
    assert store.get("obj/" + h(pin.root_bytes)) is None

    secret = b"g" * 32
    token = make_token(
        secret, source[0][0], workspace, issued_at=1, ttl_ms=10_000)
    headers = {"Authorization": "Bearer " + token}

    async def issue(_member, opened, trusted_now):
        return ScopedRequest(
            opened.method,
            "https://bucket.invalid/obj/" + opened.oid,
            (),
            trusted_now + 1_000,
        )

    gate = HttpGate(
        AsyncFromSyncReader(store), workspace, secret, lambda: 2,
        object_open=issue,
    )
    node_oid = private_keys[0].removeprefix(REMOVAL_NODE_PREFIX)
    for path in (
            "/obj/" + node_oid,
            "/obj/" + root.root,
            "/removal/" + node_oid,
            "/removal"):
        response = run(gate.handle(
            "GET", path, query={"ws": workspace}, headers=headers))
        assert response.status == 404

    opened = run(gate.handle(
        "POST", "/obj/open", query={"ws": workspace}, headers=headers,
        body=encode_object_open(ObjectOpen("GET", node_oid, 1))))
    assert opened.status == 200
    scoped = decode_scoped_request(opened.body)
    assert scoped.url.endswith("/obj/" + node_oid)
    assert "/removal" not in scoped.url
    assert store.get("obj/" + node_oid) is None


def test_concurrent_root_cas_converges_without_clobbering_private_nodes():
    workspace, alice, _alice_device = ids("race alice")
    _other, bob, _bob_device = ids("race bob")
    alice_sid = principal_sid("member", alice)
    bob_sid = principal_sid("member", bob)
    bucket = ScriptedBucket()
    first = tree.SuppressionTree(workspace, bucket.handle("alice"))
    second = tree.SuppressionTree(workspace, bucket.handle("bob"))
    paused = bucket.pause(
        "alice", "cas", REMOVAL_ROOT_KEY, when="before")

    with ThreadPoolExecutor(max_workers=2) as pool:
        alice_turn = pool.submit(
            run, first.apply(((alice_sid, suppression_slot()),)))
        paused.wait()
        bob_turn = pool.submit(
            run, second.apply(((bob_sid, suppression_slot()),)))
        assert bob_turn.result().status == "applied"
        paused.release.set()
        assert alice_turn.result().status == "retryable"

    assert run(first.apply(((alice_sid, suppression_slot()),))).status \
        == "applied"
    pin = run(second.pin())
    assert pin.verify(alice_sid, run(pin.proof(alice_sid))) == suppression_slot()
    assert pin.verify(bob_sid, run(pin.proof(bob_sid))) == suppression_slot()
    assert bucket.assert_valid_history()

    writer = bucket.handle("attacker")
    node_key = next(
        key for key in writer.list(REMOVAL_NODE_PREFIX)
        if key.startswith(REMOVAL_NODE_PREFIX))
    for key in (REMOVAL_ROOT_KEY, node_key):
        with pytest.raises(ValueError, match="conditional"):
            writer.put(key, b"clobber")
        with pytest.raises(ValueError, match="not deletable"):
            writer.delete(key)
    with pytest.raises(ValueError, match="address"):
        writer.put_if_absent(
            REMOVAL_NODE_PREFIX + "0" * 64, b"clobber")


def test_apply_at_stale_validation_pin_performs_no_mutation():
    workspace, member, _device = ids("stale validation pin")
    sid = principal_sid("member", member)
    other_sid = principal_sid("member", h(b"unrelated member"))
    bucket = ScriptedBucket()
    state = tree.SuppressionTree(workspace, bucket.handle("recipient"))
    assert run(state.apply(((sid, suppression_slot()),))).status == "applied"
    stale = run(state.pin())

    action = h(b"concurrent removal")
    assert run(state.apply((
        (sid, suppression_slot(action)),
    ))).status == "applied"
    current = run(state.pin())
    def mutations():
        return tuple(
            event for event in bucket.history
            if event.op in {"put_if_absent", "cas"})

    before = mutations()

    rejected = run(state.apply_at(
        stale, ((other_sid, suppression_slot()),)))
    assert rejected.status == "retryable"
    assert mutations() == before
    assert run(current.proof(other_sid)) is None
    assert current.verify(sid, run(current.proof(sid))) == \
        suppression_slot(action)
    assert bucket.handle("reader").get(REMOVAL_ROOT_KEY) == \
        current.root_bytes
    assert bucket.assert_valid_history()


def test_private_node_create_recovers_after_unknown_applied_outcome():
    workspace, member, _device = ids("node outcome unknown")
    sid = principal_sid("member", member)
    row = (sid, suppression_slot())
    built = tree._build(workspace, (row,))
    node_oid, = (oid for oid, _raw in built.nodes)
    bucket = ScriptedBucket()
    lose_response(
        bucket, "writer", "put_if_absent",
        tree.private_node_key(node_oid), "after")

    state = tree.SuppressionTree(workspace, bucket.handle("writer"))
    assert run(state.apply((row,))).status == "applied"
    restarted = tree.SuppressionTree(
        workspace, bucket.handle("restarted"))
    pin = run(restarted.pin())
    assert pin.verify(sid, run(pin.proof(sid))) == suppression_slot()
    assert bucket.assert_valid_history()


@pytest.mark.parametrize("unknown_when", ("before", "after"))
def test_root_cas_unknown_outcome_is_restart_safe(unknown_when):
    workspace, member, _device = ids(f"root unknown {unknown_when}")
    sid = principal_sid("member", member)
    row = (sid, suppression_slot())
    bucket = ScriptedBucket()
    lose_response(
        bucket, "writer", "cas", REMOVAL_ROOT_KEY, unknown_when)
    state = tree.SuppressionTree(workspace, bucket.handle("writer"))

    first = run(state.apply((row,)))
    assert first.status == (
        "retryable" if unknown_when == "before" else "applied")
    restarted = tree.SuppressionTree(
        workspace, bucket.handle("restarted"))
    if first.status == "retryable":
        assert run(restarted.pin()) is None
        assert run(restarted.apply((row,))).status == "applied"
    pin = run(restarted.pin())
    assert pin.verify(sid, run(pin.proof(sid))) == suppression_slot()
    assert bucket.assert_valid_history()


@pytest.mark.parametrize("first_is_min", (False, True))
def test_concurrent_actions_retry_to_the_same_minimum_fid(first_is_min):
    workspace, member, _device = ids(f"same slot {first_is_min}")
    sid = principal_sid("member", member)
    low, high = sorted((h(b"race action a"), h(b"race action b")))
    first_action, second_action = (low, high) if first_is_min else (high, low)
    bucket = ScriptedBucket()
    first = tree.SuppressionTree(workspace, bucket.handle("first"))
    second = tree.SuppressionTree(workspace, bucket.handle("second"))
    paused = bucket.pause(
        "first", "cas", REMOVAL_ROOT_KEY, when="before")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_turn = pool.submit(run, first.apply((
            (sid, suppression_slot(first_action)),
        )))
        paused.wait()
        second_turn = pool.submit(run, second.apply((
            (sid, suppression_slot(second_action)),
        )))
        assert second_turn.result().status == "applied"
        paused.release.set()
        assert first_turn.result().status == "retryable"

    retry = run(first.apply(((sid, suppression_slot(first_action)),)))
    assert retry.status == ("applied" if first_is_min else "noop")
    pin = run(second.pin())
    assert pin.verify(sid, run(pin.proof(sid))) == suppression_slot(low)
    assert bucket.assert_valid_history()


def test_existing_wrong_private_bytes_fail_before_root_publication():
    workspace, source = rows()
    built = tree._build(workspace, (source[0],))
    oid, _raw = built.nodes[0]
    bucket = ScriptedBucket({tree.private_node_key(oid): b"wrong"})
    state = tree.SuppressionTree(workspace, bucket.handle("writer"))

    with pytest.raises(ValueError, match="node conflict"):
        run(state.apply((source[0],)))
    assert bucket.handle("reader").get(REMOVAL_ROOT_KEY) is None
    assert bucket.assert_valid_history()
