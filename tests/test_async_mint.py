"""Awaited object-store authorization over real published snapshots."""
import asyncio
from collections import Counter

import pytest

from core import merkle_map, cmds, mint
from core.close import decode_pile, encode_pile
from core.node import Node, now_ms
from facts.auth import request

from .util import add_member, closed_subset

UNIQUE_FETCH_BUDGET = 49
FETCH_BYTE_BUDGET = UNIQUE_FETCH_BUDGET * merkle_map.MAX_PAGE_BYTES


def combine(*streams):
    seen, out = set(), []
    for fact in (fact for stream in streams for fact in stream):
        if fact.fid not in seen:
            seen.add(fact.fid)
            out.append(fact)
    return out


def run_async(pile, root, fetch, now, *,
              unique=UNIQUE_FETCH_BUDGET, byte_limit=FETCH_BYTE_BUDGET):
    return asyncio.run(mint.async_stateless(
        pile, root, fetch, now,
        max_unique_fetches=unique,
        max_fetch_bytes=byte_limit,
    ))


@pytest.fixture
def snapshots(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    message = cmds.post(
        node, workspace, "general", "later suppressed", ts=20)
    message_closure = decode_pile(
        closed_subset(node, workspace, {message}), workspace)[0]

    now = now_ms()
    bob_pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    node.bind_identity(workspace, founder)
    founder_facts = request.payload(
        node, workspace, "sync", now + 60_000, now + 1)
    founder_pile = encode_pile(founder_facts)
    expired = encode_pile(request.payload(
        node, workspace, "sync", now - 1, now + 2))

    cmds.remove(node, workspace, message, ts=now + 3)
    suppressed_root = node.store(workspace).get("root")
    suppressed_pile = encode_pile(combine(message_closure, founder_facts))

    cmds.evict(node, workspace, bob)
    removed_root = node.store(workspace).get("root")
    return {
        "node": node,
        "workspace": workspace,
        "now": now,
        "founder": founder,
        "bob": bob,
        "bob_pile": bob_pile,
        "founder_pile": founder_pile,
        "expired": expired,
        "suppressed_pile": suppressed_pile,
        "suppressed_root": suppressed_root,
        "removed_root": removed_root,
    }


def test_async_driver_matches_sync_decisions_from_real_snapshots(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])
    now = snapshots["now"]
    cases = (
        (
            "allow", snapshots["founder_pile"], snapshots["removed_root"],
            (snapshots["founder"], "sync"),
        ),
        (
            "suppressed history", snapshots["suppressed_pile"],
            snapshots["suppressed_root"], (snapshots["founder"], "sync"),
        ),
        (
            "removed", snapshots["bob_pile"], snapshots["removed_root"], None,
        ),
        (
            "expired", snapshots["expired"], snapshots["removed_root"], None,
        ),
        (
            "malformed", b"{", snapshots["removed_root"], None,
        ),
    )

    for name, pile, root, expected in cases:
        sync = mint.stateless(
            pile, root, lambda oid: store.get("obj/" + oid), now)
        calls = []

        async def fetch(oid):
            calls.append(oid)
            return store.get("obj/" + oid)

        assert sync == expected, name
        assert run_async(pile, root, fetch, now) == sync, name
        assert len(calls) == len(set(calls)), name


def test_async_driver_memoizes_repeated_tree_paths(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])
    pile = snapshots["founder_pile"]
    root = snapshots["removed_root"]
    now = snapshots["now"]
    sync_calls = []

    expected = mint.stateless(
        pile, root,
        lambda oid: (
            sync_calls.append(oid) or store.get("obj/" + oid)),
        now,
    )
    repeated = {
        oid for oid, count in Counter(sync_calls).items() if count > 1}
    assert repeated

    async_calls = []

    async def fetch(oid):
        async_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(pile, root, fetch, now) == expected
    assert async_calls == list(dict.fromkeys(sync_calls))
    assert repeated.isdisjoint(
        oid for oid, count in Counter(async_calls).items() if count > 1)


def test_missing_and_corrupt_pages_are_fetched_once_and_fail_closed(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])
    pile = snapshots["founder_pile"]
    root = snapshots["removed_root"]
    now = snapshots["now"]
    sync_calls = []
    assert mint.stateless(
        pile, root,
        lambda oid: (
            sync_calls.append(oid) or store.get("obj/" + oid)),
        now,
    )
    target = next(
        oid for oid, count in Counter(sync_calls).items() if count > 1)

    for replacement in (None, b"wrong bytes for this object id"):
        calls = []

        async def fetch(oid):
            calls.append(oid)
            return replacement if oid == target else store.get("obj/" + oid)

        assert run_async(pile, root, fetch, now) is None
        assert Counter(calls)[target] == 1
        assert len(calls) == len(set(calls))


def test_unique_fetch_and_aggregate_byte_budgets_are_hard(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])
    pile = snapshots["founder_pile"]
    root = snapshots["removed_root"]
    now = snapshots["now"]
    ordered = []

    async def baseline_fetch(oid):
        ordered.append(oid)
        return store.get("obj/" + oid)

    expected = run_async(pile, root, baseline_fetch, now)
    assert expected == (snapshots["founder"], "sync")
    sizes = [len(store.get("obj/" + oid)) for oid in ordered]
    total = sum(sizes)
    assert 1 < len(ordered) < UNIQUE_FETCH_BUDGET
    assert total < FETCH_BYTE_BUDGET

    exact_calls = []

    async def exact_fetch(oid):
        exact_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(
        pile, root, exact_fetch, now,
        unique=len(ordered), byte_limit=total) == expected
    assert exact_calls == ordered

    unique_calls = []

    async def unique_fetch(oid):
        unique_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(
        pile, root, unique_fetch, now,
        unique=len(ordered) - 1, byte_limit=total) is None
    assert unique_calls == ordered[:-1]

    prefix_count = len(ordered) // 2
    byte_limit = sum(sizes[:prefix_count])
    byte_calls = []

    async def byte_fetch(oid):
        byte_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(
        pile, root, byte_fetch, now,
        unique=len(ordered), byte_limit=byte_limit) is None
    transferred = [
        len(store.get("obj/" + oid)) for oid in byte_calls]
    assert byte_calls == ordered[:prefix_count + 1]
    assert sum(transferred[:-1]) <= byte_limit < sum(transferred)


def test_async_driver_never_repins_root_during_an_await(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    now = now_ms()
    pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    store = node.store(workspace)
    pinned_root = store.get("root")

    async def schedule():
        first_fetch = asyncio.Event()
        release_fetch = asyncio.Event()
        calls = []

        async def fetch(oid):
            calls.append(oid)
            if len(calls) == 1:
                first_fetch.set()
                await release_fetch.wait()
            return store.get("obj/" + oid)

        decision = asyncio.create_task(mint.async_stateless(
            pile, pinned_root, fetch, now,
            max_unique_fetches=UNIQUE_FETCH_BUDGET,
            max_fetch_bytes=FETCH_BYTE_BUDGET,
        ))
        await first_fetch.wait()
        node.bind_identity(workspace, founder)
        try:
            cmds.evict(node, workspace, bob)
        finally:
            release_fetch.set()
        return await decision, calls

    decision, calls = asyncio.run(schedule())
    current_root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    assert current_root != pinned_root
    assert decision == (bob, "sync")
    assert mint.stateless(pile, pinned_root, fetch, now) == decision
    assert mint.stateless(pile, current_root, fetch, now) is None
    assert calls and all(len(oid) == 64 for oid in calls)


@pytest.mark.parametrize(
    ("unique", "byte_limit"),
    ((-1, 0), (0, -1), (True, 0), (0, False)),
)
def test_async_driver_rejects_invalid_budget_configuration(
        unique, byte_limit):
    async def fetch(_oid):
        pytest.fail("invalid configuration fetched an object")

    with pytest.raises(ValueError, match="budget"):
        run_async(
            b"", b"", fetch, 0,
            unique=unique, byte_limit=byte_limit)
