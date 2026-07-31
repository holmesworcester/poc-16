"""Awaited object-store authorization over real published snapshots."""
import asyncio
from collections import Counter

import pytest

import facts

from core import merkle_map
from core.close import decode_pile, encode_pile
from full_peer.node import FullPeer, now_ms
from core.repository_reader import RepositoryReader
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


def run_async(workspace, pile, root, fetch, now, *,
              unique=UNIQUE_FETCH_BUDGET, byte_limit=FETCH_BYTE_BUDGET):
    return asyncio.run(RepositoryReader.mint_awaited(
        workspace, root, fetch, pile, now,
        max_unique_fetches=unique,
        max_fetch_bytes=byte_limit,
    ))


@pytest.fixture
def snapshots(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    message = facts.content.message.post(
        node, workspace, "general", "later suppressed", ts=20)
    message_closure = decode_pile(
        closed_subset(node, workspace, {message}), workspace)

    now = now_ms()
    bob_pile = encode_pile(request.payload(
        node, workspace, "sync", now + 60_000, now))
    node.bind_identity(workspace, founder)
    founder_facts = request.payload(
        node, workspace, "sync", now + 60_000, now + 1)
    founder_pile = encode_pile(founder_facts)
    expired = encode_pile(request.payload(
        node, workspace, "sync", now - 1, now + 2))

    facts.content.delete.remove(node, workspace, message, ts=now + 3)
    suppressed_root = node.store(workspace).get("root")
    suppressed_pile = encode_pile(combine(message_closure, founder_facts))

    facts.auth.removal.evict(node, workspace, bob)
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
        sync = RepositoryReader(
            snapshots["workspace"],
            root,
            lambda oid: store.get("obj/" + oid),
        ).mint(pile, now)
        calls = []

        async def fetch(oid):
            calls.append(oid)
            return store.get("obj/" + oid)

        assert sync == expected, name
        assert run_async(
            snapshots["workspace"], pile, root, fetch, now) == sync, name
        assert len(calls) == len(set(calls)), name


def test_async_driver_memoizes_repeated_tree_paths(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])
    pile = snapshots["founder_pile"]
    root = snapshots["removed_root"]
    now = snapshots["now"]
    sync_calls = []

    expected = RepositoryReader(
        snapshots["workspace"],
        root,
        lambda oid: (
            sync_calls.append(oid) or store.get("obj/" + oid)),
    ).mint(pile, now)
    repeated = {
        oid for oid, count in Counter(sync_calls).items() if count > 1}
    assert repeated

    async_calls = []

    async def fetch(oid):
        async_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(
        snapshots["workspace"], pile, root, fetch, now) == expected
    assert async_calls == list(dict.fromkeys(sync_calls))
    assert repeated.isdisjoint(
        oid for oid, count in Counter(async_calls).items() if count > 1)


def test_async_driver_opens_exactly_one_pinned_reader(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])

    class CountingReader(RepositoryReader):
        constructions = 0

        def __post_init__(self):
            type(self).constructions += 1
            super().__post_init__()

    async def fetch(oid):
        return store.get("obj/" + oid)

    decision = asyncio.run(CountingReader.mint_awaited(
        snapshots["workspace"],
        snapshots["removed_root"],
        fetch,
        snapshots["founder_pile"],
        snapshots["now"],
        max_unique_fetches=UNIQUE_FETCH_BUDGET,
        max_fetch_bytes=FETCH_BYTE_BUDGET,
    ))

    assert decision == (snapshots["founder"], "sync")
    assert CountingReader.constructions == 1


def test_missing_and_corrupt_pages_are_fetched_once_and_fail_closed(snapshots):
    store = snapshots["node"].store(snapshots["workspace"])
    pile = snapshots["founder_pile"]
    root = snapshots["removed_root"]
    now = snapshots["now"]
    sync_calls = []
    assert RepositoryReader(
        snapshots["workspace"],
        root,
        lambda oid: (
            sync_calls.append(oid) or store.get("obj/" + oid)),
    ).mint(pile, now)
    target = next(
        oid for oid, count in Counter(sync_calls).items() if count > 1)

    for replacement in (None, b"wrong bytes for this object id"):
        calls = []

        async def fetch(oid):
            calls.append(oid)
            return replacement if oid == target else store.get("obj/" + oid)

        assert run_async(
            snapshots["workspace"], pile, root, fetch, now) is None
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

    expected = run_async(
        snapshots["workspace"], pile, root, baseline_fetch, now)
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
        snapshots["workspace"], pile, root, exact_fetch, now,
        unique=len(ordered), byte_limit=total) == expected
    assert exact_calls == ordered

    unique_calls = []

    async def unique_fetch(oid):
        unique_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(
        snapshots["workspace"], pile, root, unique_fetch, now,
        unique=len(ordered) - 1, byte_limit=total) is None
    assert unique_calls == ordered[:-1]

    prefix_count = len(ordered) // 2
    byte_limit = sum(sizes[:prefix_count])
    byte_calls = []

    async def byte_fetch(oid):
        byte_calls.append(oid)
        return store.get("obj/" + oid)

    assert run_async(
        snapshots["workspace"], pile, root, byte_fetch, now,
        unique=len(ordered), byte_limit=byte_limit) is None
    transferred = [
        len(store.get("obj/" + oid)) for oid in byte_calls]
    assert byte_calls == ordered[:prefix_count + 1]
    assert sum(transferred[:-1]) <= byte_limit < sum(transferred)


def test_async_driver_never_repins_root_during_an_await(tmp_path):
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
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

        decision = asyncio.create_task(RepositoryReader.mint_awaited(
            workspace, pinned_root, fetch, pile, now,
            max_unique_fetches=UNIQUE_FETCH_BUDGET,
            max_fetch_bytes=FETCH_BYTE_BUDGET,
        ))
        await first_fetch.wait()
        node.bind_identity(workspace, founder)
        try:
            await asyncio.to_thread(
                facts.auth.removal.evict, node, workspace, bob)
        finally:
            release_fetch.set()
        return await decision, calls

    decision, calls = asyncio.run(schedule())
    current_root = store.get("root")
    fetch = lambda oid: store.get("obj/" + oid)
    assert current_root != pinned_root
    assert decision == (bob, "sync")
    assert RepositoryReader(
        workspace, pinned_root, fetch).mint(pile, now) == decision
    assert RepositoryReader(
        workspace, current_root, fetch).mint(pile, now) is None
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
            "0" * 64, b"", b"", fetch, 0,
            unique=unique, byte_limit=byte_limit)
