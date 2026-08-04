"""Concurrency contract at the stateful peer's HTTP commit boundary."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading

from core import peer_capability
from core.writer_head import decode_slot_at, head_slot_key
from full_peer.status import describe
from full_peer.walk import Peer
from tests.test_full_peer_writer_http_contract import (
    _bearer,
    _forest_fixture,
    _http,
    _serve,
)


def test_concurrent_writer_finalization_serializes_one_sql_projection(tmp_path):
    """Independent writer slots may arrive together without sharing a tx."""
    workspace, alice, bob, receiver = _forest_fixture(tmp_path)

    with _serve(receiver) as (url, secret):
        headers = _bearer(secret, alice.member, workspace)
        client = Peer(alice, workspace, url)
        client._sync_profile = peer_capability.FULL
        client._token = headers["Authorization"].removeprefix("Bearer ")
        for source in (alice, bob):
            for key in source.store(workspace).list("obj"):
                oid = key.removeprefix("obj/")
                status = client.put_obj(
                    oid, source.store(workspace).get(key))
                assert status in {201, 204}

        projection = receiver.sql(workspace)
        commit = projection.commit
        clients_ready = threading.Barrier(2)
        second_commit = threading.Event()
        guard = threading.Lock()
        state = {"calls": 0, "active": 0, "peak": 0}

        def observed_commit(*args, **kwargs):
            with guard:
                state["calls"] += 1
                call = state["calls"]
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                if call == 1:
                    # Give an unguarded second server thread ample time to
                    # enter the same connection.  The proper FullPeer lock
                    # keeps it outside until this transaction completes.
                    second_commit.wait(0.5)
                else:
                    second_commit.set()
                return commit(*args, **kwargs)
            finally:
                with guard:
                    state["active"] -= 1

        projection.commit = observed_commit

        def finalize(source):
            device = source.identity_id(workspace)
            key = head_slot_key(workspace, device)
            clients_ready.wait()
            status, _, _ = _http(
                url,
                "PUT",
                f"/mirror/{device}?ws={workspace}",
                body=source.store(workspace).get(key),
                headers=headers,
            )
            return status

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = tuple(pool.map(finalize, (alice, bob)))

    assert statuses == (201, 201)
    assert state == {"calls": 2, "active": 0, "peak": 1}
    for source in (alice, bob):
        device = source.identity_id(workspace)
        key = head_slot_key(workspace, device)
        slot = decode_slot_at(key, receiver.store(workspace).get(key))
        assert receiver.sql(workspace).projected_head(device) == slot.head


def test_background_mirror_commit_excludes_status_sql_read(tmp_path):
    """A live sync commit and control-plane read cannot share one connection."""
    workspace, alice, _bob, receiver = _forest_fixture(tmp_path)
    projection = receiver.sql(workspace)
    commit = projection.commit
    commit_entered = threading.Event()
    release_commit = threading.Event()
    status_started = threading.Event()
    status_entered_projection = threading.Event()
    ensure_projection = receiver._ensure_projection

    def blocked_commit(*args, **kwargs):
        commit_entered.set()
        if not release_commit.wait(5):
            raise AssertionError("status race did not release projection")
        return commit(*args, **kwargs)

    def observed_projection(workspace):
        status_entered_projection.set()
        return ensure_projection(workspace)

    def read_status():
        status_started.set()
        return describe(receiver)

    projection.commit = blocked_commit
    receiver._ensure_projection = observed_projection
    with ThreadPoolExecutor(max_workers=2) as pool:
        sync_future = pool.submit(
            asyncio.run,
            receiver.mirror(workspace).sync_from(
                alice.store(workspace)),
        )
        try:
            assert commit_entered.wait(5)
            status_future = pool.submit(read_status)
            assert status_started.wait(5)
            # The mirror's synchronous projection adapter owns receiver.lock
            # here, so status must wait instead of entering sqlite3.
            assert not status_entered_projection.wait(0.1)
        finally:
            release_commit.set()

        result = sync_future.result(10)
        status = status_future.result(10)

    assert result.errors == ()
    assert result.changed == 1
    assert status["workspaces"][workspace]["facts"] \
        == len(projection.fact_ids())
