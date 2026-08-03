"""Concurrency contract at the stateful peer's HTTP commit boundary."""
from concurrent.futures import ThreadPoolExecutor
import threading

from core.writer_head import decode_slot_at, head_slot_key
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
        for source in (alice, bob):
            for key in source.store(workspace).list("obj"):
                oid = key.removeprefix("obj/")
                status, _, _ = _http(
                    url,
                    "PUT",
                    f"/obj/{oid}?ws={workspace}",
                    body=source.store(workspace).get(key),
                    headers=headers,
                )
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
