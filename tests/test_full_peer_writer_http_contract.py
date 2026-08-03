"""Real-socket contract for the FullPeer per-writer forest.

This intentionally names only the target writer protocol.  The predecessor
``/root``, ``/page``, ``/pile``, and RepositoryApplier surfaces are not valid
fallbacks for these tests.
"""
import asyncio
import base64
from contextlib import contextmanager, ExitStack
import http.client
import json
from pathlib import Path
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode, urlsplit

import facts

from core.crypto import keypair
from core.grants import make_token
from core.http_stdlib import handler_for
from core.writer_head import decode_slot_at, head_slot_key
from full_peer.node import FullPeer
from full_peer.sync import sync
from tests.util import add_member


def _run(awaitable):
    return asyncio.run(awaitable)


@contextmanager
def _serve(peer, secret=b"writer-http-contract-secret-0001"):
    """Serve the production stdlib adapter on an OS-assigned loopback port."""
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler_for(peer, secret))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}", secret
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def _http(url, method, path, *, body=None, headers=None):
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(), dict(response.headers)
    except http.client.RemoteDisconnected as error:
        raise AssertionError(
            "the FullPeer writer HTTP gate closed the socket; it still lacks "
            "the target head-directory/object/mirror surface"
        ) from error
    finally:
        connection.close()


def _bearer(secret, member, workspace):
    return {
        "Authorization": "Bearer " + make_token(
            secret,
            member,
            workspace,
            issued_at=int(time.time() * 1000),
            ttl_ms=60_000,
        )
    }


def _forest_fixture(tmp_path):
    """Three genuine members with independent writer keys and closed logs."""
    alice_secret, _ = keypair()
    bob_secret, bob_public = keypair()
    carol_secret, carol_public = keypair()

    alice = FullPeer(str(tmp_path / "alice"), initial_secret=alice_secret)
    workspace = facts.auth.workspace.create(alice, "alice", ts=1)
    _, _, bob_join = add_member(
        alice,
        workspace,
        "bob",
        ts=10,
        member_identity=(bob_secret, bob_public),
        invite_identity=keypair(),
    )
    _, _, carol_join = add_member(
        alice,
        workspace,
        "carol",
        ts=20,
        member_identity=(carol_secret, carol_public),
        invite_identity=keypair(),
    )

    # Each new member starts with a self-contained authority closure in its
    # own signed writer tree.  Network sync below never reaches into another
    # peer's SQL database to make the fixture valid.
    authority = alice.sender(workspace).close(
        (bob_join, carol_join), {})
    bob = FullPeer(str(tmp_path / "bob"), initial_secret=bob_secret)
    carol = FullPeer(str(tmp_path / "carol"), initial_secret=carol_secret)
    for peer, name in ((bob, "bob"), (carol, "carol")):
        peer.add_workspace(workspace, name, peers=[])
        peer.publish_closed(workspace, (authority,))

    facts.content.message.post(
        alice, workspace, "general", "from alice", ts=30)
    facts.content.message.post(
        bob, workspace, "general", "from bob", ts=31)
    return workspace, alice, bob, carol


def _messages(peer, workspace):
    return {
        row["text"]
        for row in facts.content.message.messages(peer, workspace)
    }


def _canonical_store(peer, workspace):
    store = peer.store(workspace)
    return {
        key: store.get(key)
        for key in store.list("")
    }


def test_full_peer_http_exposes_writer_directory_and_exact_transfer(tmp_path):
    """The shared gate is an object protocol, not the retired root reader."""
    workspace, alice, bob, carol = _forest_fixture(tmp_path)

    # Give the serving peer two accepted writer slots so limit=1 exercises a
    # real continuation rather than merely checking a response shape.
    mirrored = _run(alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert mirrored.errors == ()
    expected_keys = tuple(alice.store(workspace).list(
        f"heads/{workspace}"))
    assert len(expected_keys) == 2

    with ExitStack() as stack:
        source_url, source_secret = stack.enter_context(_serve(alice))
        target_url, target_secret = stack.enter_context(_serve(carol))
        source_auth = _bearer(source_secret, carol.member, workspace)
        target_auth = _bearer(target_secret, alice.member, workspace)

        status, raw, _ = _http(
            source_url,
            "GET",
            "/heads?" + urlencode({"ws": workspace, "limit": 1}),
            headers=source_auth,
        )
        assert status == 200
        first = json.loads(raw)
        assert set(first) == {"cursor", "keys"}
        assert first["keys"] == [expected_keys[0]]
        assert isinstance(first["cursor"], str) and first["cursor"]

        status, raw, _ = _http(
            source_url,
            "GET",
            "/heads?" + urlencode({
                "ws": workspace,
                "cursor": first["cursor"],
                "limit": 1,
            }),
            headers=source_auth,
        )
        assert status == 200
        assert json.loads(raw) == {
            "cursor": None,
            "keys": [expected_keys[1]],
        }

        selected_key = head_slot_key(workspace, alice.identity_id(workspace))
        selected_slot = alice.store(workspace).get(selected_key)
        status, raw, headers = _http(
            source_url,
            "GET",
            f"/head/{alice.identity_id(workspace)}?ws={workspace}",
            headers=source_auth,
        )
        assert (status, raw) == (200, selected_slot)
        etag = next(
            value for name, value in headers.items()
            if name.lower() == "etag"
        )
        status, raw, _ = _http(
            source_url,
            "GET",
            f"/head/{alice.identity_id(workspace)}?ws={workspace}",
            headers={**source_auth, "If-None-Match": etag},
        )
        assert (status, raw) == (304, b"")

        head_oid = decode_slot_at(selected_key, selected_slot).head
        head_bytes = alice.store(workspace).get("obj/" + head_oid)
        status, raw, _ = _http(
            source_url,
            "GET",
            f"/obj/{head_oid}?ws={workspace}",
            headers=source_auth,
        )
        assert (status, raw) == (200, head_bytes)
        status, raw, _ = _http(
            source_url,
            "POST",
            f"/obj?ws={workspace}",
            body=json.dumps([head_oid]).encode(),
            headers=source_auth,
        )
        assert status == 200
        assert json.loads(raw) == [base64.b64encode(head_bytes).decode()]

        # Immutable bytes may arrive in any order, but the writer slot is the
        # final operation.  PUT /mirror asks the receiving RepositoryMirror
        # to validate the complete local candidate before publishing the slot
        # or committing the SQL projection checkpoint.
        for key in alice.store(workspace).list("obj"):
            oid = key.removeprefix("obj/")
            status, _, _ = _http(
                target_url,
                "PUT",
                f"/obj/{oid}?ws={workspace}",
                body=alice.store(workspace).get(key),
                headers=target_auth,
            )
            assert status in {201, 204}
        status, _, _ = _http(
            target_url,
            "PUT",
            f"/mirror/{alice.identity_id(workspace)}?ws={workspace}",
            body=selected_slot,
            headers=target_auth,
        )
        assert status == 201
        status, _, _ = _http(
            target_url,
            "PUT",
            f"/mirror/{alice.identity_id(workspace)}?ws={workspace}",
            body=selected_slot,
            headers=target_auth,
        )
        assert status == 204

    assert carol.store(workspace).get(selected_key) == selected_slot
    assert carol.sql(workspace).projected_head(
        alice.identity_id(workspace)) == head_oid
    assert "from alice" in _messages(carol, workspace)


def test_full_peer_sync_relays_both_ways_is_noop_and_rebuilds_sql(tmp_path):
    """Normal peer sync uses the writer forest over real stdlib sockets."""
    workspace, alice, bob, carol = _forest_fixture(tmp_path)

    with ExitStack() as stack:
        alice_url, _ = stack.enter_context(_serve(alice))
        bob_url, _ = stack.enter_context(_serve(bob))
        carol_url, _ = stack.enter_context(_serve(carol))

        # One directed dial is a two-way forest reconciliation.  Each side
        # consumes the other's signed original tree before advertising it.
        sync(bob, workspace, alice_url)
        assert _messages(alice, workspace) == \
            _messages(bob, workspace) == {"from alice", "from bob"}
        for receiver, writer in ((alice, bob), (bob, alice)):
            key = head_slot_key(workspace, writer.identity_id(workspace))
            slot = decode_slot_at(key, receiver.store(workspace).get(key))
            assert receiver.sql(workspace).projected_head(
                writer.identity_id(workspace)) == slot.head

        # Carol has no Alice connection.  Bob therefore proves that a full
        # peer relays consumed original writer heads/trees/piles, not a new
        # Bob-authored aggregate or a database-derived closure.
        sync(carol, workspace, bob_url)
        assert _messages(carol, workspace) == {"from alice", "from bob"}
        facts.content.message.post(
            carol, workspace, "general", "from carol", ts=40)
        sync(carol, workspace, bob_url)
        sync(alice, workspace, bob_url)
        expected_messages = {"from alice", "from bob", "from carol"}
        assert _messages(alice, workspace) == \
            _messages(bob, workspace) == \
            _messages(carol, workspace) == expected_messages

        # A duplicate turn is a protocol no-op on both canonical stores.  SQL
        # query reads are deliberately excluded from this equality.
        before = (
            _canonical_store(alice, workspace),
            _canonical_store(bob, workspace),
        )
        sync(alice, workspace, bob_url)
        assert (
            _canonical_store(alice, workspace),
            _canonical_store(bob, workspace),
        ) == before

    expected_facts = carol.sql(workspace).fact_ids()
    carol.sql(workspace).db.close()
    Path(carol.dir, "ws", workspace + ".idx.db").unlink()
    reopened = FullPeer(carol.dir)
    assert reopened.sql(workspace).fact_ids() == expected_facts
    assert _messages(reopened, workspace) == expected_messages
