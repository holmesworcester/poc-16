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

from core import peer_capability
from core.authority import AuthorityRepository
from core.crypto import h, keypair
from core.fact import canon
from core.grants import make_token
from core.limits import MAX_FACT_BYTES, MAX_OBJECT_BYTES
from core.object_store import ABSENT, CREATED, Versioned
from core.store import FsStore, RemoteStore
from core.writer_head import decode_slot_at, head_slot_key
from core.writer_repository import OpaqueHeadGate, RepositoryMirror
from full_peer.node import FullPeer
from full_peer.pack_http import handler_for
from full_peer import sync as sync_module
from full_peer.sync import sync
from full_peer.walk import Peer
from tests.util import add_member


def _run(awaitable):
    return asyncio.run(awaitable)


@contextmanager
def _serve(
        peer,
        secret=b"writer-http-contract-secret-0001",
        sync_profile=peer_capability.FULL):
    """Serve the production stdlib adapter on an OS-assigned loopback port."""
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler_for(
            peer, secret, sync_profile=sync_profile))
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


class _HostedEndpoint:
    """In-process hosted peer implementing the exact RemoteStore surface."""

    def __init__(self, node, workspace, url, store, authority):
        self.node = node
        self.ws = workspace
        self.cache = node.sync_state(workspace, url)
        self.cache["sync_profile"] = peer_capability.OWNER
        self.store = store
        self.authority = authority
        self._opened = None
        self._observed = {}
        self._complete = False

    @property
    def accepts_push(self):
        return False

    @property
    def accepts_owner_publish(self):
        return True

    def publish_authority(self, raw):
        result = _run(self.authority.publish(raw))
        if result.status not in {"applied", "noop"}:
            raise ValueError("hosted authority publication")
        return 201 if result.status == "applied" else 204

    def heads(self, cursor=None, limit=256):
        page = self.store.list_page(
            f"heads/{self.ws}/", cursor, limit)
        opened = tuple(
            self.store.read_versioned(key) for key in page.keys)
        self._opened = page.keys, opened
        self._observed.update(zip(page.keys, opened))
        if page.cursor is None:
            self._complete = True
        return page

    def opened_heads(self, keys):
        if self._opened is None or self._opened[0] != tuple(keys):
            raise ValueError("hosted head page")
        return self._opened[1]

    def observed_head(self, key):
        if key in self._observed:
            return True, self._observed[key]
        return self._complete, ABSENT

    def head(self, device, etag=None):
        opened = self.store.read_versioned(head_slot_key(self.ws, device))
        if opened is ABSENT:
            return None
        assert isinstance(opened, Versioned)
        if etag is not None and opened.token.value == etag:
            return None
        return opened.value, opened.token

    def obj(self, oid, *, response_limit):
        return self.store.get_bounded("obj/" + oid, response_limit)

    def objs(self, oids):
        return tuple(self.obj(
            oid, response_limit=MAX_OBJECT_BYTES) for oid in oids)

    def copy_obj(self, oid, *, response_limit, write):
        return self.store.copy_pile_object(oid, response_limit, write)

    def put_obj(self, oid, raw):
        if h(raw) != oid:
            raise ValueError("hosted immutable object")
        result = self.store.put_if_absent("obj/" + oid, raw)
        if result is CREATED:
            return 201
        if self.store.get_bounded("obj/" + oid, len(raw)) != raw:
            raise ValueError("hosted immutable collision")
        return 204

    def layout(self, _key, *, response_limit):
        return None

    async def advance_head(self, proof, proposed):
        async def authorize(raw, head):
            return await self.authority.authorize_head(
                raw, head, int(time.time() * 1000))

        result = await OpaqueHeadGate(
            self.store, authorize).advance(proof, proposed)
        return result.status


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
        target_client = Peer(alice, workspace, target_url)

        status, raw, _ = _http(
            source_url,
            "GET",
            "/heads?" + urlencode({"ws": workspace, "limit": 1}),
            headers=source_auth,
        )
        assert status == 200
        first = json.loads(raw)
        assert set(first) == {"cursor", "heads"}
        assert [entry[0] for entry in first["heads"]] == [expected_keys[0]]
        bundled = base64.b64decode(first["heads"][0][1], validate=True)
        assert bundled == alice.store(workspace).get(expected_keys[0])
        assert first["heads"][0][2] == h(bundled)
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
        second = json.loads(raw)
        assert second["cursor"] is None
        assert [entry[0] for entry in second["heads"]] == [expected_keys[1]]

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
            status = target_client.put_obj(
                oid, alice.store(workspace).get(key))
            assert status in {201, 204}
        status, _, _ = _http(
            target_url,
            "PUT",
            f"/obj/{h(b'old buffered route')}?ws={workspace}",
            body=b"old buffered route",
            headers=target_auth,
        )
        assert status == 404
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

        # A stale reverse-sync cache may later offer an older complete slot.
        # The receiver must distinguish that from an exact duplicate instead
        # of acknowledging bytes it did not leave installed.
        facts.content.message.post(
            alice, workspace, "general", "newer alice", ts=41)
        newer_slot = alice.store(workspace).get(selected_key)
        assert newer_slot != selected_slot
        for key in alice.store(workspace).list("obj"):
            oid = key.removeprefix("obj/")
            status = target_client.put_obj(
                oid, alice.store(workspace).get(key))
            assert status in {201, 204}
        status, _, _ = _http(
            target_url,
            "PUT",
            f"/mirror/{alice.identity_id(workspace)}?ws={workspace}",
            body=newer_slot,
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
        assert status == 409

    assert carol.store(workspace).get(selected_key) == newer_slot
    assert carol.sql(workspace).projected_head(
        alice.identity_id(workspace)) == decode_slot_at(
            selected_key, newer_slot).head
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


def test_reverse_sync_direct_puts_a_valid_over_buffer_pile(tmp_path):
    """The reverse half uses ObjectOpen PUT, never the removed small route."""
    workspace, alice, _bob, carol = _forest_fixture(tmp_path)
    probe = facts.content.message.message(
        workspace,
        alice.identity_id(workspace),
        "general",
        "",
        50,
    )
    padding = MAX_FACT_BYTES - len(canon(probe.to_json()))
    facts.content.message.post(
        alice, workspace, "general", "x" * padding, ts=50)
    large = [
        (key, alice.store(workspace).get(key))
        for key in alice.store(workspace).list("obj")
        if len(alice.store(workspace).get(key)) > MAX_OBJECT_BYTES
    ]
    assert len(large) == 1

    with _serve(carol) as (carol_url, _secret):
        # Alice is the dialer, so its local writer is transferred in the
        # reverse half after the ordinary remote-head scan.
        sync(alice, workspace, carol_url)

    key, raw = large[0]
    assert carol.store(workspace).get(key) == raw
    assert any(
        len(row["text"]) == padding
        for row in facts.content.message.messages(carol, workspace)
    )


def test_bundled_head_page_isolates_one_oversized_slot(tmp_path):
    """One corrupt top cannot turn bounded discovery into a page-wide wedge."""
    workspace, alice, bob, carol = _forest_fixture(tmp_path)
    _run(alice.mirror(workspace).sync_from(bob.store(workspace)))
    bad_key = head_slot_key(workspace, alice.identity_id(workspace))
    alice.store(workspace)._replace(bad_key, b"x" * 1_025)

    with _serve(alice) as (url, secret):
        remote = Peer(carol, workspace, url)
        remote.cache.update({
            "sync_profile": "sync-v1/full",
            "token": make_token(
                secret,
                carol.member,
                workspace,
                issued_at=int(time.time() * 1000),
                ttl_ms=60_000,
            ),
        })
        result = _run(carol.mirror(workspace).sync_from(
            RemoteStore(remote)))

    assert result.listed == 2
    assert result.changed == 1
    assert result.piles == 2
    assert result.errors == ((bad_key, "listed writer slot disappeared"),)
    good_key = head_slot_key(workspace, bob.identity_id(workspace))
    assert carol.store(workspace).get(good_key) \
        == alice.store(workspace).get(good_key)


def test_reverse_noop_reuses_the_directory_tops_from_the_pull(tmp_path):
    """Two-way sync does not probe every unchanged remote head twice."""
    workspace, alice, bob, carol = _forest_fixture(tmp_path)
    _run(alice.mirror(workspace).sync_from(bob.store(workspace)))

    with _serve(alice) as (url, secret):
        # First establish Carol's original writer tree at the remote peer.
        sync(carol, workspace, url)

        class CountingPeer(Peer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.requests = 0

            def _http(self, *args, **kwargs):
                self.requests += 1
                return super()._http(*args, **kwargs)

        peer = CountingPeer(carol, workspace, url)
        peer.cache.update({
            "sync_profile": "sync-v1/full",
            "token": make_token(
                secret,
                carol.member,
                workspace,
                issued_at=int(time.time() * 1000),
                ttl_ms=60_000,
            ),
        })
        remote = RemoteStore(peer)
        pulled = _run(carol.mirror(workspace).sync_from(remote))
        assert pulled.errors == ()
        assert peer.requests > 0

        peer.requests = 0
        pushed = _run(RepositoryMirror(
            workspace,
            remote,
            carol.writer_binding,
            None,
        ).sync_from(carol.store(workspace)))

    assert pushed.errors == ()
    assert pushed.changed == pushed.piles == pushed.facts == 0
    assert peer.requests == 0


def test_read_only_peer_pulls_writer_forest_without_any_reverse_put(
        tmp_path, monkeypatch):
    workspace, alice, bob, _carol = _forest_fixture(tmp_path)
    requests = []

    class CountingPeer(Peer):
        def _http(self, method, path, *args, **kwargs):
            requests.append((method, path))
            return super()._http(method, path, *args, **kwargs)

    monkeypatch.setattr(sync_module, "Peer", CountingPeer)
    with _serve(alice, sync_profile=peer_capability.READ_ONLY) as (url, _):
        pulled, pushed = sync_module.sync(bob, workspace, url)

    assert pulled == 1
    assert pushed == 0
    assert "from alice" in _messages(bob, workspace)
    assert "from bob" not in _messages(alice, workspace)
    assert requests
    assert not [request for request in requests if request[0] == "PUT"]
    assert bob.sync_state(workspace, url)["sync_profile"] \
        == peer_capability.READ_ONLY


def test_hosted_mode_pulls_all_writers_but_publishes_only_the_dialer(
        tmp_path, monkeypatch):
    workspace, alice, bob, carol = _forest_fixture(tmp_path)
    # Alice has consumed Bob and may gossip him to a full peer.  A hosted
    # owner publication must nevertheless leave Bob's independently mutable
    # slot alone.
    mirrored = _run(alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert mirrored.errors == ()

    cloud = FsStore(str(tmp_path / "hosted-cloud"))
    authority = AuthorityRepository(workspace, cloud)
    url = "memory://hosted-owner-cloud"

    def endpoint(node, candidate_workspace, candidate_url):
        assert candidate_workspace == workspace and candidate_url == url
        return _HostedEndpoint(
            node, workspace, url, cloud, authority)

    monkeypatch.setattr(sync_module, "Peer", endpoint)

    assert sync_module.sync(alice, workspace, url)[1] >= 1
    assert cloud.list(f"heads/{workspace}") == [
        head_slot_key(workspace, alice.identity_id(workspace))]

    assert sync_module.sync(bob, workspace, url)[1] >= 1
    assert set(cloud.list(f"heads/{workspace}")) == {
        head_slot_key(workspace, alice.identity_id(workspace)),
        head_slot_key(workspace, bob.identity_id(workspace)),
    }

    pulled, _published = sync_module.sync(carol, workspace, url)
    assert pulled == 1
    assert {"from alice", "from bob"} <= _messages(carol, workspace)
    # Carol advertises only her own accepted writer log after that pull.
    assert set(cloud.list(f"heads/{workspace}")) == {
        head_slot_key(workspace, peer.identity_id(workspace))
        for peer in (alice, bob, carol)
    }
