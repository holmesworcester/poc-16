"""Real-socket contract for the FullPeer per-writer forest.

This intentionally names only the running writer protocol.  The predecessor
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
import urllib.error
from urllib.parse import urlencode, urlsplit

import facts
import pytest

from bench.writer_p2p_cost import measure_two_party_sync
from core import peer_capability
from core.access import AccessGate, ControlHeadRetry
from core.close import decode_signed_pile
from core.crypto import h, keypair
from core.fact import canon
from core.grants import make_token
from core.limits import MAX_FACT_BYTES, MAX_OBJECT_BYTES
from core.object_store import ABSENT, CREATED, Versioned
from core.store import FsStore, RemoteStore
from core.writer_head import decode_head, decode_slot_at, head_slot_key
from core.writer_repository import (
    HeadGrant,
    OpaqueHeadGate,
    RepositoryMirror,
    open_accepted_pile,
)
from full_peer.node import FullPeer
from full_peer.pack_http import handler_for
from full_peer import sync as sync_module
from full_peer.sync import sync
from full_peer.walk import Peer
from tests.util import add_member


_HOSTED_PERMIT_SECRET = b"hosted owner permit contract secret" * 2


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
    # Independent semantic sinks stay in independent closed piles. Each new
    # writer bootstraps from the pile whose sink is its own membership fact.
    authority = {
        "bob": alice.sender(workspace).close((bob_join,), {}),
        "carol": alice.sender(workspace).close((carol_join,), {}),
    }
    bob = FullPeer(str(tmp_path / "bob"), initial_secret=bob_secret)
    carol = FullPeer(str(tmp_path / "carol"), initial_secret=carol_secret)
    for peer, name in ((bob, "bob"), (carol, "carol")):
        peer.add_workspace(workspace, name, peers=[])
        peer.publish_closed(workspace, (authority[name],))

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

    def __init__(self, node, workspace, url, store, access, events):
        self.node = node
        self.ws = workspace
        self.store = store
        self.access = access
        self.events = events
        self._opened = None
        self._observed = {}
        self._complete = False
        self._permit_controls = {}

    @property
    def accepts_push(self):
        return False

    @property
    def accepts_owner_publish(self):
        return True

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

    def judgment_tip(self):
        return _run(self.access.state.pin()).root_oid

    async def advance_head(self, proof, proposed):
        self.events.append((
            "head", self.node.identity_id(self.ws), proposed))
        result = await OpaqueHeadGate(
            self.store, self.access.authorize_head).advance(
                proof, proposed, int(time.time() * 1000))
        return result.status

    async def issue_head_permit(self, proof, proposed, control_piles):
        permit = await self.access.issue_head_permit(
            proof,
            proposed,
            control_piles,
            int(time.time() * 1000),
            _HOSTED_PERMIT_SECRET,
        )
        self.events.append((
            "permit", self.node.identity_id(self.ws), proposed))
        self._permit_controls[permit] = tuple(control_piles)
        return permit

    async def commit_head_permit(self, permit, proposed):
        writer = self.node.identity_id(self.ws)
        result = await self.access.commit_head_permit(
            OpaqueHeadGate(self.store, self.access.authorize_head),
            permit,
            proposed,
            _HOSTED_PERMIT_SECRET,
        )
        if result.status in {"applied", "noop"}:
            self.events.extend(
                ("control", writer, h(raw), result.status)
                for raw in self._permit_controls.get(permit, ()))
            self.events.append(("head", writer, proposed))
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


def test_two_party_sync_performance_includes_messaging_and_catchup(tmp_path):
    """Measure one real bidirectional sync, excluding only fixture/counting."""
    workspace, alice, bob, _carol = _forest_fixture(tmp_path)
    for ordinal in range(20):
        facts.content.message.post(
            alice,
            workspace,
            "general",
            f"alice performance {ordinal}",
            ts=100 + ordinal,
        )
        facts.content.message.post(
            bob,
            workspace,
            "general",
            f"bob performance {ordinal}",
            ts=1_000 + ordinal,
        )

    alice_before = set(alice.sql(workspace).fact_ids())
    bob_before = set(bob.sql(workspace).fact_ids())
    with _serve(bob) as (bob_url, _secret):
        result = measure_two_party_sync(
            alice, bob, workspace, bob_url)

    expected = alice_before | bob_before
    assert set(alice.sql(workspace).fact_ids()) == expected
    assert set(bob.sql(workspace).fact_ids()) == expected
    assert result.local_facts == len(bob_before - alice_before)
    assert result.remote_facts == len(alice_before - bob_before)
    assert result.facts == result.local_facts + result.remote_facts
    assert result.pulled_piles > 0
    assert result.pushed_piles > 0
    assert result.elapsed_seconds > 0
    assert result.facts_per_second > 0
    assert result.pull_changed == 1
    expected_messages = {
        "from alice",
        "from bob",
        *(f"alice performance {ordinal}" for ordinal in range(20)),
        *(f"bob performance {ordinal}" for ordinal in range(20)),
    }
    assert _messages(alice, workspace) == expected_messages
    assert _messages(bob, workspace) == expected_messages
    print(
        "two-party sync: "
        f"{result.facts} facts in {result.elapsed_seconds:.6f}s "
        f"({result.facts_per_second:.1f} facts/s; "
        f"local +{result.local_facts}, remote +{result.remote_facts}, "
        f"pulled={result.pulled_piles}, pushed={result.pushed_piles} piles, "
        f"pull_changed={result.pull_changed})"
    )


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
        remote._sync_profile = "sync-v1/full"
        remote._token = make_token(
            secret,
            carol.member,
            workspace,
            issued_at=int(time.time() * 1000),
            ttl_ms=60_000,
        )
        result = _run(carol.mirror(workspace).sync_from(
            RemoteStore(remote)))

    assert result.listed == 2
    assert result.changed == 1
    assert result.piles == 2
    assert result.errors == ((bad_key, "listed writer slot unreadable"),)
    good_key = head_slot_key(workspace, bob.identity_id(workspace))
    # The signed writer head is portable; recipient-owned removal/permit
    # metadata in its directory slot is intentionally not byte-identical.
    assert decode_slot_at(
        good_key, carol.store(workspace).get(good_key)).head \
        == decode_slot_at(
            good_key, alice.store(workspace).get(good_key)).head


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
        peer._sync_profile = "sync-v1/full"
        peer._token = make_token(
            secret,
            carol.member,
            workspace,
            issued_at=int(time.time() * 1000),
            ttl_ms=60_000,
        )
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
    assert not [request for request in requests if request[1] == "/authority"]
    assert not hasattr(bob, "sync_cache")


def test_hosted_owner_http_uses_exact_permit_only_for_control_head(
        tmp_path, monkeypatch):
    workspace, alice, _bob, carol = _forest_fixture(tmp_path)
    requests = []
    access = carol.access_gate(workspace)
    original_commit = access.commit_head_permit
    commit_attempts = 0

    async def retry_first_commit(head_gate, permit, proposed, secret):
        nonlocal commit_attempts
        commit_attempts += 1
        result = await original_commit(
            head_gate, permit, proposed, secret)
        if commit_attempts == 1:
            # The removal turn completed, but its typed response says the
            # exact outcome still needs reconciliation.
            raise ControlHeadRetry("injected post-removal contention")
        return result

    monkeypatch.setattr(
        access, "commit_head_permit", retry_first_commit)

    class CountingPeer(Peer):
        def _http(self, method, path, *args, **kwargs):
            requests.append((method, path))
            return super()._http(method, path, *args, **kwargs)

    monkeypatch.setattr(sync_module, "Peer", CountingPeer)
    with _serve(
            carol, sync_profile=peer_capability.OWNER) as (url, _secret):
        sync_module.sync(alice, workspace, url)
        proposed = decode_slot_at(
            head_slot_key(workspace, alice.identity_id(workspace)),
            alice.store(workspace).get(head_slot_key(
                workspace, alice.identity_id(workspace))),
        ).head
        assert ("POST", f"/head/{proposed}/permit") in requests
        assert ("POST", f"/head/{proposed}/commit") in requests
        assert requests.count(
            ("POST", f"/head/{proposed}/permit")) == 1
        assert requests.count(
            ("POST", f"/head/{proposed}/commit")) == 2
        assert commit_attempts == 2
        assert not [path for _method, path in requests
                    if path == "/removal/apply"]

        requests.clear()
        facts.content.message.post(
            alice, workspace, "general", "hosted over HTTP", ts=50)
        sync_module.sync(alice, workspace, url)

    assert not [path for _method, path in requests
                if path.endswith(("/permit", "/commit"))]
    assert any(method == "POST" and path.startswith("/head/")
               for method, path in requests)


def test_hosted_owner_same_base_loser_gets_412_and_stops_for_rebase(
        tmp_path, monkeypatch):
    workspace, alice, _bob, carol = _forest_fixture(tmp_path)
    device = alice.identity_id(workspace)
    proposed = decode_slot_at(
        head_slot_key(workspace, device),
        alice.store(workspace).get(head_slot_key(workspace, device)),
    ).head
    original = carol.head_gate(workspace)
    winner_raw = b"hosted same-base winning head"
    winner = h(winner_raw)
    requests = []
    outcomes = []
    winner_installed = False

    class CompetingGate:
        async def advance(self, proof, candidate, trusted_now):
            return await original.advance(proof, candidate, trusted_now)

        async def control_replay(self, grant, permit_oid):
            return await original.control_replay(grant, permit_oid)

        async def advance_control(self, grant, permit_oid, removal_root):
            nonlocal winner_installed
            if not winner_installed:
                winner_installed = True
                carol.store(workspace).put_if_absent(
                    "obj/" + winner, winner_raw)
                competing = await original.advance_grant(HeadGrant(
                    workspace,
                    grant.device,
                    grant.base_head,
                    winner,
                    grant.removal_root,
                ))
                assert competing.status == "applied"
            return await original.advance_control(
                grant, permit_oid, removal_root)

    monkeypatch.setattr(
        carol, "head_gate", lambda candidate: CompetingGate())

    class CountingPeer(Peer):
        def _http(self, method, path, *args, **kwargs):
            requests.append((method, path))
            return super()._http(method, path, *args, **kwargs)

        def commit_head_permit(self, *args, **kwargs):
            outcome = super().commit_head_permit(*args, **kwargs)
            outcomes.append(outcome)
            return outcome

    monkeypatch.setattr(sync_module, "Peer", CountingPeer)

    async def conflict_must_not_pause(_attempt):
        raise AssertionError("terminal HTTP 412 was retried")

    monkeypatch.setattr(
        sync_module, "_control_head_retry_pause", conflict_must_not_pause)
    with _serve(
            carol, sync_profile=peer_capability.OWNER) as (url, _secret):
        with pytest.raises(ValueError, match="requires rebase"):
            sync_module.sync(alice, workspace, url)

    assert winner_installed
    assert outcomes == ["conflict"]
    assert requests.count(("POST", f"/head/{proposed}/permit")) == 1
    assert requests.count(("POST", f"/head/{proposed}/commit")) == 1
    accepted = decode_slot_at(
        head_slot_key(workspace, device),
        carol.store(workspace).get(head_slot_key(workspace, device)),
    )
    assert accepted.head == winner


def test_peer_control_commit_replays_503_and_dropped_response_but_not_4xx():
    peer = Peer(object(), h(b"workspace"), "http://peer.invalid")
    proposed = h(b"proposed head")
    permit = b"exact permit"
    bodies = []

    def unavailable_then_applied(
            method, path, data=None, *_args, **_kwargs):
        assert (method, path) == (
            "POST", f"/head/{proposed}/commit")
        bodies.append(data)
        if len(bodies) == 1:
            raise urllib.error.HTTPError(
                "http://peer.invalid", 503, "outcome unknown", {}, None)
        return 201, b"", {}

    peer._http = unavailable_then_applied
    assert peer.commit_head_permit(permit, proposed) == "retryable"
    assert peer.commit_head_permit(permit, proposed) == "applied"
    assert len(bodies) == 2 and bodies[0] == bodies[1]

    bodies.clear()

    def dropped_then_applied(
            method, path, data=None, *_args, **_kwargs):
        assert (method, path) == (
            "POST", f"/head/{proposed}/commit")
        bodies.append(data)
        if len(bodies) == 1:
            raise http.client.RemoteDisconnected(
                "response lost after request")
        return 201, b"", {}

    peer._http = dropped_then_applied
    assert peer.commit_head_permit(permit, proposed) == "retryable"
    assert peer.commit_head_permit(permit, proposed) == "applied"
    assert len(bodies) == 2 and bodies[0] == bodies[1]

    def competing_head(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://peer.invalid", 412, "rebase required", {}, None)

    peer._http = competing_head
    assert peer.commit_head_permit(permit, proposed) == "conflict"
    assert peer.advance_head(b"ordinary proof", proposed) == "conflict"

    def ordinary_contention(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://peer.invalid", 409, "retry", {}, None)

    peer._http = ordinary_contention
    assert peer.advance_head(b"ordinary proof", proposed) == "retryable"

    def permanent_denial(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "http://peer.invalid", 403, "denied", {}, None)

    peer._http = permanent_denial
    with pytest.raises(urllib.error.HTTPError) as denied:
        peer.commit_head_permit(permit, proposed)
    assert denied.value.code == 403


def test_each_sync_turn_mints_fresh_and_never_publishes_authority(
        tmp_path, monkeypatch):
    workspace, alice, bob, _carol = _forest_fixture(tmp_path)
    requests = []

    class CountingPeer(Peer):
        def _http(self, method, path, *args, **kwargs):
            requests.append((method, path))
            return super()._http(method, path, *args, **kwargs)

    monkeypatch.setattr(sync_module, "Peer", CountingPeer)
    with _serve(alice) as (url, _secret):
        sync_module.sync(bob, workspace, url)
        sync_module.sync(bob, workspace, url)

    assert requests.count(("POST", "/mint")) == 2
    assert requests.count(("POST", "/removal/path")) == 0
    assert not [request for request in requests if request[1] == "/authority"]


def test_missing_remote_state_retries_once_with_positive_admission_chain(
        tmp_path):
    workspace, _alice, bob, _carol = _forest_fixture(tmp_path)
    calls = []

    def reject(method, path, data=None, *_args, **_kwargs):
        calls.append((method, path, data))
        raise urllib.error.HTTPError(
            "http://lost/mint", 403, "unknown member", {}, None)

    peer = Peer(bob, workspace, "http://lost")
    peer._http = reject
    with pytest.raises(urllib.error.HTTPError) as denied:
        peer.mint()

    assert denied.value.code == 403
    assert [(method, path) for method, path, _body in calls] == [
        ("POST", "/mint"),
        ("POST", "/mint"),
    ]
    first = decode_signed_pile(base64.b64decode(
        json.loads(calls[0][2])["pile"], validate=True))
    second = decode_signed_pile(base64.b64decode(
        json.loads(calls[1][2])["pile"], validate=True))
    assert [fact.t for fact in first.facts] == ["req"]
    assert [fact.t for fact in second.facts][-2:] == ["signature", "req"]
    assert len(second.facts) > len(first.facts)
    assert peer._token is peer._sync_profile is None
    assert not hasattr(peer, "authority_recover")
    assert not hasattr(peer, "publish_authority")


def test_local_publish_applies_exact_control_before_head_and_skips_content(
        tmp_path, monkeypatch):
    workspace, alice, _bob, carol = _forest_fixture(tmp_path)
    access = alice.access_gate(workspace)
    original_issue = access.issue_head_permit
    original_head_gate = alice.head_gate(workspace)
    original_apply = access.state.apply_updates
    events = []

    async def issue_permit(
            proof, proposed, controls, trusted_now, secret):
        permit = await original_issue(
            proof, proposed, controls, trusted_now, secret)
        events.append(("permit", alice.identity_id(workspace), proposed))
        return permit

    async def apply_updates(updates):
        events.append((
            "control", alice.identity_id(workspace), tuple(updates)))
        return await original_apply(updates)

    class RecordingHeadGate:
        async def advance(self, proof, proposed, trusted_now):
            events.append(("head", alice.identity_id(workspace), proposed))
            return await original_head_gate.advance(
                proof, proposed, trusted_now)

        async def control_replay(self, grant, permit_oid):
            return await original_head_gate.control_replay(
                grant, permit_oid)

        async def advance_control(self, grant, permit_oid, removal_root):
            proposed = grant.head
            events.append(("head", alice.identity_id(workspace), proposed))
            return await original_head_gate.advance_control(
                grant, permit_oid, removal_root)

    monkeypatch.setattr(access, "issue_head_permit", issue_permit)
    monkeypatch.setattr(access.state, "apply_updates", apply_updates)
    monkeypatch.setattr(
        alice, "head_gate", lambda candidate: RecordingHeadGate())

    facts.auth.removal.evict(alice, workspace, carol.member)
    assert [event[0] for event in events] == [
        "permit", "control", "head"]

    device = alice.identity_id(workspace)
    key = head_slot_key(workspace, device)
    slot = decode_slot_at(key, alice.store(workspace).get(key))
    head = decode_head(alice.store(workspace).get("obj/" + slot.head))
    exact = _run(open_accepted_pile(
        alice.store(workspace), workspace, device, head.sequence))
    evaluated = access.state.plan_control((exact,), device)
    assert events[1][1:] == (device, evaluated.updates)

    events.clear()
    facts.content.message.post(
        alice, workspace, "general", "local ordinary", ts=50)
    assert [event[0] for event in events] == ["head"]


def test_hosted_mode_pulls_all_writers_but_publishes_only_the_dialer(
        tmp_path, monkeypatch):
    workspace, alice, bob, carol = _forest_fixture(tmp_path)
    # Alice has consumed Bob and may gossip him to a full peer.  A hosted
    # owner publication must nevertheless leave Bob's independently mutable
    # slot alone.
    mirrored = _run(alice.mirror(workspace).sync_from(bob.store(workspace)))
    assert mirrored.errors == ()

    cloud = FsStore(str(tmp_path / "hosted-cloud"))
    access = AccessGate(workspace, cloud)
    events = []
    # Hosted enrollment consumes original signed clear-only control piles,
    # never an aggregate authority snapshot or SQL-derived reclosure.
    for source in (alice, bob):
        original = _run(open_accepted_pile(
            source.store(workspace),
            workspace,
            source.identity_id(workspace),
            1,
        ))
        assert _run(access.state.bootstrap(original)).status in {
            "applied", "noop"}
    url = "memory://hosted-owner-cloud"

    def endpoint(node, candidate_workspace, candidate_url):
        assert candidate_workspace == workspace and candidate_url == url
        return _HostedEndpoint(
            node, workspace, url, cloud, access, events)

    monkeypatch.setattr(sync_module, "Peer", endpoint)

    assert not hasattr(alice, "authority")

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

    # Every recipient-state join is an exact original control pile and occurs
    # before the corresponding writer head becomes visible.
    for source in (alice, bob, carol):
        device = source.identity_id(workspace)
        first_head = next(
            index for index, event in enumerate(events)
            if event[0] == "head" and event[1] == device)
        assert any(
            event[0] == "control" and event[1] == device
            and event[3] in {"applied", "noop"}
            for event in events[:first_head]
        )

    # An ordinary suffix still advances its signed writer head, but is never
    # offered to the recipient's private removal-state join.
    control_before = [event for event in events if event[0] == "control"]
    head_before = sum(event[0] == "head" for event in events)
    facts.content.message.post(
        alice, workspace, "general", "hosted ordinary", ts=50)
    assert sync_module.sync(alice, workspace, url)[1] == 1
    assert [event for event in events if event[0] == "control"] \
        == control_before
    assert sum(event[0] == "head" for event in events) == head_before + 1
