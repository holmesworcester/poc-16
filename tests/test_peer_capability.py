"""Real HTTP coverage for full, legacy, and read-only sync peers."""
import base64
import hashlib
import hmac
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

import pytest

import facts

from core import http, http_stdlib, peer_capability
from core import close as close_module
from full_peer import sync as sync_module
from core.close import decode_pile
from core.crypto import h
from core.grants import check_token, make_token
from core.ingress import ingress_key
from core.limits import MAX_PAGE_BATCH_BYTES, MAX_ROOT_BYTES
from core.object_store import STALE
from full_peer import node as node_module
from full_peer.node import FullPeer, now_ms
from full_peer.sync import sync
from full_peer.walk import Peer, PushUnsupported

from .util import all_fids, closed_subset, deliver


def replicas(tmp_path):
    remote = FullPeer(str(tmp_path / "remote"))
    workspace = facts.auth.workspace.create(remote, "alice", ts=1)
    local = FullPeer(
        str(tmp_path / "local"),
        initial_secret=remote.identity(workspace)[0])
    local.add_workspace(workspace, "local", [])
    deliver(
        local, workspace,
        closed_subset(remote, workspace, all_fids(remote, workspace)))
    assert local.store(workspace).get("root") \
        == remote.store(workspace).get("root")
    return remote, workspace, local


def test_sender_batches_verified_closures_at_the_wire_limit(
        tmp_path, monkeypatch):
    source = FullPeer(str(tmp_path / "source"))
    workspace = facts.auth.workspace.create(source, "alice", ts=1)
    first = facts.content.message.post(
        source, workspace, "general", "first batch", ts=10)
    second = facts.content.message.post(
        source, workspace, "general", "second batch", ts=11)
    view = source.reader(workspace).validated()
    units = (
        view.closure((first,)),
        view.closure((second,)),
    )
    sender = source.sender(workspace)
    single_limit = max(len(sender.pack(unit)) for unit in units)
    assert len(sender.pack((*units[0], *units[1]))) > single_limit
    monkeypatch.setattr(close_module, "MAX_PILE_BYTES", single_limit)

    batches = sender.pack_batches(units)

    assert len(batches) == 2
    assert all(len(raw) <= single_limit for raw in batches)
    assert all(decode_pile(raw, workspace) for raw in batches)
    assert all(
        set(json.loads(raw)) == {"ws", "facts"}
        for raw in batches)
    destination = FullPeer(str(tmp_path / "destination"))
    destination.add_workspace(workspace, "alice", [])
    for raw in batches:
        destination.receive_pile(workspace, "a" * 64, raw)
    assert destination.store(workspace).get("root") \
        == source.store(workspace).get("root")


@contextmanager
def serving(node, profile, tamper_cap=None):
    observed = {"mints": 0, "puts": []}

    class Edge(http_stdlib.StdlibPeerHandler):
        def _send(self, response):
            if self.path.startswith("/mint"):
                observed["mints"] += 1
                if tamper_cap is not None and response.status == 200:
                    body = json.loads(response.body)
                    body["cap"] = tamper_cap
                    response = http.HttpGate._json(
                        response.status, body, response.headers)
            return super()._send(response)

        def do_PUT(self):
            observed["puts"].append(self.path)
            if self.sync_profile == peer_capability.READ_ONLY:
                return self._send(http.Response(405))
            return super().do_PUT()

    Edge.peer = node
    Edge.secret = b"p" * 32
    Edge.sync_profile = profile
    server = ThreadingHTTPServer(("127.0.0.1", 0), Edge)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", observed, Edge
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_full_peer_serves_one_fact_object_larger_than_encoded_batch(
        tmp_path):
    remote, workspace, local = replicas(tmp_path)
    # Base64 plus the JSON envelope crosses the batch response limit while
    # the raw repository object remains inside its single-object limit.
    raw = b"x" * (3 * MAX_PAGE_BATCH_BYTES // 4 + 1)
    oid = h(raw)
    remote.store(workspace).put_if_absent("obj/" + oid, raw)

    with serving(
            remote, peer_capability.FULL) as (url, _observed, _edge):
        # The batch gate remains provider-sized. Peer.objs receives its 413,
        # falls back to the single-object GET, and that host path must cover
        # every fact object RepositoryApplier can establish.
        assert Peer(local, workspace, url).objs((oid,)) == (raw,)


def test_http_receive_retains_retryable_exact_source_for_reupload(
        tmp_path, monkeypatch):
    remote, workspace, local = replicas(tmp_path)
    fid = facts.content.message.post(
        local, workspace, "general", "retry me", ts=10)
    raw = local.sender(workspace).pack(
        local.reader(workspace).validated().closure((fid,)))
    store = remote.store(workspace)
    commit = store.cas
    before_sources = set(store.list("ingress/"))
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return STALE
        return commit(*args, **kwargs)

    def wrong_full_peer_path(*_args, **_kwargs):
        raise AssertionError("HTTP bypassed RepositoryApplier")

    monkeypatch.setattr(store, "cas", fail_once)
    monkeypatch.setattr(remote, "receive_pile", wrong_full_peer_path)
    monkeypatch.setattr(remote, "turn", wrong_full_peer_path)

    with serving(
            remote, peer_capability.FULL) as (url, _observed, edge):
        member = local.member_for(workspace)
        token = make_token(
            edge.secret, member, workspace,
            capability=peer_capability.FULL)
        request = urllib.request.Request(
            f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
            data=raw, method="PUT",
            headers={"Authorization": "Bearer " + token},
        )

        with pytest.raises(urllib.error.HTTPError) as delayed:
            urllib.request.urlopen(request)
        assert delayed.value.code == 503
        assert len(
            set(store.list("ingress/")) - before_sources
        ) == 1
        assert remote.fact_of(workspace, fid) is None

        retry = urllib.request.Request(
            f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
            data=raw, method="PUT",
            headers={"Authorization": "Bearer " + token},
        )
        assert urllib.request.urlopen(retry).status == 204

    assert len(
        set(store.list("ingress/")) - before_sources
    ) == 1
    assert remote.fact_of(workspace, fid) is not None


def test_http_rejects_invalid_pile_but_retries_storage_failure(
        tmp_path, monkeypatch):
    remote, workspace, local = replicas(tmp_path)
    member = local.member_for(workspace)
    invalid = b"{}"

    with serving(
            remote, peer_capability.FULL) as (url, _observed, edge):
        token = make_token(
            edge.secret, member, workspace,
            capability=peer_capability.FULL)

        def put(raw):
            request = urllib.request.Request(
                f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
                data=raw,
                method="PUT",
                headers={"Authorization": "Bearer " + token},
            )
            with pytest.raises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(request)
            return denied.value.code

        assert put(invalid) == 400
        digest = h(invalid)
        source = ingress_key(
            workspace, digest[:32], member, digest)
        assert remote.store(workspace).get(source) == invalid

        with monkeypatch.context() as bounded:
            bounded.setattr(close_module, "MAX_PILE_JSON_VALUES", 4)
            amplified = (
                b'{"facts":[],"junk":[0,1,2,3],"ws":"'
                + workspace.encode() + b'"}'
            )
            assert put(amplified) == 400
            amplified_digest = h(amplified)
            amplified_source = ingress_key(
                workspace, amplified_digest[:32], member,
                amplified_digest)
            assert remote.store(workspace).get(amplified_source) is None

        monkeypatch.setattr(
            remote.store(workspace),
            "put_if_absent",
            lambda *_args: (_ for _ in ()).throw(
                OSError("object store unavailable")),
        )
        assert put(b'{"facts":[],"ws":"' + workspace.encode() + b'"}') \
            == 503


def test_http_returns_retryable_until_the_workspace_anchor_arrives(tmp_path):
    author = FullPeer(str(tmp_path / "author"))
    workspace = facts.auth.workspace.create(author, "alice", ts=1)
    recipient = FullPeer(
        str(tmp_path / "recipient"),
        initial_secret=author.identity(workspace)[0],
    )
    recipient.add_workspace(workspace, "recipient", [])
    secret, member = author.identity(workspace)
    target = facts.content.message.message(
        workspace, member, "general", "later", 10)
    signed = facts.auth.signature.signature(secret, member, target, 10)
    pending = author.sender(workspace).pack((signed,))
    anchor = closed_subset(author, workspace, (workspace,))

    with serving(
            recipient, peer_capability.FULL) as (url, _observed, edge):
        token = make_token(
            edge.secret, member, workspace,
            capability=peer_capability.FULL)

        def put(raw):
            request = urllib.request.Request(
                f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
                data=raw,
                method="PUT",
                headers={"Authorization": "Bearer " + token},
            )
            try:
                return urllib.request.urlopen(request).status
            except urllib.error.HTTPError as denied:
                return denied.code

        assert put(pending) == 503
        assert put(anchor) == 204
        assert put(pending) == 204
    assert recipient.fact_of(workspace, signed.fid) == signed


def test_full_peer_constructs_one_applier_during_cold_concurrent_lookup(
        tmp_path, monkeypatch):
    node = FullPeer(str(tmp_path / "node"))
    workspace = "0" * 64
    real = node_module.RepositoryApplier
    entered = threading.Event()
    release = threading.Event()
    duplicate = threading.Event()
    calls, receivers = 0, []
    calls_lock = threading.Lock()

    def construct(*args, **kwargs):
        nonlocal calls
        with calls_lock:
            calls += 1
            first = calls == 1
            if first:
                entered.set()
            else:
                duplicate.set()
        if first:
            assert release.wait(5)
        return real(*args, **kwargs)

    monkeypatch.setattr(node_module, "RepositoryApplier", construct)
    workers = [
        threading.Thread(
            target=lambda: receivers.append(node.applier(workspace)))
        for _ in range(2)
    ]
    workers[0].start()
    assert entered.wait(5)
    workers[1].start()
    try:
        assert not duplicate.wait(0.2)
    finally:
        release.set()
    for worker in workers:
        worker.join(5)
        assert not worker.is_alive()

    assert calls == 1
    assert len(receivers) == 2
    assert receivers[0] is receivers[1]


def test_concurrent_http_receives_converge_through_one_applier(
        tmp_path, monkeypatch):
    remote, workspace, local = replicas(tmp_path)
    fids = [
        facts.content.message.post(
            local, workspace, "general", body, ts=timestamp)
        for timestamp, body in ((10, "first"), (11, "second"))
    ]
    raws = [
        local.sender(workspace).pack(
            local.reader(workspace).validated().closure((fid,)))
        for fid in fids
    ]
    store = remote.store(workspace)
    commit = store.cas
    before_sources = set(store.list("ingress/"))
    committing = threading.Barrier(2)
    receiver_ids = []
    applier_for = remote.applier

    def race_commits(*args, **kwargs):
        committing.wait(timeout=5)
        return commit(*args, **kwargs)

    def observed_applier(ws):
        receiver = applier_for(ws)
        receiver_ids.append(id(receiver))
        return receiver

    def wrong_full_peer_path(*_args, **_kwargs):
        raise AssertionError("HTTP bypassed RepositoryApplier")

    monkeypatch.setattr(store, "cas", race_commits)
    monkeypatch.setattr(remote, "applier", observed_applier)
    monkeypatch.setattr(remote, "receive_pile", wrong_full_peer_path)
    monkeypatch.setattr(remote, "turn", wrong_full_peer_path)
    statuses, errors = [], []

    with serving(
            remote, peer_capability.FULL) as (url, _observed, edge):
        member = local.member_for(workspace)
        token = make_token(
            edge.secret, member, workspace,
            capability=peer_capability.FULL)

        def upload(raw):
            try:
                request = urllib.request.Request(
                    f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
                    data=raw, method="PUT",
                    headers={"Authorization": "Bearer " + token},
                )
                statuses.append(urllib.request.urlopen(request).status)
            except urllib.error.HTTPError as error:
                statuses.append(error.code)
            except Exception as error:
                errors.append(error)

        workers = [
            threading.Thread(target=upload, args=(raw,))
            for raw in raws
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
            assert not worker.is_alive()

        assert errors == []
        assert sorted(statuses) == [204, 503]
        assert len(receiver_ids) == 2
        assert len(set(receiver_ids)) == 1
        assert len(
            set(store.list("ingress/")) - before_sources
        ) == 2
        assert sum(
            remote.fact_of(workspace, fid) is not None
            for fid in fids
        ) == 1

        monkeypatch.setattr(store, "cas", commit)
        for raw in raws:
            retry = urllib.request.Request(
                f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
                data=raw, method="PUT",
                headers={"Authorization": "Bearer " + token},
            )
            assert urllib.request.urlopen(retry).status == 204

    assert len(
        set(store.list("ingress/")) - before_sources
    ) == 2
    assert all(
        remote.fact_of(workspace, fid) is not None
        for fid in fids
    )


@pytest.mark.parametrize(
    "profile", (peer_capability.FULL, None),
    ids=("advertised-full", "legacy-no-profile"))
def test_full_and_legacy_peers_still_sync_both_directions(
        tmp_path, profile):
    remote, workspace, local = replicas(tmp_path)
    with serving(remote, profile) as (url, observed, _):
        local_fid = facts.content.message.post(
            local, workspace, "general", "from local", ts=10)
        pulled, pushed = sync(local, workspace, url)

        assert pulled == 0
        assert pushed > 0
        assert remote.fact_of(workspace, local_fid) \
            == local.fact_of(workspace, local_fid)
        # Each independently closed durable difference uses the same exact
        # pile route; there is no detached page-write side channel.
        assert len(observed["puts"]) == 2
        assert all(path.startswith("/pile/") for path in observed["puts"])

        staged = []
        real_receive = local.receive_pile

        def record_receive(ws, member, raw):
            staged.append(raw)
            return real_receive(ws, member, raw)

        local.receive_pile = record_receive
        remote_fid = facts.content.message.post(
            remote, workspace, "general", "from remote", ts=20)
        assert sync(local, workspace, url) == (1, 0)
        assert len(staged) == 2
        assert local.fact_of(workspace, remote_fid) \
            == remote.fact_of(workspace, remote_fid)
        assert local.store(workspace).get("root") \
            == remote.store(workspace).get("root")


def test_read_only_peer_pulls_when_behind_idles_when_equal_and_never_pushes(
        tmp_path):
    remote, workspace, local = replicas(tmp_path)
    with serving(
            remote, peer_capability.READ_ONLY) as (url, observed, _):
        assert sync(local, workspace, url) == (0, 0)
        assert observed["puts"] == []

        remote_fid = facts.content.message.post(
            remote, workspace, "general", "remote news", ts=10)
        assert sync(local, workspace, url) == (1, 0)
        assert local.fact_of(workspace, remote_fid) is not None

        local_fid = facts.content.message.post(
            local, workspace, "general", "pending local news", ts=20)
        action_fid = facts.content.delete.remove(local, workspace, remote_fid, ts=21)
        remote_root = remote.store(workspace).get("root")

        assert sync(local, workspace, url) == (0, 0)
        assert sync(local, workspace, url) == (0, 0)
        assert local.fact_of(workspace, local_fid) is not None
        assert local.fact_of(workspace, action_fid) is not None
        assert remote.fact_of(workspace, local_fid) is None
        assert remote.fact_of(workspace, action_fid) is None
        assert remote.store(workspace).get("root") == remote_root
        assert local.sync_cache[(workspace, url)]["pending_push"] is True
        assert local.sync_cache[(workspace, url)]["sync_profile"] \
            == peer_capability.READ_ONLY
        assert observed["puts"] == []


def test_next_304_retries_a_local_commit_that_raced_the_pinned_snapshot(
        tmp_path, monkeypatch):
    """The cache blesses the compared root, never a later local commit."""
    remote, workspace, local = replicas(tmp_path)
    real_reconcile = sync_module.reconcile_facts
    raced = {}

    def reconcile_then_commit(*args, **kwargs):
        answer = real_reconcile(*args, **kwargs)
        if not raced:
            raced["fid"] = facts.content.message.post(
                local,
                workspace,
                "general",
                "authored after the pinned comparison",
                ts=10,
            )
        return answer

    monkeypatch.setattr(
        sync_module, "reconcile_facts", reconcile_then_commit)
    with serving(
            remote, peer_capability.FULL) as (url, observed, _):
        assert sync(local, workspace, url) == (0, 0)
        assert remote.fact_of(workspace, raced["fid"]) is None
        assert observed["puts"] == []
        # A concurrent local commit invalidates the whole peer comparison.
        # The next dial must recompare instead of blessing either snapshot.
        assert (workspace, url) not in local.sync_cache

        pulled, pushed = sync(local, workspace, url)
        assert pulled == 0
        assert pushed > 0
        assert remote.fact_of(workspace, raced["fid"]) is not None
        assert observed["puts"]


@pytest.mark.parametrize(
    ("profile", "tampered"),
    (
        (peer_capability.READ_ONLY, peer_capability.FULL),
        (peer_capability.FULL, {"push": True, "v": 1}),
    ),
    ids=("widened", "malformed"))
def test_mint_capability_mismatch_is_a_safe_pull_only_default(
        tmp_path, profile, tampered):
    remote, workspace, local = replicas(tmp_path)
    local_fid = facts.content.message.post(
        local, workspace, "general", "must remain local", ts=10)

    with serving(
            remote, profile, tamper_cap=tampered) as (url, observed, _):
        assert sync(local, workspace, url) == (0, 0)
        assert local.fact_of(workspace, local_fid) is not None
        assert remote.fact_of(workspace, local_fid) is None
        assert local.sync_cache[(workspace, url)]["sync_profile"] \
            == peer_capability.READ_ONLY
        assert observed["puts"] == []


def test_remint_and_cold_cache_refresh_the_authenticated_profile(tmp_path):
    remote, workspace, local = replicas(tmp_path)
    with serving(
            remote, peer_capability.FULL) as (url, observed, edge):
        peer = Peer(local, workspace, url)
        peer.root(response_limit=MAX_ROOT_BYTES)
        assert peer.accepts_push
        assert observed["mints"] == 1

        edge.sync_profile = peer_capability.READ_ONLY
        edge.secret = b"r" * 32
        peer.root(response_limit=MAX_ROOT_BYTES)
        assert not peer.accepts_push
        assert observed["mints"] == 2

        peer.cache.clear()
        cold = Peer(local, workspace, url)
        cold.root(response_limit=MAX_ROOT_BYTES)
        assert not cold.accepts_push
        assert observed["mints"] == 3
        with pytest.raises(PushUnsupported, match="pull-only"):
            cold.put_pile(b"unsupported")
        assert observed["puts"] == []

        pending = facts.content.message.post(
            local, workspace, "general", "survives pull-only", ts=10)
        assert sync(local, workspace, url) == (0, 0)
        assert local.sync_cache[(workspace, url)]["pending_push"] is True
        assert remote.fact_of(workspace, pending) is None

        edge.sync_profile = peer_capability.FULL
        edge.secret = b"s" * 32
        pulled, pushed = sync(local, workspace, url)
        assert pulled == 0
        assert pushed > 0
        assert remote.fact_of(workspace, pending) is not None
        assert "pending_push" not in local.sync_cache[(workspace, url)]
        assert observed["puts"]
        assert all(path.startswith("/pile/") for path in observed["puts"])


def test_full_peer_has_no_detached_object_write_route(
        tmp_path):
    remote, workspace, local = replicas(tmp_path)
    raw = b"independent attachment proof"
    oid = h(raw)

    with serving(
            remote, peer_capability.FULL) as (url, observed, _):
        peer = Peer(local, workspace, url)
        peer.root(response_limit=MAX_ROOT_BYTES)

        request = urllib.request.Request(
            f"{url}/page/{oid}?ws={workspace}",
            data=raw, method="PUT",
            headers={"Authorization": "Bearer " + peer.cache["token"]},
        )
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request)
        assert denied.value.code == 404
        assert remote.store(workspace).get("obj/" + oid) is None
        assert len(observed["puts"]) == 1


def test_capability_is_hmac_bound_and_unknown_signed_versions_are_rejected():
    secret = b"capability-authentication-secret"
    workspace = "a" * 64
    token = make_token(
        secret, "member", workspace,
        capability=peer_capability.READ_ONLY)
    encoded, mac = token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(encoded))
    assert payload["cap"] == peer_capability.READ_ONLY

    payload["cap"] = peer_capability.FULL
    changed = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True).encode()).decode()
    assert check_token(
        secret, f"Bearer {changed}.{mac}", workspace) is None

    payload["cap"] = "sync-v2/full"
    payload["exp"] = now_ms() + 60_000
    raw = json.dumps(payload, sort_keys=True).encode()
    signed = base64.urlsafe_b64encode(raw).decode() + "." + hmac.new(
        secret, raw, hashlib.sha256).hexdigest()
    assert check_token(
        secret, "Bearer " + signed, workspace) is None


def test_read_only_grant_is_rejected_at_the_daemon_push_door(tmp_path):
    remote, workspace, local = replicas(tmp_path)
    raw = closed_subset(local, workspace, all_fids(local, workspace))

    with serving(
            remote, peer_capability.FULL) as (url, observed, edge):
        member = local.member_for(workspace)
        token = make_token(
            edge.secret, member, workspace,
            capability=peer_capability.READ_ONLY)
        request = urllib.request.Request(
            f"{url}/pile/{member}/{h(raw)}?ws={workspace}",
            data=raw, method="PUT",
            headers={"Authorization": "Bearer " + token},
        )
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request)

        assert denied.value.code == 401
        assert observed["puts"]


def test_push_grant_cannot_write_another_producer_segment(tmp_path):
    remote, workspace, local = replicas(tmp_path)
    raw = closed_subset(local, workspace, all_fids(local, workspace))

    with serving(
            remote, peer_capability.FULL) as (url, observed, edge):
        before = remote.store(workspace).list("ingress/")
        member = local.member_for(workspace)
        other = "0" * 64 if member != "0" * 64 else "f" * 64
        token = make_token(
            edge.secret, member, workspace,
            capability=peer_capability.FULL)
        request = urllib.request.Request(
            f"{url}/pile/{other}/{h(raw)}?ws={workspace}",
            data=raw, method="PUT",
            headers={"Authorization": "Bearer " + token},
        )
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request)

        assert denied.value.code == 403
        assert remote.store(workspace).list("ingress/") == before
        assert observed["puts"]
