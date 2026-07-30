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

from core import cmds, daemon, peer_capability
from core.crypto import h
from core.node import Node, now_ms
from core.sync import sync
from core.walk import Peer, PushUnsupported

from .util import all_fids, closed_subset, deliver


def replicas(tmp_path):
    remote = Node(str(tmp_path / "remote"))
    workspace = cmds.create(remote, "alice", ts=1)
    local = Node(
        str(tmp_path / "local"),
        initial_secret=remote.identity(workspace)[0])
    local.add_workspace(workspace, "local", [])
    deliver(
        local, workspace,
        closed_subset(remote, workspace, all_fids(remote, workspace)))
    local.turn(workspace)
    assert local.store(workspace).get("root") \
        == remote.store(workspace).get("root")
    return remote, workspace, local


@contextmanager
def serving(node, profile, tamper_cap=None):
    observed = {"mints": 0, "puts": []}

    class Edge(daemon.Handler):
        def mint(self, request):
            observed["mints"] += 1
            return super().mint(request)

        def _json(self, code, body):
            if tamper_cap is not None and isinstance(body, dict) \
                    and "grant" in body:
                body = {**body, "cap": tamper_cap}
            return super()._json(code, body)

        def do_PUT(self):
            observed["puts"].append(self.path)
            if self.sync_profile == peer_capability.READ_ONLY:
                return self._send(405)
            return super().do_PUT()

    Edge.node = node
    Edge.secret = b"peer-capability-test-secret"
    Edge.syncer = None
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


@pytest.mark.parametrize(
    "profile", (peer_capability.FULL, None),
    ids=("advertised-full", "legacy-no-profile"))
def test_full_and_legacy_peers_still_sync_both_directions(
        tmp_path, profile):
    remote, workspace, local = replicas(tmp_path)
    with serving(remote, profile) as (url, observed, _):
        local_fid = cmds.post(
            local, workspace, "general", "from local", ts=10)
        pulled, pushed = sync(local, workspace, url)

        assert pulled == 0
        assert pushed > 0
        assert remote.fact_of(workspace, local_fid) \
            == local.fact_of(workspace, local_fid)
        assert len(observed["puts"]) == 1

        remote_fid = cmds.post(
            remote, workspace, "general", "from remote", ts=20)
        assert sync(local, workspace, url) == (1, 0)
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

        remote_fid = cmds.post(
            remote, workspace, "general", "remote news", ts=10)
        assert sync(local, workspace, url) == (1, 0)
        assert local.fact_of(workspace, remote_fid) is not None

        local_fid = cmds.post(
            local, workspace, "general", "pending local news", ts=20)
        action_fid = cmds.remove(local, workspace, remote_fid, ts=21)
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
    local_fid = cmds.post(
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
        peer.root()
        assert peer.accepts_push
        assert observed["mints"] == 1

        edge.sync_profile = peer_capability.READ_ONLY
        edge.secret = b"rotated-peer-capability-secret"
        peer.root()
        assert not peer.accepts_push
        assert observed["mints"] == 2

        peer.cache.clear()
        cold = Peer(local, workspace, url)
        cold.root()
        assert not cold.accepts_push
        assert observed["mints"] == 3
        with pytest.raises(PushUnsupported, match="pull-only"):
            cold.put_pile(b"unsupported")
        with pytest.raises(PushUnsupported, match="pull-only"):
            cold.put_obj(h(b"unsupported"), b"unsupported")
        assert observed["puts"] == []

        pending = cmds.post(
            local, workspace, "general", "survives pull-only", ts=10)
        assert sync(local, workspace, url) == (0, 0)
        assert local.sync_cache[(workspace, url)]["pending_push"] is True
        assert remote.fact_of(workspace, pending) is None

        edge.sync_profile = peer_capability.FULL
        edge.secret = b"second-rotated-capability-secret"
        pulled, pushed = sync(local, workspace, url)
        assert pulled == 0
        assert pushed > 0
        assert remote.fact_of(workspace, pending) is not None
        assert "pending_push" not in local.sync_cache[(workspace, url)]
        assert len(observed["puts"]) == 1


def test_full_peer_accepts_only_correctly_addressed_immutable_objects(
        tmp_path):
    remote, workspace, local = replicas(tmp_path)
    raw = b"independent attachment proof"
    oid = h(raw)

    with serving(
            remote, peer_capability.FULL) as (url, observed, _):
        peer = Peer(local, workspace, url)
        peer.put_obj(oid, raw)
        assert remote.store(workspace).get("obj/" + oid) == raw

        request = urllib.request.Request(
            f"{url}/page/{oid}?ws={workspace}",
            data=b"different bytes", method="PUT",
            headers={"Authorization": "Bearer " + peer.cache["token"]},
        )
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request)
        assert denied.value.code == 400
        assert remote.store(workspace).get("obj/" + oid) == raw
        assert len(observed["puts"]) == 2


def test_capability_is_hmac_bound_and_unknown_signed_versions_are_rejected():
    secret = b"capability-authentication-secret"
    workspace = "a" * 64
    token = daemon.make_token(
        secret, "member", workspace,
        capability=peer_capability.READ_ONLY)
    encoded, mac = token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(encoded))
    assert payload["cap"] == peer_capability.READ_ONLY

    payload["cap"] = peer_capability.FULL
    changed = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True).encode()).decode()
    assert daemon.check_token(
        secret, f"Bearer {changed}.{mac}", workspace) is None

    payload["cap"] = "sync-v2/full"
    payload["exp"] = now_ms() + 60_000
    raw = json.dumps(payload, sort_keys=True).encode()
    signed = base64.urlsafe_b64encode(raw).decode() + "." + hmac.new(
        secret, raw, hashlib.sha256).hexdigest()
    assert daemon.check_token(
        secret, "Bearer " + signed, workspace) is None


def test_read_only_grant_is_rejected_at_the_daemon_push_door(tmp_path):
    remote, workspace, local = replicas(tmp_path)
    raw = closed_subset(local, workspace, all_fids(local, workspace))

    with serving(
            remote, peer_capability.FULL) as (url, observed, edge):
        member = local.member_for(workspace)
        token = daemon.make_token(
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
        member = local.member_for(workspace)
        other = "0" * 16 if member != "0" * 16 else "f" * 16
        token = daemon.make_token(
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
        assert remote.store(workspace).list(f"pile/{other}/") == []
        assert observed["puts"]
