"""Phase-2 queue tests using the production peerlog codecs and ingest path."""
import hashlib
import threading

import pytest

from adapters.s3 import S3Config, S3Store
from peerlog.cloud import (
    MICRO_TAIL,
    MULTIPART_EDGE,
    CloudCache,
    CloudQueue,
    MaintenanceRequired,
    MemoryCloud,
)
from peerlog.cloud import (
    Publication, Segment, Slot, _encode_segment, _micro_key, encode_slot,
)
from peerlog.cloud_s3 import S3Cloud
from peerlog.endpoint import PeerEndpoint, run_key
from peerlog.fact import Fact, Ref, fid
from peerlog.ingest import PeerState
from peerlog.log import WriterLog
from peerlog.log import encode_head
from peerlog.proof import carry, prove_run
from peerlog.session import mesh_sync
from tests.provider_fakes import FakeS3Bucket


def h(label):
    return hashlib.sha256(label.encode()).digest()


def owned(label, count, *, body_size=0):
    log = WriterLog.owned()
    for seq in range(count):
        body = (f"{label}:{seq}".encode() if not body_size
                else bytes([seq % 251]) * body_size)
        log.append(Fact("msg", 1_000 + seq, (), body))
    return log


def entries(log):
    return {(log.fact(seq).ts, fid(log.fact(seq))) for seq in log._facts}


def test_cloud_uses_exact_peer_runs_and_one_round_no_change():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("workspace"))
    log = owned("alice", 8)
    cloud.publish(log, 0, 8)

    peer = PeerEndpoint(PeerState())
    peer.state.add_owned(log)
    peer.refresh()
    # The passive sequence recipe receives the identical authenticated bytes
    # whether its source is a live peer or the object queue.
    assert cloud.read_run(log.writer, 0, 8) == peer.get(
        run_key(log.writer, 0, 8))

    replica, cache = PeerState(), CloudCache()
    cold = cloud.sync(replica, cache)
    assert cold.changed and cold.rounds == 2 and cold.facts == 8
    assert set(replica.entries()) == entries(log)

    before = store.metrics.copy()
    noop = cloud.sync(replica, cache)
    delta = store.metrics.delta(before)
    assert not noop.changed and noop.rounds == 1
    assert delta.gets == delta.conditional_gets == 1
    assert delta.downloaded_bytes == 0


def test_warm_delta_is_directory_plus_parallel_object_round():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("warm"))
    log = owned("writer", 4)
    cloud.publish(log)
    state, cache = PeerState(), CloudCache()
    cloud.sync(state, cache)

    for seq in range(4, 7):
        log.append(Fact("msg", 1_000 + seq, (), f"writer:{seq}".encode()))
    cloud.publish(log, 4, 7)
    report = cloud.sync(state, cache)
    assert report.changed and report.rounds == 2
    assert report.object_gets == 1 and report.facts == 3
    assert set(state.entries()) == entries(log)


def test_timestamp_window_uses_directory_footer_and_body_waves():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("time window"))
    log = WriterLog.owned()
    for seq, timestamp in enumerate((1_000, 50_000, 90_000)):
        log.append(Fact("msg", timestamp, (), f"at:{timestamp}".encode()))
        cloud.publish(log, seq, seq + 1)

    state = PeerState()
    report = cloud.sync(state, ts_window=(49_000, 51_000))
    assert report.rounds == 3 and report.object_gets == 4
    assert report.facts == 1
    assert set(state.logs[log.writer]._facts) == {1}


def test_three_players_reach_cloud_and_peer_mesh_convergence():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("three players"))
    endpoints = []
    expected = set()
    for player in range(3):
        log = owned(f"player-{player}", 18)
        cloud.publish(log)
        state = PeerState()
        state.add_owned(log)
        endpoints.append(PeerEndpoint(state, endpoint_id=bytes([player])))
        expected.update(entries(log))

    # A cold fourth client verifies the cloud's original-writer proofs.
    cold = PeerState()
    report = cloud.sync(cold)
    assert report.rounds == 2 and report.facts == 54
    assert set(cold.entries()) == expected

    # The same three original writers converge over the one-driver P2P path.
    mesh_sync(endpoints)
    assert all(set(endpoint.state.entries()) == expected for endpoint in endpoints)


def test_rule2_carry_is_adjacent_and_resolves_before_citing_ingest():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("rule two"))
    target = owned("target", 1)
    citing = WriterLog.owned()
    citing.append(Fact(
        "member", 2_000, (Ref(target.writer, 0),), b"needs target"))

    with pytest.raises(ValueError, match="Rule-2"):
        cloud.publish(citing)
    cloud.publish(citing, carries=(carry(target, 0),))

    state = PeerState()
    report = cloud.sync(state)
    assert report.carries == 1 and report.facts == 1 and not report.pending
    assert state.logs[target.writer].fact(0) == target.fact(0)
    assert state.logs[citing.writer].fact(0) == citing.fact(0)


def test_consumer_rejects_writer_that_bypasses_rule2_publication_check():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("hostile rule two"))
    target = owned("unpublished target", 1)
    citing = WriterLog.owned()
    citing.append(Fact(
        "member", 2_000, (Ref(target.writer, 0),), b"missing carry"))
    run = prove_run(citing, 0, 1)
    raw = _encode_segment((Publication(run),), "micro")
    key = _micro_key(cloud.workspace, citing.writer, 0, 1)
    store.create(key, raw)
    slot = Slot(
        cloud.workspace, citing.writer, encode_head(citing.head()),
        (Segment(key, 0, 1, len(raw), 1, "micro"),),
    )
    assert store.cas(cloud._slot_key(citing.writer), None, encode_slot(slot))
    cloud.repair_directory()

    state = PeerState()
    with pytest.raises(ValueError, match="Rule-2"):
        cloud.sync(state)
    assert not state.logs


def test_handoff_is_explicit_out_of_band_ticket_not_ambient_discovery():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("handoff"))
    authority = owned("authority", 1)
    inviter = WriterLog.owned()
    recipient = h("recipient device")
    inviter.append(Fact(
        "invite", 3_000, (Ref(authority.writer, 0),), b"sealed invitation"))

    with pytest.raises(ValueError, match="handoff"):
        cloud.publish(inviter, carries=(carry(authority, 0),))
    receipt = cloud.publish(
        inviter, carries=(carry(authority, 0),),
        handoff_targets=(recipient,))
    assert len(receipt.handoffs) == 1

    state = PeerState()
    with pytest.raises(ValueError, match="handoff ticket"):
        cloud.redeem_handoff(receipt.handoffs[0], h("wrong"), state)
    cloud.redeem_handoff(receipt.handoffs[0], recipient, state)
    assert set(state.logs) == {authority.writer, inviter.writer}


def test_micro_tail_folds_to_binary_ladder_and_footer_is_suffix_readable():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("ladder"))
    log = WriterLog.owned()
    for seq in range(MICRO_TAIL):
        log.append(Fact("msg", seq + 1, (), f"event:{seq}".encode()))
        cloud.publish(log, seq, seq + 1)

    slot, _token = cloud._slot_versioned(log.writer)
    assert sum(segment.kind == "micro" for segment in slot.segments) == MICRO_TAIL
    log.append(Fact("msg", MICRO_TAIL + 1, (), b"requires idle fold"))
    with pytest.raises(MaintenanceRequired):
        cloud.publish(log, MICRO_TAIL, MICRO_TAIL + 1)
    slot = cloud.fold_idle(log.writer)
    assert sum(segment.kind == "micro" for segment in slot.segments) == 0
    assert len(slot.segments) < MICRO_TAIL
    assert all(segment.size < MULTIPART_EDGE for segment in slot.segments)
    footers = [cloud.footer(segment) for segment in slot.segments]
    assert footers[0]["lo"] == 0 and footers[-1]["hi"] == MICRO_TAIL


def test_each_chat_publish_upload_is_suffix_bounded_not_log_sized():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("publish bound"))
    log = WriterLog.owned()
    uploads = []
    for seq in range(128):
        if seq and seq % MICRO_TAIL == 0:
            cloud.fold_idle(log.writer, announce=False)
        log.append(Fact("msg", seq + 1, (), b"x" * 90))
        before = store.metrics.copy()
        cloud.publish(log, seq, seq + 1, announce=False)
        uploads.append(store.metrics.delta(before).object_upload_bytes)
    assert max(uploads) < 8 * 1024
    assert uploads[-1] < uploads[0] + 512


def test_multipart_exact_five_mib_edge_is_invisible_until_complete():
    store = MemoryCloud()
    source = b"a" * MULTIPART_EDGE
    store.create("source", source)
    upload = store.begin_multipart("destination")
    store.copy_part(upload, "source", MULTIPART_EDGE)
    store.upload_part(upload, b"tail")
    assert store.get("destination")[0] is None
    assert store.complete_multipart(upload) == source + b"tail"
    assert store.get("destination")[0] == source + b"tail"
    assert store.metrics.copied_bytes == MULTIPART_EDGE


def test_s3_compatible_adapter_runs_cloud_recipe_and_exact_part_copy():
    bucket = FakeS3Bucket(page_size=2)
    configured = S3Store(
        S3Config(bucket="peerlog-cloud", prefix="queue-test"),
        client=bucket.client("queue"),
    )
    provider = S3Cloud(configured)
    cloud = CloudQueue(provider, h("s3 compatible"))
    log = owned("provider writer", 6)
    cloud.publish(log)
    replica = PeerState()
    assert cloud.sync(replica).facts == 6
    assert set(replica.entries()) == entries(log)

    provider.create("multipart/source", b"x" * MULTIPART_EDGE)
    upload = provider.begin_multipart("multipart/destination")
    provider.copy_part(upload, "multipart/source", MULTIPART_EDGE)
    provider.upload_part(upload, b"tail")
    assert provider.get("multipart/destination")[0] is None
    provider.complete_multipart(upload)
    assert provider.get("multipart/destination")[0] \
        == b"x" * MULTIPART_EDGE + b"tail"


def test_part_copy_failure_automatically_starts_complete_epoch():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("epoch fallback"))
    log = owned("large", 2, body_size=2_000_000)
    cloud.publish(log, 0, 1)
    cloud.publish(log, 1, 2)
    initial = cloud.fold_idle(log.writer)
    assert initial.segments[-1].kind == "mono"
    assert initial.segments[-1].size >= MULTIPART_EDGE

    log.append(Fact("msg", 2_000, (), b"small tail"))
    cloud.publish(log, 2, 3)
    store.fail_next_copy = True
    folded = cloud.fold_idle(log.writer)
    assert [segment.kind for segment in folded.segments] == ["mono", "epoch"]
    assert folded.segments[0].hi == folded.segments[1].lo == 2

    replica = PeerState()
    report = cloud.sync(replica)
    assert report.facts == 3 and set(replica.entries()) == entries(log)


def test_mono_append_copies_history_and_uploads_only_bounded_tail():
    store = MemoryCloud()
    cloud = CloudQueue(store, h("copy amplification"))
    log = owned("large", 2, body_size=2_000_000)
    cloud.publish(log, 0, 1)
    cloud.publish(log, 1, 2)
    old = cloud.fold_idle(log.writer).segments[0]
    log.append(Fact("msg", 2_000, (), b"delta" * 100))
    cloud.publish(log, 2, 3)

    before = store.metrics.copy()
    current = cloud.fold_idle(log.writer).segments[0]
    delta = store.metrics.delta(before)
    assert current.lo == 0 and current.hi == 3
    assert delta.part_copies == delta.multipart_completes == 1
    assert delta.copied_bytes >= MULTIPART_EDGE
    assert delta.uploaded_bytes < old.size // 10


def test_two_workspaces_publish_concurrently_without_shared_writer_slot():
    store = MemoryCloud()
    first = CloudQueue(store, h("workspace one"))
    second = CloudQueue(store, h("workspace two"))
    logs = (owned("first", 10), owned("second", 12))
    barrier = threading.Barrier(2)
    errors = []

    def publish(queue, log):
        try:
            barrier.wait()
            queue.publish(log)
        except Exception as error:  # pragma: no cover - asserted below
            errors.append(error)

    threads = [
        threading.Thread(target=publish, args=(first, logs[0])),
        threading.Thread(target=publish, args=(second, logs[1])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
    assert not errors

    left, right = PeerState(), PeerState()
    first.sync(left)
    second.sync(right)
    assert set(left.entries()) == entries(logs[0])
    assert set(right.entries()) == entries(logs[1])
    assert set(left.entries()).isdisjoint(right.entries())


def test_same_workspace_writer_races_are_repaired_without_authority_loss():
    store = MemoryCloud()
    workspace = h("same workspace")
    queues = (CloudQueue(store, workspace), CloudQueue(store, workspace))
    logs = (owned("alice", 7), owned("bob", 9))
    barrier = threading.Barrier(2)

    def publish(queue, log):
        barrier.wait()
        queue.publish(log, announce=False)
        barrier.wait()
        queue.repair_directory()

    threads = [threading.Thread(target=publish, args=pair)
               for pair in zip(queues, logs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
    assert all(not thread.is_alive() for thread in threads)

    # The digest is a hint: one deterministic repair after any racing writes
    # must recover the exact writer forest from owner slots.
    queues[0].repair_directory()
    state = PeerState()
    queues[0].sync(state)
    assert set(state.entries()) == entries(logs[0]) | entries(logs[1])
