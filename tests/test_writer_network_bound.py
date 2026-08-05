"""Real-socket and accounting coverage for the network-bound catch-up bar."""
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import threading

import facts

from bench.writer_network_bound import (
    CatchupMeasurement,
    DEFAULT_BANDWIDTH_MBIT,
    DEFAULT_LINE_BYTES,
    DEFAULT_PILES,
    DEFAULT_RATE_FRACTION,
    DEFAULT_RTT_MS,
    DEFAULT_TEXT_BYTES,
    RequestEvent,
    final_report,
    measure_catchup,
    request_waves,
)
from core import peer_capability
from full_peer.node import FullPeer
from full_peer.pack_http import handler_for


def test_live_profile_defaults_are_the_documented_evidence_shape():
    assert (
        DEFAULT_BANDWIDTH_MBIT,
        DEFAULT_RTT_MS,
        DEFAULT_PILES,
        DEFAULT_TEXT_BYTES,
        DEFAULT_LINE_BYTES,
        DEFAULT_RATE_FRACTION,
    ) == (5, 20, 16, 2 * 1024 * 1024, 8 * 1024 * 1024, .70)


@contextmanager
def serve(peer):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        handler_for(
            peer,
            b"network-bound-test-secret-00000001",
            sync_profile=peer_capability.FULL,
        ),
    )
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def test_real_socket_catchup_is_counted_only_after_durable_validation(tmp_path):
    source = FullPeer(str(tmp_path / "source"))
    source.peer_address = "http://127.0.0.1:1"
    workspace = facts.auth.workspace.create(source, "source", ts=1)
    link = facts.auth.user_invite.make(source, workspace)
    target = FullPeer(str(tmp_path / "target"))
    facts.auth.user.accept(target, link, "target")
    for ordinal in range(4):
        facts.content.message.post(
            source,
            workspace,
            "general",
            f"{ordinal}:" + "x" * (64 * 1024),
            ts=100 + ordinal,
        )

    before = set(target.sql(workspace).fact_ids())
    with serve(source) as url:
        measured = measure_catchup(target, workspace, url)
    after = set(target.sql(workspace).fact_ids())

    assert measured.facts == len(after - before) == 8
    assert measured.piles == 5
    assert measured.durable_bytes > 4 * 64 * 1024
    assert measured.logical_gets > 0
    assert measured.http_gets > 0
    assert measured.http_requests >= measured.logical_gets
    assert measured.request_waves > 0
    assert measured.elapsed_seconds > 0
    assert any("/obj" in path for path, _count in measured.request_breakdown)


def test_request_waves_group_only_observed_overlap():
    events = (
        RequestEvent("GET", "/a", 0.0, 2.0, 0, 1),
        RequestEvent("GET", "/b", 1.0, 3.0, 0, 1),
        RequestEvent("GET", "/c", 3.0, 4.0, 0, 1),
    )
    assert request_waves(events) == 2
    assert request_waves(()) == 0


def test_network_bound_verdict_uses_independent_measured_line_rate():
    measured = CatchupMeasurement(
        8.0, 100, 50, 8_000_000, 12, 9, 10, 7, 1_000, 8_500_000,
        (("GET /heads", 1),),
    )
    report = final_report(
        measured,
        bandwidth_mbit=10,
        rtt_ms=20,
        line_bytes=10_000_000,
        line_elapsed_seconds=10,
        wire_rx_bytes=8_000_000,
        minimum_fraction=DEFAULT_RATE_FRACTION,
    )
    assert report["measured_line_rate_mbps"] == 8.0
    assert report["catchup_wire_rate_mbps"] == 8.0
    assert report["line_rate_fraction"] == 1.0
    assert report["network_bound"] is True
