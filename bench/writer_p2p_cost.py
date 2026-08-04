"""Rate-independent HTTP accounting for writer-forest P2P catch-up."""
import asyncio
from dataclasses import dataclass
import time

from core.store import RemoteStore
from core.writer_head import (
    MAX_HEAD_SLOT_BYTES,
    MAX_WRITER_HEAD_BYTES,
    decode_head,
    decode_slot_at,
    head_slot_prefix,
)
from full_peer.sync import sync as full_sync
from full_peer.walk import Peer


@dataclass(frozen=True, slots=True)
class P2PVector:
    requests: int
    request_bytes: int
    response_bytes: int
    facts: int
    piles: int
    elapsed_seconds: float

    @property
    def facts_per_second(self):
        return self.facts / self.elapsed_seconds


@dataclass(frozen=True, slots=True)
class TwoPartySyncVector:
    """Facts admitted by both participants during one complete sync turn."""

    local_facts: int
    remote_facts: int
    pulled_piles: int
    pushed_piles: int
    pull_changed: int
    elapsed_seconds: float

    @property
    def facts(self):
        return self.local_facts + self.remote_facts

    @property
    def facts_per_second(self):
        return self.facts / self.elapsed_seconds


class MeteredPeer(Peer):
    """Production HTTP client with deterministic RTT and byte accounting."""

    def __init__(self, node, workspace, url, *, rtt_ms=0):
        if type(rtt_ms) not in {int, float} or rtt_ms < 0:
            raise ValueError("P2P benchmark RTT")
        super().__init__(node, workspace, url)
        self.rtt_seconds = rtt_ms / 1_000
        self.requests = self.request_bytes = self.response_bytes = 0

    def _http(self, method, path, data=None, *args, **kwargs):
        if self.rtt_seconds:
            time.sleep(self.rtt_seconds)
        self.requests += 1
        self.request_bytes += len(data or b"")
        response = super()._http(method, path, data, *args, **kwargs)
        self.response_bytes += len(response[1])
        return response


def measure_pull(node, workspace, url, token, *, rtt_ms=0):
    """Consume one remote forest through real HTTP and return exact costs."""
    peer = MeteredPeer(node, workspace, url, rtt_ms=rtt_ms)
    peer._sync_profile = "sync-v1/full"
    peer._token = token
    before = len(node.sql(workspace).fact_ids())
    started = time.perf_counter()
    result = asyncio.run(
        node.mirror(workspace).sync_from(RemoteStore(peer)))
    elapsed = time.perf_counter() - started
    if result.errors:
        raise ValueError("P2P benchmark mirror error")
    return P2PVector(
        peer.requests,
        peer.request_bytes,
        peer.response_bytes,
        len(node.sql(workspace).fact_ids()) - before,
        result.piles,
        elapsed,
    )


def _sync_snapshot(node, workspace):
    """Return durable fact IDs and accepted pile leaves for one FullPeer."""
    store = node.store(workspace)
    piles = 0
    for key in store.list(head_slot_prefix(workspace)):
        raw_slot = store.get_bounded(key, MAX_HEAD_SLOT_BYTES)
        slot = decode_slot_at(key, raw_slot)
        if slot is None:
            continue
        raw_head = store.get_bounded(
            "obj/" + slot.head, MAX_WRITER_HEAD_BYTES)
        piles += decode_head(raw_head).sequence
    return set(node.sql(workspace).fact_ids()), piles


def measure_two_party_sync(
        local, remote, workspace, url, *, sync_turn=full_sync,
        clock=time.perf_counter, snapshot=_sync_snapshot):
    """Time one complete FullPeer sync and count facts admitted on both sides.

    Fixture work and the before/after durable-fact snapshots are deliberately
    outside the timer.  Elapsed time begins immediately before ``sync_turn``
    and ends immediately after it returns.
    """
    local_facts_before, local_piles_before = snapshot(local, workspace)
    remote_facts_before, remote_piles_before = snapshot(remote, workspace)

    started = clock()
    pull_changed, reported_pushed_piles = sync_turn(local, workspace, url)
    elapsed = clock() - started

    local_facts_after, local_piles_after = snapshot(local, workspace)
    remote_facts_after, remote_piles_after = snapshot(remote, workspace)
    pulled_piles = local_piles_after - local_piles_before
    pushed_piles = remote_piles_after - remote_piles_before
    if pulled_piles < 0 or pushed_piles < 0 \
            or pushed_piles != reported_pushed_piles:
        raise AssertionError("two-party sync pile accounting")
    return TwoPartySyncVector(
        len(local_facts_after - local_facts_before),
        len(remote_facts_after - remote_facts_before),
        pulled_piles,
        pushed_piles,
        pull_changed,
        elapsed,
    )


__all__ = (
    "MeteredPeer",
    "P2PVector",
    "TwoPartySyncVector",
    "measure_pull",
    "measure_two_party_sync",
)
