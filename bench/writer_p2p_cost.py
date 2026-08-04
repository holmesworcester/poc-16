"""Rate-independent HTTP accounting for writer-forest P2P catch-up."""
import asyncio
from dataclasses import dataclass
import time

from core.store import RemoteStore
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


__all__ = ("MeteredPeer", "P2PVector", "measure_pull")
