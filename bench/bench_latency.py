"""Measure the two latency paths that must stay cheap after the tree cutover.

Hot posts report total latency, the share spent scanning sorted fact keys, and
immutable object writes. Idle dials report the local engine cost after a 304;
the first dial establishes blob completeness and every measured dial must do
no fact/index/blob work.

Run:
    python3 bench/bench_latency.py
    python3 bench/bench_latency.py 1000 5000 10000 --posts 7 --idle 100
"""
import argparse
import os
import shutil
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.bench_sync import build_seed
from core import cmds
from core import sync as sync_module


def percentile(samples, fraction):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


class SameStorePeer:
    """Conditional local peer used to isolate sync-engine overhead."""

    def __init__(self, node, workspace, url):
        self.node, self.ws = node, workspace
        self.store = node.store(workspace)
        self.cache = node.sync_cache.setdefault((workspace, url), {})

    def root(self, etag=None):
        current = self.store.etag("root")
        if etag == current:
            return None
        return self.store.get("root"), current

    def obj(self, oid):
        return self.store.get("obj/" + oid)

    def objs(self, oids):
        return tuple(self.obj(oid) for oid in oids)

    def put_pile(self, raw):
        raise AssertionError("same-root benchmark unexpectedly pushed")


def measure_scale(directory, scale, posts=7, idle=100, members=100):
    shutil.rmtree(directory, ignore_errors=True)
    node, workspace, built = build_seed(
        directory, scale, n_members=members)
    high_ts = node.idx(workspace).execute(
        "SELECT MAX(ts) FROM facts").fetchone()[0]

    scan_times = []
    original_keys = node.keys

    def timed_keys(*args):
        started = time.perf_counter()
        try:
            return original_keys(*args)
        finally:
            scan_times.append(time.perf_counter() - started)

    writes = []
    store = node.store(workspace)
    original_put = store.put

    def counted_put(key, raw):
        if key.startswith("obj/"):
            writes.append((key, len(raw)))
        return original_put(key, raw)

    node.keys = timed_keys
    store.put = counted_put
    post_times = []
    try:
        for step in range(posts):
            started = time.perf_counter()
            cmds.post(
                node, workspace, "general", f"latency-{step}",
                ts=high_ts + step + 1)
            post_times.append(time.perf_counter() - started)
    finally:
        node.keys = original_keys
        store.put = original_put

    old_peer = sync_module.Peer
    old_fetch_blobs = sync_module._fetch_blobs
    blob_scans = 0

    def counted_fetch_blobs(*args):
        nonlocal blob_scans
        blob_scans += 1
        return old_fetch_blobs(*args)

    sync_module.Peer = SameStorePeer
    sync_module._fetch_blobs = counted_fetch_blobs
    try:
        sync_module.sync(node, workspace, "local://same-store")
        idle_times = []
        for _ in range(idle):
            started = time.perf_counter()
            assert sync_module.sync(
                node, workspace, "local://same-store") == (0, 0)
            idle_times.append(time.perf_counter() - started)
    finally:
        sync_module.Peer = old_peer
        sync_module._fetch_blobs = old_fetch_blobs

    unique_writes = {}
    for oid, size in writes:
        unique_writes[oid] = size
    return {
        "facts": node.idx(workspace).execute(
            "SELECT COUNT(*) FROM facts").fetchone()[0],
        "seed_facts": built["facts"],
        "post": {
            "samples": len(post_times),
            "p50_ms": 1000 * statistics.median(post_times),
            "p95_ms": 1000 * percentile(post_times, .95),
            "key_scan_p50_ms": 1000 * statistics.median(scan_times),
            "key_scans": len(scan_times),
            "object_writes": len(writes),
            "unique_object_writes": len(unique_writes),
            "object_kib_per_post": sum(size for _, size in writes)
            / 1024 / posts,
        },
        "idle": {
            "samples": len(idle_times),
            "p50_ms": 1000 * statistics.median(idle_times),
            "p95_ms": 1000 * percentile(idle_times, .95),
            "blob_scans_including_prime": blob_scans,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("scales", nargs="*", type=int)
    parser.add_argument("--posts", type=int, default=7)
    parser.add_argument("--idle", type=int, default=100)
    parser.add_argument("--dir")
    args = parser.parse_args(argv)
    scales = args.scales or [1000, 5000, 10000]

    temporary = None
    base = args.dir
    if base is None:
        temporary = tempfile.TemporaryDirectory(prefix="poc16-latency-")
        base = temporary.name
    try:
        print(
            "seed  facts  post_p50  post_p95  keyscan  KiB/post  "
            "idle_p50  idle_p95")
        for scale in scales:
            result = measure_scale(
                os.path.join(base, str(scale)), scale, args.posts, args.idle)
            post, idle = result["post"], result["idle"]
            print(
                f"{scale:4d} {result['facts']:6d} "
                f"{post['p50_ms']:9.2f} {post['p95_ms']:9.2f} "
                f"{post['key_scan_p50_ms']:7.2f} "
                f"{post['object_kib_per_post']:9.1f} "
                f"{idle['p50_ms']:9.3f} {idle['p95_ms']:9.3f}")
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    main()
