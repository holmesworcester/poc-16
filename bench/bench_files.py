"""Measure Bao attachment overhead, authoring, and real-daemon download.

Sizes are decimal MB. Examples:

    python3 bench/bench_files.py --mode overhead 1 8 64 256
    python3 bench/bench_files.py --mode send 64 256 1024
    python3 bench/bench_files.py 8 64 256 1024
"""
import argparse
import filecmp
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import bao, cmds
from core.cli import ctl
from core.node import Node
from facts.content import file as file_family

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.environ.get(
    "BENCH_DIR", os.path.join(tempfile.gettempdir(), "poc-16-bench-files"))
PORTS = {"alice": 17511, "bob": 17512}
DEFAULT_SIZES = (8, 64, 256)
now = time.perf_counter


def url(who):
    return f"http://127.0.0.1:{PORTS[who]}"


def source(path, size):
    """Write a deterministic, nonzero payload without holding it all in RAM."""
    block = bytes(range(256)) * 4096
    with open(path, "wb") as output:
        remaining = size
        while remaining:
            part = block[:min(remaining, len(block))]
            output.write(part)
            remaining -= len(part)
    return path


def rss_gb(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1e6
    except OSError:
        pass
    return 0.0


def bench_overhead(sizes):
    """Price self-proving without engine or transport work."""
    rows = []
    with tempfile.TemporaryDirectory(dir=WORK) as scratch:
        for size in sizes:
            path = source(os.path.join(scratch, "source"), size)
            outboard = os.path.join(scratch, "outboard")
            root = bao.prepare(path, outboard)
            count = bao.geometry(size)
            proof_bytes = sum(
                len(bao.proof(path, outboard, index, size))
                for index in range(count))
            descriptor = file_family.file(
                "a" * 64, "general", "x.bin", size, root, count, 1)
            rows.append({
                "mb": size / 1e6,
                "chunks": count,
                "proof_pct": (
                    (proof_bytes - size) / size * 100 if size else 0),
                "proof_per_chunk": (
                    (proof_bytes - size) // count if count else 0),
                "descriptor_b": len(json.dumps(descriptor.to_json())),
                "outboard_mb": os.path.getsize(outboard) / 1e6,
                "tree_keys": 2 * count + 2,
            })
    return rows


def bench_send(size):
    """Author and save through the real in-process command path."""
    with tempfile.TemporaryDirectory(dir=WORK) as scratch:
        node = Node(os.path.join(scratch, "node"))
        workspace = cmds.create(node, "alice")
        input_path = source(os.path.join(scratch, "input"), size)
        start = now()
        fid = file_family.send(
            node, workspace, "general", input_path, name="big.bin")
        sent = now()
        record = file_family.resolve(node, workspace, fid)
        store = node.store(workspace)
        stored = sum(len(store.get(key)) for key in store.list("obj/"))
        output_path = os.path.join(scratch, "output")
        save_start = now()
        file_family.save(node, workspace, fid, output_path)
        saved = now()
        return {
            "mb": size / 1e6,
            "chunks": record["total"],
            "send_s": sent - start,
            "send_mb_s": size / 1e6 / (sent - start),
            "save_s": saved - save_start,
            "save_mb_s": size / 1e6 / (saved - save_start),
            "store_mb": stored / 1e6,
            "peak_rss_gb": rss_gb(os.getpid()),
            "ok": filecmp.cmp(input_path, output_path, shallow=False),
        }


def spawn(base, who):
    log = open(os.path.join(base, who + ".log"), "w")
    process = subprocess.Popen(
        [sys.executable, "-m", "core", "daemon",
         os.path.join(base, who), "--port", str(PORTS[who]),
         "--cadence", "0.2"],
        cwd=REPO,
        stdout=log,
        stderr=log,
        env={**os.environ, "TINYP2P_GRANT_TTL": "3600000"},
    )
    log.close()
    for _ in range(300):
        try:
            ctl(url(who), "core.status", [])
            return process
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"{who} never came up")


def stop(processes):
    for process in processes.values():
        process.terminate()
    for process in processes.values():
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()


def bench_download(size, timeout=3600):
    """Send and save across two real daemons while sampling verified progress."""
    with tempfile.TemporaryDirectory(dir=WORK) as scratch:
        processes = {}
        try:
            for who in PORTS:
                processes[who] = spawn(scratch, who)
            workspace = ctl(
                url("alice"), "auth.workspace.create", ["alice"])
            invite = ctl(
                url("alice"), "auth.user_invite.create", [workspace])
            ctl(url("bob"), "auth.user.join", [invite, "bob"])
            input_path = source(os.path.join(scratch, "input"), size)

            peak = {who: 0.0 for who in PORTS}
            finished = threading.Event()

            def sample():
                while not finished.is_set():
                    for who, process in processes.items():
                        peak[who] = max(peak[who], rss_gb(process.pid))
                    finished.wait(0.05)

            sampler = threading.Thread(target=sample, daemon=True)
            sampler.start()
            start = now()
            ctl(
                url("alice"), "content.file.send",
                [workspace, "general", input_path, "big.bin"])
            sent = now()

            first = None
            deadline = time.time() + timeout
            while time.time() < deadline:
                rows = ctl(
                    url("bob"), "content.file.list", [workspace])
                if rows:
                    record = rows[0]
                    if first is None and record["have"]:
                        first = now()
                    if record["complete"]:
                        break
                time.sleep(0.05)
            else:
                have = record["have"] if rows else 0
                total = record["total"] if rows else "?"
                raise RuntimeError(f"timed out at {have}/{total} chunks")
            received = now()
            finished.set()
            sampler.join(timeout=2)

            output_path = os.path.join(scratch, "output")
            result = ctl(
                url("bob"), "content.file.save",
                [workspace, record["fid"], output_path])
            mb = size / 1e6
            return {
                "mb": mb,
                "chunks": record["total"],
                "send_mb_s": mb / (sent - start),
                "ttfvc_s": first - sent,
                "dl_s": received - sent,
                "dl_mb_s": mb / (received - sent),
                "wall_mb_s": mb / (received - start),
                "rss_send_gb": peak["alice"],
                "rss_recv_gb": peak["bob"],
                "ok": result["bytes"] == size
                and filecmp.cmp(input_path, output_path, shallow=False),
            }
        finally:
            stop(processes)


def print_rows(mode, sizes):
    if mode == "overhead":
        print("      MB  chunks  proof%   B/chunk  descr B  outboard MB  tree keys")
        for row in bench_overhead(sizes):
            print(
                f"{row['mb']:8.0f} {row['chunks']:7} "
                f"{row['proof_pct']:7.3f} {row['proof_per_chunk']:9} "
                f"{row['descriptor_b']:8} {row['outboard_mb']:12.2f} "
                f"{row['tree_keys']:10}")
        return
    if mode == "send":
        print("      MB  chunks   send s  send MB/s   save s  save MB/s"
              "  store MB  RSS GB  ok")
        for size in sizes:
            row = bench_send(size)
            print(
                f"{row['mb']:8.0f} {row['chunks']:7} {row['send_s']:8.2f} "
                f"{row['send_mb_s']:10.1f} {row['save_s']:8.2f} "
                f"{row['save_mb_s']:10.1f} {row['store_mb']:9.1f} "
                f"{row['peak_rss_gb']:7.2f} {'✓' if row['ok'] else '✗':>3}")
        return
    print("      MB  chunks  send MB/s  first s     dl s  dl MB/s"
          "  wall MB/s  RSS tx  RSS rx  ok")
    for size in sizes:
        row = bench_download(size)
        print(
            f"{row['mb']:8.0f} {row['chunks']:7} {row['send_mb_s']:10.1f} "
            f"{row['ttfvc_s']:8.2f} {row['dl_s']:8.2f} "
            f"{row['dl_mb_s']:8.1f} {row['wall_mb_s']:10.1f} "
            f"{row['rss_send_gb']:7.2f} {row['rss_recv_gb']:7.2f} "
            f"{'✓' if row['ok'] else '✗':>3}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sizes", nargs="*", type=int, help="sizes in MB")
    parser.add_argument(
        "--mode", choices=("overhead", "send", "download"),
        default="download")
    args = parser.parse_args(argv)
    os.makedirs(WORK, exist_ok=True)
    sizes = [
        mb * 1_000_000 for mb in (args.sizes or DEFAULT_SIZES)]
    print_rows(args.mode, sizes)


if __name__ == "__main__":
    main()
