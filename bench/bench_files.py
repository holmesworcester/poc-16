"""Attachment throughput benchmarks for tinyp2p.

Three questions, all answered against the *real* engine paths:

  overhead  What does self-proving cost? For each size: bao's proof bytes as
            a fraction of payload, the descriptor's size, and how many keys
            the fact tree gains. bao's commitment is 32 bytes regardless of
            file size; the price is paid per slice, on the wire.

  send      One node authors an attachment from a path: build the bao tree,
            extract and verify every 256 KiB slice, spill each to obj/, then
            publish descriptor + chunks as one closed pile. MB/s here is the
            author-side ceiling, and peak RSS is the memory question.

  download  Two real daemons on real sockets. Alice sends, Bob syncs, and we
            watch Bob's progress view — which counts only chunks whose bytes
            arrived AND proved against the signed root. Reports MB/s and
            time-to-first-verified-chunk, both from the receiver's side.

Sizes are decimal MB (10^6) so MB/s reads as it does everywhere else.

Run:   python3 bench/bench_files.py                    # 8/64/256 MB download
       python3 bench/bench_files.py 1024               # add the 1 GB run
       python3 bench/bench_files.py --mode overhead
       python3 bench/bench_files.py --mode send 1024
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinyp2p import bao, cmds
from tinyp2p.cli import ctl
from tinyp2p.facts.content import file as filefam
from tinyp2p.node import Node

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.environ.get("BENCH_DIR",
    "/mnt/storage/holmes-tmp/claude-1000/-home-holmes/"
    "0121ca08-243c-456a-9707-01258ff798ef/scratchpad/benchfiles")
PORTS = {"alice": 17511, "bob": 17512}
DEFAULT_SIZES = (8, 64, 256)

perf = time.perf_counter
url = lambda who: f"http://127.0.0.1:{PORTS[who]}"


def source(path, nbytes):
    """A deterministic incompressible source file, written once."""
    block, written = os.urandom(1 << 20), 0
    with open(path, "wb") as out:
        while written < nbytes:
            take = min(len(block), nbytes - written)
            out.write(block[:take])
            written += take
    return path


def rss_gb(pid):
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1e6
    except OSError:
        pass
    return 0.0


# ---- overhead ----------------------------------------------------------------

def bench_overhead(sizes):
    """What self-proving costs, per size, with no engine in the way."""
    out = []
    with tempfile.TemporaryDirectory(dir=WORK) as scratch:
        src = source(os.path.join(scratch, "src.bin"), max(sizes))
        outboard = os.path.join(scratch, "outboard")
        for nbytes in sizes:
            partial = os.path.join(scratch, "part.bin")
            with open(src, "rb") as fh, open(partial, "wb") as ph:
                shutil.copyfileobj(fh, ph, length=1 << 20)
                ph.truncate(nbytes)
            root = bao.prepare(partial, outboard)
            count = bao.geometry(nbytes)
            proof_bytes = sum(
                len(bao.proof(partial, outboard, i, nbytes))
                for i in range(count))
            descriptor = filefam.file(
                "a" * 64, "general", "x.bin", nbytes, root, count, 1)
            out.append({
                "mb": nbytes / 1e6, "chunks": count,
                "proof_pct": (proof_bytes - nbytes) / nbytes * 100 if nbytes else 0,
                "proof_per_chunk": (proof_bytes - nbytes) // count if count else 0,
                "descriptor_b": len(json.dumps(descriptor.to_json())),
                "outboard_mb": os.path.getsize(outboard) / 1e6,
                "tree_keys": 2 * count + 2,
            })
    return out


# ---- send --------------------------------------------------------------------

def bench_send(nbytes):
    """Author-side: prove the whole file, spill every slice, publish."""
    base = os.path.join(WORK, "send")
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    try:
        node = Node(os.path.join(base, "A"))
        ws = cmds.create(node, "alice")
        src = source(os.path.join(base, "src.bin"), nbytes)
        t0 = perf()
        fid = filefam.send(node, ws, "general", src, name="big.bin")
        t1 = perf()
        record = filefam.resolve(node, ws, fid)
        store = node.store(ws)
        objs = sum(len(store.get(k)) for k in store.list("obj/"))
        out = os.path.join(base, "out.bin")
        t2 = perf()
        filefam.save(node, ws, fid, out)
        t3 = perf()
        return {
            "mb": nbytes / 1e6, "chunks": record["total"],
            "send_s": t1 - t0, "send_mb_s": nbytes / 1e6 / (t1 - t0),
            "save_s": t3 - t2, "save_mb_s": nbytes / 1e6 / (t3 - t2),
            "store_mb": objs / 1e6, "peak_rss_gb": rss_gb(os.getpid()),
            "ok": os.path.getsize(out) == nbytes,
        }
    finally:
        shutil.rmtree(base, ignore_errors=True)


# ---- download ----------------------------------------------------------------

def spawn(base, who, log_dir):
    handle = open(os.path.join(log_dir, who + ".log"), "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "tinyp2p", "daemon", os.path.join(base, who),
         "--port", str(PORTS[who]), "--cadence", "0.2"],
        cwd=REPO, stdout=handle, stderr=handle,
        env={**os.environ, "TINYP2P_GRANT_TTL": "3600000"})
    for _ in range(300):
        try:
            ctl(url(who), "GET", "status")
            return proc
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"{who} never came up")


def bench_download(nbytes, timeout=3600):
    """Receiver-side: MB/s and time-to-first-verified-chunk, over real
    sockets, with progress read from the same view a user would see."""
    base = os.path.join(WORK, "dl")
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    procs = {}
    try:
        procs = {who: spawn(base, who, base) for who in PORTS}
        ws = ctl(url("alice"), "POST", "create", {"name": "alice"})["ws"]
        link = ctl(url("alice"), "POST", "invite", {"ws": ws})["link"]
        ctl(url("bob"), "POST", "join", {"link": link, "name": "bob"})
        src = source(os.path.join(base, "src.bin"), nbytes)

        peak = {who: 0.0 for who in PORTS}
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                for who, proc in procs.items():
                    peak[who] = max(peak[who], rss_gb(proc.pid))
                time.sleep(0.05)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()

        t0 = perf()
        ctl(url("alice"), "POST", "send",
            {"ws": ws, "path": src, "name": "big.bin"})
        t1 = perf()

        first, total, have = None, None, 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                rows = ctl(url("bob"), "GET", "files", ws=ws)
            except Exception:
                rows = []
            if rows:
                row = rows[0]
                total, have = row["total"], row["have"]
                if first is None and have > 0:
                    first = perf()
                if row["complete"]:
                    break
            time.sleep(0.05)
        else:
            raise RuntimeError(f"timed out at {have}/{total} chunks")
        t2 = perf()
        stop.set()
        sampler.join(timeout=2)

        got = ctl(url("bob"), "POST", "save",
                  {"ws": ws, "fid": rows[0]["fid"],
                   "out": os.path.join(base, "out.bin")})
        mb = nbytes / 1e6
        return {
            "mb": mb, "chunks": total,
            "send_s": t1 - t0, "send_mb_s": mb / (t1 - t0),
            "ttfvc_s": (first - t1) if first else float("nan"),
            "dl_s": t2 - t1, "dl_mb_s": mb / (t2 - t1),
            "wall_s": t2 - t0, "wall_mb_s": mb / (t2 - t0),
            "rss_send_gb": peak["alice"], "rss_recv_gb": peak["bob"],
            "ok": got["bytes"] == nbytes,
        }
    finally:
        stop_all(procs)
        shutil.rmtree(base, ignore_errors=True)


def stop_all(procs):
    for proc in procs.values():
        proc.terminate()
    for proc in procs.values():
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---- driver ------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sizes", nargs="*", type=int, help="sizes in MB")
    parser.add_argument("--mode", default="download",
                        choices=("overhead", "send", "download"))
    args = parser.parse_args(argv)
    os.makedirs(WORK, exist_ok=True)
    sizes = [n * 1_000_000 for n in (args.sizes or DEFAULT_SIZES)]

    if args.mode == "overhead":
        print(f"{'MB':>8} {'chunks':>7} {'proof%':>7} {'B/chunk':>9} "
              f"{'descr B':>8} {'outboard MB':>12} {'tree keys':>10}")
        for row in bench_overhead(sizes):
            print(f"{row['mb']:>8.0f} {row['chunks']:>7} {row['proof_pct']:>7.3f} "
                  f"{row['proof_per_chunk']:>9} {row['descriptor_b']:>8} "
                  f"{row['outboard_mb']:>12.2f} {row['tree_keys']:>10}")
        return

    if args.mode == "send":
        print(f"{'MB':>8} {'chunks':>7} {'send s':>8} {'send MB/s':>10} "
              f"{'save s':>8} {'save MB/s':>10} {'store MB':>9} {'RSS GB':>7} {'ok':>3}")
        for nbytes in sizes:
            row = bench_send(nbytes)
            print(f"{row['mb']:>8.0f} {row['chunks']:>7} {row['send_s']:>8.2f} "
                  f"{row['send_mb_s']:>10.1f} {row['save_s']:>8.2f} "
                  f"{row['save_mb_s']:>10.1f} {row['store_mb']:>9.1f} "
                  f"{row['peak_rss_gb']:>7.2f} {'✓' if row['ok'] else '✗':>3}")
        return

    print(f"{'MB':>8} {'chunks':>7} {'send MB/s':>10} {'ttfvc s':>8} "
          f"{'dl s':>8} {'dl MB/s':>8} {'wall MB/s':>10} "
          f"{'RSS tx':>7} {'RSS rx':>7} {'ok':>3}")
    for nbytes in sizes:
        row = bench_download(nbytes)
        print(f"{row['mb']:>8.0f} {row['chunks']:>7} {row['send_mb_s']:>10.1f} "
              f"{row['ttfvc_s']:>8.2f} {row['dl_s']:>8.2f} {row['dl_mb_s']:>8.1f} "
              f"{row['wall_mb_s']:>10.1f} {row['rss_send_gb']:>7.2f} "
              f"{row['rss_recv_gb']:>7.2f} {'✓' if row['ok'] else '✗':>3}")


if __name__ == "__main__":
    main()
