"""Black-box daemon test: alice, bob, and carol run real daemons on real
sockets, talk through the CLI seam only, and sync is ongoing (cadence walks,
no manual sync calls). Covers join-by-invite-link, symmetric convergence,
large files as blobs, stragglers, eviction, and restart-with-wiped-index.
"""
import base64
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
import urllib.request

import pytest

from core.cli import ctl

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"alice": 17311, "bob": 17312, "carol": 17313}


def url(who):
    return f"http://127.0.0.1:{PORTS[who]}"


def spawn(tmp, who):
    log = open(tmp / f"{who}.log", "w")
    p = subprocess.Popen(
        [sys.executable, "-m", "core", "daemon", str(tmp / who),
         "--port", str(PORTS[who]), "--cadence", "0.3"],
        cwd=REPO, stdout=log, stderr=log,
        env={**os.environ, "TINYP2P_GRANT_TTL": "2000", "TINYP2P_DEBUG": "1"})
    wait_until(lambda: alive(who), 10, f"{who} daemon up")
    return p


def alive(who):
    try:
        ctl(url(who), "GET", "status")
        return True
    except Exception:
        return False


def wait_until(pred, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise AssertionError(f"timed out waiting for {what}")


def root_of(who, ws):
    return ctl(url(who), "GET", "status")["workspaces"][ws]["root"]


def texts(who, ws):
    return [m["text"] for m in ctl(url(who), "GET", "msgs", ws=ws)]


def converged(ws, *whos):
    roots = {root_of(w, ws) for w in whos}
    return len(roots) == 1 and None not in roots


def test_alice_bob_carol(tmp_path):
    procs = {}
    try:
        for who in PORTS:
            procs[who] = spawn(tmp_path, who)

        # -- create + invite + join ------------------------------------------
        ws = ctl(url("alice"), "POST", "create", {"name": "alice"})["ws"]
        link_b = ctl(url("alice"), "POST", "invite", {"ws": ws})["link"]
        link_c = ctl(url("alice"), "POST", "invite", {"ws": ws})["link"]
        assert ctl(url("bob"), "POST", "join", {"link": link_b, "name": "bob"})["ws"] == ws
        assert ctl(url("carol"), "POST", "join", {"link": link_c, "name": "carol"})["ws"] == ws

        # -- everyone talks; sync is ongoing (no manual sync anywhere) -------
        ctl(url("alice"), "POST", "post", {"ws": ws, "text": "welcome"})
        ctl(url("bob"), "POST", "post", {"ws": ws, "text": "hi from bob"})
        ctl(url("carol"), "POST", "post", {"ws": ws, "text": "hi from carol"})
        wait_until(lambda: converged(ws, "alice", "bob", "carol"), 30, "3-way convergence")
        for who in PORTS:
            assert set(texts(who, ws)) == {"welcome", "hi from bob", "hi from carol"}
            assert {m["name"] for m in ctl(url(who), "GET", "members", ws=ws)} == \
                {"alice", "bob", "carol"}

        ctl(url("bob"), "POST", "post", {"ws": ws, "text": "again"})
        wait_until(lambda: "again" in texts("carol", ws) and
                   converged(ws, "alice", "bob", "carol"), 30, "ongoing sync")

        # -- large files as standalone blobs ---------------------------------
        big = random.Random(7).randbytes(3_000_000)
        fid = ctl(url("alice"), "POST", "send",
                  {"ws": ws, "name": "big.bin",
                   "data": base64.b64encode(big).decode()})["fid"]
        small = random.Random(8).randbytes(100_000)
        fid2 = ctl(url("bob"), "POST", "send",
                   {"ws": ws, "name": "small.bin",
                    "data": base64.b64encode(small).decode()})["fid"]

        def got_file(who, f, want):
            o = ctl(url(who), "GET", "file", ws=ws, fid=f)
            return hashlib.sha256(base64.b64decode(o["data"])).digest() == \
                hashlib.sha256(want).digest()

        wait_until(lambda: got_file("bob", fid, big) and got_file("carol", fid, big),
                   45, "3MB file reaches bob and carol")
        wait_until(lambda: got_file("alice", fid2, small) and got_file("carol", fid2, small),
                   45, "bob's file reaches alice and carol")

        # -- straggler: an old-ts fact mini-folds into promoted history ------
        old = int(time.time() * 1000) - 48 * 3600 * 1000
        ctl(url("carol"), "POST", "post", {"ws": ws, "text": "late", "ts": old})
        wait_until(lambda: "late" in texts("alice", ws) and
                   converged(ws, "alice", "bob", "carol"), 30, "straggler converges")

        # -- eviction: removal kills the mint; the door shuts ----------------
        ctl(url("alice"), "POST", "evict", {"ws": ws, "member": "carol"})
        wait_until(lambda: any(m["name"] == "carol" and m["evicted"]
                               for m in ctl(url("bob"), "GET", "members", ws=ws)),
                   30, "eviction reaches bob")
        time.sleep(2.5)  # let carol's cached grant expire: the designed
        # leakage window is exactly the grant TTL, nothing more
        ctl(url("carol"), "POST", "post", {"ws": ws, "text": "ghost"})
        time.sleep(4)  # several cadences: her mint is now refused
        assert "ghost" not in texts("alice", ws)
        assert "ghost" not in texts("bob", ws)
        ctl(url("alice"), "POST", "post", {"ws": ws, "text": "after evict"})
        wait_until(lambda: "after evict" in texts("bob", ws) and
                   converged(ws, "alice", "bob"), 30, "alice+bob still converge")

        # -- restart bob with a wiped index: rebuild from his own store ------
        procs["bob"].terminate()
        procs["bob"].wait(10)
        for f in (tmp_path / "bob" / "ws").glob("*.idx.db"):
            f.unlink()
        os.unlink(tmp_path / "bob" / "app.db")
        procs["bob"] = spawn(tmp_path, "bob")
        assert "after evict" in texts("bob", ws)  # rebuilt read model, pre-walk
        ctl(url("alice"), "POST", "post", {"ws": ws, "text": "post restart"})
        wait_until(lambda: "post restart" in texts("bob", ws) and
                   converged(ws, "alice", "bob"), 30, "bob back after restart")

        # -- the actual CLI binary, end to end -------------------------------
        out = subprocess.run(
            [sys.executable, "-m", "core", "--node", url("alice"),
             "msgs", "--ws", ws[:12]],
            cwd=REPO, capture_output=True, text=True, timeout=30)
        assert out.returncode == 0 and "post restart" in out.stdout
    finally:
        for p in procs.values():
            p.terminate()
        for p in procs.values():
            try:
                p.wait(5)
            except Exception:
                p.kill()
