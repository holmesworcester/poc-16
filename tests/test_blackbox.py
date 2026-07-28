"""Black-box daemon test: alice, bob, and carol run real daemons on real
sockets, talk through the CLI seam only, and sync is ongoing (cadence walks,
no manual sync calls). Covers join-by-invite-link, symmetric convergence,
large files as blobs, stragglers, eviction, and restart-with-wiped-index.
"""
import base64
import hashlib
import os
import random
import socket
import subprocess
import sys
import time
import urllib.error

import pytest
from core.cli import ctl

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_ports(names):
    """OS-assigned ports instead of fixed numbers: concurrent suites on one
    machine collided on 17311-13 (the known flake). The daemon CLI cannot
    report a port-0 binding back, so bind-and-release is the closest the
    harness can get; all sockets are held open together so the answers are
    distinct."""
    socks = [socket.socket() for _ in names]
    try:
        for sock in socks:
            sock.bind(("127.0.0.1", 0))
        return {
            name: sock.getsockname()[1]
            for name, sock in zip(names, socks)}
    finally:
        for sock in socks:
            sock.close()


PORTS = _free_ports(("alice", "bob", "carol"))


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

        # -- malformed control requests fail closed without phantom state -----
        with pytest.raises(urllib.error.HTTPError) as unknown:
            ctl(url("alice"), "POST", "rebuild", {"ws": "missing"})
        assert unknown.value.code == 404
        assert ctl(url("alice"), "GET", "status")["workspaces"] == {}

        # -- create + invite + join ------------------------------------------
        ws = ctl(url("alice"), "POST", "create", {"name": "alice"})["ws"]
        with pytest.raises(urllib.error.HTTPError) as malformed:
            ctl(url("alice"), "GET", "file", ws=ws)
        assert malformed.value.code == 400
        link_b = ctl(url("alice"), "POST", "invite", {"ws": ws})["link"]
        link_c = ctl(url("alice"), "POST", "invite", {"ws": ws})["link"]
        assert ctl(url("bob"), "POST", "join", {"link": link_b, "name": "bob"})["ws"] == ws
        assert ctl(url("carol"), "POST", "join", {"link": link_c, "name": "carol"})["ws"] == ws

        # -- everyone talks; sync is ongoing (no manual sync anywhere) -------
        welcome = ctl(
            url("alice"), "POST", "post",
            {"ws": ws, "text": "welcome"})["fid"]
        bob_message = ctl(
            url("bob"), "POST", "post",
            {"ws": ws, "text": "hi from bob"})["fid"]
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

        # -- real deletion route + CLI: owner and admin, message and file ----
        removed = subprocess.run(
            [sys.executable, "-m", "core", "--node", url("alice"),
             "remove", "--ws", ws[:12], welcome],
            cwd=REPO, capture_output=True, text=True, timeout=30)
        assert removed.returncode == 0, removed.stderr
        refused = subprocess.run(
            [sys.executable, "-m", "core", "--node", url("alice"),
             "remove", "--ws", ws[:12], "0" * 64],
            cwd=REPO, capture_output=True, text=True, timeout=30)
        assert refused.returncode == 1
        assert "core: 400:" in refused.stderr
        assert "Traceback" not in refused.stderr
        ctl(url("alice"), "POST", "remove", {"ws": ws, "fid": bob_message})
        ctl(url("bob"), "POST", "remove", {"ws": ws, "fid": fid2})
        ctl(url("alice"), "POST", "remove", {"ws": ws, "fid": fid})

        def deletions_visible(who):
            messages = texts(who, ws)
            files = {row["fid"] for row in ctl(
                url(who), "GET", "files", ws=ws)}
            return "welcome" not in messages \
                and "hi from bob" not in messages \
                and fid not in files and fid2 not in files

        wait_until(
            lambda: all(deletions_visible(who) for who in PORTS)
            and converged(ws, *PORTS),
            45, "message and attachment deletions converge")
        with pytest.raises(urllib.error.HTTPError) as gone:
            ctl(url("carol"), "GET", "file", ws=ws, fid=fid)
        assert gone.value.code == 404

        # -- straggler: an old-ts fact mini-folds into promoted history ------
        old = int(time.time() * 1000) - 48 * 3600 * 1000
        ctl(url("carol"), "POST", "post", {"ws": ws, "text": "late", "ts": old})
        wait_until(lambda: "late" in texts("alice", ws) and
                   converged(ws, "alice", "bob", "carol"), 30, "straggler converges")

        # -- eviction: removal kills the mint; the door shuts ----------------
        ctl(url("alice"), "POST", "evict", {"ws": ws, "member": "carol"})
        wait_until(
            lambda: any(m["name"] == "carol" and m["evicted"]
                        for m in ctl(
                            url("bob"), "GET", "members", ws=ws)),
            30, "eviction reaches an authorized replica")
        time.sleep(2.5)  # let carol's cached grant expire: the designed
        # leakage window is exactly the grant TTL, nothing more
        wait_until(
            lambda: any(
                "HTTP Error 403" in failure["error"]
                for failure in ctl(url("carol"), "GET", "status")[
                    "workspaces"][ws]["sync_failures"]),
            10, "carol's remote mint is refused")
        # ctl is a trusted node-local surface, not the remote auth boundary:
        # a replica that received its own eviction rejects here too; one that
        # missed it may keep writing an isolated store, but cannot deliver it.
        try:
            ctl(url("carol"), "POST", "post", {"ws": ws, "text": "ghost"})
        except urllib.error.HTTPError as local_rejection:
            assert local_rejection.code == 403
        time.sleep(4)  # several cadences prove it cannot cross the door
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
        assert deletions_visible("bob")
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
