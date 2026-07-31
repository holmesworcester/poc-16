"""Black-box daemon test: alice, bob, and carol run real daemons on real
sockets, talk through the CLI seam only, and sync is ongoing (cadence walks,
no manual sync calls). Covers join-by-invite-link, symmetric convergence,
large files as blobs, stragglers, eviction, and restart-with-wiped-index.
"""
import hashlib
import os
import random
import socket
import subprocess
import sys
import time
import urllib.error

import pytest
from full_peer.cli import ctl

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


PORTS = _free_ports(tuple(
    f"{who}-{kind}"
    for who in ("alice", "bob", "carol")
    for kind in ("data", "control")
))


def peer_url(who):
    return f"http://127.0.0.1:{PORTS[who + '-data']}"


def control_url(who):
    return f"http://127.0.0.1:{PORTS[who + '-control']}"


def command(who, path, *argv):
    """The one node-local control envelope used by CLI and tests alike."""
    return ctl(control_url(who), path, [str(value) for value in argv])


def spawn(tmp, who):
    log = open(tmp / f"{who}.log", "w")
    p = subprocess.Popen(
        [sys.executable, "-m", "full_peer", "daemon", str(tmp / who),
         "--port", str(PORTS[who + "-data"]),
         "--control-port", str(PORTS[who + "-control"]),
         "--url", peer_url(who), "--cadence", "0.3"],
        cwd=REPO, stdout=log, stderr=log,
        env={**os.environ, "TINYP2P_GRANT_TTL": "2000", "TINYP2P_DEBUG": "1"})
    wait_until(lambda: alive(who), 10, f"{who} daemon up")
    return p


def alive(who):
    try:
        command(who, "peer.status")
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
    return command(who, "peer.status")["workspaces"][ws]["root"]


def texts(who, ws):
    return [
        message["text"]
        for message in command(who, "content.message.list", ws)
    ]


def converged(ws, *whos):
    roots = {root_of(w, ws) for w in whos}
    return len(roots) == 1 and None not in roots


def test_alice_bob_carol(tmp_path):
    procs = {}
    try:
        for who in ("alice", "bob", "carol"):
            procs[who] = spawn(tmp_path, who)

        # -- malformed control requests fail closed without phantom state -----
        with pytest.raises(urllib.error.HTTPError) as unknown:
            command("alice", "peer.rebuild", "missing")
        assert unknown.value.code == 404
        assert command("alice", "peer.status")["workspaces"] == {}

        # -- create + invite + join ------------------------------------------
        ws = command("alice", "auth.workspace.create", "alice")
        with pytest.raises(urllib.error.HTTPError) as malformed:
            command("alice", "content.file.save", ws)
        assert malformed.value.code == 400
        link_b = command("alice", "auth.user_invite.create", ws)
        link_c = command("alice", "auth.user_invite.create", ws)
        assert command("bob", "auth.user.join", link_b, "bob") == ws
        assert command("carol", "auth.user.join", link_c, "carol") == ws

        # -- everyone talks; sync is ongoing (no manual sync anywhere) -------
        welcome = command(
            "alice", "content.message.post", ws, "general", "welcome")
        bob_message = command(
            "bob", "content.message.post", ws, "general", "hi from bob")
        command(
            "carol", "content.message.post", ws, "general", "hi from carol")
        wait_until(lambda: converged(ws, "alice", "bob", "carol"), 30, "3-way convergence")
        for who in ("alice", "bob", "carol"):
            assert set(texts(who, ws)) == {"welcome", "hi from bob", "hi from carol"}
            assert {
                member["name"]
                for member in command(who, "auth.user.list", ws)
            } == \
                {"alice", "bob", "carol"}

        command("bob", "content.message.post", ws, "general", "again")
        wait_until(lambda: "again" in texts("carol", ws) and
                   converged(ws, "alice", "bob", "carol"), 30, "ongoing sync")

        # -- large files as standalone blobs ---------------------------------
        big = random.Random(7).randbytes(3_000_000)
        big_path = tmp_path / "big.bin"
        big_path.write_bytes(big)
        fid = command(
            "alice", "content.file.send",
            ws, "general", big_path, "big.bin")
        small = random.Random(8).randbytes(100_000)
        small_path = tmp_path / "small.bin"
        small_path.write_bytes(small)
        fid2 = command(
            "bob", "content.file.send",
            ws, "general", small_path, "small.bin")

        def got_file(who, f, want):
            target = tmp_path / f"{who}-{f}.received"
            command(who, "content.file.save", ws, f, target)
            return hashlib.sha256(target.read_bytes()).digest() == \
                hashlib.sha256(want).digest()

        wait_until(lambda: got_file("bob", fid, big) and got_file("carol", fid, big),
                   45, "3MB file reaches bob and carol")
        wait_until(lambda: got_file("alice", fid2, small) and got_file("carol", fid2, small),
                   45, "bob's file reaches alice and carol")

        # -- real deletion route + CLI: owner and admin, message and file ----
        removed = subprocess.run(
            [sys.executable, "-m", "full_peer", "--node", control_url("alice"),
             "content.delete.remove", ws[:12], welcome],
            cwd=REPO, capture_output=True, text=True, timeout=30)
        assert removed.returncode == 0, removed.stderr
        refused = subprocess.run(
            [sys.executable, "-m", "full_peer", "--node", control_url("alice"),
             "content.delete.remove", ws[:12], "0" * 64],
            cwd=REPO, capture_output=True, text=True, timeout=30)
        assert refused.returncode == 1
        assert "full_peer: 400:" in refused.stderr
        assert "Traceback" not in refused.stderr
        command("alice", "content.delete.remove", ws, bob_message)
        command("bob", "content.delete.remove", ws, fid2)
        command("alice", "content.delete.remove", ws, fid)

        def deletions_visible(who):
            messages = texts(who, ws)
            files = {
                row["fid"]
                for row in command(who, "content.file.list", ws)
            }
            return "welcome" not in messages \
                and "hi from bob" not in messages \
                and fid not in files and fid2 not in files

        wait_until(
            lambda: all(
                deletions_visible(who)
                for who in ("alice", "bob", "carol"))
            and converged(ws, "alice", "bob", "carol"),
            45, "message and attachment deletions converge")
        with pytest.raises(urllib.error.HTTPError) as gone:
            command(
                "carol", "content.file.save",
                ws, fid, tmp_path / "removed.bin")
        assert gone.value.code == 400

        # -- straggler: an old-ts fact mini-folds into promoted history ------
        old = int(time.time() * 1000) - 48 * 3600 * 1000
        command(
            "carol", "content.message.post",
            ws, "general", "late", old)
        wait_until(lambda: "late" in texts("alice", ws) and
                   converged(ws, "alice", "bob", "carol"), 30, "straggler converges")

        # -- eviction: removal kills the mint; the door shuts ----------------
        command("alice", "auth.removal.evict", ws, "carol")
        wait_until(
            lambda: any(m["name"] == "carol" and m["evicted"]
                        for m in command("bob", "auth.user.list", ws)),
            30, "eviction reaches an authorized replica")
        time.sleep(2.5)  # let carol's cached grant expire: the designed
        # leakage window is exactly the grant TTL, nothing more
        wait_until(
            lambda: any(
                "HTTP Error 403" in failure["error"]
                or "not a workspace member" in failure["error"]
                for failure in command("carol", "peer.status")[
                    "workspaces"][ws]["sync_failures"]),
            10, "carol's sync authorization is refused")
        # ctl is a trusted node-local surface, not the remote auth boundary:
        # a replica that received its own eviction rejects here too; one that
        # missed it may keep writing an isolated store, but cannot deliver it.
        try:
            command(
                "carol", "content.message.post",
                ws, "general", "ghost")
        except urllib.error.HTTPError as local_rejection:
            assert local_rejection.code in {400, 403}
        time.sleep(4)  # several cadences prove it cannot cross the door
        assert "ghost" not in texts("alice", ws)
        assert "ghost" not in texts("bob", ws)
        command(
            "alice", "content.message.post",
            ws, "general", "after evict")
        wait_until(lambda: "after evict" in texts("bob", ws) and
                   converged(ws, "alice", "bob"), 30, "alice+bob still converge")

        # -- restart bob with a wiped index: rebuild from his own store ------
        procs["bob"].terminate()
        procs["bob"].wait(10)
        for f in (tmp_path / "bob" / "ws").glob("*.idx.db"):
            f.unlink()
        assert not (tmp_path / "bob" / "app.db").exists()
        procs["bob"] = spawn(tmp_path, "bob")
        assert "after evict" in texts("bob", ws)  # rebuilt read model, pre-walk
        assert deletions_visible("bob")
        command(
            "alice", "content.message.post",
            ws, "general", "post restart")
        wait_until(lambda: "post restart" in texts("bob", ws) and
                   converged(ws, "alice", "bob"), 30, "bob back after restart")

        # -- the actual CLI binary, end to end -------------------------------
        out = subprocess.run(
            [sys.executable, "-m", "full_peer", "--node", control_url("alice"),
             "content.message.list", ws[:12]],
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
