"""Deterministic schedules over the shared-bucket Store test double."""
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.crypto import h
from core.object_store import CREATED, EXISTS, Applied, STALE

from .shared_bucket import InjectedCrash, ScriptedBucket


def test_two_root_cas_attempts_have_one_linearization_winner():
    bucket = ScriptedBucket({"root": b"root-0"})
    alice, bob = bucket.handle("alice"), bucket.handle("bob")
    base = alice.read_versioned("root").token
    paused = bucket.pause("alice", "cas", "root", when="before")

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(alice.cas, "root", base, b"root-a")
        paused.wait()
        b = pool.submit(bob.cas, "root", base, b"root-b")
        assert isinstance(b.result(), Applied)
        paused.release.set()
        assert a.result() is STALE

    assert alice.get("root") == b"root-b"
    assert bucket.assert_valid_history()


def test_delayed_object_visibility_means_not_written_yet():
    raw = b"immutable"
    key = "obj/" + h(raw)
    bucket = ScriptedBucket()
    alice, reader = bucket.handle("alice"), bucket.handle("reader")
    paused = bucket.pause(
        "alice", "put_if_absent", key, when="before")

    with ThreadPoolExecutor(max_workers=1) as pool:
        write = pool.submit(alice.put_if_absent, key, raw)
        paused.wait()
        assert reader.get(key) is None
        paused.release.set()
        assert write.result() is CREATED

    assert reader.get(key) == raw
    assert bucket.assert_valid_history()


def test_same_object_race_is_idempotent_and_replayable():
    raw = b"same bytes"
    key = "obj/" + h(raw)
    bucket = ScriptedBucket()
    alice, bob = bucket.handle("alice"), bucket.handle("bob")
    paused = bucket.pause(
        "alice", "put_if_absent", key, when="before")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(alice.put_if_absent, key, raw)
        paused.wait()
        second = pool.submit(bob.put_if_absent, key, raw)
        assert second.result() is CREATED
        paused.release.set()
        assert first.result() is EXISTS

    assert alice.get(key) == raw
    assert bucket.assert_valid_history()


def test_crash_boundaries_preserve_completed_atomic_operations_only():
    raw = b"orphan is harmless"
    key = "obj/" + h(raw)
    bucket = ScriptedBucket({"root": b"root-0"})
    writer = bucket.handle("writer")
    bucket.crash(
        "writer", "put_if_absent", key, when="after")

    with pytest.raises(InjectedCrash, match="after put_if_absent"):
        writer.put_if_absent(key, raw)
    assert writer.get(key) == raw
    assert writer.get("root") == b"root-0"

    bucket.crash("writer", "cas", "root", when="before")
    with pytest.raises(InjectedCrash, match="before cas"):
        writer.cas(
            "root", writer.read_versioned("root").token, b"root-1")
    assert writer.get("root") == b"root-0"
    assert bucket.assert_valid_history()


def test_authoritative_keys_reject_unconditional_or_bad_address_writes():
    bucket = ScriptedBucket()
    writer = bucket.handle("writer")

    with pytest.raises(ValueError, match="conditional"):
        writer.put("root", b"clobber")
    with pytest.raises(ValueError, match="conditional"):
        writer.put("obj/" + "0" * 64, b"clobber")
    with pytest.raises(ValueError, match="address"):
        writer.put_if_absent("obj/" + "0" * 64, b"wrong hash")
