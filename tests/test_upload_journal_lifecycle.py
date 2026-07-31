"""Crash, concurrency, discovery, and collection of local sender state."""
from dataclasses import replace
import multiprocessing
import os
from pathlib import Path

import pytest

from deploy.upload_wire import UploadCapability
from full_peer.upload_journal import (
    UploadJournalError,
    UploadProgress,
    UploadSource,
)
import full_peer.upload_journal as journal


WORKSPACE = "a" * 64
MEMBER = "b" * 64
NOW = 7_000


class Crash(BaseException):
    pass


def build(root, pile=b"one closed pile"):
    return UploadSource.create(root, WORKSPACE, MEMBER, pile)


def progress(source, number=1, **changes):
    session = f"{number:032x}"
    expiry = NOW + number * 10_000
    value = UploadProgress(
        source.source_id,
        session,
        f"cursor_{number}",
        expiry,
        UploadCapability(
            f"https://bucket.example/pile/{session}",
            (("if-none-match", "*"),), expiry - 1),
    )
    return replace(value, **changes)


def _hold_writer(path, ready, release):
    with UploadSource.load(path).writer():
        ready.set()
        if not release.wait(10):
            raise RuntimeError("writer test timed out")


def _die_before_replace(path, value):
    source = UploadSource.load(path)
    journal.os.replace = lambda _old, _new: os._exit(23)
    source.advance(value)


def _die_during_create(root):
    original = journal._new
    calls = 0

    def write_then_die(path, raw):
        nonlocal calls
        original(path, raw)
        calls += 1
        if calls == 1:
            os._exit(24)

    journal._new = write_then_die
    UploadSource.create(root, WORKSPACE, MEMBER, b"one closed pile")


def _create_concurrently(root, barrier, results):
    barrier.wait(10)
    try:
        results.put(("ok", build(root).source_id))
    except BaseException as error:
        results.put(("error", repr(error)))


def test_create_is_atomic_content_addressed_and_deduplicates(tmp_path):
    root = tmp_path / "uploads"
    first = build(root)
    second = build(root)

    assert first.source_id == second.source_id
    assert first.verify_body() == b"one closed pile"
    assert {path.name for path in Path(first.path).iterdir()} \
        == {"pile", "source.json"}
    assert not (root / ".creating").exists()

    with open(first.body_path, "wb") as out:
        out.write(b"tampered")
    with pytest.raises(UploadJournalError, match="collision"):
        build(root)


def test_create_recovers_actual_hard_crash_after_first_fsync(tmp_path):
    root = tmp_path / "uploads"
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_die_during_create, args=(root,))
    process.start()
    process.join(10)
    if process.is_alive():
        process.kill()
        process.join()

    assert process.exitcode == 24
    assert (root / ".creating" / "pile").read_bytes() == b"one closed pile"
    assert not [path for path in root.iterdir() if len(path.name) == 64]

    source = build(root)

    assert source.verify_body() == b"one closed pile"
    assert not [path for path in root.iterdir()
                if path.name.startswith((".creating", ".building"))]


def test_concurrent_duplicate_create_converges_on_one_source(tmp_path):
    root = tmp_path / "uploads"
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(2), context.Queue()
    processes = [context.Process(
        target=_create_concurrently, args=(root, barrier, results),
    ) for _ in range(2)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join()

    outcomes = [results.get(timeout=2) for _ in processes]
    assert all(process.exitcode == 0 for process in processes)
    assert len(set(outcomes)) == 1
    assert outcomes[0][0] == "ok"
    assert [path.name for path in root.iterdir()
            if len(path.name) == 64] == [outcomes[0][1]]
    assert not (root / ".creating").exists()


def test_create_refuses_hostile_crash_slot_symlink(tmp_path):
    root, outside = tmp_path / "uploads", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    sentinel = outside / "keep"
    sentinel.write_bytes(b"untouched")
    (root / ".creating").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UploadJournalError, match="creation collision"):
        build(root)

    assert sentinel.read_bytes() == b"untouched"
    assert (root / ".creating").is_symlink()


def test_discovery_is_bounded_sorted_and_restart_safe(tmp_path):
    root = tmp_path / "uploads"
    sources = [build(root, f"pile-{index}".encode()) for index in range(3)]
    page = UploadSource.discover(root, NOW, limit=2)
    tail = UploadSource.discover(root, NOW, page.cursor, limit=2)

    assert page.cursor is not None and tail.cursor is None
    assert [row.source_id for row in (*page.uploads, *tail.uploads)] \
        == sorted(source.source_id for source in sources)
    assert all(row.state == "active" and not row.collectible
               for row in (*page.uploads, *tail.uploads))


def test_session_updates_are_atomic_monotone_and_restartable(tmp_path):
    source = build(tmp_path / "uploads")
    first = progress(source)
    source.advance(first)
    source.advance(first)
    second = progress(source, 2)
    source.advance(second)
    assert UploadSource.load(source.path).progress() == second

    done = replace(second, status="applied")
    source.advance(done)
    with pytest.raises(UploadJournalError, match="rollback"):
        source.advance(progress(source, 3))
    assert source.status(NOW).state == "completed"


def test_crash_before_replace_preserves_the_last_complete_session(tmp_path):
    source = build(tmp_path / "uploads")
    retained = progress(source)
    source.advance(retained)
    advanced = progress(source, 2)
    context = multiprocessing.get_context("spawn")

    process = context.Process(
        target=_die_before_replace, args=(source.path, advanced))
    process.start()
    process.join(10)
    if process.is_alive():
        process.kill()
        process.join()

    assert process.exitcode == 23
    assert source.progress() == retained
    source.advance(advanced)
    assert source.progress() == advanced
    assert not list(Path(source.path).glob(".session.json*"))


def test_writer_fence_is_cross_process_and_collection_never_races(tmp_path):
    source = build(tmp_path / "uploads")
    source.advance(progress(source))
    source.advance(replace(progress(source), status="noop"))
    context = multiprocessing.get_context("spawn")
    ready, release = context.Event(), context.Event()
    process = context.Process(
        target=_hold_writer, args=(source.path, ready, release))
    process.start()
    try:
        assert ready.wait(10)
        with pytest.raises(UploadJournalError, match="active"):
            UploadSource.collect(
                Path(source.path).parent, WORKSPACE, source.source_id, NOW)
    finally:
        release.set()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join()
    assert process.exitcode == 0


def test_abandonment_is_local_immediate_and_does_not_delete_bucket_data(
        tmp_path):
    root = tmp_path / "uploads"
    source = build(root)
    source.advance(progress(source))

    assert source.status(NOW).state == "active"
    abandoned = source.abandon(NOW)
    assert abandoned.state == "abandoned" and abandoned.collectible
    assert source.abandon(NOW) == abandoned
    assert UploadSource.collect(
        root, WORKSPACE, source.source_id, NOW) == source.source_id
    assert not Path(source.path).exists()


@pytest.mark.parametrize("status,state", [
    ("applied", "completed"),
    ("noop", "completed"),
    ("rejected", "rejected"),
])
def test_terminal_apply_results_are_collectible(tmp_path, status, state):
    source = build(tmp_path / status)
    source.advance(progress(source))
    source.advance(replace(progress(source), status=status))
    row = source.status(NOW)
    assert row.state == state and row.collectible
    assert UploadSource.collect(
        Path(source.path).parent, WORKSPACE, source.source_id, NOW)


def test_expiry_alone_is_not_completion_but_user_may_abandon(tmp_path):
    source = build(tmp_path / "uploads")
    lease = progress(source)
    source.advance(lease)
    row = source.status(lease.expires_at_ms)
    assert row.state == "expired" and not row.collectible
    with pytest.raises(UploadJournalError, match="not collectible"):
        UploadSource.collect(
            Path(source.path).parent, WORKSPACE, source.source_id,
            lease.expires_at_ms)
    assert source.abandon(lease.expires_at_ms).collectible


def test_hostile_files_and_workspace_confusion_fail_closed(tmp_path):
    root = tmp_path / "uploads"
    source = build(root)
    with open(source.body_path, "wb") as out:
        out.write(b"tampered")
    with pytest.raises(UploadJournalError, match="integrity"):
        UploadSource.load(source.path)

    with pytest.raises(UploadJournalError, match="workspace"):
        UploadSource.collect(
            root, "c" * 64, source.source_id, NOW)

    hostile = root / ("d" * 64)
    hostile.symlink_to(source.path, target_is_directory=True)
    with pytest.raises(UploadJournalError, match="unavailable"):
        UploadSource.load(hostile)
