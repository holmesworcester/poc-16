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
    UploadSourceBuilder,
)
import full_peer.upload_journal as journal


WORKSPACE = "a" * 64
MEMBER = "b" * 16
NOW = 7_000


class Crash(BaseException):
    pass


def build(root, pile=b"one closed pile"):
    return UploadSourceBuilder(root, WORKSPACE, MEMBER).finish(pile)


def progress(source, number=1, **changes):
    session = f"{number:032x}"
    expiry = NOW + number * 10_000
    value = UploadProgress(
        source.source_id,
        session,
        f"cursor_{number}",
        expiry,
        UploadCapability(
            "PUT", f"https://bucket.example/pile/{session}",
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
    source.save(value)


def test_builder_is_atomic_content_addressed_and_deduplicates(tmp_path):
    root = tmp_path / "uploads"
    first = build(root)
    second = build(root)

    assert first.source_id == second.source_id
    assert first.verify_body() == b"one closed pile"
    assert {path.name for path in Path(first.path).iterdir()} \
        == {"pile", "source.json"}
    assert not list((root / ".building").iterdir())

    with open(first.body_path, "wb") as out:
        out.write(b"tampered")
    with pytest.raises(UploadJournalError, match="collision"):
        build(root)


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
    source.save(first)
    delivered = replace(first, uploaded=True)
    source.save(delivered)

    with pytest.raises(UploadJournalError, match="rollback"):
        source.save(first)
    second = progress(source, 2)
    source.restart(second)
    assert UploadSource.load(source.path).progress() == second

    done = replace(second, uploaded=True, status="applied")
    source.save(done)
    with pytest.raises(UploadJournalError, match="restart"):
        source.restart(progress(source, 3))
    assert source.status(NOW).state == "completed"


def test_crash_before_replace_preserves_the_last_complete_session(tmp_path):
    source = build(tmp_path / "uploads")
    retained = progress(source)
    source.save(retained)
    advanced = replace(retained, uploaded=True)
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
    source.save(advanced)
    assert source.progress() == advanced
    assert not list(Path(source.path).glob(".session.json*"))


def test_writer_fence_is_cross_process_and_collection_never_races(tmp_path):
    source = build(tmp_path / "uploads")
    source.save(replace(progress(source), uploaded=True, status="noop"))
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
    source.save(progress(source))

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
    source.save(replace(
        progress(source), uploaded=True, status=status))
    row = source.status(NOW)
    assert row.state == state and row.collectible
    assert UploadSource.collect(
        Path(source.path).parent, WORKSPACE, source.source_id, NOW)


def test_expiry_alone_is_not_completion_but_user_may_abandon(tmp_path):
    source = build(tmp_path / "uploads")
    lease = progress(source)
    source.save(lease)
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
