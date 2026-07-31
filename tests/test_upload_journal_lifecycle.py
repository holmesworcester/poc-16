"""Crash, concurrency, discovery, and collection for local upload state."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import threading

import pytest

import facts
from full_peer.node import FullPeer
from full_peer.upload_client import UploadRetryable
from full_peer.upload_journal import (
    UploadJournalError,
    UploadSource,
)
import full_peer.upload_journal as journal
from tests.test_upload_client import (
    Crash,
    FakeProvider,
    UploadClient,
    world,
)


def _node_source(node, workspace, pile, objects=()):
    builder = node.start_upload(workspace)
    for raw in objects:
        builder.add(raw)
    return builder.finish(pile)


def test_killed_upload_is_discoverable_after_restart_and_paginates(tmp_path):
    (
        node, workspace, _, clock, _, _, broker, _, proof,
    ) = world(tmp_path, objects=())
    first = _node_source(node, workspace, b'{"facts":[],"one":1}')
    second = _node_source(node, workspace, b'{"facts":[],"two":2}', (b"x",))
    crashed = False

    def kill_once(bucket, key, raw):
        nonlocal crashed
        if not crashed:
            crashed = True
            return "crash-before"

    with pytest.raises(Crash):
        UploadClient(
            first, broker, FakeProvider(kill_once), clock).run(proof)

    restarted = FullPeer(node.dir)
    restarted.now_ms = clock
    rows = facts.content.file.uploads(restarted, workspace)["uploads"]
    assert {row["source_id"] for row in rows} == {
        first.source_id, second.source_id}
    retained = next(
        row for row in rows if row["source_id"] == first.source_id)
    assert retained["state"] == "active"
    assert retained["cursor_index"] == retained["delivered_index"] == 0

    root = Path(node.dir) / "uploads"
    page = UploadSource.discover(root, clock(), limit=1)
    assert len(page.uploads) == 1 and page.cursor is not None
    tail = UploadSource.discover(root, clock(), page.cursor, limit=1)
    assert len(tail.uploads) == 1 and tail.cursor is None


def test_two_resume_commands_are_one_writer_and_one_delivery(tmp_path):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"a", b"b"))
    copies = (source, UploadSource.load(source.path))
    bucket = FakeProvider()
    entered, release = threading.Event(), threading.Event()
    real_open, opens = broker.open, 0

    def blocked_open(*args):
        nonlocal opens
        opens += 1
        entered.set()
        assert release.wait(5)
        return real_open(*args)

    broker.open = blocked_open
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            UploadClient(copies[0], broker, bucket, clock).run, proof)
        assert entered.wait(5)
        second = pool.submit(
            UploadClient(copies[1], broker, bucket, clock).run, proof)
        assert not second.done()
        assert opens == 1
        release.set()
        results = first.result(5), second.result(5)

    assert results[0] == results[1]
    assert opens == nonces.count == 1
    assert len(bucket.calls) == 3
    assert source.progress().pile_delivered


def test_abandonment_retains_every_issued_session_expiry(tmp_path):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    attempts = 0

    def restart_then_kill(bucket, key, raw):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            clock.value += 10_000
            return "poison"
        return "crash-before"

    with pytest.raises(Crash):
        UploadClient(
            source, broker, FakeProvider(restart_then_kill), clock).run(proof)
    progress = source.progress()
    assert nonces.count == 2
    assert progress.issued_until_ms == progress.expires_at_ms
    assert source.status(progress.expires_at_ms).state == "expired"

    status = source.abandon(clock())
    assert status.state == "abandoned"
    assert status.collect_after_ms == progress.issued_until_ms
    assert not status.collectible
    with pytest.raises(UploadJournalError, match="not collectible"):
        UploadSource.collect(
            Path(source.path).parent, source.workspace,
            source.source_id, clock())


def test_collection_refuses_partial_delivery_and_recovers_after_crash(
        tmp_path, monkeypatch):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    builder = journal.UploadSourceBuilder(
        Path(source.path).parent, source.workspace, source.member)
    sibling = builder.finish(b'{"facts":[],"sibling":true}')

    def fail_pile(bucket, key, raw):
        if "/piles/" in key:
            return "retry"

    with pytest.raises(UploadRetryable):
        UploadClient(
            source, broker, FakeProvider(fail_pile), clock,
            put_attempts=1).run(proof)
    assert source.progress().delivered_index == 1
    assert not source.progress().pile_delivered
    with pytest.raises(UploadJournalError, match="not collectible"):
        UploadSource.collect(
            Path(source.path).parent, source.workspace,
            source.source_id, clock())

    source.abandon(clock())
    clock.value = source.progress().issued_until_ms
    real_rmtree, failed = journal.shutil.rmtree, False

    def crash_during_delete(path):
        nonlocal failed
        if Path(path).name.startswith(".collecting-") and not failed:
            failed = True
            raise Crash
        return real_rmtree(path)

    monkeypatch.setattr(journal.shutil, "rmtree", crash_during_delete)
    with pytest.raises(Crash):
        UploadSource.collect(
            Path(source.path).parent, source.workspace,
            source.source_id, clock())
    assert not Path(source.path).exists()
    assert Path(sibling.path).exists()

    monkeypatch.setattr(journal.shutil, "rmtree", real_rmtree)
    assert UploadSource.collect(
        Path(source.path).parent, source.workspace,
        source.source_id, clock()) == source.source_id
    assert Path(sibling.path).exists()


def test_completed_collection_is_local_and_does_not_mutate_repository(
        tmp_path):
    (
        node, workspace, _, clock, _, _, broker, _, proof,
    ) = world(tmp_path)
    source = _node_source(node, workspace, b'{"facts":[],"done":true}')
    before = node.store(workspace).get_bounded("root", 1024 * 1024)

    UploadClient(source, broker, FakeProvider(), clock).run(proof)
    node.now_ms = clock
    row = facts.content.file.uploads(node, workspace)["uploads"][0]
    assert row["state"] == "completed"
    assert row["collectible"]
    assert facts.content.file.collect_upload(
        node, workspace, source.source_id) == source.source_id

    assert not Path(source.path).exists()
    assert node.store(workspace).get_bounded("root", 1024 * 1024) == before


def test_abandoned_source_cannot_resume(tmp_path):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path)
    source.abandon(clock())

    with pytest.raises(UploadJournalError, match="abandoned"):
        UploadClient(source, broker, FakeProvider(), clock).run(proof)


def test_journal_replace_is_crash_safe_and_cannot_move_cursor_backward(
        tmp_path, monkeypatch):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"a", b"b"))

    with pytest.raises(Crash):
        UploadClient(
            source, broker,
            FakeProvider(lambda bucket, key, raw: "crash-before"),
            clock,
        ).run(proof)
    retained = source.progress()
    stale = replace(retained, cursor_index=0)
    advanced = replace(retained, delivered_index=1)

    def crash_replace(source_path, target_path):
        raise Crash

    monkeypatch.setattr(journal.os, "replace", crash_replace)
    with pytest.raises(Crash):
        UploadSource.load(source.path).save(advanced)
    assert source.progress() == retained
    monkeypatch.undo()

    with pytest.raises(UploadJournalError, match="rollback"):
        UploadSource.load(source.path).save(stale)
    assert source.progress() == retained
