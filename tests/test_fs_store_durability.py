"""Crash-point durability for the stronger local ObjectStore assumption."""
import os

import pytest

from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    RetryableStoreError,
)
from core.store import FsStore


class InjectedCrash(OSError):
    pass


def _restart(path):
    return FsStore(str(path))


def _immutable(value):
    return "obj/" + h(value)


def _seed_sibling(store):
    value = b"unrelated durable value"
    key = _immutable(value)
    assert store.put_if_absent(key, value) is CREATED
    return key, value


def _no_temps(path):
    assert not tuple(path.rglob("*.tmp"))


@pytest.mark.parametrize("phase", (
    "temp-create",
    "data-write",
    "file-fsync",
    "link-before",
))
def test_create_failure_before_linearization_keeps_absence_and_other_keys(
        tmp_path, monkeypatch, phase):
    store = FsStore(str(tmp_path))
    sibling_key, sibling = _seed_sibling(store)
    value = b"new immutable value"
    key = _immutable(value)

    if phase == "temp-create":
        monkeypatch.setattr(
            "core.store.tempfile.mkstemp",
            lambda **_kwargs: (_ for _ in ()).throw(
                InjectedCrash("temp create")))
    elif phase == "data-write":
        write = store._write_temp

        def written_then_lost(stream, raw):
            write(stream, raw)
            raise InjectedCrash("data write")
        monkeypatch.setattr(store, "_write_temp", written_then_lost)
    elif phase == "file-fsync":
        fsync = store._fsync_file

        def synced_then_lost(fd):
            fsync(fd)
            raise InjectedCrash("file fsync")

        monkeypatch.setattr(
            store, "_fsync_file", synced_then_lost)
    else:
        monkeypatch.setattr(
            "core.store.os.link",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("link before")))

    with pytest.raises(RetryableStoreError):
        store.put_if_absent(key, value)

    reopened = _restart(tmp_path)
    assert reopened.get(key) is None
    assert reopened.get(sibling_key) == sibling
    _no_temps(tmp_path)


@pytest.mark.parametrize("phase", (
    "link-after",
    "directory-fsync",
    "response-loss",
))
def test_create_failure_after_linearization_is_unknown_and_reconciles_new(
        tmp_path, monkeypatch, phase):
    store = FsStore(str(tmp_path))
    sibling_key, sibling = _seed_sibling(store)
    value = b"ambiguous immutable value"
    key = _immutable(value)

    if phase == "link-after":
        link = os.link

        def applied_then_lost(source, target):
            link(source, target)
            raise InjectedCrash("link response")

        monkeypatch.setattr("core.store.os.link", applied_then_lost)
    elif phase == "directory-fsync":
        monkeypatch.setattr(
            store, "_fsync_directory",
            lambda _directory: (_ for _ in ()).throw(
                InjectedCrash("directory fsync")))
    else:
        monkeypatch.setattr(
            store, "_after_durable_write",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("lost response")))

    with pytest.raises(OutcomeUnknown, match="create outcome unknown"):
        store.put_if_absent(key, value)

    reopened = _restart(tmp_path)
    assert reopened.get(key) == value
    assert reopened.get(sibling_key) == sibling
    # An exact retry reconciles without replacing the established object.
    assert reopened.put_if_absent(key, value) is EXISTS
    _no_temps(tmp_path)


@pytest.mark.parametrize("phase", (
    "temp-create",
    "data-write",
    "file-fsync",
    "replace-before",
))
def test_cas_failure_before_linearization_preserves_old_value(
        tmp_path, monkeypatch, phase):
    store = FsStore(str(tmp_path))
    sibling_key, sibling = _seed_sibling(store)
    assert isinstance(store.cas("removal", ABSENT, b"old"), Applied)
    token = store.read_versioned("removal").token

    if phase == "temp-create":
        monkeypatch.setattr(
            "core.store.tempfile.mkstemp",
            lambda **_kwargs: (_ for _ in ()).throw(
                InjectedCrash("temp create")))
    elif phase == "data-write":
        write = store._write_temp

        def written_then_lost(stream, raw):
            write(stream, raw)
            raise InjectedCrash("data write")
        monkeypatch.setattr(store, "_write_temp", written_then_lost)
    elif phase == "file-fsync":
        fsync = store._fsync_file

        def synced_then_lost(fd):
            fsync(fd)
            raise InjectedCrash("file fsync")

        monkeypatch.setattr(
            store, "_fsync_file", synced_then_lost)
    else:
        monkeypatch.setattr(
            "core.store.os.replace",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("replace before")))

    with pytest.raises(RetryableStoreError):
        store.cas("removal", token, b"new")

    reopened = _restart(tmp_path)
    assert reopened.get("removal") == b"old"
    assert reopened.get(sibling_key) == sibling
    _no_temps(tmp_path)


@pytest.mark.parametrize("phase", (
    "replace-after",
    "directory-fsync",
    "response-loss",
))
def test_cas_failure_after_linearization_is_unknown_and_reconciles_new(
        tmp_path, monkeypatch, phase):
    store = FsStore(str(tmp_path))
    sibling_key, sibling = _seed_sibling(store)
    assert isinstance(store.cas("removal", ABSENT, b"old"), Applied)
    token = store.read_versioned("removal").token

    if phase == "replace-after":
        replace = os.replace

        def applied_then_lost(source, target):
            replace(source, target)
            raise InjectedCrash("replace response")

        monkeypatch.setattr("core.store.os.replace", applied_then_lost)
    elif phase == "directory-fsync":
        monkeypatch.setattr(
            store, "_fsync_directory",
            lambda _directory: (_ for _ in ()).throw(
                InjectedCrash("directory fsync")))
    else:
        monkeypatch.setattr(
            store, "_after_durable_write",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("lost response")))

    with pytest.raises(OutcomeUnknown, match="replacement outcome unknown"):
        store.cas("removal", token, b"new")

    reopened = _restart(tmp_path)
    reconciled = reopened.read_versioned("removal")
    assert reconciled.value == b"new"
    assert reconciled.token.value == h(b"new")
    assert reopened.get(sibling_key) == sibling
    _no_temps(tmp_path)


def test_acknowledged_create_and_cas_survive_restart_and_collision(
        tmp_path):
    store = FsStore(str(tmp_path))
    immutable = b"acknowledged immutable"
    immutable_key = _immutable(immutable)
    assert store.put_if_absent(immutable_key, immutable) is CREATED
    assert isinstance(store.cas("removal", ABSENT, b"acknowledged"), Applied)
    assert store.put_if_absent("invite/collision", b"incumbent") is CREATED

    reopened = _restart(tmp_path)
    assert reopened.get(immutable_key) == immutable
    assert reopened.get("removal") == b"acknowledged"
    assert reopened.put_if_absent(
        "invite/collision", b"challenger") is EXISTS
    assert reopened.get("invite/collision") == b"incumbent"
    _no_temps(tmp_path)


def test_existing_create_crosses_directory_barrier_before_exists(
        tmp_path, monkeypatch):
    store = FsStore(str(tmp_path))
    value = b"concurrent equal immutable"
    key = _immutable(value)
    assert store.put_if_absent(key, value) is CREATED
    barriers = []
    fsync = store._fsync_directory

    def observed(directory):
        barriers.append(directory)
        fsync(directory)

    monkeypatch.setattr(store, "_fsync_directory", observed)
    assert store.put_if_absent(key, value) is EXISTS
    assert barriers == [os.path.dirname(store._p(key))]


@pytest.mark.parametrize("operation", ("create", "replace"))
def test_same_store_reread_completes_failed_directory_barrier(
        tmp_path, monkeypatch, operation):
    store = FsStore(str(tmp_path))
    if operation == "create":
        value = b"uncertain create"
        key = _immutable(value)
        store._makedirs(os.path.dirname(store._p(key)))
        invoke = lambda: store.put_if_absent(key, value)
    else:
        key, value = "removal", b"uncertain replacement"
        invoke = lambda: store.cas(key, ABSENT, value)
    fsync = store._fsync_directory
    calls = 0

    def fail_once(directory):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InjectedCrash("first directory barrier")
        fsync(directory)

    monkeypatch.setattr(store, "_fsync_directory", fail_once)
    with pytest.raises(OutcomeUnknown):
        invoke()

    # A caller may reconcile an unknown result only after this read has
    # successfully retried the containing-directory durability barrier.
    assert store.get_bounded(key, len(value)) == value
    assert calls == 2
    assert key not in store._uncertain_keys
