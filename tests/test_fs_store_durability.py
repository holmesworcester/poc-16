"""Crash-point durability for the stronger local ObjectStore assumption."""
import os
import builtins

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
        fsync = store._fsync_directory
        calls = 0

        def fail_replacement_barrier(directory):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise InjectedCrash("directory fsync")
            fsync(directory)

        monkeypatch.setattr(
            store, "_fsync_directory", fail_replacement_barrier)
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
    failure_call = 1 if operation == "create" else 2

    def fail_once(directory):
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise InjectedCrash("first directory barrier")
        fsync(directory)

    monkeypatch.setattr(store, "_fsync_directory", fail_once)
    with pytest.raises(OutcomeUnknown):
        invoke()

    # A caller may reconcile an unknown result only after this read has
    # successfully retried the containing-directory durability barrier.
    assert store.get_bounded(key, len(value)) == value
    assert calls == failure_call + 1
    assert key not in store._uncertain_keys


def test_fresh_store_first_read_persists_the_containing_directory(
        tmp_path, monkeypatch):
    store = FsStore(str(tmp_path))
    assert isinstance(store.cas("removal", ABSENT, b"visible"), Applied)
    reopened = FsStore(str(tmp_path))
    barriers = []
    fsync = reopened._fsync_directory

    def observed(directory):
        barriers.append(directory)
        fsync(directory)

    monkeypatch.setattr(reopened, "_fsync_directory", observed)
    assert reopened.get_bounded("removal", 7) == b"visible"
    assert barriers == [str(tmp_path)]


def test_temp_cleanup_failure_never_masks_typed_precommit_failure(
        tmp_path, monkeypatch):
    store = FsStore(str(tmp_path))
    value = b"cleanup preserves primary error"
    key = _immutable(value)
    monkeypatch.setattr(
        "core.store.os.link",
        lambda *_args: (_ for _ in ()).throw(
            InjectedCrash("link did not apply")))
    monkeypatch.setattr(
        "core.store.os.remove",
        lambda *_args: (_ for _ in ()).throw(
            InjectedCrash("temp cleanup")))

    with pytest.raises(RetryableStoreError, match="create did not commit"):
        store.put_if_absent(key, value)


@pytest.mark.parametrize("reader", ("has", "copy"))
@pytest.mark.parametrize("fresh", (False, True))
def test_streaming_and_existence_reads_complete_directory_barrier(
        tmp_path, monkeypatch, reader, fresh):
    store = FsStore(str(tmp_path))
    value = b"pile visible only after the namespace barrier"
    key = _immutable(value)
    store._makedirs(os.path.dirname(store._p(key)))
    fsync = store._fsync_directory
    calls = 0

    def fail_once(directory):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InjectedCrash("lost create barrier")
        fsync(directory)

    monkeypatch.setattr(store, "_fsync_directory", fail_once)
    with pytest.raises(OutcomeUnknown):
        store.put_if_absent(key, value)

    observed = _restart(tmp_path) if fresh else store
    barriers = []
    observed_fsync = observed._fsync_directory

    def record(directory):
        barriers.append(directory)
        observed_fsync(directory)

    monkeypatch.setattr(observed, "_fsync_directory", record)
    if reader == "has":
        assert observed.has(key)
    else:
        chunks = []
        assert observed.copy_pile_object(
            key[4:], len(value), chunks.append) == len(value)
        assert b"".join(chunks) == value
    assert barriers == [os.path.dirname(observed._p(key))]


@pytest.mark.parametrize("operation", ("create", "replacement"))
def test_failed_namespace_mutation_and_readback_is_typed_unknown(
        tmp_path, monkeypatch, operation):
    store = FsStore(str(tmp_path))
    primary = InjectedCrash("namespace response lost")
    secondary = InjectedCrash("readback unavailable")
    if operation == "create":
        value = b"ambiguous create with failed readback"
        key = _immutable(value)
        mutate = os.link

        def applied_then_lost(source, target):
            mutate(source, target)
            raise primary

        monkeypatch.setattr("core.store.os.link", applied_then_lost)
        invoke = lambda: store.put_if_absent(key, value)
    else:
        key = "removal"
        value = b"ambiguous replacement with failed readback"
        mutate = os.replace

        def applied_then_lost(source, target):
            mutate(source, target)
            raise primary

        monkeypatch.setattr("core.store.os.replace", applied_then_lost)
        invoke = lambda: store.cas(key, ABSENT, value)
    path_value = store._path_value
    failed = False

    def failed_once(*args):
        nonlocal failed
        if not failed:
            failed = True
            raise secondary
        return path_value(*args)

    monkeypatch.setattr(store, "_path_value", failed_once)

    with pytest.raises(OutcomeUnknown) as raised:
        invoke()
    assert raised.value.__cause__ is primary
    assert any("readback also failed" in note
               for note in raised.value.__notes__)
    assert key in store._uncertain_keys

    barriers = []
    fsync = store._fsync_directory

    def observed(directory):
        barriers.append(directory)
        fsync(directory)

    monkeypatch.setattr(store, "_fsync_directory", observed)
    assert store.get_bounded(key, len(value)) == value
    assert barriers == [os.path.dirname(store._p(key))]
    assert key not in store._uncertain_keys


@pytest.mark.parametrize("phase", ("mkdir", "parent-fsync"))
def test_directory_setup_failures_are_typed_precommit(
        tmp_path, monkeypatch, phase):
    store = FsStore(str(tmp_path))
    value = b"directory setup failure"
    key = _immutable(value)
    if phase == "mkdir":
        monkeypatch.setattr(
            "core.store.os.mkdir",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("mkdir")))
    else:
        monkeypatch.setattr(
            store, "_fsync_directory",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("parent fsync")))

    with pytest.raises(
            RetryableStoreError, match="directory setup did not commit"):
        store.put_if_absent(key, value)


@pytest.mark.parametrize("phase", ("open", "flock"))
def test_cas_lock_failures_are_typed_precommit(
        tmp_path, monkeypatch, phase):
    store = FsStore(str(tmp_path))
    if phase == "open":
        original_open = builtins.open

        def fail_lock(path, *args, **kwargs):
            if path == store._cas_lock:
                raise InjectedCrash("lock open")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", fail_lock)
    else:
        monkeypatch.setattr(
            "core.store.fcntl.flock",
            lambda *_args: (_ for _ in ()).throw(
                InjectedCrash("lock acquire")))

    with pytest.raises(
            RetryableStoreError, match="CAS lock did not commit"):
        store.cas("removal", ABSENT, b"never committed")
    assert not os.path.exists(store._p("removal"))
