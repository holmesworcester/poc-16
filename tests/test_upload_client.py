"""Running client refinement of the stateless direct-upload broker."""
import asyncio
from dataclasses import replace
from pathlib import Path
import random
from urllib.parse import unquote, urlsplit

import pytest

import facts
from full_peer import bao_native as bao
from core.close import encode_pile
from core.crypto import h
from full_peer.node import FullPeer
from core.staged_intent import (
    StagedObjectsPending,
    confirm_staged_object,
    decode_staged_pile,
    parse_staging_key,
)
from deploy.upload_broker import (
    AuthorizedPut,
    UploadBroker,
    UploadCapability,
)
from deploy.upload_client import (
    CREATED,
    UploadClient as RunningUploadClient,
    UploadCreateConflict,
    UploadOutcomeUnknown,
    UploadRetryable,
    UploadRollback,
)
from deploy.upload_journal import UploadSource, UploadSourceBuilder
from deploy.upload_session import (
    SessionKey,
    UploadSessionPolicy,
)
from core.http import AsyncFromSyncReader
from facts._commands import offer_source
from facts.auth import request
from facts.content import file as file_family
from facts.content import message as message_family


NOW = 2_000_000
KEY = SessionKey(
    "key00001", b"k" * 32, 0, NOW + 10_000_000)


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class Nonces:
    def __init__(self):
        self.count = 0

    def __call__(self, size):
        self.count += 1
        return self.count.to_bytes(size, "big")


class Signer:
    def __init__(self, provider, clock):
        self.provider_binding = f"fake-{provider}-ingress-v1"
        self.provider, self.clock, self.puts = provider, clock, []

    def sign(self, put):
        assert isinstance(put, AuthorizedPut)
        self.puts.append(put)
        return UploadCapability(
            "PUT",
            f"https://{self.provider}.example/{put.key}?signature=opaque",
            (
                ("content-length", str(put.size)),
                ("content-type", put.content_type),
                ("if-none-match", "*"),
            ),
            min(self.clock() + 60_000, put.not_after_ms),
        )


class DirectBroker:
    """The narrow transport executed in-process, as a fake endpoint would."""

    def __init__(self, broker):
        self.broker, self.issues = broker, []
        self.provider_origin = (
            f"https://{broker.signer.provider}.example")

    def open(self, proof, manifest, pile):
        return asyncio.run(self.broker.open(proof, manifest, pile))

    def issue(self, cursor, start, leaves, proof):
        self.issues.append((start, len(leaves)))
        return self.broker.issue(cursor, start, leaves, proof)

    def finalize(self, cursor):
        return self.broker.finalize(cursor)


class Crash(BaseException):
    pass


class FakeProvider:
    """Create-only S3/R2 behavior with deterministic failure injection."""

    def __init__(self, action=None):
        self.objects, self.calls, self.action = {}, [], action
        self.max_body = 0

    def put(self, capability, body, size):
        key = unquote(urlsplit(capability.url).path).lstrip("/")
        raw = body.read(size + 1)
        assert len(raw) == size
        self.calls.append(key)
        self.max_body = max(self.max_body, len(raw))
        action = self.action(self, key, raw) \
            if self.action is not None else None
        if action == "crash-before":
            raise Crash
        if action == "unknown-before":
            raise UploadOutcomeUnknown("before apply")
        if action == "retry":
            raise UploadRetryable("definitely not applied")
        if action in {"crash-after", "unknown-after"}:
            if key in self.objects:
                raise UploadCreateConflict("incumbent")
            self.objects[key] = raw
            if action == "crash-after":
                raise Crash
            raise UploadOutcomeUnknown("after apply")
        if action == "poison":
            self.objects[key] = b"poison"
            raise UploadCreateConflict("opaque incumbent")
        if key in self.objects:
            raise UploadCreateConflict("opaque incumbent")
        self.objects[key] = raw
        return CREATED


def UploadClient(source, broker, puts, now, **options):
    """Keep test call sites terse while retaining an independent origin."""
    return RunningUploadClient(
        source, broker, puts, now,
        provider_origin=getattr(
            broker, "provider_origin", "https://s3.example"),
        **options,
    )


def world(tmp_path, provider="s3", objects=()):
    clock, nonces = Clock(), Nonces()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    member = node.member_for(workspace)
    signer = Signer(provider, clock)
    policy = UploadSessionPolicy(
        f"fake-{provider}-broker-v1", KEY.key_id, (KEY,),
        ttl_ms=120_000, max_ttl_ms=120_000, clock_skew_ms=1_000)
    broker = DirectBroker(UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, signer, clock, policy, nonce=nonces))
    builder = UploadSourceBuilder(
        tmp_path / "uploads", workspace, member)
    for raw in objects:
        builder.add(raw)
    source = builder.finish(b'{"facts":[],"ws":"' + workspace.encode() + b'"}')

    def proof():
        now = clock()
        return encode_pile(request.payload(
            node, workspace, "upload", now + 60_000, now))

    return (
        node, workspace, member, clock, nonces, signer,
        broker, source, proof,
    )


@pytest.mark.parametrize("provider", ("s3", "r2"))
@pytest.mark.parametrize("count", (0, 2))
def test_fake_providers_receive_objects_first_and_exact_pile_last(
        tmp_path, provider, count):
    raw_objects = tuple(f"object-{index}".encode() for index in range(count))
    (
        _, workspace, member, clock, _, signer, broker, source, proof,
    ) = world(tmp_path, provider, raw_objects)
    bucket = FakeProvider()

    result = UploadClient(
        source, broker, bucket, clock, batch_size=1).run(proof)

    assert result.object_count == count
    assert len(bucket.objects) == count + 1
    addresses = [parse_staging_key(key) for key in bucket.calls]
    assert [address.object_class for address in addresses] == (
        ["obj"] * count + ["pile"])
    assert all(address.workspace == workspace for address in addresses)
    assert all(address.member in {None, member} for address in addresses)
    assert len({address.session for address in addresses}) == 1
    assert signer.puts[-1].object_class == "pile"
    intent = decode_staged_pile(
        workspace, bucket.calls[-1], bucket.objects[bucket.calls[-1]])
    assert intent.member == member


def test_4096_objects_use_random_bounded_batches_and_one_body_memory(
        tmp_path, monkeypatch):
    # Keep the scale test about protocol/request bounds; durability fsync is
    # exercised by the crash tests below.
    monkeypatch.setattr("deploy.upload_journal.os.fsync", lambda fd: None)
    objects = tuple(
        index.to_bytes(4, "big") for index in range(4_096))
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, "r2", objects)
    rng = random.Random(0xC1E17)
    bucket = FakeProvider()

    result = UploadClient(
        source, broker, bucket, clock,
        batch_size=lambda start, left: rng.randint(1, min(256, left)),
    ).run(proof)

    assert result.object_count == 4_096
    assert sum(size for _, size in broker.issues) == 4_096
    assert max(size for _, size in broker.issues) <= 256
    assert bucket.max_body == max(
        max(map(len, objects)), source.pile.size)
    assert source.progress().delivered_index == 4_096
    assert broker.issues[-1][0] + broker.issues[-1][1] == 4_096


def test_crash_after_issue_reissues_covered_authority_without_skipping(
        tmp_path):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"a", b"b"))
    first = True

    def crash_once(bucket, key, raw):
        nonlocal first
        if first:
            first = False
            return "crash-before"

    with pytest.raises(Crash):
        UploadClient(
            source, broker, FakeProvider(crash_once), clock).run(proof)
    retained = source.progress()
    assert retained.cursor_index == 2
    assert retained.delivered_index == 0

    bucket = FakeProvider()
    result = UploadClient(source, broker, bucket, clock).run(proof)

    assert result.session == retained.session
    assert broker.issues[-1] == (0, 2)
    assert source.progress().delivered_index == 2


@pytest.mark.parametrize("failure", ("unknown-before", "unknown-after"))
def test_timeout_before_retries_same_capability_but_after_apply_uses_new_session(
        tmp_path, failure):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    failed = False

    def once(bucket, key, raw):
        nonlocal failed
        if not failed:
            failed = True
            return failure

    result = UploadClient(
        source, broker, FakeProvider(once), clock).run(proof)

    assert nonces.count == (1 if failure == "unknown-before" else 2)
    assert result.session == f"{nonces.count:032x}"


def test_crash_after_apply_and_equal_precondition_restart_conservatively(
        tmp_path):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    failed = False
    bucket = FakeProvider()

    def crash_after(bucket, key, raw):
        nonlocal failed
        if not failed:
            failed = True
            return "crash-after"

    bucket.action = crash_after
    with pytest.raises(Crash):
        UploadClient(source, broker, bucket, clock).run(proof)
    old = source.progress().session
    bucket.action = None

    result = UploadClient(source, broker, bucket, clock).run(proof)

    assert result.session != old
    assert nonces.count == 2
    assert any(f"/{old}/" in key for key in bucket.objects)
    assert any(f"/{result.session}/" in key for key in bucket.objects)


def test_timeout_after_pile_apply_restarts_whole_session_safely(tmp_path):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path)
    failed = False

    def after_pile(bucket, key, raw):
        nonlocal failed
        if not failed:
            failed = True
            return "unknown-after"

    bucket = FakeProvider(after_pile)
    result = UploadClient(source, broker, bucket, clock).run(proof)

    assert nonces.count == 2
    assert result.session == f"{2:032x}"
    assert len(bucket.objects) == 2
    assert all(
        parse_staging_key(key).object_class == "pile"
        for key in bucket.objects)


def test_partial_success_persists_each_receipt_and_resumes_inside_cursor(
        tmp_path):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"a", b"b", b"c", b"d"))
    bucket = FakeProvider()

    def stop_on_third(bucket, key, raw):
        if len(bucket.objects) == 2:
            return "retry"

    bucket.action = stop_on_third
    with pytest.raises(UploadRetryable):
        UploadClient(
            source, broker, bucket, clock, put_attempts=2).run(proof)
    retained = source.progress()
    assert (retained.cursor_index, retained.delivered_index) == (4, 2)
    bucket.action = None

    UploadClient(source, broker, bucket, clock).run(proof)

    assert broker.issues[-1] == (2, 2)
    assert source.progress().delivered_index == 4


def test_rollback_response_is_rejected_without_clobbering_journal(
        tmp_path):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"a", b"b"))
    first = True

    def crash(bucket, key, raw):
        nonlocal first
        if first:
            first = False
            return "crash-before"

    with pytest.raises(Crash):
        UploadClient(source, broker, FakeProvider(crash), clock).run(proof)
    retained = source.progress()

    class Rollback:
        open = broker.open
        finalize = broker.finalize

        def issue(self, cursor, start, leaves, range_proof):
            return replace(
                broker.issue(cursor, start, leaves, range_proof),
                next_index=0,
            )

    with pytest.raises(UploadRollback):
        UploadClient(
            source, Rollback(), FakeProvider(), clock).run(proof)
    assert source.progress() == retained


def test_expired_session_opens_fresh_authority_from_same_source(
        tmp_path):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    first = True

    def crash(bucket, key, raw):
        nonlocal first
        if first:
            first = False
            return "crash-before"

    with pytest.raises(Crash):
        UploadClient(source, broker, FakeProvider(crash), clock).run(proof)
    old = source.progress()
    clock.value = old.expires_at_ms

    result = UploadClient(
        source, broker, FakeProvider(), clock).run(proof)

    assert nonces.count == 2
    assert result.session != old.session


def test_poisoned_incumbent_is_abandoned_not_mistaken_for_equal(
        tmp_path):
    (
        _, _, _, clock, nonces, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    poisoned = False

    def poison_once(bucket, key, raw):
        nonlocal poisoned
        if not poisoned:
            poisoned = True
            return "poison"

    result = UploadClient(
        source, broker, FakeProvider(poison_once), clock).run(proof)

    assert nonces.count == 2
    assert result.session == f"{2:032x}"


@pytest.mark.parametrize("field", ("workspace", "member", "session"))
def test_foreign_capability_binding_fails_before_provider_put(
        tmp_path, field):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(() if field == "member" else (b"one",)))

    class Foreign:
        open = broker.open

        def issue(self, cursor, start, leaves, range_proof):
            result = broker.issue(cursor, start, leaves, range_proof)
            if field == "member":
                return result
            grant = result.objects[0]
            address = parse_staging_key(
                unquote(urlsplit(grant.capability.url).path).lstrip("/"))
            values = {
                "workspace": address.workspace,
                "member": source.member,
                "session": address.session,
            }
            values[field] = {
                "workspace": "f" * 64,
                "member": "e" * 16,
                "session": "d" * 32,
            }[field]
            wrong = (
                "ingress/v1/workspaces/"
                f"{values['workspace']}/objects/{values['session']}/"
                f"{grant.leaf.digest}"
            )
            capability = replace(
                grant.capability,
                url=f"https://s3.example/{wrong}?signature=opaque")
            return replace(
                result,
                objects=(replace(grant, capability=capability),),
            )

        def finalize(self, cursor):
            result = broker.finalize(cursor)
            if field != "member":
                return result
            grant = result.pile
            address = parse_staging_key(
                unquote(urlsplit(grant.capability.url).path).lstrip("/"))
            wrong = (
                "ingress/v1/workspaces/"
                f"{address.workspace}/piles/{address.session}/"
                f"{'e' * 16}/{grant.leaf.digest}"
            )
            return replace(
                result,
                pile=replace(
                    grant,
                    capability=replace(
                        grant.capability,
                        url=f"https://s3.example/{wrong}?signature=opaque"),
                ),
            )

    bucket = FakeProvider()
    with pytest.raises(Exception, match="authority mismatch"):
        UploadClient(source, Foreign(), bucket, clock).run(proof)
    assert bucket.calls == []


@pytest.mark.parametrize(
    "host", ("broker.example", "127.0.0.1", "metadata.internal"))
def test_broker_cannot_redirect_upload_body_off_trusted_provider_origin(
        tmp_path, host):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"secret body",))

    class Redirect:
        provider_origin = broker.provider_origin
        open = broker.open
        finalize = broker.finalize

        def issue(self, cursor, start, leaves, range_proof):
            result = broker.issue(cursor, start, leaves, range_proof)
            grant = result.objects[0]
            parsed = urlsplit(grant.capability.url)
            capability = replace(
                grant.capability,
                url=f"https://{host}{parsed.path}?signature=opaque",
            )
            return replace(
                result,
                objects=(replace(grant, capability=capability),),
            )

    bucket = FakeProvider()
    with pytest.raises(Exception, match="invalid upload capability"):
        UploadClient(source, Redirect(), bucket, clock).run(proof)
    assert bucket.calls == []


def test_source_manifest_and_session_journal_are_separate_and_restartable(
        tmp_path):
    (
        _, _, _, clock, _, _, broker, source, proof,
    ) = world(tmp_path, objects=(b"one",))
    source_raw = (Path(source.path) / "source.json").read_bytes()
    first = True

    def crash(bucket, key, raw):
        nonlocal first
        if first:
            first = False
            return "crash-before"

    with pytest.raises(Crash):
        UploadClient(source, broker, FakeProvider(crash), clock).run(proof)
    reloaded = UploadSource.load(source.path)

    assert (Path(source.path) / "source.json").read_bytes() == source_raw
    assert reloaded.progress() == source.progress()
    assert reloaded.progress().cursor_index == 1
    assert reloaded.progress().delivered_index == 0


def test_real_message_and_multichunk_pile_derives_missing_bao_object(
        tmp_path):
    (
        node, workspace, member, clock, _, _, broker, _, proof,
    ) = world(tmp_path)
    path = tmp_path / "two-slices.bin"
    path.write_bytes(b"a" * (bao.WIDTH + 17))
    builder = UploadSourceBuilder(
        tmp_path / "real-upload", workspace, member)
    blobs = []
    descriptor, news, deps = file_family._prepare(
        node, workspace, "general", path, None, 10,
        lambda digest, raw: blobs.append((digest, raw)),
    )
    message, signed = message_family._author(
        node, workspace, "general", "attachment follows", 11)
    provider = offer_source(
        node, workspace, "member", message.body["pk"])
    news += [signed, message]
    deps.update({
        signed.fid: [],
        message.fid: [signed.fid, provider],
    })
    stream = node.sender(workspace).close(news, deps)
    # Deliberately spool only one of two available Bao proofs. Fact validity
    # and the pile marker are independent of detached byte completeness.
    assert len(blobs) == 2
    builder.add(blobs[0][1])
    source = builder.finish(node.sender(workspace).pack(stream))
    bucket = FakeProvider()

    UploadClient(source, broker, bucket, clock).run(proof)

    pile_key = bucket.calls[-1]
    intent = decode_staged_pile(
        workspace, pile_key, bucket.objects[pile_key])
    assert {fact.t for fact in intent.stream} >= {
        "msg", "file_bao", "chunk"}
    assert descriptor.fid in {fact.fid for fact in intent.stream}
    assert intent.blob_refs == tuple(sorted(digest for digest, _ in blobs))
    present = []
    missing = []
    for key in intent.object_keys:
        raw = bucket.objects.get(key)
        try:
            confirm_staged_object(intent, key, raw)
            present.append(key)
        except StagedObjectsPending:
            missing.append(key)
    assert len(present) == len(missing) == 1


def test_generic_family_commands_direct_upload_without_writable_daemon(
        tmp_path, monkeypatch):
    (
        node, workspace, _, clock, nonces, _, broker, _, _,
    ) = world(tmp_path)
    bucket = FakeProvider()
    path = tmp_path / "attachment.bin"
    path.write_bytes(b"x" * (bao.WIDTH + 5))

    def direct(source, broker_url, provider_origin, proof_factory):
        assert broker_url == "https://broker.example"
        assert provider_origin == "https://s3.example"
        return UploadClient(
            source, broker, bucket, clock).run(proof_factory)

    host_calls = []
    run_upload = node.run_upload

    def observed(source, broker_url, provider_origin, proof_factory):
        host_calls.append(source.source_id)
        return run_upload(
            source, broker_url, provider_origin, proof_factory)

    monkeypatch.setattr(node, "run_upload", observed)
    monkeypatch.setattr(
        "deploy.upload_client_http.run_http", direct)
    message = facts.invoke_command(
        node,
        "content.message.upload",
        [
            workspace, "general", "hello", "https://broker.example",
            "https://s3.example", "10",
        ],
    )
    attachment = facts.invoke_command(
        node,
        "content.file.upload",
        [
            workspace, "general", str(path), "https://broker.example",
            "https://s3.example",
        ],
    )

    assert message["objects"] == 0
    assert attachment["objects"] == 2
    assert host_calls == [message["upload"], attachment["upload"]]
    assert nonces.count == 2
    assert node.fact_of(workspace, message["fid"]) is None
    assert node.fact_of(workspace, attachment["fid"]) is None
    assert [parse_staging_key(key).object_class for key in bucket.calls] == [
        "pile", "obj", "obj", "pile"]
