"""Crash/retry refinement tests for one exact-pile sender."""
from dataclasses import replace
import json
from urllib.parse import unquote, urlsplit

import pytest

from core.ingress import ingress_key
from core.fact import canon
from deploy.upload_wire import (
    FinalizedUpload,
    OpenedUpload,
    UploadCapability,
)
from full_peer.upload_client import (
    CREATED,
    UploadCapabilityRejected,
    UploadClient as RunningUploadClient,
    UploadCreateConflict,
    UploadOutcomeUnknown,
    UploadProtocolError,
    UploadRetryable,
    UploadSessionRejected,
)
from full_peer.upload_journal import UploadJournalError, UploadSource


NOW = 2_000_000
WORKSPACE = "a" * 64
MEMBER = "b" * 64


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class Broker:
    provider_origin = "https://s3.example"

    def __init__(self, source, clock):
        self.source, self.clock = source, clock
        self.opens, self.finalizes = [], []
        self.status, self.finalize_errors = "applied", []
        self.mutate_capability = None

    def open(self, proof, pile):
        self.opens.append(proof)
        count = len(self.opens)
        session = f"{count:032x}"
        key = ingress_key(
            self.source.workspace, session, self.source.member,
            pile.digest)
        capability = UploadCapability(
            f"https://s3.example/{key}?opaque=1",
            tuple(sorted((
                ("content-length", str(pile.size)),
                ("content-type", "application/octet-stream"),
                ("if-none-match", "*"),
            ))),
            self.clock() + 30_000,
        )
        if self.mutate_capability is not None:
            capability = self.mutate_capability(capability)
        return OpenedUpload(
            session, f"cursor_{count}", capability,
            self.clock() + 60_000)

    def finalize(self, cursor):
        self.finalizes.append(cursor)
        if self.finalize_errors:
            raise self.finalize_errors.pop(0)
        return FinalizedUpload(self.status)


class Provider:
    """Create-only bucket with replayable before/after-response faults."""

    def __init__(self, actions=()):
        self.actions, self.objects, self.calls = list(actions), {}, []

    def put(self, capability, body, size):
        key = unquote(urlsplit(capability.url).path).lstrip("/")
        raw = body.read(size + 1)
        assert len(raw) == size
        self.calls.append((key, raw))
        action = self.actions.pop(0) if self.actions else "create"
        if action == "retry":
            raise UploadRetryable("definitely absent")
        if action == "reject":
            raise UploadCapabilityRejected("expired grant")
        if action == "unknown-before":
            raise UploadOutcomeUnknown("response lost before create")
        if action == "unknown-after":
            self.objects.setdefault(key, raw)
            raise UploadOutcomeUnknown("response lost after create")
        if key in self.objects:
            raise UploadCreateConflict("incumbent")
        self.objects[key] = raw
        return CREATED


def source(tmp_path, pile=b'{"facts":[],"ws":"' + b"a" * 64 + b'"}'):
    return UploadSource.create(
        tmp_path / "uploads", WORKSPACE, MEMBER, pile)


def client(source, broker, provider, clock, **options):
    return RunningUploadClient(
        source, broker, provider, clock,
        provider_origin=broker.provider_origin,
        **options,
    )


def test_sender_puts_one_exact_immutable_pile_then_finalizes(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker, provider = Broker(upload, clock), Provider()

    result = client(upload, broker, provider, clock).run(b"proof")

    progress = upload.progress()
    assert result.status == "applied"
    assert len(provider.calls) == 1
    assert provider.calls[0][1] == upload.verify_body()
    assert broker.finalizes == [progress.cursor]
    assert progress.status == "applied"
    assert upload.status(clock()).collectible


def test_lost_put_response_replays_create_and_finalize_proves_digest(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker = Broker(upload, clock)
    provider = Provider(("unknown-after", "create"))

    result = client(upload, broker, provider, clock).run(lambda: b"proof")

    assert result.status == "applied"
    assert len(provider.calls) == 2
    assert len(provider.objects) == 1
    assert len(broker.opens) == 1
    assert len(broker.finalizes) == 1


def test_absent_or_delayed_pile_is_retryable_on_same_persisted_lease(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker = Broker(upload, clock)
    broker.status = "retryable"
    provider = Provider(("unknown-before", "unknown-before"))

    with pytest.raises(UploadRetryable):
        client(upload, broker, provider, clock, put_attempts=2).run(b"proof")
    retained = upload.progress()
    assert retained.status is None
    assert len(broker.opens) == 1

    broker.status = "applied"
    assert client(upload, broker, provider, clock).run(b"new proof").status \
        == "applied"
    assert len(broker.opens) == 1
    assert broker.finalizes == [retained.cursor, retained.cursor]


def test_rejected_capability_reopens_with_fresh_authority(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker = Broker(upload, clock)
    provider = Provider(("reject", "create"))
    proofs = iter((b"proof-1", b"proof-2"))

    result = client(upload, broker, provider, clock).run(lambda: next(proofs))

    assert result.session == f"{2:032x}"
    assert broker.opens == [b"proof-1", b"proof-2"]
    assert upload.progress().session == result.session


def test_rejected_finalize_reuploads_under_a_new_session(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker, provider = Broker(upload, clock), Provider()
    broker.finalize_errors = [UploadSessionRejected("expired")]

    result = client(upload, broker, provider, clock).run(b"proof")

    assert result.session == f"{2:032x}"
    assert len(provider.objects) == 2
    assert len(broker.opens) == 2


def test_expired_local_lease_reopens_without_server_queue_state(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker, provider = Broker(upload, clock), Provider()
    first = client(upload, broker, provider, clock)._open(b"proof")
    clock.value = first.expires_at_ms

    result = client(upload, broker, provider, clock).run(b"fresh proof")

    assert result.session != first.session
    assert broker.opens == [b"proof", b"fresh proof"]


def test_capability_must_bind_origin_headers_pile_and_exact_session_key(
        tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker = Broker(upload, clock)
    broker.mutate_capability = lambda cap: replace(
        cap, url=cap.url.replace("s3.example", "attacker.example"))

    with pytest.raises(UploadProtocolError, match="capability"):
        client(upload, broker, Provider(), clock).run(b"proof")
    assert upload.progress() is None


def test_terminal_result_is_idempotent_and_body_tampering_fails_closed(
        tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker, provider = Broker(upload, clock), Provider()
    first = client(upload, broker, provider, clock).run(b"proof")
    assert client(upload, broker, provider, clock).run(b"ignored") == first
    assert len(provider.calls) == len(broker.finalizes) == 1

    other = source(tmp_path / "other", b"different")
    # body_path is deliberately a plain path; mutate it as a hostile crash
    # artifact and prove no broker/provider effect follows.
    with open(other.body_path, "wb") as out:
        out.write(b"tampered")
    other_broker, other_provider = Broker(other, clock), Provider()
    with pytest.raises(UploadJournalError, match="integrity"):
        client(other, other_broker, other_provider, clock).run(b"proof")
    assert len(other_broker.opens) == 1
    assert not other_provider.calls and not other_broker.finalizes


def test_resumed_journal_cannot_redirect_the_exact_put(tmp_path):
    upload, clock = source(tmp_path), Clock()
    broker, provider = Broker(upload, clock), Provider()
    broker.status = "retryable"
    with pytest.raises(UploadRetryable):
        client(upload, broker, provider, clock, put_attempts=1).run(b"proof")

    document = json.loads(open(upload.session_path, "rb").read())
    document["capability"]["url"] = \
        "https://attacker.example/collect-the-pile"
    with open(upload.session_path, "wb") as out:
        out.write(canon(document))

    resumed = type(upload).load(upload.path)
    effects = Provider()
    with pytest.raises(UploadProtocolError, match="capability"):
        client(resumed, broker, effects, clock).run(b"unused")
    assert not effects.calls
