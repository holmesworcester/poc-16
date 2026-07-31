"""Full-peer crash-safe OPEN/ISSUE/FINALIZE delivery to exact provider PUTs."""
from dataclasses import dataclass, replace
from enum import Enum
from typing import BinaryIO, Protocol
from urllib.parse import unquote, urlsplit

from core.limits import PAGE_BATCH
from core.staged_intent import SESSION_HEX_BYTES, staging_key
import deploy.upload_wire as wire
from deploy.upload_session import (
    MAX_SESSION_CLOCK_SKEW_MS,
    MAX_SESSION_TTL_MS,
    UploadLeaf,
    UploadManifest,
    valid_cursor,
)
from full_peer.upload_journal import (
    UploadProgress,
    UploadSource,
)


DEFAULT_SESSION_RESTARTS = 3
DEFAULT_PUT_ATTEMPTS = 3


class UploadClientError(RuntimeError):
    pass


class UploadProtocolError(UploadClientError):
    pass


class UploadRollback(UploadProtocolError):
    pass


class UploadSessionRejected(UploadClientError):
    pass


class UploadCapabilityRejected(UploadClientError):
    pass


class UploadCreateConflict(UploadClientError):
    """A PUT-only client cannot prove that a create incumbent is equal."""


class UploadRetryable(UploadClientError):
    pass


class UploadOutcomeUnknown(UploadClientError):
    pass


class PutResult(Enum):
    CREATED = "created"


CREATED = PutResult.CREATED


class BrokerTransport(Protocol):
    def open(
            self, proof: bytes, manifest: UploadManifest,
            pile: UploadLeaf) -> wire.OpenedUpload: ...

    def issue(
            self, cursor: str, start: int, leaves: tuple[UploadLeaf, ...],
            proof: bytes) -> wire.IssuedUpload: ...

    def finalize(self, cursor: str) -> wire.FinalizedUpload: ...


class PutTransport(Protocol):
    def put(
            self, capability: wire.UploadCapability, body: BinaryIO,
            size: int) -> PutResult: ...


@dataclass(frozen=True)
class UploadResult:
    source_id: str
    session: str
    object_count: int
    pile_digest: str


def _hex(value, length):
    return isinstance(value, str) and len(value) == length \
        and all(c in "0123456789abcdef" for c in value)


class UploadClient:
    """Persist cursor authority before PUT and each receipt after PUT."""

    def __init__(
            self, source, broker, puts, now, *, batch_size=PAGE_BATCH,
            put_attempts=DEFAULT_PUT_ATTEMPTS,
            session_restarts=DEFAULT_SESSION_RESTARTS,
            provider_origin):
        if not isinstance(source, UploadSource) \
                or not all(callable(getattr(broker, name, None))
                           for name in ("open", "issue", "finalize")) \
                or not callable(getattr(puts, "put", None)) \
                or not callable(now):
            raise TypeError("upload client dependency")
        if not callable(batch_size) and (
                type(batch_size) is not int
                or not 1 <= batch_size <= PAGE_BATCH):
            raise ValueError("upload batch size")
        if type(put_attempts) is not int or put_attempts < 1 \
                or type(session_restarts) is not int or session_restarts < 0:
            raise ValueError("upload retry bound")
        origin = urlsplit(provider_origin)
        if origin.scheme != "https" or not origin.hostname \
                or origin.username is not None or origin.password is not None \
                or origin.path not in {"", "/"} \
                or origin.query or origin.fragment:
            raise ValueError("upload provider origin")
        self.source, self.broker, self.puts, self.now = (
            source, broker, puts, now)
        self.provider_origin = (
            origin.scheme, origin.hostname, origin.port)
        self.batch_size = batch_size
        self.put_attempts, self.session_restarts = (
            put_attempts, session_restarts)

    def _now(self):
        value = self.now()
        if type(value) is not int or value < 0:
            raise UploadClientError("upload client clock")
        return value

    def _batch_end(self, start, stop):
        size = self.batch_size(start, stop - start) \
            if callable(self.batch_size) else self.batch_size
        if type(size) is not int or not 1 <= size <= PAGE_BATCH:
            raise UploadClientError("upload batch policy")
        return min(stop, start + size)

    def _open(self, proof_factory, previous=None):
        proof = proof_factory() if callable(proof_factory) else proof_factory
        result = self.broker.open(
            proof, self.source.vector.manifest, self.source.pile)
        now = self._now()
        if not isinstance(proof, bytes) \
                or not isinstance(result, wire.OpenedUpload) \
                or not _hex(result.session, SESSION_HEX_BYTES) \
                or not valid_cursor(result.cursor) \
                or type(result.expires_at_ms) is not int \
                or not now < result.expires_at_ms \
                <= now + MAX_SESSION_TTL_MS + MAX_SESSION_CLOCK_SKEW_MS:
            raise UploadProtocolError("invalid OPEN response")
        issued_until = (
            None if previous is not None
            and previous.issued_until_ms is None
            else max(
                result.expires_at_ms,
                previous.issued_until_ms if previous is not None else 0,
            )
        )
        progress = UploadProgress(
            self.source.source_id, result.session, result.cursor,
            0, 0, result.expires_at_ms, issued_until)
        if previous is None:
            self.source.save(progress)
        else:
            self.source.restart(progress)
        return progress

    def _capability(self, grant, leaf, kind, progress):
        if not isinstance(grant, wire.GrantedUpload) or grant.leaf != leaf:
            raise UploadProtocolError("broker changed upload leaf")
        cap = grant.capability
        parsed = urlsplit(cap.url) if isinstance(
            cap, wire.UploadCapability) and isinstance(cap.url, str) else None
        if parsed is None or cap.method != "PUT" \
                or parsed.scheme != "https" or not parsed.hostname \
                or (parsed.scheme, parsed.hostname, parsed.port) \
                != self.provider_origin \
                or parsed.username is not None or parsed.password is not None \
                or parsed.fragment or type(cap.expires_at_ms) is not int \
                or not self._now() < cap.expires_at_ms \
                <= progress.expires_at_ms:
            raise UploadProtocolError("invalid upload capability")
        if not isinstance(cap.headers, tuple) or any(
                not isinstance(pair, tuple) or len(pair) != 2
                or not all(isinstance(value, str) for value in pair)
                for pair in cap.headers):
            raise UploadProtocolError("invalid upload headers")
        headers = dict(cap.headers)
        names = [pair[0] for pair in cap.headers]
        if names != sorted(names) or len(names) != len(set(names)) \
                or any(
                    name != name.lower()
                    for name, value in cap.headers) \
                or headers.get("content-length") != str(leaf.size) \
                or headers.get("content-type") != wire.UPLOAD_CONTENT_TYPE \
                or headers.get("if-none-match") != "*":
            raise UploadProtocolError("unsafe upload headers")
        key = staging_key(
            self.source.workspace, self.source.member, progress.session,
            kind, leaf.digest)
        if not unquote(parsed.path).endswith("/" + key):
            raise UploadProtocolError("upload capability authority mismatch")
        return cap

    def _put(self, capability, leaf, kind):
        path = self.source.body_path(leaf, kind)
        failure = None
        for _ in range(self.put_attempts):
            self.source._verify(path, leaf, kind)
            try:
                with open(path, "rb") as body:
                    receipt = self.puts.put(
                        capability, body, leaf.size)
            except (UploadOutcomeUnknown, UploadRetryable) as error:
                failure = error
                continue
            if receipt is not CREATED:
                raise UploadProtocolError("invalid provider PUT receipt")
            return
        raise failure

    def _issue(self, progress):
        count, start = (
            len(self.source.vector.leaves), progress.delivered_index)
        stop = progress.cursor_index if start < progress.cursor_index else count
        end = self._batch_end(start, stop)
        leaves = self.source.vector.leaves[start:end]
        result = self.broker.issue(
            progress.cursor, start, leaves,
            self.source.vector.proof(start, end))
        if not isinstance(result, wire.IssuedUpload) \
                or type(result.next_index) is not int:
            raise UploadProtocolError("invalid ISSUE response")
        if result.next_index < progress.cursor_index:
            raise UploadRollback("ISSUE response rolled back cursor")
        advancing = start == progress.cursor_index
        expected = end if advancing else progress.cursor_index
        if result.next_index != expected \
                or result.expires_at_ms != progress.expires_at_ms \
                or not valid_cursor(result.cursor) \
                or not advancing and result.cursor != progress.cursor \
                or not isinstance(result.objects, tuple) \
                or len(result.objects) != len(leaves):
            raise UploadProtocolError("ISSUE response changed session")
        if advancing:
            progress = replace(
                progress, cursor=result.cursor,
                cursor_index=result.next_index)
            self.source.save(progress)  # authority before any covered PUT
        capabilities = tuple(
            self._capability(grant, leaf, "obj", progress)
            for grant, leaf in zip(result.objects, leaves))
        for capability, leaf in zip(capabilities, leaves):
            self._put(capability, leaf, "obj")
            progress = replace(
                progress,
                delivered_index=progress.delivered_index + 1)
            self.source.save(progress)  # one receipt, one durable step
        return progress

    def _finalize(self, progress):
        result = self.broker.finalize(progress.cursor)
        if not isinstance(result, wire.FinalizedUpload) \
                or result.cursor != progress.cursor \
                or result.expires_at_ms != progress.expires_at_ms:
            raise UploadProtocolError("FINALIZE response changed session")
        capability = self._capability(
            result.pile, self.source.pile, "pile", progress)
        self._put(capability, self.source.pile, "pile")
        progress = replace(progress, pile_delivered=True)
        self.source.save(progress)
        return progress

    def run(self, proof_factory):
        """Upload bounded object batches, then the sole precommitted pile."""
        with self.source.writer():
            self.source.require_resumable()
            return self._run(proof_factory)

    def _run(self, proof_factory):
        restarts = 0
        progress = self.source.progress()
        if progress is None:
            progress = self._open(proof_factory)
        elif progress.expires_at_ms <= self._now() \
                and not progress.pile_delivered:
            progress = self._open(proof_factory, progress)
        while True:
            if progress.pile_delivered:
                return self._result(progress)
            try:
                while progress.delivered_index < len(
                        self.source.vector.leaves):
                    progress = self._issue(progress)
                if progress.cursor_index != len(self.source.vector.leaves):
                    raise UploadProtocolError("delivery exceeded authority")
                progress = self._finalize(progress)
            except (
                    UploadCapabilityRejected,
                    UploadCreateConflict,
                    UploadSessionRejected,
            ):
                if restarts >= self.session_restarts:
                    raise
                restarts += 1
                progress = self._open(proof_factory, progress)
                continue
            return self._result(progress)

    def _result(self, progress):
        return UploadResult(
            self.source.source_id, progress.session,
            len(self.source.vector.leaves), self.source.pile.digest)


__all__ = (
    "CREATED",
    "UploadCapabilityRejected",
    "UploadClient",
    "UploadCreateConflict",
    "UploadOutcomeUnknown",
    "UploadProtocolError",
    "UploadRetryable",
    "UploadRollback",
    "UploadSessionRejected",
)
