"""Full-peer ``OPEN -> exact pile PUT -> FINALIZE`` state machine."""
from dataclasses import dataclass, replace
from enum import Enum
from typing import BinaryIO, Protocol
from urllib.parse import unquote, urlsplit

from core.staged_intent import SESSION_HEX_BYTES, staging_key
import deploy.upload_wire as wire
from deploy.upload_session import (
    MAX_SESSION_CLOCK_SKEW_MS,
    MAX_SESSION_TTL_MS,
    UploadLeaf,
    valid_cursor,
)
from full_peer.upload_journal import UploadProgress, UploadSource


DEFAULT_SESSION_RESTARTS = 3
DEFAULT_PUT_ATTEMPTS = 3


class UploadClientError(RuntimeError):
    pass


class UploadProtocolError(UploadClientError):
    pass


class UploadSessionRejected(UploadClientError):
    pass


class UploadCapabilityRejected(UploadClientError):
    pass


class UploadCreateConflict(UploadClientError):
    """The exact create-only PUT already has an incumbent."""


class UploadRetryable(UploadClientError):
    pass


class UploadOutcomeUnknown(UploadClientError):
    pass


class PutResult(Enum):
    CREATED = "created"


CREATED = PutResult.CREATED


class BrokerTransport(Protocol):
    def open(self, proof: bytes, pile: UploadLeaf) -> wire.OpenedUpload: ...

    def finalize(self, cursor: str) -> wire.FinalizedUpload: ...


class PutTransport(Protocol):
    def put(
            self, capability: wire.UploadCapability, body: BinaryIO,
            size: int) -> PutResult: ...


@dataclass(frozen=True, slots=True)
class UploadResult:
    source_id: str
    session: str
    pile_digest: str
    status: str


def _hex(value, length):
    return isinstance(value, str) and len(value) == length \
        and all(character in "0123456789abcdef" for character in value)


class UploadClient:
    """Persist one exact lease before PUT and one terminal apply result."""

    def __init__(
            self, source, broker, puts, now, *,
            put_attempts=DEFAULT_PUT_ATTEMPTS,
            session_restarts=DEFAULT_SESSION_RESTARTS,
            provider_origin):
        if not isinstance(source, UploadSource) \
                or not all(callable(getattr(broker, name, None))
                           for name in ("open", "finalize")) \
                or not callable(getattr(puts, "put", None)) \
                or not callable(now):
            raise TypeError("upload client dependency")
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
        self.provider_origin = (origin.scheme, origin.hostname, origin.port)
        self.put_attempts = put_attempts
        self.session_restarts = session_restarts

    def _now(self):
        value = self.now()
        if type(value) is not int or value < 0:
            raise UploadClientError("upload client clock")
        return value

    def _capability(self, grant, progress):
        if not isinstance(grant, wire.GrantedUpload) \
                or grant.leaf != self.source.pile:
            raise UploadProtocolError("broker changed upload pile")
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
                or any(name != name.lower() for name in names) \
                or headers.get("content-length") != str(self.source.pile.size) \
                or headers.get("content-type") != wire.UPLOAD_CONTENT_TYPE \
                or headers.get("if-none-match") != "*":
            raise UploadProtocolError("unsafe upload headers")
        key = staging_key(
            self.source.workspace,
            self.source.member,
            progress.session,
            "pile",
            self.source.pile.digest,
        )
        if not unquote(parsed.path).endswith("/" + key):
            raise UploadProtocolError("upload capability authority mismatch")
        return cap

    def _open(self, proof_factory, previous=None):
        proof = proof_factory() if callable(proof_factory) else proof_factory
        result = self.broker.open(proof, self.source.pile)
        now = self._now()
        if not isinstance(proof, bytes) \
                or not isinstance(result, wire.OpenedUpload) \
                or not _hex(result.session, SESSION_HEX_BYTES) \
                or not valid_cursor(result.cursor) \
                or type(result.expires_at_ms) is not int \
                or not now < result.expires_at_ms \
                <= now + MAX_SESSION_TTL_MS + MAX_SESSION_CLOCK_SKEW_MS:
            raise UploadProtocolError("invalid OPEN response")
        provisional = UploadProgress(
            self.source.source_id,
            result.session,
            result.cursor,
            result.expires_at_ms,
            result.pile.capability,
        )
        capability = self._capability(result.pile, provisional)
        progress = replace(provisional, capability=capability)
        if previous is None:
            self.source.save(progress)
        else:
            self.source.restart(progress)
        return progress

    def _put(self, progress):
        failure = None
        for _ in range(self.put_attempts):
            self.source.verify_body()
            try:
                with open(self.source.body_path, "rb") as body:
                    receipt = self.puts.put(
                        progress.capability, body, self.source.pile.size)
            except UploadCreateConflict:
                # The unique session key may be the successful first PUT whose
                # response was lost. FINALIZE performs the authoritative hash
                # check, so a conflict is safe to probe rather than restart.
                break
            except (UploadOutcomeUnknown, UploadRetryable) as error:
                failure = error
                continue
            if receipt is not CREATED:
                raise UploadProtocolError("invalid provider PUT receipt")
            break
        else:
            if failure is None:
                raise UploadRetryable("provider PUT did not complete")
            # FINALIZE distinguishes a successful lost response from a body
            # that is still absent. A retryable result keeps this lease live.
        progress = replace(progress, uploaded=True)
        self.source.save(progress)
        return progress

    def _finalize(self, progress):
        result = self.broker.finalize(progress.cursor)
        if not isinstance(result, wire.FinalizedUpload):
            raise UploadProtocolError("invalid FINALIZE response")
        if result.status == "retryable":
            raise UploadRetryable("recipient has not applied the exact pile")
        progress = replace(progress, status=result.status)
        self.source.save(progress)
        return progress

    def run(self, proof_factory):
        with self.source.writer():
            self.source.require_resumable()
            return self._run(proof_factory)

    def _run(self, proof_factory):
        restarts = 0
        progress = self.source.progress()
        if progress is not None and progress.status is not None:
            return self._result(progress)
        if progress is None:
            progress = self._open(proof_factory)
        elif progress.expires_at_ms <= self._now():
            progress = self._open(proof_factory, progress)
        while True:
            try:
                progress = self._put(progress)
                progress = self._finalize(progress)
            except (UploadCapabilityRejected, UploadSessionRejected):
                if restarts >= self.session_restarts:
                    raise
                restarts += 1
                progress = self._open(proof_factory, progress)
                continue
            return self._result(progress)

    def _result(self, progress):
        return UploadResult(
            self.source.source_id,
            progress.session,
            self.source.pile.digest,
            progress.status,
        )


__all__ = (
    "CREATED",
    "UploadCapabilityRejected",
    "UploadClient",
    "UploadCreateConflict",
    "UploadOutcomeUnknown",
    "UploadProtocolError",
    "UploadRetryable",
    "UploadSessionRejected",
)
