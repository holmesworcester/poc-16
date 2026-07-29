"""Credential-free design model for future direct bucket uploads.

This is explicitly a contract/problem-finding model, not proof of an upload
broker, database-free publisher, provider, or F10: those runtimes do not exist
yet. It composes the seeded history vocabulary from ``provider_conformance``
with F10's ``Obligation`` vocabulary. Its abstract durable-root events check
retirement ordering only. Future implementations must refine them through
``ObligationTrace`` and an authenticated, read-back root witness.
"""
import ast
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
from pathlib import Path
import random

from core.crypto import h
from tests.ingress_obligations import Obligation
from tests.provider_conformance import ConformanceRun, DEFAULT_SEED


MAX_CAPABILITY_CASES = 32
MAX_BROKER_ATTACKS = 8
MAX_NOTIFICATION_SCRIPTS = 16
MAX_NOTIFICATION_STEPS = 12
MAX_PROMOTION_CASES = 16
# A deliberately tiny execution budget for this corpus, not the protocol's
# object-size limit. Large-object compatibility is measured by x1p.17.10.
MAX_CORPUS_UPLOAD_BYTES = 4 * 1024 * 1024

SHA256 = "sha256"
REQUIRED_SIGNED_HEADERS = frozenset({
    "content-length",
    "content-type",
    "host",
    "if-none-match",
    # A symbolic signed condition, not the name or semantics of a provider
    # header. Each adapter must refine this to a live-tested raw-upload or
    # streaming-verifier mechanism that actually binds all body bytes.
    "abstract-body-sha256",
})
AUTHORITY_DIMENSIONS = frozenset({
    "provider",
    "endpoint",
    "operation",
    "bucket",
    "workspace",
    "member",
    "object-class",
    "key",
    "digest",
    "size",
    "content-type",
    "signed-headers",
    "expiry",
    "create-only",
    "body",
})
NOTIFICATION_FAULTS = frozenset({
    "drop",
    "duplicate",
    "delay",
    "reorder",
    "replay",
    "apply-then-lose-response",
    "pile-only-durable-work",
})


def _model_diagnostic(run):
    history = "\n".join(
        f"  {index + 1}. {event}"
        for index, event in enumerate(run.history)
    ) or "  <empty>"
    return (
        "direct-upload contract-model failure\n"
        f"candidate={run.provider}\nseed={run.seed:#x}\n"
        f"history:\n{history}"
    )


@contextmanager
def _model_capture(run):
    """Attach replay context without calling the model provider evidence."""
    try:
        yield run
    except BaseException as error:
        add_note = getattr(error, "add_note", None)
        if callable(add_note):
            add_note(_model_diagnostic(run))
        raise


def _key(workspace, member, object_class, digest):
    prefix = f"workspaces/{workspace}/"
    if object_class == "obj":
        return prefix + "obj/" + digest
    if object_class == "pile":
        return prefix + f"pile/{member}/" + digest
    return prefix + object_class + "/" + digest


@dataclass(frozen=True)
class UploadCapability:
    provider: str
    endpoint: str
    operation: str
    bucket: str
    workspace: str
    member: str
    object_class: str
    key: str
    digest: str
    size: int
    content_type: str
    signed_headers: frozenset[str]
    expires_at: int
    create_only: bool
    checksum_algorithm: str = SHA256


@dataclass(frozen=True)
class UploadRequest:
    provider: str
    endpoint: str
    operation: str
    bucket: str
    workspace: str
    member: str
    object_class: str
    key: str
    digest: str
    size: int
    content_type: str
    signed_headers: frozenset[str]
    now: int
    create_only: bool
    checksum_algorithm: str
    body: bytes


@dataclass(frozen=True)
class CapabilityMutation:
    name: str
    dimensions: frozenset[str]
    request: UploadRequest
    expect_authorized: bool = False


@dataclass(frozen=True)
class UploadResult:
    status: str
    authorized: bool
    applied: bool


@dataclass(frozen=True)
class CapabilityReport:
    provider: str
    seed: int
    mutations: tuple[str, ...]


class CapabilityViolation(AssertionError):
    def __init__(self, run, mutation, reason):
        self.seed = run.seed
        self.mutation = mutation
        self.reason = reason
        self.prefix = tuple(run.history)
        super().__init__(
            f"first unsupported capability result: {mutation.name}: "
            f"{reason}\n{_model_diagnostic(run)}")


def exact_capability(
        provider, object_class, body, *,
        workspace="a" * 64, member="b" * 16, now=1_000):
    """One fully attenuated grant; provider signing is intentionally abstract."""
    if provider == "s3":
        endpoint = "https://s3.us-west-2.amazonaws.com"
    elif provider == "r2":
        endpoint = "https://" + "c" * 32 \
            + ".r2.cloudflarestorage.com"
    else:
        raise ValueError("provider")
    digest = h(body)
    return UploadCapability(
        provider,
        endpoint,
        "PUT",
        "direct-upload-bucket",
        workspace,
        member,
        object_class,
        _key(workspace, member, object_class, digest),
        digest,
        len(body),
        "application/octet-stream",
        REQUIRED_SIGNED_HEADERS,
        now + 60,
        True,
    )


def exact_request(capability, body, *, now=1_000):
    return UploadRequest(
        capability.provider,
        capability.endpoint,
        capability.operation,
        capability.bucket,
        capability.workspace,
        capability.member,
        capability.object_class,
        capability.key,
        capability.digest,
        capability.size,
        capability.content_type,
        capability.signed_headers,
        now,
        capability.create_only,
        capability.checksum_algorithm,
        body,
    )


def capability_mutations(capability, request, seed=DEFAULT_SEED):
    """Return bounded, constraint-preserving authority mutations."""
    wrong_body = (
        bytes([request.body[0] ^ 1]) + request.body[1:]
        if request.body else None
    )
    substitute_body = request.body + b"!"
    other_digest = h(substitute_body)
    other_workspace = "d" * 64
    other_member = "e" * 16
    alternate_class = "pile" \
        if request.object_class == "obj" else "obj"
    sibling = request.key.rsplit("/", 1)[0] + "/" + "f" * 64
    cases = [
        CapabilityMutation(
            "provider", frozenset({"provider"}),
            replace(request, provider=(
                "r2" if request.provider == "s3" else "s3"))),
        CapabilityMutation(
            "endpoint", frozenset({"endpoint"}),
            replace(request, endpoint="https://cached.example.invalid")),
        CapabilityMutation(
            "operation", frozenset({"operation"}),
            replace(request, operation="DELETE")),
        CapabilityMutation(
            "bucket", frozenset({"bucket"}),
            replace(request, bucket="another-bucket")),
        CapabilityMutation(
            "workspace", frozenset({"workspace"}),
            replace(request, workspace=other_workspace)),
        CapabilityMutation(
            "member", frozenset({"member"}),
            replace(request, member=other_member)),
        CapabilityMutation(
            "object-class", frozenset({"object-class"}),
            replace(request, object_class=alternate_class)),
        CapabilityMutation(
            "key", frozenset({"key"}),
            replace(request, key=sibling)),
        CapabilityMutation(
            "root-key", frozenset({"key", "object-class"}),
            replace(request, key=(
                f"workspaces/{request.workspace}/root"),
                object_class="root")),
        CapabilityMutation(
            "digest", frozenset({"digest"}),
            replace(request, digest="0" * 64)),
        CapabilityMutation(
            "size", frozenset({"size"}),
            replace(request, size=request.size + 1)),
        CapabilityMutation(
            "content-type", frozenset({"content-type"}),
            replace(request, content_type="text/plain")),
        CapabilityMutation(
            "missing-signed-condition", frozenset({"signed-headers"}),
            replace(
                request,
                signed_headers=request.signed_headers - {"if-none-match"})),
        CapabilityMutation(
            "extra-signed-constraint", frozenset({"signed-headers"}),
            replace(
                request,
                signed_headers=request.signed_headers | {"x-extra-auth"}),
            expect_authorized=True),
        CapabilityMutation(
            "expired", frozenset({"expiry"}),
            replace(request, now=capability.expires_at + 1)),
        CapabilityMutation(
            "condition", frozenset({"create-only"}),
            replace(request, create_only=False)),
        CapabilityMutation(
            "body-binding-algorithm", frozenset({"body"}),
            replace(request, checksum_algorithm="unsigned")),
        CapabilityMutation(
            "body-checksum-substitution",
            frozenset({"body", "digest", "key", "size"}),
            replace(
                request,
                body=substitute_body,
                digest=other_digest,
                size=len(substitute_body),
                key=_key(
                    request.workspace, request.member,
                    request.object_class, other_digest))),
        CapabilityMutation(
            "workspace-key-swap",
            frozenset({"workspace", "key"}),
            replace(
                request,
                workspace=other_workspace,
                key=_key(
                    other_workspace, request.member,
                    request.object_class, request.digest))),
        CapabilityMutation(
            "member-key-swap",
            frozenset({"member", "key"}),
            replace(
                request,
                member=other_member,
                key=_key(
                    request.workspace, other_member,
                    request.object_class, request.digest))),
    ]
    if wrong_body is not None:
        cases.append(CapabilityMutation(
            "key-body-mismatch", frozenset({"body"}),
            replace(request, body=wrong_body)))
    if len(cases) > MAX_CAPABILITY_CASES:
        raise AssertionError("capability corpus budget")
    random.Random(seed ^ 0xD1EC7).shuffle(cases)
    return tuple(cases)


@dataclass(frozen=True)
class UploadImplementation:
    """Candidate semantics, not evidence of any provider's implementation."""

    name: str = "exact"
    path: str = "raw-presigned"
    body_binding: str = SHA256
    ignored: frozenset[str] = frozenset()
    prefix_keys: bool = False
    overwrite_existing: bool = False

    def execute(
            self, capability, request, store, *, lose_response=False):
        authorized = self._authorized(capability, request)
        if not authorized:
            return UploadResult("rejected", False, False)
        address = (
            request.provider, request.endpoint,
            request.bucket, request.key)
        incumbent = store.get(address)
        if incumbent is not None:
            if incumbent == request.body:
                return UploadResult(
                    "precondition-failed"
                    if self.path == "raw-presigned" else "equal-replay",
                    True,
                    False,
                )
            if not self.overwrite_existing:
                return UploadResult(
                    "precondition-failed"
                    if self.path == "raw-presigned" else "collision",
                    True,
                    False,
                )
        store[address] = request.body
        return UploadResult(
            "outcome-unknown" if lose_response else "created",
            True,
            True)

    def _authorized(self, capability, request):
        dimensions = {
            "provider": request.provider == capability.provider,
            "endpoint": request.endpoint == capability.endpoint,
            "operation": request.operation == capability.operation == "PUT",
            "bucket": request.bucket == capability.bucket,
            "workspace": request.workspace == capability.workspace,
            "member": request.member == capability.member,
            "object-class": (
                request.object_class == capability.object_class),
            "key": request.key == capability.key,
            "digest": request.digest == capability.digest,
            "size": (
                request.size == capability.size
                and len(request.body) == capability.size),
            "content-type": (
                request.content_type == capability.content_type),
            "signed-headers": (
                capability.signed_headers <= request.signed_headers
                and REQUIRED_SIGNED_HEADERS <= request.signed_headers),
            "expiry": request.now <= capability.expires_at,
            "create-only": (
                request.create_only is capability.create_only is True),
            "body": (
                h(request.body) == capability.digest
                and request.checksum_algorithm == SHA256
                and capability.checksum_algorithm == SHA256),
        }
        if self.prefix_keys:
            dimensions["key"] = request.key.startswith(
                capability.key.rsplit("/", 1)[0] + "/")
        return all(
            allowed or dimension in self.ignored
            for dimension, allowed in dimensions.items())


def _capability_failure(run, mutation, reason):
    run.record(f"capability {mutation.name}", reason)
    raise CapabilityViolation(run, mutation, reason)


def exercise_capability_corpus(
        implementation, capability, request, run):
    """Check exact attenuation and immutable state after every result."""
    with _model_capture(run):
        if len(request.body) > MAX_CORPUS_UPLOAD_BYTES:
            raise ValueError(
                "direct-upload corpus input exceeds its execution budget")
        profile = CapabilityMutation(
            "implementation-profile",
            frozenset({"body"}),
            request)
        if implementation.body_binding != SHA256:
            _capability_failure(
                run, profile,
                f"{implementation.body_binding} is not SHA-256 body binding")
        if implementation.path not in {
                "raw-presigned", "upload-verifier"}:
            _capability_failure(
                run, profile,
                f"unmodeled upload path {implementation.path}")

        address = (
            request.provider, request.endpoint,
            request.bucket, request.key)
        store = {}
        result = implementation.execute(capability, request, store)
        if not result.authorized or store != {address: request.body}:
            _capability_failure(run, profile, "exact request did not create")
        run.record("exact request", result.status)

        before = dict(store)
        replay = implementation.execute(capability, request, store)
        expected_replay = (
            "precondition-failed"
            if implementation.path == "raw-presigned"
            else "equal-replay"
        )
        if replay.status != expected_replay or replay.applied \
                or store != before:
            _capability_failure(run, profile, "equal replay was not idempotent")
        run.record("equal replay", replay.status)

        store = {}
        unknown = implementation.execute(
            capability, request, store, lose_response=True)
        if unknown.status != "outcome-unknown" \
                or store != {address: request.body}:
            _capability_failure(
                run, profile,
                "applied-but-lost response lacks exact stored bytes")
        run.record("applied response lost", unknown.status)
        retry = implementation.execute(capability, request, store)
        if retry.status != expected_replay or retry.applied \
                or store != {address: request.body}:
            _capability_failure(
                run, profile,
                "retry after a lost response was not an equal replay")
        run.record("retry outcome-unknown", retry.status)

        wrong = b"occupied by nonmatching bytes"
        store = {address: wrong}
        collision = implementation.execute(
            capability, request, store)
        if collision.applied or store != {address: wrong}:
            _capability_failure(
                run, CapabilityMutation(
                    "colliding-existing-key",
                    frozenset({"create-only", "body"}),
                    request),
                "immutable collision was overwritten")
        run.record("colliding existing key", collision.status)

        mutations = capability_mutations(
            capability, request, run.seed)
        for mutation in mutations:
            store = {}
            result = implementation.execute(
                capability, mutation.request, store)
            if mutation.expect_authorized:
                expected_address = (
                    mutation.request.provider,
                    mutation.request.endpoint,
                    mutation.request.bucket,
                    mutation.request.key,
                )
                if not result.authorized or not result.applied \
                        or store != {
                            expected_address: mutation.request.body}:
                    _capability_failure(
                        run, mutation,
                        "safe attenuation tightening did not create "
                        "the one exact value")
                run.record(
                    f"accept {mutation.name}", result.status)
                continue
            if result.authorized or result.applied or store:
                _capability_failure(
                    run, mutation,
                    f"mutation accepted as {result.status}")
            run.record(f"reject {mutation.name}", result.status)
        return CapabilityReport(
            capability.provider,
            run.seed,
            tuple(mutation.name for mutation in mutations))


@dataclass(frozen=True)
class BrokerParentCredential:
    """Provider parent authority, independent of narrow child capabilities."""

    provider: str
    ingress_bucket: str
    canonical_bucket: str
    scopes: tuple[tuple[str, frozenset[str]], ...]

    def allows(self, bucket, operation):
        return operation in dict(self.scopes).get(bucket, frozenset())


@dataclass(frozen=True)
class BrokerAttack:
    name: str
    bucket: str
    operation: str
    key: str


class BrokerBoundaryViolation(AssertionError):
    def __init__(self, run, attack):
        self.attack = attack
        self.seed = run.seed
        self.prefix = tuple(run.history)
        super().__init__(
            f"broker parent reaches canonical authority: "
            f"{attack.operation} {attack.bucket}/{attack.key}\n"
            f"{_model_diagnostic(run)}")


class IngressRetirementViolation(AssertionError):
    def __init__(self, run, attack):
        self.attack = attack
        self.seed = run.seed
        self.prefix = tuple(run.history)
        super().__init__(
            "broker parent can erase acknowledged ingress work: "
            f"{attack.operation} {attack.bucket}/{attack.key}\n"
            f"{_model_diagnostic(run)}")


def isolated_broker_parent(provider):
    """Canonical-isolation model of today's broad ingress parent."""
    return BrokerParentCredential(
        provider,
        f"{provider}-untrusted-ingress",
        f"{provider}-canonical-workspaces",
        ((
            f"{provider}-untrusted-ingress",
            frozenset({"GET", "LIST", "PUT", "DELETE"}),
        ),),
    )


def retirement_safe_broker_parent(provider):
    """Desired parent authority if acknowledged ingress is in threat scope."""
    ingress = f"{provider}-untrusted-ingress"
    return BrokerParentCredential(
        provider,
        ingress,
        f"{provider}-canonical-workspaces",
        ((ingress, frozenset({"PUT"})),),
    )


def single_bucket_broker_parent(provider):
    """Negative control matching a bucket-scoped read/write/list parent."""
    bucket = f"{provider}-canonical-workspaces"
    return BrokerParentCredential(
        provider, bucket, bucket,
        ((bucket, frozenset({"GET", "LIST", "PUT", "DELETE"})),),
    )


def exercise_broker_parent_boundary(credential, run):
    """Compromise the broker parent; child attenuation is not a defense."""
    workspace = "a" * 64
    attacks = [
        BrokerAttack("read-root", credential.canonical_bucket, "GET",
                     f"workspaces/{workspace}/root"),
        BrokerAttack("list-workspace", credential.canonical_bucket, "LIST",
                     f"workspaces/{workspace}/"),
        BrokerAttack("replace-root", credential.canonical_bucket, "PUT",
                     f"workspaces/{workspace}/root"),
        BrokerAttack("occupy-object", credential.canonical_bucket, "PUT",
                     f"workspaces/{workspace}/obj/" + "0" * 64),
        BrokerAttack("forge-pile", credential.canonical_bucket, "PUT",
                     f"workspaces/{workspace}/pile/" + "b" * 16 + "/"
                     + "0" * 64),
        BrokerAttack("delete-object", credential.canonical_bucket, "DELETE",
                     f"workspaces/{workspace}/obj/" + "0" * 64),
    ]
    if len(attacks) > MAX_BROKER_ATTACKS:
        raise AssertionError("broker attack corpus budget")
    random.Random(run.seed ^ 0xB20CE2).shuffle(attacks)
    with _model_capture(run):
        for attack in attacks:
            allowed = credential.allows(
                attack.bucket, attack.operation)
            run.record(
                f"broker-parent {attack.name}",
                "allowed" if allowed else "denied")
            if allowed:
                raise BrokerBoundaryViolation(run, attack)
        return tuple(attack.name for attack in attacks)


def exercise_ingress_retirement_boundary(credential, run):
    """An acknowledged staging object/pile must outlive broker compromise."""
    digest = "0" * 64
    attacks = [
        BrokerAttack(
            "delete-acknowledged-object",
            credential.ingress_bucket,
            "DELETE",
            f"session/obj/{digest}",
        ),
        BrokerAttack(
            "delete-acknowledged-pile",
            credential.ingress_bucket,
            "DELETE",
            f"session/pile/{'b' * 16}/{digest}",
        ),
    ]
    if len(attacks) > MAX_BROKER_ATTACKS:
        raise AssertionError("broker attack corpus budget")
    random.Random(run.seed ^ 0xF10).shuffle(attacks)
    with _model_capture(run):
        for attack in attacks:
            allowed = credential.allows(
                attack.bucket, attack.operation)
            run.record(
                f"broker-parent {attack.name}",
                "allowed" if allowed else "denied")
            if allowed:
                raise IngressRetirementViolation(run, attack)
        return tuple(attack.name for attack in attacks)


@dataclass(frozen=True)
class NotificationStep:
    operation: str
    target: str = ""
    response_lost: bool = False

    def __str__(self):
        suffix = ":lost-response" if self.response_lost else ""
        return f"{self.operation}:{self.target}{suffix}"


@dataclass(frozen=True)
class NotificationScript:
    name: str
    faults: frozenset[str]
    steps: tuple[NotificationStep, ...]
    expect_drained: bool
    expect_publications: int


@dataclass(frozen=True)
class SemanticEvent:
    seq: int
    operation: str
    key: str
    raw: bytes | None


@dataclass(frozen=True)
class NotificationReport:
    seed: int
    scripts: tuple[str, ...]


class NotificationViolation(AssertionError):
    def __init__(self, run, script, event, reason):
        self.seed = run.seed
        self.script = script
        self.event = event
        self.reason = reason
        self.prefix = tuple(run.history)
        at = "" if event is None else f" at semantic event #{event.seq}"
        super().__init__(
            f"first unsupported notification history: {script.name}{at}: "
            f"{reason}\n{_model_diagnostic(run)}")


def notification_corpus(seed=DEFAULT_SEED):
    scripts = [
        NotificationScript(
            "dropped-event-fair-scan",
            frozenset({"drop", "pile-only-durable-work"}),
            (
                NotificationStep("put", "object"),
                NotificationStep("put", "pile"),
                NotificationStep("drop", "pile"),
                NotificationStep("scan"),
            ),
            True, 1),
        NotificationScript(
            "duplicate-delivery",
            frozenset({"duplicate"}),
            (
                NotificationStep("put", "object"),
                NotificationStep("put", "pile"),
                NotificationStep("notify", "pile"),
                NotificationStep("notify", "pile"),
            ),
            True, 1),
        NotificationScript(
            "delayed-delivery",
            frozenset({"delay"}),
            (
                NotificationStep("put", "object"),
                NotificationStep("put", "pile"),
                NotificationStep("delay", "pile"),
                NotificationStep("notify", "pile"),
            ),
            True, 1),
        NotificationScript(
            "pile-before-object-reordered",
            frozenset({"reorder", "pile-only-durable-work"}),
            (
                NotificationStep("put", "pile"),
                NotificationStep("notify", "pile"),
                NotificationStep("put", "object"),
                # Deployments may filter notifications to pile/. Progress
                # therefore comes from the fair scan, not an obj/ event.
                NotificationStep("scan"),
            ),
            True, 1),
        NotificationScript(
            "stale-event-replay",
            frozenset({"replay"}),
            (
                NotificationStep("put", "object"),
                NotificationStep("put", "pile"),
                NotificationStep("notify", "pile"),
                NotificationStep("notify", "pile"),
                NotificationStep("scan"),
            ),
            True, 1),
        NotificationScript(
            "applied-pile-response-lost",
            frozenset({
                "apply-then-lose-response",
                "drop",
                "pile-only-durable-work",
            }),
            (
                NotificationStep("put", "object"),
                NotificationStep("put", "pile", True),
                NotificationStep("drop", "pile"),
                NotificationStep("scan"),
            ),
            True, 1),
        NotificationScript(
            "notification-without-durable-pile",
            frozenset({"replay", "pile-only-durable-work"}),
            (
                NotificationStep("notify", "pile"),
                NotificationStep("scan"),
            ),
            False, 0),
    ]
    if len(scripts) > MAX_NOTIFICATION_SCRIPTS \
            or any(
                len(script.steps) > MAX_NOTIFICATION_STEPS
                for script in scripts):
        raise AssertionError("notification corpus budget")
    random.Random(seed ^ 0xA071F1).shuffle(scripts)
    return tuple(scripts)


@dataclass(frozen=True)
class NotificationImplementation:
    name: str = "exact"
    scheduled_scan: bool = True
    event_as_work: bool = False
    delete_before_publish: bool = False

    def run(self, script, run):
        object_raw = b"attachment-object"
        object_key = "obj/" + h(object_raw)
        pile_raw = b"closed-pile-intent"
        pile_key = "pile/" + "b" * 16 + "/" + h(pile_raw)
        names = {"object": object_key, "pile": pile_key}
        raws = {"object": object_raw, "pile": pile_raw}
        data, events = {}, []

        def emit(operation, key, raw=None):
            event = SemanticEvent(
                len(events) + 1, operation, key, raw)
            events.append(event)
            run.record(f"{script.name} {operation} {key}", "applied")

        def drain(key):
            raw = data.get(key)
            if raw is None:
                return
            if self.delete_before_publish:
                emit("delete", key, raw)
                data.pop(key, None)
                return
            if data.get(object_key) != object_raw:
                return
            emit("publish", key, raw)
            emit("delete", key, raw)
            data.pop(key, None)

        def scan():
            if not self.scheduled_scan:
                emit("scan-disabled", "", None)
                return
            emit("scan", "", None)
            for key in sorted(
                    key for key in data if key.startswith("pile/")):
                drain(key)

        for step in script.steps:
            key = names.get(step.target, "")
            raw = raws.get(step.target)
            if step.operation == "put":
                data.setdefault(key, raw)
                emit(
                    "put-" + step.target, key, raw)
                if step.response_lost:
                    emit("response-lost", key, raw)
            elif step.operation == "notify":
                emit("notify", key, raw)
                if self.event_as_work and key not in data:
                    emit("publish", key, raw)
                elif step.target == "pile":
                    drain(key)
                else:
                    scan()
            elif step.operation in {"drop", "delay"}:
                emit(step.operation, key, raw)
            elif step.operation == "scan":
                scan()
            else:
                raise AssertionError(f"unknown step {step}")
        return tuple(events), {
            pile_key: (pile_raw, (object_key,)),
        }


def _notification_failure(run, script, event, reason):
    run.record(f"notification failure {script.name}", reason)
    raise NotificationViolation(run, script, event, reason)


def _check_notification_history(run, script, events, intents):
    data, obligations, witnesses, publications = {}, {}, {}, 0
    for event in events:
        if event.operation == "put-object":
            data[event.key] = event.raw
        elif event.operation == "put-pile":
            incumbent = data.get(event.key)
            if incumbent is not None and incumbent != event.raw:
                _notification_failure(
                    run, script, event, "pile bytes were overwritten")
            if incumbent is None:
                obligations[event.key] = Obligation(
                    event.key, event.raw, event.seq)
            data[event.key] = event.raw
        elif event.operation == "publish":
            intent = intents.get(event.key)
            if intent is None or data.get(event.key) != event.raw:
                _notification_failure(
                    run, script, event,
                    "notification manufactured work without a durable pile")
            raw, required = intent
            if raw != event.raw or any(key not in data for key in required):
                _notification_failure(
                    run, script, event,
                    "publication lacks its exact pile/object closure")
            witnesses[event.key] = (event.seq, event.raw)
            publications += 1
        elif event.operation == "delete":
            obligation = obligations.get(event.key)
            witness = witnesses.get(event.key)
            if obligation is None or data.get(event.key) != event.raw \
                    or witness is None or witness[0] < obligation.created_seq \
                    or witness[1] != obligation.raw:
                _notification_failure(
                    run, script, event,
                    "retirement order lacks an exact durable "
                    "publication event")
            obligations.pop(event.key)
            data.pop(event.key, None)

    if script.expect_drained:
        ready = [
            obligation for obligation in obligations.values()
            if all(
                key in data
                for key in intents[obligation.key][1])
        ]
        if ready:
            _notification_failure(
                run, script, None,
                "fair recovery left a ready durable pile unprocessed")
    if publications != script.expect_publications:
        _notification_failure(
            run, script, None,
            f"expected {script.expect_publications} publications, "
            f"observed {publications}")


def exercise_notification_corpus(implementation, run):
    with _model_capture(run):
        scripts = notification_corpus(run.seed)
        for script in scripts:
            events, intents = implementation.run(script, run)
            _check_notification_history(
                run, script, events, intents)
        return NotificationReport(
            run.seed, tuple(script.name for script in scripts))


@dataclass(frozen=True)
class PromotionCase:
    name: str
    crash_after: str | None = None
    poison_staging: bool = False
    intent_fault: str | None = None
    canonical_collision: bool = False


@dataclass(frozen=True)
class PromotionImplementation:
    """One logical publisher candidate; physical adapters stay external."""

    name: str = "exact"
    verify_sha256: bool = True
    validate_intent: bool = True
    durable_root: bool = True
    delete_before_root: bool = False
    overwrite_canonical: bool = False


@dataclass(frozen=True)
class StagedIntent:
    """Symbolic authorization input, not the production signed pile codec."""

    workspace: str
    member: str
    object_digests: tuple[str, ...]
    member_authorized: bool


@dataclass(frozen=True)
class PromotionEvent:
    seq: int
    generation: int
    operation: str
    bucket: str
    key: str
    raw: bytes | None


@dataclass(frozen=True)
class PromotionReport:
    provider: str
    seed: int
    cases: tuple[str, ...]


class PromotionViolation(AssertionError):
    def __init__(self, run, case, event, reason):
        self.case = case
        self.event = event
        self.seed = run.seed
        self.reason = reason
        self.prefix = tuple(run.history)
        at = "" if event is None else f" at event #{event.seq}"
        super().__init__(
            f"first unsupported staging history: {case.name}{at}: "
            f"{reason}\n{_model_diagnostic(run)}")


def promotion_corpus(seed=DEFAULT_SEED):
    cases = [
        PromotionCase("clean"),
        PromotionCase("crash-after-validate", "validate"),
        PromotionCase("crash-after-promote", "promote"),
        PromotionCase("crash-after-root", "root"),
        PromotionCase("crash-after-pile-delete", "pile-delete"),
        PromotionCase("crash-after-object-delete", "object-delete"),
        PromotionCase("poison-staging-key", poison_staging=True),
        PromotionCase(
            "foreign-workspace-intent",
            intent_fault="foreign-workspace"),
        PromotionCase(
            "foreign-member-intent",
            intent_fault="foreign-member"),
        PromotionCase(
            "unauthorized-member-intent",
            intent_fault="unauthorized-member"),
        PromotionCase(
            "missing-staged-object",
            intent_fault="missing-object"),
        PromotionCase(
            "canonical-object-collision",
            canonical_collision=True),
    ]
    if len(cases) > MAX_PROMOTION_CASES:
        raise AssertionError("promotion corpus budget")
    random.Random(seed ^ 0x570A6E).shuffle(cases)
    return tuple(cases)


def _encode_staged_intent(intent):
    return json.dumps(
        {
            "member": intent.member,
            "member_authorized": intent.member_authorized,
            "objects": list(intent.object_digests),
            "workspace": intent.workspace,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _decode_staged_intent(raw):
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid staged intent encoding") from error
    if not isinstance(value, dict) or set(value) != {
            "member", "member_authorized", "objects", "workspace"}:
        raise ValueError("invalid staged intent shape")
    objects = value["objects"]
    if not isinstance(objects, list) or not objects \
            or any(
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
                for digest in objects):
        raise ValueError("invalid staged object digest")
    if len(set(objects)) != len(objects):
        raise ValueError("duplicate staged object digest")
    if not isinstance(value["workspace"], str) \
            or not isinstance(value["member"], str) \
            or type(value["member_authorized"]) is not bool:
        raise ValueError("invalid staged intent authority")
    return StagedIntent(
        value["workspace"],
        value["member"],
        tuple(objects),
        value["member_authorized"],
    )


def _intent_violation(intent, workspace, member):
    if intent.workspace != workspace:
        return "foreign workspace"
    if intent.member != member:
        return "foreign member"
    if not intent.member_authorized:
        return "member authorization missing"
    return None


def promotion_history(implementation, case, provider, run):
    """Produce a trace whose retry actors retain only durable bucket state."""
    ingress_bucket = f"{provider}-untrusted-ingress"
    canonical_bucket = f"{provider}-canonical-workspaces"
    workspace = "a" * 64
    member = "b" * 16
    object_raw = b"staged attachment bytes"
    staged_raw = object_raw + b" poison" \
        if case.poison_staging else object_raw
    digest = h(object_raw)
    session = "session-" + "1" * 16
    stage_object = f"{session}/obj/{digest}"
    intent = StagedIntent(
        "d" * 64
        if case.intent_fault == "foreign-workspace" else workspace,
        "e" * 16
        if case.intent_fault == "foreign-member" else member,
        (digest,),
        case.intent_fault != "unauthorized-member",
    )
    pile_raw = _encode_staged_intent(intent)
    stage_pile = f"{session}/pile/{member}/{h(pile_raw)}"
    canonical_object = (
        f"workspaces/{workspace}/obj/{digest}")
    canonical_root = f"workspaces/{workspace}/root"
    events, ingress, canonical = [], {}, {}
    generation = 0

    def emit(operation, bucket, key, raw=None):
        event = PromotionEvent(
            len(events) + 1, generation,
            operation, bucket, key, raw)
        events.append(event)
        run.record(
            f"{case.name} actor-{generation} "
            f"{operation} {bucket}/{key}",
            "applied",
        )

    if case.intent_fault != "missing-object":
        ingress[stage_object] = staged_raw
        emit("put-stage-object", ingress_bucket, stage_object, staged_raw)
    ingress[stage_pile] = pile_raw
    emit("put-stage-pile", ingress_bucket, stage_pile, pile_raw)
    if case.canonical_collision:
        canonical[canonical_object] = b"preexisting wrong canonical bytes"
        emit(
            "seed-canonical-collision",
            canonical_bucket,
            canonical_object,
            canonical[canonical_object],
        )

    def turn(crash_after=None):
        nonlocal generation
        generation += 1
        emit("start-turn", ingress_bucket, stage_pile)
        pile = ingress.get(stage_pile)
        if pile is None:
            return

        try:
            parsed = _decode_staged_intent(pile)
        except ValueError:
            emit("reject-intent", ingress_bucket, stage_pile, pile)
            return
        violation = _intent_violation(parsed, workspace, member)
        if implementation.validate_intent and violation is not None:
            emit("reject-intent", ingress_bucket, stage_pile, pile)
            return

        candidates = []
        for declared_digest in parsed.object_digests:
            source = f"{session}/obj/{declared_digest}"
            candidate = ingress.get(source)
            if candidate is None:
                emit("wait-object", ingress_bucket, source)
                return
            if implementation.verify_sha256 \
                    and h(candidate) != declared_digest:
                emit("reject-poison", ingress_bucket, source, candidate)
                return
            candidates.append((declared_digest, source, candidate))
        emit("validate", ingress_bucket, stage_pile, pile)
        if crash_after == "validate":
            emit("crash", ingress_bucket, stage_pile)
            return

        for declared_digest, _source, candidate in candidates:
            destination = (
                f"workspaces/{workspace}/obj/{declared_digest}")
            incumbent = canonical.get(destination)
            if incumbent is not None and incumbent != candidate \
                    and not implementation.overwrite_canonical:
                emit(
                    "canonical-collision",
                    canonical_bucket, destination, incumbent)
                return
            canonical[destination] = candidate
            emit("promote", canonical_bucket, destination, candidate)
        if crash_after == "promote":
            emit("crash", canonical_bucket, canonical_object)
            return

        if implementation.delete_before_root:
            emit("delete-stage-pile", ingress_bucket, stage_pile, pile)
            ingress.pop(stage_pile, None)
        root_is_durable = canonical.get(canonical_root) == pile
        volatile_root = False
        if not root_is_durable:
            if implementation.durable_root:
                canonical[canonical_root] = pile
                emit("commit-root", canonical_bucket, canonical_root, pile)
                root_is_durable = True
            else:
                volatile_root = True
                emit("cache-root", canonical_bucket, canonical_root, pile)
        if crash_after == "root":
            emit("crash", canonical_bucket, canonical_root)
            return
        if not root_is_durable and not volatile_root:
            return

        if stage_pile in ingress:
            emit("delete-stage-pile", ingress_bucket, stage_pile, pile)
            ingress.pop(stage_pile, None)
        if crash_after == "pile-delete":
            emit("crash", ingress_bucket, stage_pile)
            return
        for _declared_digest, source, candidate in candidates:
            if source in ingress:
                emit(
                    "delete-stage-object",
                    ingress_bucket, source, candidate)
                ingress.pop(source, None)
            if crash_after == "object-delete":
                emit("crash", ingress_bucket, source)
                return

    turn(case.crash_after)
    if case.crash_after is not None:
        # This call creates a new logical actor generation. It can derive
        # state only from ingress/canonical, never a previous local variable.
        turn()
    return tuple(events), {
        "ingress_bucket": ingress_bucket,
        "canonical_bucket": canonical_bucket,
        "workspace": workspace,
        "member": member,
        "session": session,
        "stage_object": stage_object,
        "stage_pile": stage_pile,
        "canonical_object": canonical_object,
        "canonical_root": canonical_root,
        "object_raw": object_raw,
        "pile_raw": pile_raw,
        "poison": case.poison_staging,
        "intent_fault": case.intent_fault,
        "canonical_collision": case.canonical_collision,
    }


def _promotion_failure(run, case, event, reason):
    run.record(f"promotion failure {case.name}", reason)
    raise PromotionViolation(run, case, event, reason)


def _promotion_address_failure(run, case, event, expected):
    ingress = expected["ingress_bucket"]
    canonical = expected["canonical_bucket"]
    exact = {
        "put-stage-object": (ingress, expected["stage_object"]),
        "put-stage-pile": (ingress, expected["stage_pile"]),
        "seed-canonical-collision": (
            canonical, expected["canonical_object"]),
        "canonical-collision": (
            canonical, expected["canonical_object"]),
        "commit-root": (canonical, expected["canonical_root"]),
        "cache-root": (canonical, expected["canonical_root"]),
        "delete-stage-pile": (ingress, expected["stage_pile"]),
        "delete-stage-object": (ingress, expected["stage_object"]),
    }
    required = exact.get(event.operation)
    if required is not None \
            and (event.bucket, event.key) != required:
        return (
            f"{event.operation} escaped its exact bucket/key authority")
    return None


def check_promotion_history(run, case, events, expected):
    """Check every state transition against exact address and closure."""
    ingress, canonical, obligations, promoted = {}, {}, {}, set()
    roots = {}
    allowed_operations = {
        "cache-root",
        "canonical-collision",
        "commit-root",
        "crash",
        "delete-stage-object",
        "delete-stage-pile",
        "promote",
        "put-stage-object",
        "put-stage-pile",
        "reject-intent",
        "reject-poison",
        "seed-canonical-collision",
        "start-turn",
        "validate",
        "wait-object",
    }
    for event in events:
        if event.operation not in allowed_operations:
            _promotion_failure(
                run, case, event,
                f"unknown promotion operation {event.operation}")
        address_reason = _promotion_address_failure(
            run, case, event, expected)
        if address_reason is not None:
            _promotion_failure(
                run, case, event, address_reason)
        if event.operation == "put-stage-object":
            ingress[event.key] = event.raw
        elif event.operation == "put-stage-pile":
            ingress[event.key] = event.raw
            obligations[event.key] = Obligation(
                event.key, event.raw, event.seq)
        elif event.operation == "seed-canonical-collision":
            canonical[event.key] = event.raw
        elif event.operation == "promote":
            pile = ingress.get(expected["stage_pile"])
            try:
                intent = _decode_staged_intent(pile)
            except (TypeError, ValueError):
                _promotion_failure(
                    run, case, event,
                    "promotion lacks a typed durable staged intent")
            violation = _intent_violation(
                intent, expected["workspace"], expected["member"])
            if violation is not None:
                _promotion_failure(
                    run, case, event,
                    f"unauthorized staged intent reached promotion: "
                    f"{violation}")
            digest = event.key.rsplit("/", 1)[-1]
            expected_key = (
                f"workspaces/{expected['workspace']}/obj/{digest}")
            if event.bucket != expected["canonical_bucket"] \
                    or event.key != expected_key \
                    or digest not in intent.object_digests:
                _promotion_failure(
                    run, case, event,
                    "promotion escaped its exact bucket/key/"
                    "declared-digest authority")
            if h(event.raw) != digest:
                _promotion_failure(
                    run, case, event,
                    "canonical object key does not bind promoted bytes")
            incumbent = canonical.get(event.key)
            if incumbent is not None and incumbent != event.raw:
                _promotion_failure(
                    run, case, event,
                    "promotion overwrote canonical immutable bytes")
            source = f"{expected['session']}/obj/{digest}"
            if ingress.get(source) != event.raw:
                _promotion_failure(
                    run, case, event,
                    "promotion bytes are not the declared staged object")
            canonical[event.key] = event.raw
            promoted.add((event.key, event.raw))
        elif event.operation == "commit-root":
            pile = ingress.get(expected["stage_pile"])
            try:
                intent = _decode_staged_intent(pile)
            except (TypeError, ValueError):
                _promotion_failure(
                    run, case, event,
                    "root commit lacks typed durable staged intent")
            violation = _intent_violation(
                intent, expected["workspace"], expected["member"])
            closure = all(
                h(canonical.get(
                    f"workspaces/{expected['workspace']}/obj/{digest}",
                    b"")) == digest
                for digest in intent.object_digests
            )
            if violation is not None or not closure \
                    or pile != event.raw:
                _promotion_failure(
                    run, case, event,
                    "abstract root commit lacks exact promoted closure")
            canonical[event.key] = event.raw
            roots[expected["stage_pile"]] = (event.seq, event.raw)
        elif event.operation == "delete-stage-pile":
            obligation = obligations.get(event.key)
            witness = roots.get(event.key)
            if obligation is None or ingress.get(event.key) != event.raw \
                    or witness is None \
                    or witness[0] < obligation.created_seq \
                    or witness[1] != obligation.raw \
                    or canonical.get(expected["canonical_root"]) \
                    != obligation.raw:
                _promotion_failure(
                    run, case, event,
                    "retirement lacks an abstract durable root commit")
            obligations.pop(event.key)
            ingress.pop(event.key, None)
        elif event.operation == "delete-stage-object":
            witness = (
                expected["canonical_object"], event.raw)
            if witness not in promoted \
                    or canonical.get(witness[0]) != witness[1]:
                _promotion_failure(
                    run, case, event,
                    "staged object deleted before exact promotion")
            ingress.pop(event.key, None)

    canonical_raw = canonical.get(expected["canonical_object"])
    blocked = (
        expected["poison"]
        or expected["intent_fault"] is not None
        or expected["canonical_collision"]
    )
    if blocked:
        if canonical_raw == expected["object_raw"]:
            _promotion_failure(
                run, case, None,
                "blocked staging work reached canonical storage")
        if expected["stage_pile"] not in obligations:
            _promotion_failure(
                run, case, None,
                "blocked session lost its durable pile")
    else:
        if canonical_raw != expected["object_raw"] \
                or expected["stage_pile"] in obligations:
            _promotion_failure(
                run, case, None,
                "fair retry did not promote and retire exact session")


def exercise_promotion_corpus(implementation, provider, run):
    """Compare staging on either provider without choosing deployment policy."""
    with _model_capture(run):
        cases = promotion_corpus(run.seed)
        for case in cases:
            events, expected = promotion_history(
                implementation, case, provider, run)
            check_promotion_history(
                run, case, events, expected)
        return PromotionReport(
            provider, run.seed, tuple(case.name for case in cases))


@dataclass(frozen=True)
class IntegrationSeam:
    path: str
    symbol: str
    role: str


INTEGRATION_SEAMS = (
    IntegrationSeam(
        "tests/provider_conformance.py",
        "ConformanceRun",
        "seeded provider histories"),
    IntegrationSeam(
        "tests/ingress_obligations.py",
        "ObligationTrace",
        "required authenticated F10 refinement"),
    IntegrationSeam(
        "core/close.py",
        "decode_pile",
        "production signed-pile codec refinement"),
    IntegrationSeam(
        "core/mint.py",
        "stateless",
        "production workspace/member/closure authorization refinement"),
    IntegrationSeam(
        "core/daemon.py",
        "Handler.do_PUT",
        "legacy writable proxy compatibility"),
    IntegrationSeam(
        "adapters/s3/store.py",
        "S3Store",
        "direct S3 storage refinement"),
    IntegrationSeam(
        "adapters/r2/s3.py",
        "R2S3Store",
        "R2 S3-compatible refinement"),
    IntegrationSeam(
        "adapters/r2/worker.py",
        "R2BindingStore",
        "native R2 publisher storage"),
    IntegrationSeam(
        "deploy/aws_lambda/app.py",
        "handler",
        "segregated future AWS entrypoint"),
    IntegrationSeam(
        "deploy/cloudflare_worker/runtime.py",
        "handle",
        "segregated future Cloudflare entrypoint"),
)


def integration_inventory(root):
    """Resolve exact current symbols without pretending future roles exist."""
    root = Path(root)
    found = []
    for seam in INTEGRATION_SEAMS:
        path = root / seam.path
        tree = ast.parse(path.read_text(), filename=str(path))
        names = set()

        class Symbols(ast.NodeVisitor):
            def __init__(self):
                self.stack = []

            def visit_ClassDef(self, node):
                names.add(".".join(self.stack + [node.name]))
                self.stack.append(node.name)
                self.generic_visit(node)
                self.stack.pop()

            def visit_FunctionDef(self, node):
                names.add(".".join(self.stack + [node.name]))
                self.stack.append(node.name)
                self.generic_visit(node)
                self.stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

        Symbols().visit(tree)
        if seam.symbol in names:
            found.append(seam)
    return tuple(found)


def unbuilt_direct_upload_symbols(root):
    """Ratchet that this method does not masquerade as the future runtime."""
    root = Path(root)
    wanted = {"UploadBroker", "PilePublisher", "DirectUploader"}
    found = []
    for directory in ("core", "adapters", "deploy"):
        for path in sorted((root / directory).rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)) \
                        and node.name in wanted:
                    found.append((
                        str(path.relative_to(root)),
                        node.name,
                        node.lineno))
    return tuple(found)
