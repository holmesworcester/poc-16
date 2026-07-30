"""Credential-free contract models for direct bucket uploads.

The production architecture is already split into three roles: ``PileSender``
may use SQL for local authorship, ``RepositoryApplier`` owns exact-pile
application and root CAS, and ``RepositoryReader`` is a pinned DB-free view.
Those running roles, including their crash and replay behavior, are tested
with production object stores elsewhere.

This module keeps only the boundaries that benefit from a small seeded model:
broker minting, exact provider-visible PUT authority, notification hints with
fair scans, and broker-parent isolation. Client-writable ingress is put-only;
its retained markers are not a second repository and are not cleaned up here.
"""
import ast
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
from pathlib import Path
import random
from urllib.parse import urlsplit

from core.crypto import h
from core.shape import valid_fid
from tests.provider_conformance import ConformanceRun, DEFAULT_SEED


MAX_BROKER_MINT_CASES = 24
MAX_WIRE_PUT_CASES = 24
MAX_BROKER_ATTACKS = 8
MAX_NOTIFICATION_SCRIPTS = 16
MAX_NOTIFICATION_STEPS = 12
# A deliberately tiny execution budget for this corpus, not the protocol's
# object-size limit. Large-object compatibility is measured by x1p.17.10.
MAX_CORPUS_UPLOAD_BYTES = 4 * 1024 * 1024

SHA256 = "sha256"
BODY_SHA256_HEADER = "abstract-body-sha256"
REQUIRED_PUT_HEADER_NAMES = frozenset({
    "content-length",
    "content-type",
    "host",
    "if-none-match",
    # A symbolic signed condition, not the name or semantics of a provider
    # header. Each adapter must refine this to a live-tested raw-upload or
    # streaming-verifier mechanism that actually binds all body bytes.
    BODY_SHA256_HEADER,
})
BROKER_MINT_DIMENSIONS = frozenset({
    "auth-workspace",
    "auth-member",
    "auth-evidence",
    "auth-descriptor",
    "member-active",
    "descriptor-commitment",
    "descriptor-canonical",
    "descriptor-workspace",
    "descriptor-member",
    "workspace-shape",
    "member-shape",
    "object-class",
    "digest",
    "size",
    "content-type",
})
WIRE_PUT_DIMENSIONS = frozenset({
    "endpoint",
    "operation",
    "bucket",
    "key",
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


def _valid_digest(value):
    return isinstance(value, str) \
        and len(value) == 64 \
        and all(c in "0123456789abcdef" for c in value)


def _valid_member(value):
    return isinstance(value, str) \
        and len(value) == 16 \
        and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class ProviderUploadProfile:
    provider: str
    endpoint: str
    bucket: str
    ttl_seconds: int = 60
    max_bytes: int = 5 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class UploadDescriptor:
    workspace: str
    member: str
    object_class: str
    digest: str
    size: int
    content_type: str


@dataclass(frozen=True)
class MintAuthorization:
    workspace: str
    member: str
    descriptor_oid: str
    evidence: str


@dataclass(frozen=True)
class BrokerState:
    """Pinned broker-side authority, not caller-supplied PUT metadata."""

    authorization: MintAuthorization
    member_active: bool


@dataclass(frozen=True)
class BrokerMintRequest:
    authorization: MintAuthorization
    descriptor_raw: bytes


@dataclass(frozen=True)
class WirePutCapability:
    """Claims recovered from a valid provider signature.

    This deliberately contains only claims an S3/R2 service (or upload
    verifier) can enforce. Workspace/member/class/digest semantics reach this
    boundary only through the exact derived key or signed header values.
    """

    endpoint: str
    operation: str
    bucket: str
    key: str
    signed_headers: tuple[tuple[str, str], ...]
    expires_at: int


@dataclass(frozen=True)
class WirePut:
    """The actual request surface visible to the provider.

    The opaque signature bytes are represented by pairing this value with the
    verified ``WirePutCapability`` claims. This model does not construct or
    validate a real provider signature.
    """

    endpoint: str
    operation: str
    bucket: str
    key: str
    headers: tuple[tuple[str, str], ...]
    credential_expires_at: int
    now: int
    body: bytes


@dataclass(frozen=True)
class BrokerMintMutation:
    name: str
    dimensions: frozenset[str]
    state: BrokerState
    request: BrokerMintRequest


@dataclass(frozen=True)
class WirePutMutation:
    name: str
    dimensions: frozenset[str]
    request: WirePut
    expect_authorized: bool = False


@dataclass(frozen=True)
class UploadResult:
    status: str
    authorized: bool
    applied: bool


@dataclass(frozen=True)
class BrokerMintReport:
    provider: str
    seed: int
    mutations: tuple[str, ...]


@dataclass(frozen=True)
class WirePutReport:
    endpoint: str
    seed: int
    mutations: tuple[str, ...]


class BrokerMintViolation(AssertionError):
    def __init__(self, run, mutation, reason):
        self.seed = run.seed
        self.mutation = mutation
        self.reason = reason
        self.prefix = tuple(run.history)
        super().__init__(
            f"first unsupported broker mint result: {mutation.name}: "
            f"{reason}\n{_model_diagnostic(run)}")


class WirePutViolation(AssertionError):
    def __init__(self, run, mutation, reason):
        self.seed = run.seed
        self.mutation = mutation
        self.reason = reason
        self.prefix = tuple(run.history)
        super().__init__(
            f"first unsupported provider PUT result: {mutation.name}: "
            f"{reason}\n{_model_diagnostic(run)}")


def provider_upload_profile(provider):
    if provider == "s3":
        endpoint = "https://s3.us-west-2.amazonaws.com"
    elif provider == "r2":
        endpoint = "https://" + "c" * 32 \
            + ".r2.cloudflarestorage.com"
    else:
        raise ValueError("provider")
    return ProviderUploadProfile(
        provider, endpoint, "direct-upload-bucket")


def encode_upload_descriptor(descriptor):
    return json.dumps(
        {
            "content_type": descriptor.content_type,
            "digest": descriptor.digest,
            "member": descriptor.member,
            "object_class": descriptor.object_class,
            "size": descriptor.size,
            "workspace": descriptor.workspace,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _parse_upload_descriptor(raw):
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid upload descriptor encoding") from error
    if not isinstance(value, dict) or set(value) != {
            "content_type", "digest", "member", "object_class", "size",
            "workspace"}:
        raise ValueError("invalid upload descriptor shape")
    if not all(
            isinstance(value[name], str)
            for name in (
                "content_type", "digest", "member", "object_class",
                "workspace")) \
            or type(value["size"]) is not int:
        raise ValueError("invalid upload descriptor fields")
    return UploadDescriptor(
        value["workspace"],
        value["member"],
        value["object_class"],
        value["digest"],
        value["size"],
        value["content_type"],
    )


def decode_upload_descriptor(raw):
    descriptor = _parse_upload_descriptor(raw)
    if encode_upload_descriptor(descriptor) != raw:
        raise ValueError("non-canonical upload descriptor")
    return descriptor


def _model_evidence(workspace, member, descriptor_oid):
    """Opaque accepted evidence in this model, not a proof construction."""
    return h(
        b"accepted-workspace-upload-proof\0"
        + workspace.encode() + b"\0"
        + member.encode() + b"\0"
        + descriptor_oid.encode())


def _authorization(workspace, member, descriptor_raw):
    descriptor_oid = h(descriptor_raw)
    return MintAuthorization(
        workspace,
        member,
        descriptor_oid,
        _model_evidence(workspace, member, descriptor_oid),
    )


def exact_broker_mint(
        provider, object_class, body, *,
        workspace="a" * 64, member="b" * 16):
    """Build one accepted broker input and its trusted provider profile.

    ``BrokerState`` stands for the runtime's already-verified, pinned DAG
    authorization. The model evidence is intentionally not claimed to be a
    deployable authentication scheme.
    """
    descriptor = UploadDescriptor(
        workspace,
        member,
        object_class,
        h(body),
        len(body),
        "application/octet-stream",
    )
    raw = encode_upload_descriptor(descriptor)
    authorization = _authorization(workspace, member, raw)
    return (
        provider_upload_profile(provider),
        BrokerState(authorization, True),
        BrokerMintRequest(authorization, raw),
    )


def _signed_put_headers(profile, descriptor):
    host = urlsplit(profile.endpoint).netloc
    return tuple(sorted({
        "content-length": str(descriptor.size),
        "content-type": descriptor.content_type,
        "host": host,
        "if-none-match": "*",
        BODY_SHA256_HEADER: descriptor.digest,
    }.items()))


@dataclass(frozen=True)
class BrokerImplementation:
    """Candidate broker policy, not proof of a production verifier."""

    name: str = "exact"
    ignored: frozenset[str] = frozenset()

    def mint(self, profile, state, request, *, now=1_000):
        try:
            descriptor = _parse_upload_descriptor(
                request.descriptor_raw)
        except ValueError:
            return None
        authorization = request.authorization
        expected = state.authorization
        dimensions = {
            "auth-workspace": (
                authorization.workspace == expected.workspace),
            "auth-member": authorization.member == expected.member,
            "auth-evidence": authorization.evidence == expected.evidence,
            "auth-descriptor": (
                authorization.descriptor_oid
                == expected.descriptor_oid),
            "member-active": state.member_active,
            "descriptor-commitment": (
                h(request.descriptor_raw)
                == authorization.descriptor_oid),
            "descriptor-canonical": (
                encode_upload_descriptor(descriptor)
                == request.descriptor_raw),
            "descriptor-workspace": (
                descriptor.workspace == authorization.workspace),
            "descriptor-member": (
                descriptor.member == authorization.member),
            "workspace-shape": (
                valid_fid(authorization.workspace)
                and valid_fid(descriptor.workspace)),
            "member-shape": (
                _valid_member(authorization.member)
                and _valid_member(descriptor.member)),
            "object-class": descriptor.object_class in {"obj", "pile"},
            "digest": _valid_digest(descriptor.digest),
            "size": 0 <= descriptor.size <= profile.max_bytes,
            "content-type": (
                descriptor.content_type
                == "application/octet-stream"),
        }
        if not all(
                allowed or dimension in self.ignored
                for dimension, allowed in dimensions.items()):
            return None
        return WirePutCapability(
            profile.endpoint,
            "PUT",
            profile.bucket,
            _key(
                descriptor.workspace,
                descriptor.member,
                descriptor.object_class,
                descriptor.digest,
            ),
            _signed_put_headers(profile, descriptor),
            now + profile.ttl_seconds,
        )


def _accepted_descriptor_case(
        descriptor, authority_workspace, authority_member, *,
        active=True):
    raw = encode_upload_descriptor(descriptor)
    authorization = _authorization(
        authority_workspace, authority_member, raw)
    state = BrokerState(authorization, active)
    return state, BrokerMintRequest(authorization, raw)


def broker_mint_mutations(state, request, seed=DEFAULT_SEED):
    """Mutate only inputs the broker authorization boundary observes."""
    descriptor = decode_upload_descriptor(request.descriptor_raw)
    other_workspace = "d" * 64
    other_member = "e" * 16
    alternate_digest = (
        "f" * 64 if descriptor.digest != "f" * 64 else "e" * 64)

    def accepted(
            name, dimensions, candidate, *,
            bind_descriptor_identity=False):
        candidate_state, candidate_request = _accepted_descriptor_case(
            candidate,
            candidate.workspace
            if bind_descriptor_identity
            else request.authorization.workspace,
            candidate.member
            if bind_descriptor_identity
            else request.authorization.member)
        return BrokerMintMutation(
            name, frozenset(dimensions),
            candidate_state, candidate_request)

    noncanonical = json.dumps(
        json.loads(request.descriptor_raw), sort_keys=True).encode()
    noncanonical_auth = _authorization(
        descriptor.workspace, descriptor.member, noncanonical)
    swapped_descriptor = replace(
        descriptor,
        workspace=other_workspace,
        member=other_member)
    swapped_raw = encode_upload_descriptor(swapped_descriptor)
    swapped_authorization = _authorization(
        other_workspace, other_member, swapped_raw)
    cases = [
        BrokerMintMutation(
            "issuer-and-descriptor-swap",
            frozenset({
                "auth-workspace",
                "auth-member",
                "auth-evidence",
                "auth-descriptor",
            }),
            state,
            BrokerMintRequest(
                swapped_authorization, swapped_raw)),
        BrokerMintMutation(
            "authorization-workspace-swap",
            frozenset({"auth-workspace", "descriptor-workspace"}),
            state,
            replace(
                request,
                authorization=replace(
                    request.authorization,
                    workspace=other_workspace))),
        BrokerMintMutation(
            "authorization-member-swap",
            frozenset({"auth-member", "descriptor-member"}),
            state,
            replace(
                request,
                authorization=replace(
                    request.authorization,
                    member=other_member))),
        BrokerMintMutation(
            "authorization-evidence",
            frozenset({"auth-evidence"}),
            state,
            replace(
                request,
                authorization=replace(
                    request.authorization,
                    evidence="0" * 64))),
        BrokerMintMutation(
            "authorization-descriptor",
            frozenset({"auth-descriptor", "descriptor-commitment"}),
            state,
            replace(
                request,
                authorization=replace(
                    request.authorization,
                    descriptor_oid="0" * 64))),
        BrokerMintMutation(
            "inactive-member",
            frozenset({"member-active"}),
            replace(state, member_active=False),
            request),
        BrokerMintMutation(
            "noncanonical-descriptor",
            frozenset({"descriptor-canonical"}),
            BrokerState(noncanonical_auth, True),
            BrokerMintRequest(noncanonical_auth, noncanonical)),
        accepted(
            "foreign-workspace-descriptor",
            {"descriptor-workspace"},
            replace(descriptor, workspace=other_workspace)),
        accepted(
            "foreign-member-descriptor",
            {"descriptor-member"},
            replace(descriptor, member=other_member)),
        accepted(
            "workspace-path-injection",
            {"workspace-shape"},
            replace(descriptor, workspace="a" * 63 + "/"),
            bind_descriptor_identity=True),
        accepted(
            "member-path-injection",
            {"member-shape"},
            replace(descriptor, member="b" * 15 + "/"),
            bind_descriptor_identity=True),
        accepted(
            "root-object-class",
            {"object-class"},
            replace(descriptor, object_class="root")),
        accepted(
            "malformed-digest",
            {"digest"},
            replace(descriptor, digest="not-a-digest")),
        accepted(
            "negative-size",
            {"size"},
            replace(descriptor, size=-1)),
        accepted(
            "unapproved-content-type",
            {"content-type"},
            replace(descriptor, content_type="text/plain")),
        BrokerMintMutation(
            "descriptor-substitution",
            frozenset({"descriptor-commitment"}),
            state,
            replace(
                request,
                descriptor_raw=encode_upload_descriptor(
                    replace(descriptor, digest=alternate_digest)))),
        BrokerMintMutation(
            "descriptor-and-oid-without-new-proof",
            frozenset({"auth-descriptor"}),
            state,
            replace(
                request,
                authorization=replace(
                    request.authorization,
                    descriptor_oid=h(encode_upload_descriptor(
                        replace(
                            descriptor,
                            digest=alternate_digest)))),
                descriptor_raw=encode_upload_descriptor(
                    replace(descriptor, digest=alternate_digest)))),
    ]
    if len(cases) > MAX_BROKER_MINT_CASES:
        raise AssertionError("broker mint corpus budget")
    random.Random(seed ^ 0xD1EC7).shuffle(cases)
    return tuple(cases)


@dataclass(frozen=True)
class WirePutImplementation:
    """Candidate wire semantics, not provider implementation evidence."""

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
            request.endpoint, request.bucket, request.key)
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
        try:
            actual_headers = _header_map(request.headers)
            signed_headers = dict(capability.signed_headers)
        except ValueError:
            actual_headers = {
                raw_name.lower(): value
                for raw_name, value in request.headers
            }
            signed_headers = dict(capability.signed_headers)
            headers_well_formed = False
        else:
            headers_well_formed = True
        signed_names = frozenset(signed_headers)
        signed_match = headers_well_formed and all(
            actual_headers.get(name) == value
            for name, value in signed_headers.items())
        signed_match = signed_match \
            and REQUIRED_PUT_HEADER_NAMES <= signed_names
        expected_digest = signed_headers.get(BODY_SHA256_HEADER)
        try:
            expected_size = int(signed_headers.get(
                "content-length", "invalid"))
        except ValueError:
            expected_size = -1
        dimensions = {
            "endpoint": request.endpoint == capability.endpoint,
            "operation": request.operation == capability.operation == "PUT",
            "bucket": request.bucket == capability.bucket,
            "key": request.key == capability.key,
            "signed-headers": signed_match,
            "expiry": (
                request.credential_expires_at == capability.expires_at
                and request.now <= capability.expires_at),
            "create-only": (
                signed_headers.get("if-none-match") == "*"
                and actual_headers.get("if-none-match") == "*"),
            "body": (
                self.body_binding == SHA256
                and h(request.body) == expected_digest
                and len(request.body) == expected_size),
        }
        if self.prefix_keys:
            dimensions["key"] = request.key.startswith(
                capability.key.rsplit("/", 1)[0] + "/")
        return all(
            allowed or dimension in self.ignored
            for dimension, allowed in dimensions.items())


def _header_map(headers):
    result = {}
    for raw_name, value in headers:
        name = raw_name.lower()
        if name in result:
            raise ValueError(f"duplicate header {name}")
        result[name] = value
    return result


def exact_wire_put(capability, body, *, now=1_000):
    return WirePut(
        capability.endpoint,
        capability.operation,
        capability.bucket,
        capability.key,
        capability.signed_headers,
        capability.expires_at,
        now,
        body,
    )


def _replace_header(request, name, value):
    headers = [
        (raw_name, raw_value)
        for raw_name, raw_value in request.headers
        if raw_name.lower() != name
    ]
    if value is not None:
        headers.append((name, value))
    return replace(request, headers=tuple(sorted(headers)))


def wire_put_mutations(capability, request, seed=DEFAULT_SEED):
    """Mutate only the signed request surface a provider can observe."""
    wrong_body = (
        bytes([request.body[0] ^ 1]) + request.body[1:]
        if request.body else None
    )
    substitute_body = request.body + b"!"
    sibling = request.key.rsplit("/", 1)[0] + "/" + "f" * 64
    cases = [
        WirePutMutation(
            "endpoint",
            frozenset({"endpoint"}),
            replace(
                request,
                endpoint="https://cached.example.invalid")),
        WirePutMutation(
            "operation",
            frozenset({"operation"}),
            replace(request, operation="DELETE")),
        WirePutMutation(
            "bucket",
            frozenset({"bucket"}),
            replace(request, bucket="another-bucket")),
        WirePutMutation(
            "sibling-key",
            frozenset({"key"}),
            replace(request, key=sibling)),
        WirePutMutation(
            "root-key",
            frozenset({"key"}),
            replace(
                request,
                key=request.key.split("/obj/", 1)[0] + "/root"
                if "/obj/" in request.key
                else request.key.split("/pile/", 1)[0] + "/root")),
        WirePutMutation(
            "missing-signed-header",
            frozenset({"signed-headers"}),
            _replace_header(request, "content-type", None)),
        WirePutMutation(
            "content-length-header",
            frozenset({"signed-headers"}),
            _replace_header(
                request, "content-length",
                str(len(request.body) + 1))),
        WirePutMutation(
            "content-type-header",
            frozenset({"signed-headers"}),
            _replace_header(request, "content-type", "text/plain")),
        WirePutMutation(
            "host-header",
            frozenset({"signed-headers"}),
            _replace_header(request, "host", "other.invalid")),
        WirePutMutation(
            "body-digest-header",
            frozenset({"signed-headers"}),
            _replace_header(request, BODY_SHA256_HEADER, "0" * 64)),
        WirePutMutation(
            "create-only-condition",
            frozenset({"signed-headers", "create-only"}),
            _replace_header(request, "if-none-match", "present")),
        WirePutMutation(
            "duplicate-signed-header",
            frozenset({"signed-headers"}),
            replace(
                request,
                headers=request.headers
                + (("Content-Type", "application/octet-stream"),))),
        WirePutMutation(
            "credential-expiry-claim",
            frozenset({"expiry"}),
            replace(
                request,
                credential_expires_at=capability.expires_at + 60)),
        WirePutMutation(
            "replay-after-expiry",
            frozenset({"expiry"}),
            replace(request, now=capability.expires_at + 1)),
        WirePutMutation(
            "extra-unsigned-header",
            frozenset({"signed-headers"}),
            replace(
                request,
                headers=request.headers + (("x-client-trace", "safe"),)),
            expect_authorized=True),
        WirePutMutation(
            "header-name-case",
            frozenset({"signed-headers"}),
            replace(
                request,
                headers=tuple(
                    (name.upper(), value)
                    for name, value in request.headers)),
            expect_authorized=True),
    ]
    if wrong_body is not None:
        cases.append(WirePutMutation(
            "same-length-body-substitution",
            frozenset({"body"}),
            replace(request, body=wrong_body)))
    substituted = replace(request, body=substitute_body)
    substituted = _replace_header(
        substituted, "content-length", str(len(substitute_body)))
    substituted = _replace_header(
        substituted, BODY_SHA256_HEADER, h(substitute_body))
    cases.append(WirePutMutation(
        "body-and-header-substitution",
        frozenset({"signed-headers", "body"}),
        substituted))
    if len(cases) > MAX_WIRE_PUT_CASES:
        raise AssertionError("wire PUT corpus budget")
    random.Random(seed ^ 0x517E).shuffle(cases)
    return tuple(cases)


def _broker_mint_failure(run, mutation, reason):
    run.record(f"broker mint {mutation.name}", reason)
    raise BrokerMintViolation(run, mutation, reason)


def _wire_put_failure(run, mutation, reason):
    run.record(f"provider PUT {mutation.name}", reason)
    raise WirePutViolation(run, mutation, reason)


def exercise_broker_mint_corpus(
        implementation, profile, state, request, run):
    """Check the broker decision before any provider capability exists."""
    with _model_capture(run):
        capability = implementation.mint(
            profile, state, request)
        if capability is None:
            _broker_mint_failure(
                run,
                BrokerMintMutation(
                    "exact", frozenset(), state, request),
                "exact canonical request did not mint")
        run.record("broker mint exact", capability.key)
        mutations = broker_mint_mutations(
            state, request, run.seed)
        for mutation in mutations:
            minted = implementation.mint(
                profile, mutation.state, mutation.request)
            if minted is not None:
                _broker_mint_failure(
                    run, mutation,
                    f"unauthorized descriptor minted {minted.key}")
            run.record(f"broker reject {mutation.name}", "rejected")
        return BrokerMintReport(
            profile.provider,
            run.seed,
            tuple(mutation.name for mutation in mutations))


def exercise_wire_put_corpus(
        implementation, capability, request, run):
    """Check exact attenuation using provider-visible claims only."""
    with _model_capture(run):
        if len(request.body) > MAX_CORPUS_UPLOAD_BYTES:
            raise ValueError(
                "direct-upload corpus input exceeds its execution budget")
        profile = WirePutMutation(
            "implementation-profile",
            frozenset({"body"}),
            request)
        if implementation.body_binding != SHA256:
            _wire_put_failure(
                run, profile,
                f"{implementation.body_binding} is not SHA-256 body binding")
        if implementation.path not in {
                "raw-presigned", "upload-verifier"}:
            _wire_put_failure(
                run, profile,
                f"unmodeled upload path {implementation.path}")

        address = (
            request.endpoint, request.bucket, request.key)
        store = {}
        result = implementation.execute(capability, request, store)
        if not result.authorized or store != {address: request.body}:
            _wire_put_failure(
                run, profile, "exact PUT did not create")
        run.record("provider PUT exact", result.status)

        before = dict(store)
        replay = implementation.execute(capability, request, store)
        expected_replay = (
            "precondition-failed"
            if implementation.path == "raw-presigned"
            else "equal-replay"
        )
        if replay.status != expected_replay or replay.applied \
                or store != before:
            _wire_put_failure(
                run, profile, "equal replay was not idempotent")
        run.record("provider PUT equal replay", replay.status)

        store = {}
        unknown = implementation.execute(
            capability, request, store, lose_response=True)
        if unknown.status != "outcome-unknown" \
                or store != {address: request.body}:
            _wire_put_failure(
                run, profile,
                "applied-but-lost response lacks exact stored bytes")
        run.record("provider PUT response lost", unknown.status)
        retry = implementation.execute(capability, request, store)
        if retry.status != expected_replay or retry.applied \
                or store != {address: request.body}:
            _wire_put_failure(
                run, profile,
                "retry after a lost response was not an equal replay")
        run.record("provider PUT retry outcome-unknown", retry.status)

        wrong = b"occupied by nonmatching bytes"
        store = {address: wrong}
        collision = implementation.execute(
            capability, request, store)
        if collision.applied or store != {address: wrong}:
            _wire_put_failure(
                run, WirePutMutation(
                    "colliding-existing-key",
                    frozenset({"create-only", "body"}),
                    request),
                "immutable collision was overwritten")
        run.record("provider PUT colliding key", collision.status)

        mutations = wire_put_mutations(
            capability, request, run.seed)
        for mutation in mutations:
            store = {}
            result = implementation.execute(
                capability, mutation.request, store)
            if mutation.expect_authorized:
                expected_address = (
                    mutation.request.endpoint,
                    mutation.request.bucket,
                    mutation.request.key,
                )
                if not result.authorized or not result.applied \
                        or store != {
                            expected_address: mutation.request.body}:
                    _wire_put_failure(
                        run, mutation,
                        "safe wire variation did not create "
                        "the one exact value")
                run.record(
                    f"provider accept {mutation.name}", result.status)
                continue
            if result.authorized or result.applied or store:
                _wire_put_failure(
                    run, mutation,
                    f"wire mutation accepted as {result.status}")
            run.record(
                f"provider reject {mutation.name}", result.status)
        return WirePutReport(
            capability.endpoint,
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


def put_only_ingress_parent(provider):
    """Least-privilege parent for client-writable retained ingress."""
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
    expect_applied: bool
    expect_applications: int


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
    repeat_root_application: bool = False

    def run(self, script, run):
        object_raw = b"attachment-object"
        object_key = "obj/" + h(object_raw)
        pile_raw = b"closed-pile-intent"
        pile_key = "pile/" + "b" * 16 + "/" + h(pile_raw)
        names = {"object": object_key, "pile": pile_key}
        raws = {"object": object_raw, "pile": pile_raw}
        data, applications, events = {}, set(), []

        def emit(operation, key, raw=None):
            event = SemanticEvent(
                len(events) + 1, operation, key, raw)
            events.append(event)
            run.record(f"{script.name} {operation} {key}", "applied")

        def apply_ready(key):
            raw = data.get(key)
            if raw is None:
                return
            if data.get(object_key) != object_raw:
                return
            if key in applications:
                emit(
                    "apply-root" if self.repeat_root_application
                    else "apply-noop",
                    key,
                    raw,
                )
                return
            emit("apply-root", key, raw)
            applications.add(key)

        def scan():
            if not self.scheduled_scan:
                emit("scan-disabled", "", None)
                return
            emit("scan", "", None)
            for key in sorted(
                    key for key in data if key.startswith("pile/")):
                apply_ready(key)

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
                    emit("apply-root", key, raw)
                elif step.target == "pile":
                    apply_ready(key)
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
    data, applications = {}, {}
    for event in events:
        if event.operation == "put-object":
            data[event.key] = event.raw
        elif event.operation == "put-pile":
            incumbent = data.get(event.key)
            if incumbent is not None and incumbent != event.raw:
                _notification_failure(
                    run, script, event, "pile bytes were overwritten")
            data[event.key] = event.raw
        elif event.operation == "apply-root":
            intent = intents.get(event.key)
            if intent is None or data.get(event.key) != event.raw:
                _notification_failure(
                    run, script, event,
                    "notification manufactured work without a durable pile")
            raw, required = intent
            if raw != event.raw or any(key not in data for key in required):
                _notification_failure(
                    run, script, event,
                    "root application lacks its exact pile/object closure")
            if event.key in applications:
                _notification_failure(
                    run, script, event,
                    "retained marker repeated a root application")
            applications[event.key] = (event.seq, event.raw)
        elif event.operation == "apply-noop":
            if data.get(event.key) != event.raw \
                    or event.key not in applications:
                _notification_failure(
                    run, script, event,
                    "application noop lacks a prior exact root application")

    if script.expect_applied:
        ready = [
            key for key, (raw, required) in intents.items()
            if data.get(key) == raw
            and all(required_key in data for required_key in required)
            and key not in applications
        ]
        if ready:
            _notification_failure(
                run, script, None,
                "fair recovery left a ready durable pile unapplied")
    if len(applications) != script.expect_applications:
        _notification_failure(
            run, script, None,
            f"expected {script.expect_applications} root applications, "
            f"observed {len(applications)}")


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
        "core/close.py",
        "decode_pile",
        "production signed-pile codec refinement"),
    IntegrationSeam(
        "core/mint.py",
        "stateless",
        "production workspace/member/closure authorization refinement"),
    IntegrationSeam(
        "core/pile_sender.py",
        "PileSender",
        "built SQL-permitted exact-pile author"),
    IntegrationSeam(
        "core/repository_applier.py",
        "RepositoryApplier",
        "built DB-free application and root-CAS owner"),
    IntegrationSeam(
        "core/repository_reader.py",
        "RepositoryReader",
        "built DB-free pinned-root reader"),
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
        "native R2 application storage"),
    IntegrationSeam(
        "deploy/aws_lambda/app.py",
        "handler",
        "segregated future AWS entrypoint"),
    IntegrationSeam(
        "deploy/upload_broker.py",
        "UploadBroker",
        "production kernel-authorized exact staging capability broker"),
    IntegrationSeam(
        "deploy/aws_upload_broker/signer.py",
        "S3UploadSigner",
        "production exact SigV4 isolated-ingress translator"),
    IntegrationSeam(
        "deploy/cloudflare_worker/runtime.py",
        "handle",
        "segregated future Cloudflare entrypoint"),
)


def integration_inventory(root):
    """Resolve the exact built role and provider integration symbols."""
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
