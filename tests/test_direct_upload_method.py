"""Direct-upload broker and provider models fail closed under mutations."""
from dataclasses import fields, replace
from pathlib import Path

import pytest

from tests.direct_upload_method import (
    BODY_SHA256_HEADER,
    BROKER_MINT_DIMENSIONS,
    INTEGRATION_SEAMS,
    NOTIFICATION_FAULTS,
    REQUIRED_PUT_HEADER_NAMES,
    WIRE_PUT_DIMENSIONS,
    BrokerImplementation,
    BrokerBoundaryViolation,
    BrokerMintViolation,
    NotificationImplementation,
    NotificationViolation,
    WirePut,
    WirePutCapability,
    WirePutImplementation,
    WirePutViolation,
    broker_mint_mutations,
    exact_broker_mint,
    exact_wire_put,
    exercise_broker_parent_boundary,
    exercise_broker_mint_corpus,
    exercise_notification_corpus,
    exercise_wire_put_corpus,
    integration_inventory,
    isolated_broker_parent,
    notification_corpus,
    put_only_ingress_parent,
    single_bucket_broker_parent,
    wire_put_mutations,
)
from tests.provider_conformance import ConformanceRun


def _mint(provider, object_class, body, **kwargs):
    profile, state, request = exact_broker_mint(
        provider, object_class, body, **kwargs)
    capability = BrokerImplementation().mint(
        profile, state, request)
    assert capability is not None
    return profile, state, request, capability


@pytest.mark.parametrize("provider", ("s3", "r2"))
@pytest.mark.parametrize("object_class", ("obj", "pile"))
@pytest.mark.parametrize("path", ("raw-presigned", "upload-verifier"))
def test_broker_then_wire_attenuation_survives_both_seeded_corpora(
        provider, object_class, path):
    body = f"{provider}:{object_class}:body".encode()
    profile, state, mint_request, capability = _mint(
        provider, object_class, body)
    broker_run = ConformanceRun(
        f"direct-upload-broker-{provider}", seed=0xD1EC7)
    wire_run = ConformanceRun(
        f"direct-upload-wire-{provider}-{path}", seed=0xD1EC7)

    broker_report = exercise_broker_mint_corpus(
        BrokerImplementation(),
        profile, state, mint_request, broker_run)
    wire_report = exercise_wire_put_corpus(
        WirePutImplementation(path=path),
        capability, exact_wire_put(capability, body), wire_run)

    assert broker_report.provider == provider
    assert wire_report.endpoint == profile.endpoint
    assert set(broker_report.mutations)
    assert set(wire_report.mutations)
    assert len(broker_run.history) > len(broker_report.mutations)
    assert len(wire_run.history) > len(wire_report.mutations)


def test_broker_mutations_cover_only_broker_authority_and_are_replayable():
    body = b"inventory"
    _profile, state, request, _capability = _mint(
        "s3", "pile", body)

    first = broker_mint_mutations(
        state, request, seed=17)
    replay = broker_mint_mutations(
        state, request, seed=17)
    alternate = broker_mint_mutations(
        state, request, seed=18)

    covered = frozenset().union(*(
        mutation.dimensions for mutation in first))
    assert covered == BROKER_MINT_DIMENSIONS
    assert first == replay
    assert [case.name for case in first] != [
        case.name for case in alternate]


def test_wire_mutations_cover_only_provider_visible_authority_and_replay():
    body = b"wire-inventory"
    _profile, _state, _mint_request, capability = _mint(
        "r2", "obj", body)
    request = exact_wire_put(capability, body)

    first = wire_put_mutations(capability, request, seed=17)
    replay = wire_put_mutations(capability, request, seed=17)
    alternate = wire_put_mutations(capability, request, seed=18)

    covered = frozenset().union(*(
        mutation.dimensions for mutation in first))
    assert covered == WIRE_PUT_DIMENSIONS
    assert first == replay
    assert [case.name for case in first] != [
        case.name for case in alternate]


def test_every_broker_mutation_has_a_planted_weak_policy():
    profile, state, request, _capability = _mint(
        "s3", "pile", b"weak-broker-policy")
    mutations = broker_mint_mutations(
        state, request, seed=0xBAD)

    for mutation in mutations:
        weak = BrokerImplementation(
            name=f"ignored-{mutation.name}",
            ignored=mutation.dimensions)
        minted = weak.mint(
            profile, mutation.state, mutation.request)
        assert minted is not None, mutation.name

    first = mutations[0]
    run = ConformanceRun("weak-broker", seed=0xBAD)
    with pytest.raises(BrokerMintViolation) as caught:
        exercise_broker_mint_corpus(
            BrokerImplementation(ignored=first.dimensions),
            profile, state, request, run)

    assert caught.value.seed == 0xBAD
    assert caught.value.prefix
    assert caught.value.mutation.dimensions <= first.dimensions


def test_every_hostile_wire_mutation_has_a_planted_weak_policy():
    body = b"weak-wire-policy"
    _profile, _state, _mint_request, capability = _mint(
        "s3", "pile", body)
    request = exact_wire_put(capability, body)
    mutations = [
        mutation
        for mutation in wire_put_mutations(
            capability, request, seed=0xBAD)
        if not mutation.expect_authorized
    ]

    for mutation in mutations:
        weak = WirePutImplementation(
            name=f"ignored-{mutation.name}",
            ignored=mutation.dimensions)
        result = weak.execute(
            capability, mutation.request, {})
        assert result.authorized, mutation.name

    first = mutations[0]
    run = ConformanceRun("weak-wire", seed=0xBAD)
    with pytest.raises(WirePutViolation) as caught:
        exercise_wire_put_corpus(
            WirePutImplementation(ignored=first.dimensions),
            capability, request, run)

    assert caught.value.seed == 0xBAD
    assert caught.value.prefix
    assert caught.value.mutation.dimensions <= first.dimensions


def test_wire_surface_contains_no_issuer_only_semantic_fields():
    assert {field.name for field in fields(WirePut)} == {
        "endpoint",
        "operation",
        "bucket",
        "key",
        "headers",
        "credential_expires_at",
        "now",
        "body",
    }
    assert {field.name for field in fields(WirePutCapability)} == {
        "endpoint",
        "operation",
        "bucket",
        "key",
        "signed_headers",
        "expires_at",
    }
    invisible = {
        "workspace", "member", "object_class", "digest", "evidence"}
    assert not invisible & {
        field.name for field in fields(WirePut)}
    assert not invisible & {
        field.name for field in fields(WirePutCapability)}


@pytest.mark.parametrize("object_class", ("obj", "pile"))
def test_broker_derives_key_and_signed_values_from_canonical_descriptor(
        object_class):
    workspace = "7" * 64
    member = "8" * 16
    body = b"broker-derived, never client-selected"
    profile, _state, mint_request, capability = _mint(
        "s3",
        object_class,
        body,
        workspace=workspace,
        member=member,
    )
    signed = dict(capability.signed_headers)

    assert {field.name for field in fields(type(mint_request))} == {
        "authorization", "descriptor_raw"}
    assert profile.endpoint not in mint_request.descriptor_raw.decode()
    assert profile.bucket not in mint_request.descriptor_raw.decode()
    if object_class == "obj":
        assert capability.key == (
            f"workspaces/{workspace}/obj/{signed[BODY_SHA256_HEADER]}")
    else:
        assert capability.key == (
            f"workspaces/{workspace}/pile/{member}/"
            f"{signed[BODY_SHA256_HEADER]}")
    assert signed["content-length"] == str(len(body))
    assert signed["content-type"] == "application/octet-stream"
    assert signed["if-none-match"] == "*"


def test_object_issuer_is_erased_but_pile_issuer_is_key_bound():
    body = b"same immutable upload"
    object_one = _mint(
        "s3", "obj", body, member="b" * 16)[3]
    object_two = _mint(
        "s3", "obj", body, member="c" * 16)[3]
    pile_one = _mint(
        "s3", "pile", body, member="b" * 16)[3]
    pile_two = _mint(
        "s3", "pile", body, member="c" * 16)[3]

    assert object_one == object_two
    assert pile_one != pile_two
    assert f"/pile/{'b' * 16}/" in pile_one.key
    assert f"/pile/{'c' * 16}/" in pile_two.key


def test_issuer_and_descriptor_swap_cannot_mint_under_original_authority():
    profile, state, request, _capability = _mint(
        "r2", "pile", b"issuer-bound")
    mutation = next(
        mutation for mutation in broker_mint_mutations(
            state, request, seed=1)
        if mutation.name == "issuer-and-descriptor-swap")

    assert BrokerImplementation().mint(
        profile, mutation.state, mutation.request) is None


@pytest.mark.parametrize(
    "name",
    ("workspace-path-injection", "member-path-injection"),
)
def test_authenticated_path_fragments_cannot_escape_the_derived_prefix(name):
    profile, state, request, _capability = _mint(
        "r2", "pile", b"path-shape")
    mutation = next(
        mutation for mutation in broker_mint_mutations(
            state, request, seed=2)
        if mutation.name == name)

    assert BrokerImplementation().mint(
        profile, mutation.state, mutation.request) is None
    weak = BrokerImplementation(ignored=mutation.dimensions)
    unsafe = weak.mint(
        profile, mutation.state, mutation.request)
    assert unsafe is not None
    assert unsafe.key.count("/") > 4


def test_prefix_key_grant_is_not_mistaken_for_exact_attenuation():
    body = b"prefix-grant"
    _profile, _state, _mint_request, capability = _mint(
        "s3", "obj", body)
    request = exact_wire_put(capability, body)

    with pytest.raises(WirePutViolation) as caught:
        exercise_wire_put_corpus(
            WirePutImplementation(
                name="prefix-grant", prefix_keys=True),
            capability, request,
            ConformanceRun("prefix-grant", seed=0xBAD))

    assert "key" in caught.value.mutation.dimensions


def test_overwrite_on_replay_is_caught_before_mutation_cases():
    body = b"immutable"
    _profile, _state, _mint_request, capability = _mint(
        "s3", "obj", body)
    request = exact_wire_put(capability, body)
    weak = WirePutImplementation(
        name="overwrite", overwrite_existing=True)

    with pytest.raises(WirePutViolation) as caught:
        exercise_wire_put_corpus(
            weak, capability, request,
            ConformanceRun("overwrite", seed=4))

    assert caught.value.mutation.name == "colliding-existing-key"
    assert "overwritten" in caught.value.reason


@pytest.mark.parametrize("binding", ("unsigned", "md5"))
def test_non_collision_resistant_presigner_profiles_are_not_evidence(binding):
    body = b"provider-2xx-is-not-integrity"
    _profile, _state, _mint_request, capability = _mint(
        "r2", "obj", body)
    request = exact_wire_put(capability, body)

    with pytest.raises(
            WirePutViolation,
            match=rf"{binding} is not SHA-256 body binding"):
        exercise_wire_put_corpus(
            WirePutImplementation(
                name=f"raw-{binding}", body_binding=binding),
            capability, request,
            ConformanceRun(f"raw-{binding}", seed=9))


def test_body_sha256_is_an_abstract_condition_not_provider_evidence():
    capability = _mint(
        "s3", "obj", b"symbolic-condition")[3]
    signed = dict(capability.signed_headers)

    assert BODY_SHA256_HEADER in signed
    assert "x-amz-checksum-sha256" not in signed
    assert frozenset(signed) == REQUIRED_PUT_HEADER_NAMES


def test_incomplete_signed_capability_is_not_exact_provider_authority():
    body = b"incomplete presigner surface"
    capability = _mint("s3", "obj", body)[3]
    capability = replace(
        capability,
        signed_headers=tuple(
            item for item in capability.signed_headers
            if item[0] != "if-none-match"))
    request = exact_wire_put(capability, body)

    result = WirePutImplementation().execute(
        capability, request, {})

    assert not result.authorized


def test_extra_signed_constraint_is_safe_but_missing_condition_is_not():
    body = b"signed-conditions"
    capability = _mint("s3", "obj", body)[3]
    request = exact_wire_put(capability, body)
    mutations = {
        mutation.name: mutation
        for mutation in wire_put_mutations(capability, request, seed=1)
    }

    assert mutations["extra-unsigned-header"].expect_authorized
    assert mutations["header-name-case"].expect_authorized
    assert not mutations["create-only-condition"].expect_authorized
    assert not mutations["missing-signed-header"].expect_authorized


@pytest.mark.parametrize(
    ("path", "replay_status"),
    [
        ("raw-presigned", "precondition-failed"),
        ("upload-verifier", "equal-replay"),
    ],
)
def test_replay_classification_separates_provider_result_from_readback(
        path, replay_status):
    body = b"immutable replay"
    capability = _mint("s3", "obj", body)[3]
    request = exact_wire_put(capability, body)
    store = {}
    implementation = WirePutImplementation(path=path)

    assert implementation.execute(
        capability, request, store).status == "created"
    replay = implementation.execute(capability, request, store)

    assert replay.status == replay_status
    assert not replay.applied
    assert next(iter(store.values())) == body


def test_empty_body_binding_mutation_is_not_masked_by_size():
    capability = _mint("s3", "obj", b"")[3]
    request = exact_wire_put(capability, b"")

    with pytest.raises(WirePutViolation) as caught:
        exercise_wire_put_corpus(
            WirePutImplementation(
                name="unsigned-empty-body",
                body_binding="unsigned"),
            capability,
            request,
            ConformanceRun("unsigned-empty-body", seed=1),
        )

    assert caught.value.mutation.name == "implementation-profile"


def test_exact_key_with_wrong_body_is_rejected_without_occupying_the_oid():
    body = b"legitimate immutable bytes"
    capability = _mint("r2", "obj", body)[3]
    request = exact_wire_put(capability, body)
    mutation = next(
        mutation for mutation in wire_put_mutations(
            capability, request, seed=1)
        if mutation.name == "same-length-body-substitution")
    store = {}

    result = WirePutImplementation().execute(
        capability, mutation.request, store)

    assert not result.authorized
    assert store == {}


def test_notification_corpus_is_seeded_bounded_and_covers_every_fault():
    first = notification_corpus(seed=23)
    replay = notification_corpus(seed=23)
    alternate = notification_corpus(seed=24)

    assert first == replay
    assert [case.name for case in first] != [
        case.name for case in alternate]
    assert frozenset().union(*(case.faults for case in first)) \
        == NOTIFICATION_FAULTS


def test_notifications_are_hints_and_fair_scan_applies_durable_piles():
    run = ConformanceRun("notification-contract", seed=0xE7E)

    report = exercise_notification_corpus(
        NotificationImplementation(), run)

    assert set(report.scripts) == {
        script.name for script in notification_corpus(0xE7E)}
    assert any("response-lost" in event for event in run.history)
    assert any("scan" in event for event in run.history)
    assert any("apply-root" in event for event in run.history)
    assert any("apply-noop" in event for event in run.history)
    assert not any(" delete " in event for event in run.history)


@pytest.mark.parametrize(
    ("implementation", "reason"),
    [
        (
            NotificationImplementation(
                name="event-is-work", event_as_work=True),
            "manufactured work"),
        (
            NotificationImplementation(
                name="no-fallback-scan", scheduled_scan=False),
            "ready durable pile"),
        (
            NotificationImplementation(
                name="repeat-root-application",
                repeat_root_application=True),
            "repeated a root application"),
    ],
)
def test_weak_notification_consumers_emit_first_failing_trace(
        implementation, reason):
    run = ConformanceRun(implementation.name, seed=0x5157)

    with pytest.raises(NotificationViolation) as caught:
        exercise_notification_corpus(implementation, run)

    violation = caught.value
    assert reason in violation.reason
    assert violation.seed == 0x5157
    assert violation.prefix
    assert "direct-upload contract-model failure" in str(violation)


@pytest.mark.parametrize("provider", ("s3", "r2"))
def test_broker_parent_compromise_cannot_reach_canonical_workspace(provider):
    credential = isolated_broker_parent(provider)
    run = ConformanceRun(
        f"{provider}-isolated-broker-parent", seed=0xB20CE2)

    attacks = exercise_broker_parent_boundary(credential, run)

    assert set(attacks) == {
        "read-root",
        "list-workspace",
        "replace-root",
        "occupy-object",
        "forge-pile",
        "delete-object",
    }
    assert credential.allows(credential.ingress_bucket, "PUT")
    assert credential.allows(credential.ingress_bucket, "DELETE")


@pytest.mark.parametrize("provider", ("s3", "r2"))
def test_client_ingress_parent_is_put_only(provider):
    credential = put_only_ingress_parent(provider)

    assert dict(credential.scopes) == {
        credential.ingress_bucket: frozenset({"PUT"})}
    assert credential.allows(credential.ingress_bucket, "PUT")
    assert all(
        not credential.allows(credential.ingress_bucket, operation)
        for operation in ("GET", "LIST", "DELETE"))


@pytest.mark.parametrize("provider", ("s3", "r2"))
def test_single_bucket_parent_is_a_replayable_negative_control(provider):
    run = ConformanceRun(
        f"{provider}-single-bucket-parent", seed=0xB20CE2)

    with pytest.raises(BrokerBoundaryViolation) as caught:
        exercise_broker_parent_boundary(
            single_bucket_broker_parent(provider), run)

    violation = caught.value
    assert violation.attack.bucket.endswith("canonical-workspaces")
    assert violation.seed == 0xB20CE2
    assert violation.prefix
    assert "direct-upload contract-model failure" in str(violation)

    replay = ConformanceRun(
        f"{provider}-single-bucket-parent", seed=0xB20CE2)
    with pytest.raises(BrokerBoundaryViolation) as replayed:
        exercise_broker_parent_boundary(
            single_bucket_broker_parent(provider), replay)
    assert replayed.value.attack == violation.attack
    assert replayed.value.prefix == violation.prefix


def test_current_integration_seams_name_built_repository_roles():
    root = Path(__file__).parents[1]

    assert integration_inventory(root) == INTEGRATION_SEAMS
    by_symbol = {seam.symbol: seam.path for seam in INTEGRATION_SEAMS}
    assert by_symbol["UploadBroker"] == "deploy/upload_broker.py"
    assert by_symbol["PileSender"] == "core/pile_sender.py"
    assert by_symbol["RepositoryApplier"] == \
        "core/repository_applier.py"
    assert by_symbol["RepositoryReader"] == \
        "core/repository_reader.py"
