"""The future direct-upload design fails closed under authority mutations."""
from dataclasses import replace
from pathlib import Path

import pytest

from tests.direct_upload_method import (
    AUTHORITY_DIMENSIONS,
    INTEGRATION_SEAMS,
    NOTIFICATION_FAULTS,
    BrokerBoundaryViolation,
    CapabilityViolation,
    IngressRetirementViolation,
    NotificationImplementation,
    NotificationViolation,
    PromotionCase,
    PromotionImplementation,
    PromotionViolation,
    UploadImplementation,
    capability_mutations,
    check_promotion_history,
    exact_capability,
    exact_request,
    exercise_broker_parent_boundary,
    exercise_capability_corpus,
    exercise_ingress_retirement_boundary,
    exercise_notification_corpus,
    exercise_promotion_corpus,
    integration_inventory,
    isolated_broker_parent,
    notification_corpus,
    promotion_corpus,
    promotion_history,
    retirement_safe_broker_parent,
    single_bucket_broker_parent,
    unbuilt_direct_upload_symbols,
)
from tests.provider_conformance import ConformanceRun


@pytest.mark.parametrize("provider", ("s3", "r2"))
@pytest.mark.parametrize("object_class", ("obj", "pile"))
@pytest.mark.parametrize("path", ("raw-presigned", "upload-verifier"))
def test_exact_attenuation_survives_the_complete_seeded_corpus(
        provider, object_class, path):
    body = f"{provider}:{object_class}:body".encode()
    capability = exact_capability(provider, object_class, body)
    request = exact_request(capability, body)
    run = ConformanceRun(
        f"direct-upload-{provider}-{path}", seed=0xD1EC7)

    report = exercise_capability_corpus(
        UploadImplementation(path=path),
        capability, request, run)

    assert report.provider == provider
    assert set(report.mutations)
    assert len(run.history) > len(report.mutations)


def test_mutation_inventory_covers_every_authority_dimension_and_is_replayable():
    body = b"inventory"
    capability = exact_capability("s3", "pile", body)
    request = exact_request(capability, body)

    first = capability_mutations(capability, request, seed=17)
    replay = capability_mutations(capability, request, seed=17)
    alternate = capability_mutations(capability, request, seed=18)

    covered = frozenset().union(*(
        mutation.dimensions for mutation in first))
    assert covered == AUTHORITY_DIMENSIONS
    assert first == replay
    assert [case.name for case in first] != [
        case.name for case in alternate]


@pytest.mark.parametrize("dimension", sorted(AUTHORITY_DIMENSIONS))
def test_every_ignored_authority_dimension_has_a_first_failing_replay(
        dimension):
    body = b"weak-policy"
    capability = exact_capability("s3", "pile", body)
    request = exact_request(capability, body)
    implementation = UploadImplementation(
        name=f"ignored-{dimension}",
        ignored=frozenset({dimension}))
    run = ConformanceRun(implementation.name, seed=0xBAD)

    with pytest.raises(CapabilityViolation) as caught:
        exercise_capability_corpus(
            implementation, capability, request, run)

    violation = caught.value
    assert dimension in violation.mutation.dimensions
    assert violation.seed == 0xBAD
    assert violation.prefix
    assert f"seed={violation.seed:#x}" in str(violation)


def test_prefix_key_grant_is_not_mistaken_for_exact_attenuation():
    body = b"prefix-grant"
    capability = exact_capability("s3", "obj", body)
    request = exact_request(capability, body)

    with pytest.raises(CapabilityViolation) as caught:
        exercise_capability_corpus(
            UploadImplementation(
                name="prefix-grant", prefix_keys=True),
            capability, request,
            ConformanceRun("prefix-grant", seed=0xBAD))

    assert "key" in caught.value.mutation.dimensions


def test_overwrite_on_replay_is_caught_before_mutation_cases():
    body = b"immutable"
    capability = exact_capability("s3", "obj", body)
    request = exact_request(capability, body)
    weak = UploadImplementation(
        name="overwrite", overwrite_existing=True)

    with pytest.raises(CapabilityViolation) as caught:
        exercise_capability_corpus(
            weak, capability, request,
            ConformanceRun("overwrite", seed=4))

    assert caught.value.mutation.name == "colliding-existing-key"
    assert "overwritten" in caught.value.reason


@pytest.mark.parametrize("binding", ("unsigned", "md5"))
def test_non_collision_resistant_presigner_profiles_are_not_evidence(binding):
    body = b"provider-2xx-is-not-integrity"
    capability = exact_capability("r2", "obj", body)
    request = exact_request(capability, body)

    with pytest.raises(
            CapabilityViolation,
            match=rf"{binding} is not SHA-256 body binding"):
        exercise_capability_corpus(
            UploadImplementation(
                name=f"raw-{binding}", body_binding=binding),
            capability, request,
            ConformanceRun(f"raw-{binding}", seed=9))


def test_body_sha256_is_an_abstract_condition_not_provider_evidence():
    capability = exact_capability("s3", "obj", b"symbolic-condition")

    assert "abstract-body-sha256" in capability.signed_headers
    assert "x-amz-checksum-sha256" not in capability.signed_headers


def test_extra_signed_constraint_is_safe_but_missing_condition_is_not():
    capability = exact_capability("s3", "obj", b"signed-conditions")
    request = exact_request(capability, b"signed-conditions")
    mutations = {
        mutation.name: mutation
        for mutation in capability_mutations(capability, request, seed=1)
    }

    assert mutations["extra-signed-constraint"].expect_authorized
    assert not mutations["missing-signed-condition"].expect_authorized


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
    capability = exact_capability("s3", "obj", body)
    request = exact_request(capability, body)
    store = {}
    implementation = UploadImplementation(path=path)

    assert implementation.execute(
        capability, request, store).status == "created"
    replay = implementation.execute(capability, request, store)

    assert replay.status == replay_status
    assert not replay.applied
    assert next(iter(store.values())) == body


def test_empty_body_binding_mutation_is_not_masked_by_size():
    capability = exact_capability("s3", "obj", b"")
    request = exact_request(capability, b"")
    mutation = next(
        mutation for mutation in capability_mutations(
            capability, request, seed=1)
        if mutation.name == "body-binding-algorithm")

    with pytest.raises(CapabilityViolation) as caught:
        exercise_capability_corpus(
            UploadImplementation(
                name="ignored-empty-body-binding",
                ignored=frozenset({"body"})),
            capability,
            request,
            ConformanceRun("ignored-empty-body-binding", seed=1),
        )

    assert caught.value.mutation == mutation


def test_exact_key_with_wrong_body_is_rejected_without_occupying_the_oid():
    body = b"legitimate immutable bytes"
    capability = exact_capability("r2", "obj", body)
    request = exact_request(capability, body)
    mutation = next(
        mutation for mutation in capability_mutations(
            capability, request, seed=1)
        if mutation.name == "key-body-mismatch")
    store = {}

    result = UploadImplementation().execute(
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


def test_notifications_are_hints_and_fair_scan_drains_durable_piles():
    run = ConformanceRun("notification-contract", seed=0xE7E)

    report = exercise_notification_corpus(
        NotificationImplementation(), run)

    assert set(report.scripts) == {
        script.name for script in notification_corpus(0xE7E)}
    assert any("response-lost" in event for event in run.history)
    assert any("scan" in event for event in run.history)


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
                name="delete-on-event", delete_before_publish=True),
            "retirement order"),
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
def test_put_only_parent_preserves_acknowledged_ingress(provider):
    credential = retirement_safe_broker_parent(provider)
    run = ConformanceRun(
        f"{provider}-put-only-parent", seed=0xF10)

    attacks = exercise_ingress_retirement_boundary(credential, run)

    assert set(attacks) == {
        "delete-acknowledged-object",
        "delete-acknowledged-pile",
    }
    assert credential.allows(credential.ingress_bucket, "PUT")
    assert not credential.allows(credential.ingress_bucket, "DELETE")


@pytest.mark.parametrize("provider", ("s3", "r2"))
def test_broad_ingress_parent_can_erase_acknowledged_work(provider):
    run = ConformanceRun(
        f"{provider}-broad-ingress-parent", seed=0xF10)

    with pytest.raises(IngressRetirementViolation) as caught:
        exercise_ingress_retirement_boundary(
            isolated_broker_parent(provider), run)

    violation = caught.value
    assert violation.attack.operation == "DELETE"
    assert violation.seed == 0xF10
    assert violation.prefix


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


def test_promotion_corpus_is_seeded_bounded_and_covers_crash_boundaries():
    first = promotion_corpus(seed=31)
    replay = promotion_corpus(seed=31)
    alternate = promotion_corpus(seed=32)

    assert first == replay
    assert [case.name for case in first] != [
        case.name for case in alternate]
    assert {case.name for case in first} == {
        "clean",
        "crash-after-validate",
        "crash-after-promote",
        "crash-after-root",
        "crash-after-pile-delete",
        "crash-after-object-delete",
        "poison-staging-key",
        "foreign-workspace-intent",
        "foreign-member-intent",
        "unauthorized-member-intent",
        "missing-staged-object",
        "canonical-object-collision",
    }


@pytest.mark.parametrize("provider", ("s3", "r2"))
def test_staging_promotion_obeys_abstract_retirement_order(provider):
    run = ConformanceRun(
        f"{provider}-staging-promotion", seed=0x570A6E)

    report = exercise_promotion_corpus(
        PromotionImplementation(), provider, run)

    assert report.provider == provider
    assert set(report.cases) == {
        case.name for case in promotion_corpus(0x570A6E)}
    assert any(
        event.startswith("crash-after-validate actor-1 crash")
        for event in run.history)
    assert any(
        event.startswith("crash-after-promote actor-1 crash")
        for event in run.history)
    assert any(
        event.startswith("crash-after-root actor-1 crash")
        for event in run.history)


def test_retry_after_root_crash_uses_a_fresh_actor_and_durable_root():
    run = ConformanceRun("cold-retry", seed=0x570A6E)
    events, _expected = promotion_history(
        PromotionImplementation(),
        PromotionCase("crash-after-root", crash_after="root"),
        "r2",
        run,
    )

    turns = [
        event.generation
        for event in events if event.operation == "start-turn"
    ]
    committed = next(
        event for event in events if event.operation == "commit-root")
    retired = next(
        event for event in events
        if event.operation == "delete-stage-pile")
    assert turns == [1, 2]
    assert committed.generation == 1
    assert retired.generation == 2


@pytest.mark.parametrize(
    ("operation", "bucket_field"),
    [
        ("promote", "ingress_bucket"),
        ("commit-root", "ingress_bucket"),
        ("delete-stage-pile", "canonical_bucket"),
    ],
)
def test_promotion_oracle_rejects_wrong_bucket_state_transitions(
        operation, bucket_field):
    run = ConformanceRun("wrong-bucket", seed=7)
    case = PromotionCase("clean")
    events, expected = promotion_history(
        PromotionImplementation(), case, "r2", run)
    events = list(events)
    index = next(
        index for index, event in enumerate(events)
        if event.operation == operation)
    events[index] = replace(
        events[index], bucket=expected[bucket_field])

    with pytest.raises(
            PromotionViolation,
            match=r"escaped its exact bucket/key"):
        check_promotion_history(
            run, case, tuple(events), expected)


def test_promotion_oracle_rejects_undeclared_cross_workspace_copy():
    run = ConformanceRun("undeclared-copy", seed=8)
    case = PromotionCase("clean")
    events, expected = promotion_history(
        PromotionImplementation(), case, "r2", run)
    events = list(events)
    index = next(
        index for index, event in enumerate(events)
        if event.operation == "promote")
    legitimate = events[index]
    digest = legitimate.key.rsplit("/", 1)[-1]
    events.insert(
        index + 1,
        replace(
            legitimate,
            key=f"workspaces/{'f' * 64}/obj/{digest}"),
    )

    with pytest.raises(
            PromotionViolation,
            match=r"declared-digest authority"):
        check_promotion_history(
            run, case, tuple(events), expected)


def test_promotion_oracle_rejects_unknown_state_transition():
    run = ConformanceRun("unknown-transition", seed=9)
    case = PromotionCase("clean")
    events, expected = promotion_history(
        PromotionImplementation(), case, "r2", run)
    events = list(events)
    index = next(
        index for index, event in enumerate(events)
        if event.operation == "validate")
    events[index] = replace(
        events[index], operation="overwrite-root")

    with pytest.raises(
            PromotionViolation,
            match=r"unknown promotion operation"):
        check_promotion_history(
            run, case, tuple(events), expected)


@pytest.mark.parametrize(
    ("implementation", "reason"),
    [
        (
            PromotionImplementation(
                name="unchecked-staging-bytes", verify_sha256=False),
            "canonical object key does not bind promoted bytes",
        ),
        (
            PromotionImplementation(
                name="early-pile-retirement", delete_before_root=True),
            "retirement lacks an abstract durable root commit",
        ),
        (
            PromotionImplementation(
                name="process-cache-root", durable_root=False),
            "retirement lacks an abstract durable root commit",
        ),
        (
            PromotionImplementation(
                name="unchecked-staged-intent", validate_intent=False),
            "unauthorized staged intent reached promotion",
        ),
        (
            PromotionImplementation(
                name="overwrite-canonical", overwrite_canonical=True),
            "promotion overwrote canonical immutable bytes",
        ),
    ],
)
def test_weak_promotion_policies_emit_first_failing_trace(
        implementation, reason):
    run = ConformanceRun(implementation.name, seed=0x570A6E)

    with pytest.raises(PromotionViolation) as caught:
        exercise_promotion_corpus(implementation, "r2", run)

    violation = caught.value
    assert reason in violation.reason
    assert violation.seed == 0x570A6E
    assert violation.prefix
    assert "direct-upload contract-model failure" in str(violation)

    replay = ConformanceRun(implementation.name, seed=0x570A6E)
    with pytest.raises(PromotionViolation) as replayed:
        exercise_promotion_corpus(implementation, "r2", replay)
    assert replayed.value.case == violation.case
    assert replayed.value.reason == violation.reason
    assert replayed.value.prefix == violation.prefix


def test_current_integration_seams_are_explicit_and_runtime_is_still_unbuilt():
    root = Path(__file__).parents[1]

    assert integration_inventory(root) == INTEGRATION_SEAMS
    assert unbuilt_direct_upload_symbols(root) == ()
