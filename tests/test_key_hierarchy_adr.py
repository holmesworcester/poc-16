"""Executable reference model for the poc-16 key-hierarchy ADR.

This is deliberately a decision-model test, not a hardware-provider
implementation. Later x1o provider work must run the same lifecycle contract
against its real provider API.
"""

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from nacl import public
from nacl.exceptions import CryptoError


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "key_hierarchy_v1.json"
ADR_PATH = ROOT / "docs" / "KEY_HIERARCHY_ADR.md"
FIXTURE = json.loads(FIXTURE_PATH.read_text())
GENERATIONS = FIXTURE["decision"]["recipient_generations"]
PURGE_OPERATION_TARGETS = FIXTURE["decision"]["purge_operation_targets"]
RECIPIENT_SUITE = FIXTURE["decision"]["software_recipient_suite"]


def generation_index(generation):
    return GENERATIONS.index(generation)


def batch_commitment(operations):
    canonical = json.dumps(
        sorted(operations), separators=(",", ":")
    ).encode()
    return hashlib.sha256(b"poc16-retirement-batch-v1\0" + canonical).hexdigest()


def purge_targets_for_operations(operations):
    unknown = sorted(set(operations) - PURGE_OPERATION_TARGETS.keys())
    if unknown:
        raise ValueError(f"unknown purge operations: {unknown}")
    return frozenset(
        cover_id
        for operation in operations
        for cover_id in PURGE_OPERATION_TARGETS[operation]
    )


@dataclass(frozen=True)
class Envelope:
    generation: str
    ciphertext: bytes


@dataclass(frozen=True)
class ProviderSnapshot:
    disk: dict
    handles: dict
    hardware_claims: dict
    hardware_floor: int


@dataclass(frozen=True)
class TransitionClaim:
    successor: str
    successor_suite: str
    successor_public: bytes
    next_generation: str
    next_suite: str
    next_public: bytes
    retirement_batch_commitment: str


@dataclass(frozen=True)
class PreparedTransition:
    """Caller-saved transition inputs; retries reuse this exact value."""

    predecessor: str
    successor: str
    successor_suite: str
    successor_public: bytes
    next_generation: str
    next_suite: str
    next_public: bytes
    operations: tuple

    @property
    def claim(self):
        return TransitionClaim(
            self.successor,
            self.successor_suite,
            self.successor_public,
            self.next_generation,
            self.next_suite,
            self.next_public,
            batch_commitment(self.operations),
        )


class ProviderModel:
    """Small provider state machine with a privileged snapshot attacker.

    `_handles` stands in for opaque key blobs/secure handles. Normal callers
    never receive private bytes. The explicit test-only attacker accessor is
    used solely to prove that even already-known P material cannot open
    independently generated S or T ciphertext.
    """

    def __init__(self, *, capacity=3, rollback_resistant=True):
        self.capacity = capacity
        self.rollback_resistant = rollback_resistant
        self._handles = {}
        self._hardware_claims = {}
        self._hardware_floor = 0
        self.peak_handles = 0
        self.disk = {
            "active": GENERATIONS[0],
            "staged": GENERATIONS[1],
            "prepared_next": None,
            "claims": {},
            "manifests": {},
            "covers": {},
            "fenced": set(),
            "migrated": {},
            "destroyed": {},
            "promoted": {},
            "finalized": {GENERATIONS[0]},
            "wrap_eligible": {GENERATIONS[0]},
            "leases": {},
        }
        assert self._generate(GENERATIONS[0]) == "generated"
        assert self._generate(GENERATIONS[1]) == "generated"

    @property
    def handle_count(self):
        return len(self._handles)

    @property
    def active(self):
        return self.disk["active"]

    @property
    def staged(self):
        return self.disk["staged"]

    @property
    def wrap_eligible(self):
        return {
            generation
            for generation in self.disk["wrap_eligible"]
            if not self._is_retired(generation)
            and generation in self._handles
        }

    def _is_retired(self, generation):
        return generation_index(generation) < self._hardware_floor

    def _generate(self, generation):
        if generation in self._handles:
            return "already-generated"
        if self.handle_count >= self.capacity:
            return "capacity-failure-before-predecessor-destruction"
        self._handles[generation] = bytes(public.PrivateKey.generate())
        self.peak_handles = max(self.peak_handles, self.handle_count)
        return "generated"

    def prepare_next(self, generation):
        expected_index = generation_index(self.staged) + 1
        if generation_index(generation) != expected_index:
            return "invalid-recursive-schedule"
        result = self._generate(generation)
        if result == "capacity-failure-before-predecessor-destruction":
            return result
        self.disk["prepared_next"] = generation
        return "prepared"

    def public_key(self, generation):
        private_key = public.PrivateKey(self._usable_private(generation))
        return bytes(private_key.public_key)

    def export_private(self, generation):
        del generation
        raise PermissionError("recipient generation private keys are non-exportable")

    def _privileged_private_for_test(self, generation):
        """Model a pre-purge compromise; this is not a provider API."""
        return self._handles[generation]

    def _usable_private(self, generation):
        if generation_index(generation) < self._hardware_floor:
            raise CryptoError("recipient generation is below hardware floor")
        try:
            return self._handles[generation]
        except KeyError as error:
            raise CryptoError("recipient generation handle is unavailable") from error

    def _claim_handles_match(self, claim):
        if (
            claim.successor_suite != RECIPIENT_SUITE
            or claim.next_suite != RECIPIENT_SUITE
        ):
            return False
        expected = (
            (claim.successor, claim.successor_public),
            (claim.next_generation, claim.next_public),
        )
        for generation, expected_public in expected:
            private_bytes = self._handles.get(generation)
            if private_bytes is None:
                return False
            actual_public = bytes(
                public.PrivateKey(private_bytes).public_key
            )
            if actual_public != expected_public:
                return False
        return True

    def claim(self, prepared):
        predecessor = prepared.predecessor
        claim = prepared.claim
        prior = self._hardware_claims.get(predecessor)
        if prior is None:
            prior = self.disk["claims"].get(predecessor)
        if prior is not None:
            if prior != claim:
                return "conflict"
            try:
                manifest = purge_targets_for_operations(prepared.operations)
            except ValueError:
                return "invalid-purge-operation"
            # Rehydrate rollbackable metadata from the exact caller-supplied
            # prepared state after a hardware claim survived disk rollback.
            self.disk["claims"][predecessor] = claim
            self.disk["manifests"][predecessor] = manifest
            return "coalesced"

        if generation_index(predecessor) < self._hardware_floor:
            return "retired-predecessor"
        if predecessor != self.active:
            return "inactive-predecessor"
        if prepared.successor != self.staged:
            return "invalid-successor"
        if prepared.next_generation != self.disk["prepared_next"]:
            return "invalid-next-commitment"
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        try:
            manifest = purge_targets_for_operations(prepared.operations)
        except ValueError:
            return "invalid-purge-operation"

        self.disk["claims"][predecessor] = claim
        self.disk["manifests"][predecessor] = manifest
        if self.rollback_resistant:
            self._hardware_claims[predecessor] = claim
        return "accepted"

    def acquire_writer_lease(self, writer):
        generation = self.active
        if (
            self._is_retired(generation)
            or generation not in self._handles
            or generation in self.disk["fenced"]
            or generation not in self.disk["finalized"]
        ):
            return "rejected"
        self.disk["leases"][writer] = generation
        return "accepted"

    def _cover_aad(self, cover_id, generation):
        return (
            b"poc16-cover-v1\0"
            + generation.encode()
            + b"\0"
            + cover_id.encode()
        )

    def _seal(self, generation, cover_id, plaintext):
        key = public.PrivateKey(self._usable_private(generation)).public_key
        bound_plaintext = self._cover_aad(cover_id, generation) + b"\0" + plaintext
        return Envelope(
            generation,
            bytes(public.SealedBox(key).encrypt(bound_plaintext)),
        )

    def _open(self, cover_id, envelope):
        key = public.PrivateKey(self._usable_private(envelope.generation))
        bound_plaintext = public.SealedBox(key).decrypt(envelope.ciphertext)
        prefix = self._cover_aad(cover_id, envelope.generation) + b"\0"
        if not bound_plaintext.startswith(prefix):
            raise CryptoError("cover context mismatch")
        return bound_plaintext[len(prefix) :]

    def seed_cover(self, cover_id, plaintext):
        assert self.active in self.wrap_eligible
        self.disk["covers"][cover_id] = self._seal(
            self.active, cover_id, plaintext
        )

    def commit_cover(self, writer, cover_id, plaintext):
        generation = self.disk["leases"].get(writer)
        if (
            generation is None
            or self._is_retired(generation)
            or generation not in self._handles
            or generation in self.disk["fenced"]
        ):
            return "rejected"
        self.disk["covers"][cover_id] = self._seal(
            generation, cover_id, plaintext
        )
        return "accepted"

    def open_cover(self, cover_id):
        return self._open(cover_id, self.disk["covers"][cover_id])

    def cover_envelope(self, cover_id):
        return self.disk["covers"][cover_id]

    def seal_external(self, generation, plaintext):
        key = public.PrivateKey(self._usable_private(generation)).public_key
        return bytes(public.SealedBox(key).encrypt(plaintext))

    def fence_and_drain(self, predecessor):
        if (
            predecessor != self.active
            or self._is_retired(predecessor)
            or predecessor not in self._handles
        ):
            return "inactive-predecessor", []
        self.disk["fenced"].add(predecessor)
        aborted = sorted(
            writer
            for writer, generation in self.disk["leases"].items()
            if generation == predecessor
        )
        for writer in aborted:
            del self.disk["leases"][writer]
        return "fenced", aborted

    def migrate(self, predecessor, successor, purge_cover_ids):
        if predecessor not in self.disk["fenced"]:
            return "writer-fence-required"
        claim = self.disk["claims"].get(predecessor)
        if claim is None:
            return "transition-claim-required"
        if claim.successor != successor:
            return "claim-successor-mismatch"
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        manifest = self.disk["manifests"].get(predecessor)
        if manifest is None:
            return "retirement-manifest-required"
        if frozenset(purge_cover_ids) != manifest:
            return "retirement-manifest-mismatch"
        migrated = {}
        for cover_id, envelope in self.disk["covers"].items():
            if cover_id in manifest:
                continue
            if envelope.generation == successor:
                migrated[cover_id] = envelope
                continue
            if envelope.generation != predecessor:
                return "unexpected-cover-generation"
            plaintext = self._open(cover_id, envelope)
            migrated[cover_id] = self._seal(successor, cover_id, plaintext)
        self.disk["covers"] = migrated
        self.disk["migrated"][predecessor] = (successor, manifest)
        return "migrated"

    def destroy(self, predecessor, successor):
        claim = self.disk["claims"].get(predecessor)
        if claim is None:
            return "transition-claim-required"
        if claim.successor != successor:
            return "claim-successor-mismatch"
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        manifest = self.disk["manifests"].get(predecessor)
        if self.disk["migrated"].get(predecessor) != (successor, manifest):
            return "migration-required"
        if any(cover_id in self.disk["covers"] for cover_id in manifest):
            return "purge-target-remains"
        if any(
            envelope.generation == predecessor
            for envelope in self.disk["covers"].values()
        ):
            return "predecessor-cover-remains"
        prior = self.disk["destroyed"].get(predecessor)
        if prior is not None:
            if prior != successor:
                return "destruction-successor-conflict"
            if self.rollback_resistant:
                self._hardware_floor = max(
                    self._hardware_floor, generation_index(claim.successor)
                )
            return "already-destroyed"
        if predecessor not in self._handles:
            if (
                self.rollback_resistant
                and self._hardware_claims.get(predecessor) == claim
                and generation_index(claim.successor) <= self._hardware_floor
            ):
                self.disk["destroyed"][predecessor] = claim.successor
                return "already-destroyed"
            return "missing-handle-without-destruction-evidence"
        del self._handles[predecessor]
        self.disk["destroyed"][predecessor] = successor
        if self.rollback_resistant:
            self._hardware_floor = max(
                self._hardware_floor, generation_index(claim.successor)
            )
        return "destroyed"

    def promote(self, prepared):
        predecessor = prepared.predecessor
        successor = prepared.successor
        next_generation = prepared.next_generation
        expected = prepared.claim
        if self.disk["claims"].get(predecessor) != expected:
            return "claim-mismatch"
        prior = self.disk["promoted"].get(predecessor)
        if prior is not None:
            return "already-promoted" if prior == expected else "promotion-conflict"
        if self.disk["destroyed"].get(predecessor) != successor:
            return "destruction-required"
        if self.disk["migrated"].get(predecessor) != (
            successor,
            self.disk["manifests"].get(predecessor),
        ):
            return "migration-required"
        if self.active != predecessor:
            return "active-predecessor-mismatch"
        if self._is_retired(successor):
            return "successor-already-retired"
        if not self._claim_handles_match(expected):
            return "prepared-key-mismatch"
        before = self.handle_count
        self.disk["active"] = successor
        self.disk["staged"] = next_generation
        self.disk["prepared_next"] = None
        self.disk["wrap_eligible"] = set()
        self.disk["promoted"][predecessor] = expected
        assert self.handle_count == before
        return "promoted-without-allocation"

    def finalize(self, predecessor, successor):
        claim = self.disk["claims"].get(predecessor)
        if claim is None or claim.successor != successor:
            return "completion-evidence-required"
        if (
            self.disk["destroyed"].get(predecessor) != successor
            or self.disk["promoted"].get(predecessor) != claim
        ):
            return "completion-evidence-required"
        if successor in self.disk["finalized"]:
            return "already-finalized"
        if (
            self.active != successor
            or self._is_retired(successor)
            or successor not in self._handles
        ):
            return "completion-evidence-required"
        self.disk["finalized"].add(successor)
        self.disk["wrap_eligible"] = {successor}
        return "finalized"

    def snapshot(self):
        return ProviderSnapshot(
            deepcopy(self.disk),
            deepcopy(self._handles),
            deepcopy(self._hardware_claims),
            self._hardware_floor,
        )

    def restore(self, snapshot):
        self.disk = deepcopy(snapshot.disk)
        if not self.rollback_resistant:
            self._handles = deepcopy(snapshot.handles)
            self._hardware_claims = deepcopy(snapshot.hardware_claims)
            self._hardware_floor = snapshot.hardware_floor

    def reconcile_status(self):
        if generation_index(self.active) < self._hardware_floor:
            return "stale-snapshot-fail-closed"
        return "current"


def prepared_transition(provider, transition, *, operations=None):
    if operations is None:
        operations = transition["purge_operations"]
    return PreparedTransition(
        predecessor=transition["predecessor"],
        successor=transition["successor"],
        successor_suite=RECIPIENT_SUITE,
        successor_public=provider.public_key(transition["successor"]),
        next_generation=transition["next"],
        next_suite=RECIPIENT_SUITE,
        next_public=provider.public_key(transition["next"]),
        operations=tuple(operations),
    )


def complete_transition(provider, transition, prepared=None):
    predecessor = transition["predecessor"]
    successor = transition["successor"]
    next_generation = transition["next"]
    operations = transition["purge_operations"]
    purge_cover_ids = purge_targets_for_operations(operations)

    assert provider.prepare_next(next_generation) == "prepared"
    assert provider.handle_count == 3
    if prepared is None:
        prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.claim(prepared) == "coalesced"
    assert provider.claim(
        replace(
            prepared,
            next_public=bytes(public.PrivateKey.generate().public_key),
        )
    ) == "conflict"
    assert provider.claim(
        replace(
            prepared,
            successor_public=bytes(public.PrivateKey.generate().public_key),
        )
    ) == "conflict"
    assert provider.claim(
        replace(
            prepared,
            operations=prepared.operations + ("conflicting-purge-operation",),
        )
    ) == "conflict"

    assert provider.fence_and_drain(predecessor)[0] == "fenced"
    assert provider.migrate(
        predecessor, successor, purge_cover_ids
    ) == "migrated"
    assert provider.destroy(predecessor, successor) == "destroyed"
    assert provider.destroy(predecessor, successor) == "already-destroyed"
    assert provider.handle_count == 2
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.promote(prepared) == "already-promoted"
    assert provider.wrap_eligible == set()
    assert provider.finalize(predecessor, successor) == "finalized"
    assert provider.finalize(predecessor, successor) == "already-finalized"
    assert provider.wrap_eligible == {successor}
    return prepared


def cover_fixture():
    return {
        item["id"]: bytes.fromhex(item["plaintext_hex"])
        for item in FIXTURE["cover_records"]
    }


def test_adr_selects_bounded_independent_generations_and_explicit_tiers():
    decision = FIXTURE["decision"]
    assert decision["primary"] == "independent-nonexportable-recipient-generations"
    assert decision["portable_fallback"] == "independent-random-software-generations"
    assert decision["stable_content_root"] == "rejected-in-v1"
    assert decision["first_frontier_only_rotation"] == "rejected-in-v1"
    assert decision["steady_handle_count"] == 2
    assert decision["transition_peak_handle_count"] == 3

    tiers = {tier["name"]: tier for tier in FIXTURE["guarantee_tiers"]}
    assert tiers["normal-disk"]["snapshot_erasure_claim"] is False
    assert tiers["hardware-isolated"]["nonexportable_private_key"] is True
    assert tiers["hardware-isolated"]["snapshot_erasure_claim"] is False
    assert tiers["rollback-resistant"]["deleted_keyblob_replay_blocked"] is True
    assert tiers["rollback-resistant"]["old_claim_replay_blocked"] is True
    assert tiers["rollback-resistant"]["snapshot_erasure_claim"] is True


def test_three_recursive_transitions_are_unique_and_return_to_two_handles():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    assert provider.handle_count == 2
    assert provider.peak_handles == 2

    for transition in FIXTURE["decision"]["transition_batches"]:
        predecessor_private = provider._privileged_private_for_test(
            transition["predecessor"]
        )
        assert provider.prepare_next(transition["next"]) == "prepared"
        prepared = prepared_transition(provider, transition)

        for generation in (transition["successor"], transition["next"]):
            ciphertext = provider.seal_external(generation, b"future generation")
            with pytest.raises(CryptoError):
                public.SealedBox(
                    public.PrivateKey(predecessor_private)
                ).decrypt(ciphertext)

        # complete_transition performs an idempotent prepare of the same T/U/V.
        complete_transition(provider, transition, prepared)
        assert provider.handle_count == 2
        assert provider.active == transition["successor"]
        assert provider.staged == transition["next"]

    assert provider.peak_handles == 3
    assert provider.active == "U"
    assert provider.staged == "V"
    with pytest.raises(PermissionError):
        provider.export_private("U")


def test_generation_keys_are_independent_across_provider_instances():
    first = ProviderModel(capacity=3, rollback_resistant=True)
    second = ProviderModel(capacity=3, rollback_resistant=True)

    for generation in ("P", "S"):
        assert first.public_key(generation) != second.public_key(generation)
        assert first._privileged_private_for_test(
            generation
        ) != second._privileged_private_for_test(generation)

    transition = FIXTURE["decision"]["transition_batches"][0]
    assert first.prepare_next("T") == "prepared"
    assert second.prepare_next("T") == "prepared"
    assert prepared_transition(
        first, transition
    ).claim != prepared_transition(second, transition).claim


def test_two_handle_capacity_fails_before_predecessor_destruction():
    provider = ProviderModel(capacity=2, rollback_resistant=True)
    secret = cover_fixture()["frontier-root"]
    provider.seed_cover("frontier-root", secret)

    assert provider.prepare_next("T") == (
        "capacity-failure-before-predecessor-destruction"
    )
    assert provider.handle_count == 2
    assert provider.active == "P"
    assert provider.open_cover("frontier-root") == secret
    assert provider.disk["destroyed"] == {}
    assert provider.wrap_eligible == {"P"}


def test_fence_migrates_survivors_purges_target_and_blocks_late_writer():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    covers = cover_fixture()
    for cover_id, plaintext in covers.items():
        provider.seed_cover(cover_id, plaintext)

    assert provider.acquire_writer_lease("writer-before-fence") == "accepted"
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P") == (
        "fenced",
        ["writer-before-fence"],
    )
    assert provider.acquire_writer_lease("writer-after-fence") == "rejected"
    assert provider.commit_cover(
        "writer-before-fence", "racing-cover", b"must not commit"
    ) == "rejected"

    purge_cover_ids = purge_targets_for_operations(
        transition["purge_operations"]
    )
    assert provider.migrate("P", "S", purge_cover_ids) == "migrated"
    assert "retained-node-a" not in provider.disk["covers"]
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.finalize("P", "S") == "finalized"

    assert provider.open_cover("frontier-root") == covers["frontier-root"]
    assert provider.open_cover("retained-node-b") == covers["retained-node-b"]
    assert all(
        envelope.generation == "S"
        for envelope in provider.disk["covers"].values()
    )


def test_transition_steps_reject_unclaimed_successors_and_changed_manifest():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    covers = cover_fixture()
    for cover_id, plaintext in covers.items():
        provider.seed_cover(cover_id, plaintext)

    transition = FIXTURE["decision"]["transition_batches"][0]
    operations = transition["purge_operations"]
    manifest = purge_targets_for_operations(operations)
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"

    assert provider.migrate("P", "T", manifest) == "claim-successor-mismatch"
    assert provider.migrate("P", "S", set()) == "retirement-manifest-mismatch"
    assert provider.open_cover("retained-node-a") == covers["retained-node-a"]
    assert provider.migrate("P", "S", manifest) == "migrated"

    floor_before = provider._hardware_floor
    assert provider.destroy("P", "T") == "claim-successor-mismatch"
    assert provider.destroy("P", "P") == "claim-successor-mismatch"
    assert provider._hardware_floor == floor_before
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.destroy("P", "S") == "already-destroyed"
    assert provider._hardware_floor == generation_index("S")
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.finalize("P", "S") == "finalized"

    complete_transition(
        provider, FIXTURE["decision"]["transition_batches"][1]
    )
    assert provider.finalize("P", "T") == "completion-evidence-required"
    assert provider.wrap_eligible == {"T"}


def test_claim_binds_actual_public_keys_and_rejects_replaced_staged_handle():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"

    del provider._handles["T"]
    assert provider.prepare_next("T") == "prepared"
    replacement = prepared_transition(provider, transition)
    assert replacement.next_public != prepared.next_public
    assert provider.claim(replacement) == "conflict"

    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "prepared-key-mismatch"
    assert provider.disk["destroyed"] == {}
    assert provider.open_cover("frontier-root") == b"survivor"


def test_destroy_retry_rehydrates_evidence_from_protected_retirement_state():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    pre_destruction_snapshot = provider.snapshot()

    assert provider.destroy("P", "S") == "destroyed"
    provider.restore(pre_destruction_snapshot)
    assert provider.reconcile_status() == "stale-snapshot-fail-closed"
    assert provider.disk["destroyed"] == {}
    assert provider.destroy("P", "S") == "already-destroyed"
    assert provider.disk["destroyed"] == {"P": "S"}
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.finalize("P", "S") == "finalized"
    assert provider.open_cover("frontier-root") == b"survivor"


def test_rollback_resistant_restore_cannot_revive_p_or_fork_its_claim():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    deleted_secret = cover_fixture()["retained-node-a"]
    provider.seed_cover("retained-node-a", deleted_secret)
    assert provider.acquire_writer_lease("stale-writer") == "accepted"
    old_snapshot = provider.snapshot()

    transition = FIXTURE["decision"]["transition_batches"][0]
    prepared = complete_transition(provider, transition)
    provider.restore(old_snapshot)

    assert provider.reconcile_status() == "stale-snapshot-fail-closed"
    assert provider.wrap_eligible == set()
    assert provider.acquire_writer_lease("new-writer") == "rejected"
    assert provider.commit_cover(
        "stale-writer", "late-cover", b"must not commit"
    ) == "rejected"
    with pytest.raises(CryptoError):
        provider.open_cover("retained-node-a")
    assert provider.claim(prepared) == "coalesced"
    assert provider.claim(
        replace(prepared, operations=("forked-purge-operation",))
    ) == "conflict"


def test_nonrollback_restore_honestly_models_resurrection_and_claim_fork():
    provider = ProviderModel(capacity=3, rollback_resistant=False)
    deleted_secret = cover_fixture()["retained-node-a"]
    provider.seed_cover("retained-node-a", deleted_secret)
    old_snapshot = provider.snapshot()

    transition = FIXTURE["decision"]["transition_batches"][0]
    complete_transition(provider, transition)
    provider.restore(old_snapshot)

    assert provider.reconcile_status() == "current"
    assert provider.open_cover("retained-node-a") == deleted_secret
    assert provider.prepare_next("T") == "prepared"
    forked = prepared_transition(
        provider, transition, operations=["forked-purge-operation"]
    )
    assert provider.claim(forked) == "accepted"


def test_rejected_roots_and_platform_limits_are_explicit():
    candidates = {
        candidate["name"]: candidate
        for candidate in FIXTURE["hierarchy_candidates"]
    }
    assert candidates["independent-generation-handles"]["status"] == "accepted"
    assert candidates["stable-device-box-wraps-all-generations"]["status"] == (
        "rejected"
    )
    assert candidates[
        "deterministic-forward-schedule-without-monotonic-state"
    ]["status"] == "rejected"
    assert candidates["tpm-root-gated-by-exact-monotonic-position"]["status"] == (
        "deferred-provider-extension"
    )
    assert candidates[
        "independent-node-keys-first-frontier-only"
    ]["status"] == "rejected-in-v1"

    platforms = {platform["name"]: platform for platform in FIXTURE["platforms"]}
    assert platforms[
        "apple-security-framework-secure-enclave"
    ]["key_agreement_suite"] == "P-256"
    assert platforms[
        "apple-security-framework-secure-enclave"
    ]["maximum_default_tier"] == "hardware-isolated"
    assert platforms[
        "android-keystore-or-strongbox"
    ]["maximum_default_tier"] == "hardware-isolated"
    assert platforms[
        "tpm-2-policy-nv-provider"
    ]["maximum_default_tier"] == "rollback-resistant-when-provisioned"
    assert platforms["software-only"]["maximum_default_tier"] == "normal-disk"
    for platform in platforms.values():
        assert all(source.startswith("https://") for source in platform["sources"])


def test_adr_records_protocol_crash_backup_and_algorithm_requirements():
    prose = " ".join(ADR_PATH.read_text().split())
    for required in (
        "Decision: independent, non-exportable recipient-generation handles",
        "two handles at steady state",
        "P, S, and T",
        "no timestamp",
        "writer fence",
        "same-device restore",
        "StrongBox alone",
        "TPM2_PolicyNV",
        "normal-disk",
        "hardware-isolated",
        "rollback-resistant",
        "first-F-only mode is rejected",
        "new device is readmitted",
        "No allocation is permitted after P destruction",
    ):
        assert required in prose
