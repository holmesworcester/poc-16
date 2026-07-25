"""Executable reference model for the poc-16 key-hierarchy ADR.

This is deliberately a decision-model test, not a hardware-provider
implementation. Later x1o provider work must run the same lifecycle contract
against its real provider API.
"""

import hashlib
import hmac
import json
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
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
COVER_CONTEXT = FIXTURE["cover_context"]


def generation_index(generation):
    return GENERATIONS.index(generation)


def batch_commitment(operations):
    canonical = json.dumps(
        sorted(set(operations)), separators=(",", ":")
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
class CoverContext:
    version: int
    provider_suite: str
    recipient_lineage_id: str
    generation: str
    content_scope_id: str
    frontier_id: str
    secret_kind: str
    range_start: int
    range_width: int
    bit_depth: int
    event_id_prefix: str
    source_secret_ref: str
    tombstone_context: str
    recovery_policy_ref: str


@dataclass(frozen=True)
class Envelope:
    context: CoverContext
    ciphertext: bytes

    @property
    def generation(self):
        return self.context.generation


@dataclass(frozen=True)
class CoverRecord:
    """Authoritative local metadata kept separately from the envelope."""

    expected_context: CoverContext
    secret_commitment: str
    envelope: Envelope


@dataclass(frozen=True)
class MigrationProof:
    successor: str
    manifest: frozenset
    survivor_commitments: frozenset
    survivor_contexts: frozenset


@dataclass(frozen=True)
class ProviderSnapshot:
    disk: dict
    handles: dict
    generation_publics: dict
    generation_suites: dict
    generation_positions: dict
    provider_epoch: str
    protected_active: str
    protected_staged: str
    protected_transitions: dict
    protected_fences: set
    protected_migrations: dict
    protected_retirements: dict
    protected_completions: dict
    hardware_floor: int


@dataclass(frozen=True)
class TransitionClaim:
    successor: str
    successor_position: int
    successor_suite: str
    successor_public: bytes
    next_generation: str
    next_position: int
    next_suite: str
    next_public: bytes
    retirement_batch_commitment: str


@dataclass(frozen=True)
class AcceptedTransition:
    claim: TransitionClaim
    manifest: frozenset


@dataclass(frozen=True)
class DestructionIntent:
    predecessor: str
    predecessor_suite: str
    predecessor_public: bytes
    accepted_transition: AcceptedTransition
    migration_proof: MigrationProof


@dataclass(frozen=True)
class ParentClaimRef:
    predecessor: str
    claim_id: str


@dataclass(frozen=True)
class PreparedTransition:
    """Caller-saved transition inputs; retries reuse this exact value."""

    predecessor: str
    successor: str
    successor_position: int
    successor_suite: str
    successor_public: bytes
    next_generation: str
    next_position: int
    next_suite: str
    next_public: bytes
    operations: tuple

    @property
    def claim(self):
        return TransitionClaim(
            self.successor,
            self.successor_position,
            self.successor_suite,
            self.successor_public,
            self.next_generation,
            self.next_position,
            self.next_suite,
            self.next_public,
            batch_commitment(self.operations),
        )


def transition_claim_id(predecessor, claim):
    canonical = json.dumps(
        {
            "predecessor": predecessor,
            "successor": claim.successor,
            "successor_position": claim.successor_position,
            "successor_suite": claim.successor_suite,
            "successor_public": claim.successor_public.hex(),
            "next_generation": claim.next_generation,
            "next_position": claim.next_position,
            "next_suite": claim.next_suite,
            "next_public": claim.next_public.hex(),
            "retirement_batch_commitment": (
                claim.retirement_batch_commitment
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(b"poc16-transition-claim-v1\0" + canonical).hexdigest()


def local_secret_commitment(cover_id, context, plaintext):
    """Generation-independent id of one canonical local cover secret."""
    canonical = json.dumps(
        {
            "cover_id": cover_id,
            "recipient_lineage_id": context.recipient_lineage_id,
            "content_scope_id": context.content_scope_id,
            "frontier_id": context.frontier_id,
            "secret_kind": context.secret_kind,
            "range_start": context.range_start,
            "range_width": context.range_width,
            "bit_depth": context.bit_depth,
            "event_id_prefix": context.event_id_prefix,
            "source_secret_ref": context.source_secret_ref,
            "tombstone_context": context.tombstone_context,
            "recovery_policy_ref": context.recovery_policy_ref,
            "plaintext_hex": plaintext.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(b"poc16-local-cover-secret-v1\0" + canonical).hexdigest()


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
        self._generation_publics = {}
        self._generation_suites = {}
        self._generation_positions = {}
        self._provider_epoch = hashlib.sha256(
            b"poc16-provider-epoch-v1\0" + bytes(public.PrivateKey.generate())
        ).hexdigest()
        self._restore_binding_valid = True
        self._protected_active = GENERATIONS[0]
        self._protected_staged = GENERATIONS[1]
        self._protected_transitions = {}
        self._protected_fences = set()
        self._protected_migrations = {}
        self._protected_retirements = {}
        self._protected_completions = {}
        self._hardware_floor = 0
        self.peak_handles = 0
        self.disk = {
            "provider_epoch": self._provider_epoch,
            "generation_commitments": {},
            "generation_positions": {},
            "active": GENERATIONS[0],
            "staged": GENERATIONS[1],
            "prepared_next": None,
            "claims": {},
            "manifests": {},
            "covers": {},
            "fenced": set(),
            "migrated": {},
            "destruction_intents": {},
            "destroyed": {},
            "promoted": {},
            "finalized": {GENERATIONS[0]},
            "wrap_eligible": {GENERATIONS[0]},
            "parent_claim_refs": {GENERATIONS[0]: None},
            "leases": {},
        }
        assert self._generate(GENERATIONS[0], position=0) == "generated"
        assert self._generate(GENERATIONS[1], position=1) == "generated"

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
        schedule_matches = self._active_pair_matches_parent_claim()
        return {
            generation
            for generation in self.disk["wrap_eligible"]
            if generation == self.active
            and schedule_matches
            and not self._is_retired(generation)
            and self._handle_matches_generation_commitment(generation)
        }

    def _is_retired(self, generation):
        return self._generation_position(generation) < self._hardware_floor

    def _generation_position(self, generation):
        try:
            return self._generation_positions[generation]
        except KeyError as error:
            raise ValueError(f"unknown generation id: {generation}") from error

    def _generate(self, generation, *, position=None):
        if position is None:
            if generation in self._generation_positions:
                position = self._generation_positions[generation]
            elif generation in GENERATIONS:
                position = generation_index(generation)
            else:
                return "generation-position-required"
        prior_position = self._generation_positions.setdefault(
            generation,
            position,
        )
        if prior_position != position:
            return "generation-position-conflict"
        self.disk["generation_positions"].setdefault(generation, position)
        if generation in self._handles:
            self.disk["generation_commitments"].setdefault(
                generation,
                (
                    self._generation_suites[generation],
                    self._generation_publics[generation],
                ),
            )
            return "already-generated"
        if self.handle_count >= self.capacity:
            return "capacity-failure-before-predecessor-destruction"
        private_bytes = bytes(public.PrivateKey.generate())
        self._handles[generation] = private_bytes
        self._generation_publics.setdefault(
            generation,
            bytes(public.PrivateKey(private_bytes).public_key),
        )
        self._generation_suites.setdefault(generation, RECIPIENT_SUITE)
        self.disk["generation_commitments"].setdefault(
            generation,
            (
                self._generation_suites[generation],
                self._generation_publics[generation],
            ),
        )
        self.peak_handles = max(self.peak_handles, self.handle_count)
        return "generated"

    def prepare_next(self, generation):
        expected_position = self._generation_position(self.staged) + 1
        if (
            generation in GENERATIONS
            and generation_index(generation) != expected_position
        ):
            return "invalid-recursive-schedule"
        known_position = self._generation_positions.get(generation)
        if known_position is not None and known_position != expected_position:
            return "invalid-recursive-schedule"
        if (
            self.active not in self.disk["finalized"]
            or self.active not in self.disk["wrap_eligible"]
        ):
            return "unfinalized-predecessor"
        if not self._active_pair_matches_parent_claim():
            return "recursive-commitment-mismatch"
        if (
            generation in self._generation_publics
            and generation not in self._handles
        ):
            return "generation-id-reuse"
        result = self._generate(generation, position=expected_position)
        if result == "capacity-failure-before-predecessor-destruction":
            return result
        if not self._handle_matches_generation_commitment(generation):
            return "generation-id-reuse"
        self.disk["prepared_next"] = generation
        return "prepared"

    def discard_prepared(self, generation):
        if self.disk["prepared_next"] != generation:
            return "not-prepared"
        accepted = self._accepted_transition(self.active)
        if accepted is not None:
            return "generation-bound-by-claim"
        if generation in (self.active, self.staged):
            return "scheduled-generation"
        self._handles.pop(generation, None)
        self.disk["prepared_next"] = None
        return "discarded"

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
        if self._generation_position(generation) < self._hardware_floor:
            raise CryptoError("recipient generation is below hardware floor")
        try:
            return self._handles[generation]
        except KeyError as error:
            raise CryptoError("recipient generation handle is unavailable") from error

    def _handle_matches_public(
        self,
        generation,
        expected_suite,
        expected_public,
    ):
        private_bytes = self._handles.get(generation)
        if private_bytes is None:
            return False
        actual_public = bytes(public.PrivateKey(private_bytes).public_key)
        return (
            expected_suite == RECIPIENT_SUITE
            and self._provider_metadata_matches((generation,))
            and self._generation_suites.get(generation) == expected_suite
            and actual_public == expected_public
            and self._generation_publics.get(generation) == expected_public
        )

    def _provider_metadata_matches(self, generations):
        if (
            not self._restore_binding_valid
            or self.disk.get("provider_epoch") != self._provider_epoch
        ):
            return False
        disk_commitments = self.disk.get("generation_commitments", {})
        return all(
            disk_commitments.get(generation)
            == (
                self._generation_suites.get(generation),
                self._generation_publics.get(generation),
            )
            and self.disk.get("generation_positions", {}).get(generation)
            == self._generation_positions.get(generation)
            and self._generation_suites.get(generation) is not None
            and self._generation_publics.get(generation) is not None
            for generation in generations
        )

    def _handle_matches_generation_commitment(self, generation):
        expected_suite = self._generation_suites.get(generation)
        expected_public = self._generation_publics.get(generation)
        return (
            expected_suite is not None
            and expected_public is not None
            and self._handle_matches_public(
                generation,
                expected_suite,
                expected_public,
            )
        )

    def _private_for_committed_generation(self, generation, expected_suite):
        private_bytes = self._usable_private(generation)
        if not self._provider_metadata_matches((generation,)):
            raise CryptoError("recipient provider binding mismatch")
        if self._generation_suites.get(generation) != expected_suite:
            raise CryptoError("recipient provider suite mismatch")
        if not self._handle_matches_generation_commitment(generation):
            raise CryptoError("recipient generation commitment mismatch")
        return private_bytes

    def _claim_handles_match(self, claim):
        expected = (
            (
                claim.successor,
                claim.successor_position,
                claim.successor_suite,
                claim.successor_public,
            ),
            (
                claim.next_generation,
                claim.next_position,
                claim.next_suite,
                claim.next_public,
            ),
        )
        for generation, position, expected_suite, expected_public in expected:
            if (
                self._generation_positions.get(generation) != position
                or not self._handle_matches_public(
                    generation,
                    expected_suite,
                    expected_public,
                )
            ):
                return False
        return True

    def _accepted_transition(self, predecessor):
        """Return only the immutable transition for this exact predecessor."""
        if self.rollback_resistant:
            return self._protected_transitions.get(predecessor)
        claim = self.disk["claims"].get(predecessor)
        manifest = self.disk["manifests"].get(predecessor)
        if claim is None or manifest is None:
            return None
        return AcceptedTransition(claim, manifest)

    def _accepted_claim(self, predecessor):
        accepted = self._accepted_transition(predecessor)
        return None if accepted is None else accepted.claim

    def _protected_live_position_matches(self):
        """Require the rollbackable head to name one completed protected edge."""
        if not self.rollback_resistant:
            return True
        if (
            not self._provider_metadata_matches((self.active, self.staged))
            or self.active != self._protected_active
            or self.staged != self._protected_staged
            or self._generation_position(self.active) != self._hardware_floor
        ):
            return False
        parent_ref = self.disk["parent_claim_refs"].get(self.active)
        if self.active == GENERATIONS[0]:
            return parent_ref is None
        if parent_ref is None:
            return False
        accepted = self._protected_transitions.get(parent_ref.predecessor)
        retirement = self._protected_retirements.get(parent_ref.predecessor)
        completion = self._protected_completions.get(parent_ref.predecessor)
        if (
            accepted is None
            or retirement is None
            or completion != retirement
            or retirement.accepted_transition != accepted
        ):
            return False
        claim = accepted.claim
        return (
            claim.successor == self.active
            and claim.successor_position
            == self._generation_position(self.active)
            and claim.next_generation == self.staged
            and claim.next_position
            == self._generation_position(self.staged)
            and parent_ref
            == ParentClaimRef(
                parent_ref.predecessor,
                transition_claim_id(parent_ref.predecessor, claim),
            )
        )

    def _active_pair_matches_parent_claim(self):
        """Validate the causal P/S/T chain without selecting a latest key."""
        if not self._protected_live_position_matches():
            return False
        parent_ref = self.disk["parent_claim_refs"].get(self.active)
        if self.active == GENERATIONS[0]:
            return (
                parent_ref is None
                and self.staged == GENERATIONS[1]
                and self._handle_matches_generation_commitment(self.active)
                and self._handle_matches_generation_commitment(self.staged)
            )
        if parent_ref is None:
            return False
        parent = self._accepted_claim(parent_ref.predecessor)
        if parent is None:
            return False
        if transition_claim_id(parent_ref.predecessor, parent) != (
            parent_ref.claim_id
        ):
            return False
        if (
            parent.successor != self.active
            or parent.successor_position
            != self._generation_position(self.active)
            or parent.next_generation != self.staged
            or parent.next_position != self._generation_position(self.staged)
            or parent.successor_suite != RECIPIENT_SUITE
            or parent.next_suite != RECIPIENT_SUITE
        ):
            return False
        expected = (
            (
                self.active,
                parent.successor_suite,
                parent.successor_public,
            ),
            (
                self.staged,
                parent.next_suite,
                parent.next_public,
            ),
        )
        for generation, expected_suite, expected_public in expected:
            if not self._handle_matches_public(
                generation,
                expected_suite,
                expected_public,
            ):
                return False
        return True

    def claim(self, prepared):
        predecessor = prepared.predecessor
        claim = prepared.claim
        try:
            manifest = purge_targets_for_operations(prepared.operations)
        except ValueError:
            return "invalid-purge-operation"
        prior = self._accepted_transition(predecessor)
        if prior is not None:
            if prior != AcceptedTransition(claim, manifest):
                return "conflict"
            # Rehydrate rollbackable metadata from the exact caller-supplied
            # prepared state after a hardware claim survived disk rollback.
            self.disk["claims"][predecessor] = claim
            self.disk["manifests"][predecessor] = manifest
            return "coalesced"

        if not set(prepared.operations):
            return "empty-retirement-batch"
        if self._generation_position(predecessor) < self._hardware_floor:
            return "retired-predecessor"
        if predecessor != self.active:
            return "inactive-predecessor"
        if (
            predecessor not in self.disk["finalized"]
            or predecessor not in self.disk["wrap_eligible"]
        ):
            return "unfinalized-predecessor"
        if (
            self.rollback_resistant
            and (
                self._generation_position(predecessor) != self._hardware_floor
                or not self._protected_live_position_matches()
            )
        ):
            return "protected-position-mismatch"
        if prepared.successor != self.staged:
            return "invalid-successor"
        if prepared.next_generation != self.disk["prepared_next"]:
            return "invalid-next-commitment"
        predecessor_position = self._generation_position(predecessor)
        if (
            claim.successor_position != predecessor_position + 1
            or claim.next_position != predecessor_position + 2
        ):
            return "invalid-recursive-schedule"
        if not self._active_pair_matches_parent_claim():
            return "recursive-commitment-mismatch"
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        if self.rollback_resistant:
            # This is the provider-protected compare-and-set. It is the
            # authority; rollbackable mirrors are written only after it commits.
            self._protected_transitions[predecessor] = AcceptedTransition(
                claim,
                manifest,
            )
        self.disk["claims"][predecessor] = claim
        self.disk["manifests"][predecessor] = manifest
        return "accepted"

    def acquire_writer_lease(self, writer, generation):
        if (
            generation != self.active
            or self._is_retired(generation)
            or generation not in self.wrap_eligible
            or self._fence_closed(generation)
        ):
            return "rejected"
        self.disk["leases"][writer] = generation
        return "accepted"

    def _fence_closed(self, generation):
        return (
            generation in self.disk["fenced"]
            or generation in self._protected_fences
        )

    def _authoritative_fence_closed(self, generation):
        if self.rollback_resistant:
            return generation in self._protected_fences
        return generation in self.disk["fenced"]

    def _cover_context(self, cover_id, generation):
        record = next(
            (
                item
                for item in FIXTURE["cover_records"]
                if item["id"] == cover_id
            ),
            None,
        )
        if record is None:
            record = {
                "secret_kind": "HistoryNode",
                "range_start": 0,
                "range_width": 1,
                "bit_depth": 256,
                "event_id_prefix": "00" * 32,
                "source_secret_ref": "00" * 32,
                "tombstone_context": "00" * 32,
            }
        return CoverContext(
            version=COVER_CONTEXT["version"],
            provider_suite=COVER_CONTEXT["provider_suite"],
            recipient_lineage_id=COVER_CONTEXT["recipient_lineage_id"],
            generation=generation,
            content_scope_id=COVER_CONTEXT["content_scope_id"],
            frontier_id=COVER_CONTEXT["frontier_id"],
            secret_kind=record["secret_kind"],
            range_start=record["range_start"],
            range_width=record["range_width"],
            bit_depth=record["bit_depth"],
            event_id_prefix=record["event_id_prefix"],
            source_secret_ref=record["source_secret_ref"],
            tombstone_context=record["tombstone_context"],
            recovery_policy_ref=COVER_CONTEXT["recovery_policy_ref"],
        )

    def _cover_aad(self, cover_id, context, secret_commitment):
        return b"poc16-cover-envelope\0" + json.dumps(
            {
                "cover_id": cover_id,
                "secret_commitment": secret_commitment,
                **asdict(context),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def _seal(self, generation, cover_id, plaintext, secret_commitment):
        context = self._cover_context(cover_id, generation)
        key = public.PrivateKey(
            self._private_for_committed_generation(
                generation,
                context.provider_suite,
            )
        ).public_key
        bound_plaintext = (
            self._cover_aad(cover_id, context, secret_commitment)
            + b"\0"
            + plaintext
        )
        return Envelope(
            context,
            bytes(public.SealedBox(key).encrypt(bound_plaintext)),
        )

    def _record(self, generation, cover_id, plaintext):
        expected_context = self._cover_context(cover_id, generation)
        secret_commitment = local_secret_commitment(
            cover_id,
            expected_context,
            plaintext,
        )
        return CoverRecord(
            expected_context,
            secret_commitment,
            self._seal(
                generation,
                cover_id,
                plaintext,
                secret_commitment,
            ),
        )

    def _open(
        self,
        cover_id,
        expected_context,
        expected_secret_commitment,
        envelope,
    ):
        if envelope.context != expected_context:
            raise CryptoError("cover context does not match authoritative record")
        key = public.PrivateKey(
            self._private_for_committed_generation(
                expected_context.generation,
                expected_context.provider_suite,
            )
        )
        bound_plaintext = public.SealedBox(key).decrypt(envelope.ciphertext)
        prefix = (
            self._cover_aad(
                cover_id,
                expected_context,
                expected_secret_commitment,
            )
            + b"\0"
        )
        if not bound_plaintext.startswith(prefix):
            raise CryptoError("cover context mismatch")
        plaintext = bound_plaintext[len(prefix) :]
        actual_commitment = local_secret_commitment(
            cover_id,
            expected_context,
            plaintext,
        )
        if not hmac.compare_digest(
            actual_commitment,
            expected_secret_commitment,
        ):
            raise CryptoError("cover secret commitment mismatch")
        return plaintext

    def seed_cover(self, cover_id, plaintext):
        assert self.active in self.wrap_eligible
        self.disk["covers"][cover_id] = self._record(
            self.active, cover_id, plaintext
        )

    def commit_cover(self, writer, cover_id, plaintext):
        generation = self.disk["leases"].get(writer)
        if (
            generation is None
            or self._is_retired(generation)
            or generation not in self.wrap_eligible
            or self._fence_closed(generation)
        ):
            return "rejected"
        self.disk["covers"][cover_id] = self._record(
            generation, cover_id, plaintext
        )
        return "accepted"

    def open_cover(self, cover_id):
        record = self.disk["covers"][cover_id]
        return self._open(
            cover_id,
            record.expected_context,
            record.secret_commitment,
            record.envelope,
        )

    def cover_envelope(self, cover_id):
        return self.disk["covers"][cover_id].envelope

    def cover_record(self, cover_id):
        return self.disk["covers"][cover_id]

    def seal_external(self, generation, plaintext):
        key = public.PrivateKey(
            self._private_for_committed_generation(
                generation,
                self._generation_suites[generation],
            )
        ).public_key
        return bytes(public.SealedBox(key).encrypt(plaintext))

    def fence_and_drain(self, predecessor):
        if (
            predecessor != self.active
            or self._is_retired(predecessor)
            or predecessor not in self._handles
        ):
            return "inactive-predecessor", []
        if not self._handle_matches_generation_commitment(predecessor):
            return "predecessor-key-mismatch", []
        if self._accepted_claim(predecessor) is None:
            return "transition-claim-required", []
        self._protected_fences.add(predecessor)
        self.disk["fenced"].add(predecessor)
        aborted = sorted(
            writer
            for writer, generation in self.disk["leases"].items()
            if generation == predecessor
        )
        for writer in aborted:
            del self.disk["leases"][writer]
        return "fenced", aborted

    def _accepted_migration(self, predecessor):
        if self.rollback_resistant:
            return self._protected_migrations.get(predecessor)
        return self.disk["migrated"].get(predecessor)

    @staticmethod
    def _survivor_commitments(covers):
        return frozenset(
            (cover_id, record.secret_commitment)
            for cover_id, record in covers.items()
        )

    @staticmethod
    def _survivor_contexts(covers):
        return frozenset(
            (cover_id, record.expected_context)
            for cover_id, record in covers.items()
        )

    def _migration_matches_current_covers(self, migration_proof):
        return (
            migration_proof.survivor_commitments
            == self._survivor_commitments(self.disk["covers"])
            and migration_proof.survivor_contexts
            == self._survivor_contexts(self.disk["covers"])
        )

    def _destruction_intent(
        self,
        predecessor,
        accepted,
        migration_proof,
    ):
        return DestructionIntent(
            predecessor,
            self._generation_suites[predecessor],
            self._generation_publics[predecessor],
            accepted,
            migration_proof,
        )

    def migrate(self, predecessor, successor, purge_cover_ids):
        if not self._authoritative_fence_closed(predecessor):
            return "writer-fence-required"
        accepted = self._accepted_transition(predecessor)
        if accepted is None:
            return "transition-claim-required"
        claim = accepted.claim
        if claim.successor != successor:
            return "claim-successor-mismatch"
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        if not self._handle_matches_generation_commitment(predecessor):
            return "predecessor-key-mismatch"
        manifest = accepted.manifest
        if frozenset(purge_cover_ids) != manifest:
            return "retirement-manifest-mismatch"
        migrated = {}
        for cover_id, record in self.disk["covers"].items():
            if cover_id in manifest:
                continue
            generation = record.expected_context.generation
            if generation not in (predecessor, successor):
                return "unexpected-cover-generation"
            plaintext = self._open(
                cover_id,
                record.expected_context,
                record.secret_commitment,
                record.envelope,
            )
            if generation == successor:
                migrated[cover_id] = record
            else:
                migrated[cover_id] = self._record(
                    successor,
                    cover_id,
                    plaintext,
                )
        proof = MigrationProof(
            successor,
            manifest,
            self._survivor_commitments(migrated),
            self._survivor_contexts(migrated),
        )
        prior = self._accepted_migration(predecessor)
        if prior is not None and prior != proof:
            return "migration-proof-mismatch"
        if self.rollback_resistant and prior is None:
            # Freeze the exact survivor identities and plaintext commitments in
            # protected state before replacing rollbackable cover storage.
            self._protected_migrations[predecessor] = proof
        self.disk["covers"] = migrated
        self.disk["migrated"][predecessor] = proof
        return "coalesced" if prior is not None else "migrated"

    def destroy(self, predecessor, successor):
        accepted = self._accepted_transition(predecessor)
        if accepted is None:
            return "transition-claim-required"
        claim = accepted.claim
        if claim.successor != successor:
            return "claim-successor-mismatch"
        if not self._authoritative_fence_closed(predecessor):
            return "writer-fence-required"
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        manifest = accepted.manifest
        migration_proof = self._accepted_migration(predecessor)
        if (
            migration_proof is None
            or migration_proof.successor != successor
            or migration_proof.manifest != manifest
        ):
            return "migration-required"
        # These immutable records are the exact inputs validated in this
        # serialized retirement operation. No mutable lookup may be trusted
        # after the provider opens them.
        validated_covers = dict(self.disk["covers"])
        current_survivors = self._survivor_commitments(validated_covers)
        expected_survivors = migration_proof.survivor_commitments
        if {cover_id for cover_id, _ in current_survivors} != {
            cover_id for cover_id, _ in expected_survivors
        }:
            return "survivor-set-mismatch"
        if current_survivors != expected_survivors:
            return "survivor-commitment-mismatch"
        if any(cover_id in validated_covers for cover_id in manifest):
            return "purge-target-remains"
        if any(
            record.expected_context.generation != successor
            for record in validated_covers.values()
        ):
            return "unexpected-survivor-generation"
        if (
            self._survivor_contexts(validated_covers)
            != migration_proof.survivor_contexts
        ):
            return "survivor-context-mismatch"
        try:
            for cover_id, record in validated_covers.items():
                self._open(
                    cover_id,
                    record.expected_context,
                    record.secret_commitment,
                    record.envelope,
                )
        except CryptoError:
            return "successor-cover-validation-failed"
        if set(self.disk["covers"]) != set(validated_covers):
            return "survivor-set-changed-during-validation"
        if self.disk["covers"] != validated_covers:
            return "survivor-record-changed-during-validation"
        if not self._authoritative_fence_closed(predecessor):
            return "writer-fence-required"
        if self._accepted_transition(predecessor) != accepted:
            return "protected-claim-required"
        if self._accepted_migration(predecessor) != migration_proof:
            return "migration-proof-mismatch"
        # S/T and a still-needed P are checked again after all provider opens,
        # immediately adjacent to the serialized irreversible operation.
        if not self._claim_handles_match(claim):
            return "prepared-key-mismatch"
        prior = self.disk["destroyed"].get(predecessor)
        if prior is not None and prior != successor:
            return "destruction-successor-conflict"
        expected_retirement = self._destruction_intent(
            predecessor,
            accepted,
            migration_proof,
        )
        if self.rollback_resistant:
            if self._protected_transitions.get(predecessor) != accepted:
                return "protected-claim-required"
            protected_retirement = self._protected_retirements.get(predecessor)
            if (
                protected_retirement is not None
                and protected_retirement != expected_retirement
            ):
                return "protected-retirement-conflict"
            retirement_was_committed = protected_retirement is not None
            if not retirement_was_committed:
                if not self._handle_matches_generation_commitment(predecessor):
                    return "predecessor-key-mismatch"
                if (
                    self._hardware_floor
                    != self._generation_position(predecessor)
                ):
                    return "protected-position-mismatch"
                self._commit_protected_retirement(
                    predecessor,
                    successor,
                    expected_retirement,
                )
            elif (
                self._hardware_floor
                != self._generation_position(successor)
            ):
                return "protected-position-mismatch"
            self._delete_retired_handle(predecessor)
            self.disk["destroyed"][predecessor] = successor
            return (
                "already-destroyed"
                if retirement_was_committed or prior is not None
                else "destroyed"
            )

        intent = self.disk["destruction_intents"].get(predecessor)
        if intent is not None and intent != expected_retirement:
            return "destruction-intent-conflict"
        if prior is not None and intent is None:
            return "destruction-intent-required"
        if predecessor in self._handles:
            if not self._handle_matches_generation_commitment(predecessor):
                return "predecessor-key-mismatch"
        elif intent is None:
            return "missing-handle-without-destruction-evidence"
        if intent is None:
            # Lower tiers cannot atomically combine platform key deletion with
            # the application database. Persist the exact resumable intent
            # before invoking the irreversible provider operation.
            self.disk["destruction_intents"][predecessor] = expected_retirement
        self._delete_retired_handle(predecessor)
        self.disk["destroyed"][predecessor] = successor
        return "already-destroyed" if prior is not None else "destroyed"

    def _commit_protected_retirement(
        self,
        predecessor,
        successor,
        retirement,
    ):
        """One provider transaction: bind the exact edge and advance its floor."""
        self._protected_retirements[predecessor] = retirement
        self._hardware_floor = self._generation_position(successor)
        self._protected_active = successor
        self._protected_staged = (
            retirement.accepted_transition.claim.next_generation
        )

    def _destruction_complete(
        self,
        predecessor,
        successor,
        accepted,
        migration_proof,
    ):
        if (
            self.disk["destroyed"].get(predecessor) != successor
            or predecessor in self._handles
        ):
            return False
        expected = self._destruction_intent(
            predecessor,
            accepted,
            migration_proof,
        )
        if self.rollback_resistant:
            return (
                self._protected_retirements.get(predecessor) == expected
                and self._hardware_floor
                == self._generation_position(successor)
            )
        return self.disk["destruction_intents"].get(predecessor) == expected

    def _delete_retired_handle(self, predecessor):
        self._handles.pop(predecessor, None)

    def promote(self, prepared):
        predecessor = prepared.predecessor
        successor = prepared.successor
        next_generation = prepared.next_generation
        expected = prepared.claim
        accepted = self._accepted_transition(predecessor)
        if accepted is None or accepted.claim != expected:
            return "claim-mismatch"
        prior = self.disk["promoted"].get(predecessor)
        if prior is not None and prior != expected:
            return "promotion-conflict"
        if (
            prior == expected
            and successor in self.disk["finalized"]
            and self.disk["wrap_eligible"] == {successor}
        ):
            return "already-promoted"
        if self.disk["destroyed"].get(predecessor) != successor:
            return "destruction-required"
        migration_proof = self._accepted_migration(predecessor)
        if (
            migration_proof is None
            or migration_proof.successor != successor
            or migration_proof.manifest != accepted.manifest
            or not self._migration_matches_current_covers(migration_proof)
        ):
            return "migration-required"
        expected_parent_ref = ParentClaimRef(
            predecessor,
            transition_claim_id(predecessor, expected),
        )
        current_parent_ref = self.disk["parent_claim_refs"].get(successor)
        if self.active not in (predecessor, successor):
            return "active-predecessor-mismatch"
        if (
            self.staged not in (successor, next_generation)
            or self.disk["prepared_next"] not in (next_generation, None)
            or self.disk["wrap_eligible"] not in ({predecessor}, set())
            or current_parent_ref not in (None, expected_parent_ref)
        ):
            return "promotion-state-conflict"
        if not self._destruction_complete(
            predecessor,
            successor,
            accepted,
            migration_proof,
        ):
            return "destruction-required"
        if self._is_retired(successor):
            return "successor-already-retired"
        if not self._claim_handles_match(expected):
            return "prepared-key-mismatch"
        replaying_partial_projection = (
            prior is not None
            or self.active == successor
            or self.staged == next_generation
            or self.disk["prepared_next"] is None
            or self.disk["wrap_eligible"] == set()
            or current_parent_ref == expected_parent_ref
        )
        before = self.handle_count
        self._project_promotion(prepared, expected_parent_ref)
        assert self.handle_count == before
        return (
            "already-promoted"
            if replaying_partial_projection
            else "promoted-without-allocation"
        )

    def _project_promotion(self, prepared, expected_parent_ref):
        predecessor = prepared.predecessor
        successor = prepared.successor
        self.disk["active"] = successor
        self.disk["staged"] = prepared.next_generation
        self.disk["prepared_next"] = None
        self.disk["wrap_eligible"] = set()
        self.disk["parent_claim_refs"][successor] = expected_parent_ref
        self.disk["promoted"][predecessor] = prepared.claim

    def finalize(self, predecessor, successor):
        accepted = self._accepted_transition(predecessor)
        if accepted is None or accepted.claim.successor != successor:
            return "completion-evidence-required"
        claim = accepted.claim
        migration_proof = self._accepted_migration(predecessor)
        if (
            migration_proof is None
            or migration_proof.successor != successor
            or migration_proof.manifest != accepted.manifest
            or not self._migration_matches_current_covers(migration_proof)
            or not self._destruction_complete(
                predecessor,
                successor,
                accepted,
                migration_proof,
            )
        ):
            return "completion-evidence-required"
        expected_parent_ref = ParentClaimRef(
            predecessor,
            transition_claim_id(predecessor, claim),
        )
        if (
            self.disk["destroyed"].get(predecessor) != successor
            or self.disk["promoted"].get(predecessor) != claim
            or self.disk["parent_claim_refs"].get(successor)
            != expected_parent_ref
        ):
            return "completion-evidence-required"
        if (
            self.active != successor
            or self.staged != claim.next_generation
            or self._is_retired(successor)
            or not self._claim_handles_match(claim)
        ):
            return "completion-evidence-required"
        expected_completion = self._destruction_intent(
            predecessor,
            accepted,
            migration_proof,
        )
        prior_completion = None
        if self.rollback_resistant:
            prior_completion = self._protected_completions.get(predecessor)
            if (
                prior_completion is not None
                and prior_completion != expected_completion
            ):
                return "completion-evidence-conflict"
            if prior_completion is None:
                # Protected completion is authoritative. Rollbackable
                # finalized/eligibility mirrors are a replayable projection.
                self._protected_completions[predecessor] = expected_completion
        already_projected = (
            successor in self.disk["finalized"]
            and self.disk["wrap_eligible"] == {successor}
        )
        self._project_finalization(successor)
        return (
            "already-finalized"
            if prior_completion is not None or already_projected
            else "finalized"
        )

    def _project_finalization(self, successor):
        self.disk["finalized"].add(successor)
        self.disk["wrap_eligible"] = {successor}

    def snapshot(self):
        return ProviderSnapshot(
            deepcopy(self.disk),
            deepcopy(self._handles),
            deepcopy(self._generation_publics),
            deepcopy(self._generation_suites),
            deepcopy(self._generation_positions),
            self._provider_epoch,
            self._protected_active,
            self._protected_staged,
            deepcopy(self._protected_transitions),
            deepcopy(self._protected_fences),
            deepcopy(self._protected_migrations),
            deepcopy(self._protected_retirements),
            deepcopy(self._protected_completions),
            self._hardware_floor,
        )

    def restore(self, snapshot):
        self.disk = deepcopy(snapshot.disk)
        if not self.rollback_resistant:
            self._handles = deepcopy(snapshot.handles)
            self._generation_publics = deepcopy(snapshot.generation_publics)
            self._generation_suites = deepcopy(snapshot.generation_suites)
            self._generation_positions = deepcopy(
                snapshot.generation_positions
            )
            self._provider_epoch = snapshot.provider_epoch
            self._protected_active = snapshot.protected_active
            self._protected_staged = snapshot.protected_staged
            self._restore_binding_valid = True
            self._protected_transitions = deepcopy(
                snapshot.protected_transitions
            )
            self._protected_fences = deepcopy(snapshot.protected_fences)
            self._protected_migrations = deepcopy(
                snapshot.protected_migrations
            )
            self._protected_retirements = deepcopy(
                snapshot.protected_retirements
            )
            self._protected_completions = deepcopy(
                snapshot.protected_completions
            )
            self._hardware_floor = snapshot.hardware_floor
            return "restored"
        self._restore_binding_valid = self._snapshot_matches_provider(snapshot)
        return (
            "restored"
            if self._restore_binding_valid
            else "provider-state-mismatch-fail-closed"
        )

    def _snapshot_matches_provider(self, snapshot):
        if (
            snapshot.provider_epoch != self._provider_epoch
            or snapshot.disk.get("provider_epoch") != self._provider_epoch
            or snapshot.disk.get("generation_commitments")
            != {
                generation: (
                    snapshot.generation_suites[generation],
                    snapshot.generation_publics[generation],
                )
                for generation in snapshot.generation_publics
            }
            or snapshot.disk.get("generation_positions")
            != snapshot.generation_positions
        ):
            return False
        for generation, expected_public in snapshot.generation_publics.items():
            if (
                self._generation_publics.get(generation) != expected_public
                or self._generation_suites.get(generation)
                != snapshot.generation_suites.get(generation)
                or self._generation_positions.get(generation)
                != snapshot.generation_positions.get(generation)
            ):
                return False
        return self._current_protected_handles_match() and all(
            bytes(public.PrivateKey(private_bytes).public_key)
            == snapshot.generation_publics[generation]
            for generation, private_bytes in snapshot.handles.items()
        )

    def _current_protected_handles_match(self):
        for generation in (self._protected_active, self._protected_staged):
            private_bytes = self._handles.get(generation)
            if private_bytes is None:
                return False
            if (
                self._generation_suites.get(generation) != RECIPIENT_SUITE
                or bytes(public.PrivateKey(private_bytes).public_key)
                != self._generation_publics.get(generation)
            ):
                return False
        return True

    def reconcile_status(self):
        if (
            not self._current_protected_handles_match()
            or not self._provider_metadata_matches((self.active, self.staged))
        ):
            return "provider-state-mismatch-fail-closed"
        if self._generation_position(self.active) < self._hardware_floor:
            return "stale-snapshot-fail-closed"
        if not self._protected_live_position_matches():
            return "protected-position-mismatch-fail-closed"
        return "current"


def prepared_transition(provider, transition, *, operations=None):
    if operations is None:
        operations = transition["purge_operations"]
    return PreparedTransition(
        predecessor=transition["predecessor"],
        successor=transition["successor"],
        successor_position=provider._generation_position(
            transition["successor"]
        ),
        successor_suite=RECIPIENT_SUITE,
        successor_public=provider.public_key(transition["successor"]),
        next_generation=transition["next"],
        next_position=provider._generation_position(transition["next"]),
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


def forge_cover_record(
    provider,
    cover_id,
    generation,
    plaintext,
    secret_commitment,
    *,
    context=None,
):
    """Use only public material, as an attacker who can replace disk records."""
    if context is None:
        context = provider._cover_context(cover_id, generation)
    key = public.PrivateKey(provider._usable_private(generation)).public_key
    bound_plaintext = (
        provider._cover_aad(cover_id, context, secret_commitment)
        + b"\0"
        + plaintext
    )
    return CoverRecord(
        context,
        secret_commitment,
        Envelope(
            context,
            bytes(public.SealedBox(key).encrypt(bound_plaintext)),
        ),
    )


def test_adr_selects_bounded_independent_generations_and_explicit_tiers():
    decision = FIXTURE["decision"]
    assert decision["primary"] == "independent-nonexportable-recipient-generations"
    assert decision["portable_fallback"] == "independent-random-software-generations"
    assert decision["stable_content_root"] == "rejected-in-v1"
    assert decision["first_frontier_only_rotation"] == "rejected-in-v1"
    assert decision["steady_handle_count"] == 2
    assert decision["transition_peak_handle_count"] == 3
    assert decision["parent_claim_link"] == "explicit-claim-id"
    assert decision["next_claim_requires_finalized_predecessor"] is True
    assert decision["writer_lease_generation"] == "caller-supplied-exact"
    assert decision["generation_identity"] == "immutable-suite-and-public-key"
    assert decision["generation_position_identity"] == (
        "opaque-id-bound-to-monotonic-position-on-claim"
    )
    assert decision["unclaimed_generation_discard"] == (
        "fresh-id-at-same-position"
    )
    assert decision["provider_epoch_binding"] == (
        "protected-lineage-and-suite-qualified-public-keys"
    )
    assert decision["provider_open_revalidates_generation"] is True
    assert decision["restore_revalidates_live_handles"] is True
    assert (
        decision["cover_expected_context"]
        == "separate-authoritative-record"
    )
    assert decision["duplicate_operation_refs"] == "canonical-set"
    assert decision["empty_retirement_batch"] == (
        "rejected-before-claim-cas"
    )
    assert decision["protected_fence_phase_required"] is True
    assert decision["protected_live_position_required"] is True
    assert decision["destroy_revalidates_survivors"] is True
    assert decision["retirement_validation"] == (
        "serialized-post-open-record-and-handle-recheck"
    )
    assert (
        decision["migration_proof"]
        == "exact-survivor-id-secret-commitment-and-context-set"
    )
    assert decision["protected_claim_before_rollbackable_mirror"] is True
    assert decision["protected_claim_includes_manifest"] is True
    assert decision["migration_proof_cas"] == "protected-first-immutable"
    assert (
        decision["retirement_order"]
        == "protected-disable-before-handle-delete"
    )
    assert decision["protected_retirement_evidence"] == (
        "exact-transition-and-migration-proof"
    )
    assert (
        decision["lower_tier_destruction_intent"]
        == "exact-before-delete"
    )
    assert (
        decision["wrap_eligibility"]
        == "live-active-staged-public-commitments"
    )
    assert decision["promotion_projection"] == (
        "retirement-backed-and-replayable"
    )
    assert decision["finalization_revalidates_parent_claim"] is True
    assert decision["finalization_projection"] == (
        "protected-completion-first-replayable-mirrors"
    )

    tiers = {tier["name"]: tier for tier in FIXTURE["guarantee_tiers"]}
    assert tiers["normal-disk"]["snapshot_erasure_claim"] is False
    assert tiers["hardware-isolated"]["nonexportable_private_key"] is True
    assert tiers["hardware-isolated"]["snapshot_erasure_claim"] is False
    assert tiers["rollback-resistant"]["deleted_keyblob_replay_blocked"] is True
    assert tiers["rollback-resistant"]["old_claim_replay_blocked"] is True
    assert tiers["rollback-resistant"]["snapshot_erasure_claim"] is True


def test_fixture_pins_generation_independent_local_secret_commitments():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    for item in FIXTURE["cover_records"]:
        cover_id = item["id"]
        plaintext = bytes.fromhex(item["plaintext_hex"])
        p_context = provider._cover_context(cover_id, "P")
        s_context = provider._cover_context(cover_id, "S")
        expected = item["secret_commitment"]

        assert local_secret_commitment(cover_id, p_context, plaintext) == expected
        assert local_secret_commitment(cover_id, s_context, plaintext) == expected
        assert provider._record("P", cover_id, plaintext).secret_commitment == (
            expected
        )


def test_local_secret_commitment_binds_semantics_but_not_recipient_generation():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "retained-node-a"
    plaintext = cover_fixture()[cover_id]
    context = provider._cover_context(cover_id, "P")
    commitment = local_secret_commitment(cover_id, context, plaintext)
    mutations = {
        "recipient_lineage_id": "other-lineage",
        "content_scope_id": "other-workspace",
        "frontier_id": "other-frontier",
        "secret_kind": "FrontierRoot",
        "range_start": context.range_start + 1,
        "range_width": context.range_width + 1,
        "bit_depth": context.bit_depth + 1,
        "event_id_prefix": "ff" * 32,
        "source_secret_ref": "ee" * 32,
        "tombstone_context": "dd" * 32,
        "recovery_policy_ref": "other-policy",
    }
    for field, value in mutations.items():
        assert local_secret_commitment(
            cover_id,
            replace(context, **{field: value}),
            plaintext,
        ) != commitment

    assert local_secret_commitment(
        "other-cover",
        context,
        plaintext,
    ) != commitment
    assert local_secret_commitment(
        cover_id,
        context,
        plaintext[:-1] + bytes([plaintext[-1] ^ 1]),
    ) != commitment
    for field, value in {
        "generation": "S",
        "provider_suite": "P-256",
    }.items():
        assert local_secret_commitment(
            cover_id,
            replace(context, **{field: value}),
            plaintext,
        ) == commitment


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


@pytest.mark.parametrize("restore_api", (False, True))
def test_foreign_provider_snapshot_fails_closed_before_private_use(restore_api):
    source = ProviderModel(capacity=3, rollback_resistant=True)
    source.seed_cover("frontier-root", b"source-provider secret")
    snapshot = source.snapshot()
    target = ProviderModel(capacity=3, rollback_resistant=True)

    assert target._provider_epoch != snapshot.provider_epoch
    assert target.public_key("P") != snapshot.generation_publics["P"]
    if restore_api:
        assert target.restore(snapshot) == (
            "provider-state-mismatch-fail-closed"
        )
    else:
        # Also model bypassing the restore API and replacing application state
        # directly. Every operation still compares the canonical binding.
        target.disk = deepcopy(snapshot.disk)

    assert target.reconcile_status() == "provider-state-mismatch-fail-closed"
    assert target.wrap_eligible == set()
    assert target.acquire_writer_lease("foreign-writer", "P") == "rejected"
    with pytest.raises(CryptoError, match="provider binding"):
        target.open_cover("frontier-root")


def test_restore_compares_suite_qualified_commitments_with_same_provider_epoch():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    snapshot = provider.snapshot()
    replacement_public = bytes(public.PrivateKey.generate().public_key)
    publics = dict(snapshot.generation_publics)
    publics["P"] = replacement_public
    disk = deepcopy(snapshot.disk)
    disk["generation_commitments"]["P"] = (
        RECIPIENT_SUITE,
        replacement_public,
    )
    tampered = replace(snapshot, disk=disk, generation_publics=publics)

    assert provider.restore(tampered) == (
        "provider-state-mismatch-fail-closed"
    )
    assert provider.wrap_eligible == set()
    assert provider.acquire_writer_lease("tampered-writer", "P") == "rejected"


@pytest.mark.parametrize("generation", ("P", "S"))
@pytest.mark.parametrize("replace_handle", (False, True))
def test_restore_rejects_missing_or_replaced_live_protected_handle(
    generation,
    replace_handle,
):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    snapshot = provider.snapshot()
    del provider._handles[generation]
    if replace_handle:
        assert provider._generate(generation) == "generated"

    assert provider.restore(snapshot) == (
        "provider-state-mismatch-fail-closed"
    )
    assert provider.reconcile_status() == (
        "provider-state-mismatch-fail-closed"
    )
    assert provider.wrap_eligible == set()
    assert provider.acquire_writer_lease("restored-writer", "P") == "rejected"


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


def test_unclaimed_next_id_can_be_discarded_and_replaced_at_same_position():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    first = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    abandoned_public = provider.public_key("T")
    assert provider.discard_prepared("T") == "discarded"
    assert "T" not in provider._handles
    assert provider._generation_publics["T"] == abandoned_public
    assert provider.prepare_next("T") == "generation-id-reuse"

    fresh_t = "fresh-T-generation-fact"
    assert provider.prepare_next(fresh_t) == "prepared"
    assert provider._generation_position(fresh_t) == generation_index("T")
    replacement_first = {**first, "next": fresh_t}
    prepared = prepared_transition(provider, replacement_first)
    wrong_position = replace(
        prepared,
        next_position=prepared.next_position + 1,
    )
    assert provider.claim(wrong_position) == "invalid-recursive-schedule"
    assert provider._protected_transitions == {}
    assert provider.claim(prepared) == "accepted"
    assert provider.discard_prepared(fresh_t) == "generation-bound-by-claim"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.finalize("P", "S") == "finalized"
    assert provider.active == "S"
    assert provider.staged == fresh_t

    # The fresh opaque id still occupies schedule position T, so recursion
    # proceeds to another caller-supplied id at position U.
    second = {
        **FIXTURE["decision"]["transition_batches"][1],
        "successor": fresh_t,
        "next": "fresh-U-generation-fact",
    }
    complete_transition(provider, second)
    assert provider.active == fresh_t
    assert provider.staged == "fresh-U-generation-fact"


def test_fence_migrates_survivors_purges_target_and_blocks_late_writer():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    covers = cover_fixture()
    for cover_id, plaintext in covers.items():
        provider.seed_cover(cover_id, plaintext)

    assert provider.acquire_writer_lease(
        "writer-before-fence", "P"
    ) == "accepted"
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P") == (
        "fenced",
        ["writer-before-fence"],
    )
    assert provider.acquire_writer_lease(
        "writer-after-fence", "P"
    ) == "rejected"
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
        record.expected_context.generation == "S"
        for record in provider.disk["covers"].values()
    )


def test_saved_predecessor_writer_retry_is_not_rebound_to_successor():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("retained-node-a", b"purged secret")
    transition = FIXTURE["decision"]["transition_batches"][0]
    complete_transition(provider, transition)

    assert "retained-node-a" not in provider.disk["covers"]
    assert provider.acquire_writer_lease(
        "late-P-retry", "P"
    ) == "rejected"
    assert provider.disk["leases"].get("late-P-retry") is None
    assert provider.commit_cover(
        "late-P-retry",
        "retained-node-a",
        b"purged secret",
    ) == "rejected"
    assert "retained-node-a" not in provider.disk["covers"]


def test_protected_fence_survives_pre_destruction_snapshot_rollback():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    assert provider.acquire_writer_lease(
        "pre-fence-writer", "P"
    ) == "accepted"
    pre_fence_snapshot = provider.snapshot()

    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    assert "P" in provider._protected_fences
    assert provider._hardware_floor == 0

    provider.restore(pre_fence_snapshot)
    assert provider.disk["fenced"] == set()
    assert provider.disk["leases"] == {"pre-fence-writer": "P"}
    assert "P" in provider._protected_fences
    assert provider.acquire_writer_lease(
        "post-rollback-writer", "P"
    ) == "rejected"
    assert provider.commit_cover(
        "pre-fence-writer",
        "late-cover",
        b"must not commit",
    ) == "rejected"
    assert "late-cover" not in provider.disk["covers"]


def test_disk_only_fence_cannot_authorize_strong_migration_or_retirement():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    manifest = purge_targets_for_operations(prepared.operations)

    provider.disk["fenced"].add("P")
    assert provider._protected_fences == set()
    assert provider.migrate("P", "S", manifest) == "writer-fence-required"
    assert provider.destroy("P", "S") == "writer-fence-required"
    assert provider._protected_migrations == {}
    assert provider._protected_retirements == {}
    assert provider._hardware_floor == generation_index("P")
    assert "P" in provider._handles

    assert provider.fence_and_drain("P")[0] == "fenced"
    assert provider.migrate("P", "S", manifest) == "migrated"


def test_cover_envelope_authenticates_every_context_field():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "retained-node-a"
    plaintext = cover_fixture()[cover_id]
    provider.seed_cover(cover_id, plaintext)
    envelope = provider.cover_envelope(cover_id)

    mutations = {
        "version": envelope.context.version + 1,
        "provider_suite": "P-256",
        "recipient_lineage_id": "other-lineage",
        "generation": "S",
        "content_scope_id": "other-workspace",
        "frontier_id": "other-frontier",
        "secret_kind": "FrontierRoot",
        "range_start": envelope.context.range_start + 1,
        "range_width": envelope.context.range_width + 1,
        "bit_depth": envelope.context.bit_depth + 1,
        "event_id_prefix": "ff" * 32,
        "source_secret_ref": "ee" * 32,
        "tombstone_context": "dd" * 32,
        "recovery_policy_ref": "other-policy",
    }
    for field, value in mutations.items():
        relabeled = replace(
            envelope,
            context=replace(envelope.context, **{field: value}),
        )
        with pytest.raises(CryptoError, match="context|decrypt"):
            provider._open(
                cover_id,
                envelope.context,
                provider.cover_record(cover_id).secret_commitment,
                relabeled,
            )

    transplanted_context = provider._cover_context(
        "transplanted-record", "P"
    )
    with pytest.raises(CryptoError, match="context"):
        provider._open(
            "transplanted-record",
            transplanted_context,
            provider.cover_record(cover_id).secret_commitment,
            envelope,
        )
    tampered = replace(
        envelope,
        ciphertext=envelope.ciphertext[:-1]
        + bytes([envelope.ciphertext[-1] ^ 1]),
    )
    with pytest.raises(CryptoError):
        provider._open(
            cover_id,
            envelope.context,
            provider.cover_record(cover_id).secret_commitment,
            tampered,
        )


def test_cover_open_rejects_valid_ciphertext_for_self_described_foreign_context():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "retained-node-a"
    expected = provider._cover_context(cover_id, "P")
    foreign = replace(
        expected,
        content_scope_id="other-workspace",
        frontier_id="other-frontier",
    )
    key = public.PrivateKey(provider._usable_private("P")).public_key
    commitment = local_secret_commitment(
        cover_id,
        foreign,
        b"foreign secret",
    )
    bound = (
        provider._cover_aad(cover_id, foreign, commitment)
        + b"\0"
        + b"foreign secret"
    )
    envelope = Envelope(
        foreign,
        bytes(public.SealedBox(key).encrypt(bound)),
    )

    with pytest.raises(CryptoError, match="authoritative record"):
        provider._open(cover_id, expected, commitment, envelope)


def test_cover_open_does_not_take_expected_generation_from_envelope():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "retained-node-a"
    expected = provider._cover_context(cover_id, "P")
    self_described = provider._cover_context(cover_id, "S")
    key = public.PrivateKey(provider._usable_private("S")).public_key
    commitment = local_secret_commitment(
        cover_id,
        self_described,
        b"staged plaintext",
    )
    bound = (
        provider._cover_aad(cover_id, self_described, commitment)
        + b"\0"
        + b"staged plaintext"
    )
    envelope = Envelope(
        self_described,
        bytes(public.SealedBox(key).encrypt(bound)),
    )

    with pytest.raises(CryptoError, match="authoritative record"):
        provider._open(cover_id, expected, commitment, envelope)


def test_cover_open_rejects_authoritative_suite_relabeling():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "retained-node-a"
    plaintext = b"wrong-suite plaintext"
    context = replace(
        provider._cover_context(cover_id, "P"),
        provider_suite="P-256",
    )
    commitment = local_secret_commitment(cover_id, context, plaintext)
    key = public.PrivateKey(provider._usable_private("P")).public_key
    bound = (
        provider._cover_aad(cover_id, context, commitment)
        + b"\0"
        + plaintext
    )
    envelope = Envelope(
        context,
        bytes(public.SealedBox(key).encrypt(bound)),
    )

    with pytest.raises(CryptoError, match="suite"):
        provider._open(cover_id, context, commitment, envelope)


def test_cover_open_rejects_ciphertext_for_a_recreated_generation_handle():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "retained-node-a"
    context = provider._cover_context(cover_id, "P")
    original_public = provider.public_key("P")
    del provider._handles["P"]
    assert provider._generate("P") == "generated"
    assert provider.public_key("P") != original_public

    plaintext = b"replacement-handle plaintext"
    commitment = local_secret_commitment(cover_id, context, plaintext)
    forged = forge_cover_record(
        provider,
        cover_id,
        "P",
        plaintext,
        commitment,
    )
    with pytest.raises(CryptoError, match="generation commitment"):
        provider._open(
            cover_id,
            context,
            commitment,
            forged.envelope,
        )


def test_migration_reopens_successor_labeled_records_before_destroying_p():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"

    record = provider.cover_record("frontier-root")
    provider.disk["covers"]["frontier-root"] = replace(
        record,
        envelope=replace(
            record.envelope,
            context=replace(record.envelope.context, generation="S"),
        ),
    )
    manifest = purge_targets_for_operations(prepared.operations)
    with pytest.raises(CryptoError):
        provider.migrate("P", "S", manifest)

    assert provider.disk["migrated"] == {}
    assert "P" in provider._handles
    assert provider.destroy("P", "S") == "migration-required"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("ciphertext", "successor-cover-validation-failed"),
        ("authoritative-generation", "unexpected-survivor-generation"),
        ("envelope-generation", "successor-cover-validation-failed"),
        ("deleted-record", "survivor-set-mismatch"),
    ),
)
def test_destroy_revalidates_each_successor_record_after_migration(
    mutation,
    expected,
):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"

    record = provider.cover_record("frontier-root")
    if mutation == "deleted-record":
        del provider.disk["covers"]["frontier-root"]
    elif mutation == "ciphertext":
        envelope = replace(
            record.envelope,
            ciphertext=record.envelope.ciphertext[:-1]
            + bytes([record.envelope.ciphertext[-1] ^ 1]),
        )
        record = replace(record, envelope=envelope)
    elif mutation == "authoritative-generation":
        record = replace(
            record,
            expected_context=replace(
                record.expected_context,
                generation="P",
            ),
        )
    else:
        record = replace(
            record,
            envelope=replace(
                record.envelope,
                context=replace(
                    record.envelope.context,
                    generation="T",
                ),
            ),
        )
    if mutation != "deleted-record":
        provider.disk["covers"]["frontier-root"] = record

    assert provider.destroy("P", "S") == expected
    assert "P" in provider._handles
    assert provider._hardware_floor == generation_index("P")
    assert provider.disk["destroyed"] == {}


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("delete-successor", "prepared-key-mismatch"),
        ("replace-successor", "prepared-key-mismatch"),
        ("delete-next", "prepared-key-mismatch"),
        ("replace-predecessor", "predecessor-key-mismatch"),
        (
            "replace-cover-record",
            "survivor-record-changed-during-validation",
        ),
        ("delete-cover-record", "survivor-set-changed-during-validation"),
    ),
)
def test_retirement_rechecks_records_and_handles_after_survivor_open(
    mutation,
    expected,
):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    real_open = provider._open
    mutated = False

    def open_then_race(*args):
        nonlocal mutated
        plaintext = real_open(*args)
        if mutated:
            return plaintext
        mutated = True
        if mutation == "delete-successor":
            del provider._handles["S"]
        elif mutation == "replace-successor":
            del provider._handles["S"]
            assert provider._generate("S") == "generated"
        elif mutation == "delete-next":
            del provider._handles["T"]
        elif mutation == "replace-predecessor":
            del provider._handles["P"]
            assert provider._generate("P") == "generated"
        elif mutation == "replace-cover-record":
            record = provider.cover_record("frontier-root")
            provider.disk["covers"]["frontier-root"] = replace(
                record,
                envelope=replace(
                    record.envelope,
                    ciphertext=record.envelope.ciphertext[:-1]
                    + bytes([record.envelope.ciphertext[-1] ^ 1]),
                ),
            )
        else:
            del provider.disk["covers"]["frontier-root"]
        return plaintext

    provider._open = open_then_race
    assert provider.destroy("P", "S") == expected
    assert provider._hardware_floor == generation_index("P")
    assert provider._protected_retirements == {}
    assert provider.disk["destroyed"] == {}
    assert "P" in provider._handles


@pytest.mark.parametrize(
    ("replace_commitment", "open_succeeds", "destroy_result"),
    (
        (False, False, "successor-cover-validation-failed"),
        (True, True, "survivor-commitment-mismatch"),
    ),
)
def test_destroy_rejects_public_key_forgery_of_a_survivor_secret(
    replace_commitment,
    open_succeeds,
    destroy_result,
):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "frontier-root"
    provider.seed_cover(cover_id, b"canonical survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"

    canonical_record = provider.cover_record(cover_id)
    attacker_plaintext = b"attacker replacement"
    commitment = canonical_record.secret_commitment
    if replace_commitment:
        commitment = local_secret_commitment(
            cover_id,
            canonical_record.expected_context,
            attacker_plaintext,
        )
    provider.disk["covers"][cover_id] = forge_cover_record(
        provider,
        cover_id,
        "S",
        attacker_plaintext,
        commitment,
    )

    if open_succeeds:
        # The forged record is internally consistent, but it cannot change the
        # immutable commitment map captured by migration.
        assert provider.open_cover(cover_id) == attacker_plaintext
    else:
        # Keeping the canonical commitment exposes the changed plaintext.
        with pytest.raises(CryptoError, match="secret commitment"):
            provider.open_cover(cover_id)
    assert provider.destroy("P", "S") == destroy_result
    assert "P" in provider._handles
    assert provider._hardware_floor == generation_index("P")
    assert provider.disk["destroyed"] == {}


def test_protected_migration_proof_binds_authoritative_survivor_context():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    cover_id = "frontier-root"
    plaintext = b"canonical survivor"
    provider.seed_cover(cover_id, plaintext)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"

    canonical = provider.cover_record(cover_id)
    substituted_context = replace(
        canonical.expected_context,
        version=canonical.expected_context.version + 1,
    )
    provider.disk["covers"][cover_id] = forge_cover_record(
        provider,
        cover_id,
        "S",
        plaintext,
        canonical.secret_commitment,
        context=substituted_context,
    )
    # The replacement is internally valid and uses only public S material, but
    # it is not the exact authoritative context frozen before retirement.
    assert provider.open_cover(cover_id) == plaintext
    assert provider.destroy("P", "S") == "survivor-context-mismatch"
    assert provider._protected_retirements == {}
    assert provider._hardware_floor == generation_index("P")
    assert "P" in provider._handles


def test_migration_retry_cannot_shrink_the_first_survivor_proof():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"first survivor")
    provider.seed_cover("retained-node-b", b"second survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    frozen = provider._accepted_migration("P")
    assert {
        cover_id for cover_id, _ in frozen.survivor_commitments
    } == {"frontier-root", "retained-node-b"}

    del provider.disk["covers"]["retained-node-b"]
    assert provider.migrate("P", "S", manifest) == "migration-proof-mismatch"
    assert provider._accepted_migration("P") == frozen
    assert provider.destroy("P", "S") == "survivor-set-mismatch"
    assert "P" in provider._handles
    assert provider._hardware_floor == generation_index("P")


def test_transition_steps_reject_unclaimed_successors_and_changed_manifest():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    covers = cover_fixture()
    for cover_id, plaintext in covers.items():
        provider.seed_cover(cover_id, plaintext)

    assert provider.fence_and_drain("P") == (
        "transition-claim-required",
        [],
    )
    assert provider.disk["fenced"] == set()
    assert provider._protected_fences == set()

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

    provider.disk["destroyed"]["P"] = "S"
    assert provider.promote(prepared) == "destruction-required"
    assert provider.active == "P"
    assert "P" in provider._handles
    del provider.disk["destroyed"]["P"]

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
    assert provider.prepare_next("T") == "generation-id-reuse"
    assert provider._generate("T") == "generated"
    replacement = prepared_transition(provider, transition)
    assert replacement.next_public != prepared.next_public
    assert provider.claim(replacement) == "conflict"

    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "prepared-key-mismatch"
    assert provider.disk["destroyed"] == {}
    assert provider.open_cover("frontier-root") == b"survivor"


def test_duplicate_operation_refs_have_one_canonical_batch_commitment():
    operations = ("purge-node-b", "purge-node-c")
    duplicated = (
        "purge-node-c",
        "purge-node-b",
        "purge-node-b",
        "purge-node-c",
    )
    assert batch_commitment(operations) == batch_commitment(duplicated)
    assert purge_targets_for_operations(operations) == (
        purge_targets_for_operations(duplicated)
    )

    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    duplicate_retry = replace(
        prepared,
        operations=prepared.operations + prepared.operations,
    )
    assert duplicate_retry.claim == prepared.claim
    assert provider.claim(duplicate_retry) == "coalesced"


def test_empty_retirement_batch_does_not_consume_protected_claim():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    empty = prepared_transition(provider, transition, operations=())

    assert provider.claim(empty) == "empty-retirement-batch"
    assert provider._protected_transitions == {}
    assert provider.disk["claims"] == {}
    assert provider.disk["manifests"] == {}

    real = prepared_transition(provider, transition)
    assert provider.claim(real) == "accepted"
    assert provider._protected_transitions["P"].claim == real.claim


def test_claim_repairs_disk_only_partial_write_before_preventing_a_fork():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    before_claim = provider.snapshot()
    prepared = prepared_transition(provider, transition)
    manifest = purge_targets_for_operations(prepared.operations)

    # Model the unsafe legacy crash boundary: rollbackable mirrors exist but
    # the protected compare-and-set did not happen.
    provider.disk["claims"]["P"] = prepared.claim
    provider.disk["manifests"]["P"] = manifest
    assert provider._protected_transitions == {}

    # A disk-only value is not mistaken for an accepted claim. The exact retry
    # first commits the protected authority, then repairs the mirrors.
    assert provider.claim(prepared) == "accepted"
    assert provider._protected_transitions["P"] == AcceptedTransition(
        prepared.claim,
        manifest,
    )
    assert provider.disk["claims"]["P"] == prepared.claim

    provider.restore(before_claim)
    forked = replace(
        prepared,
        operations=("forked-purge-operation",),
    )
    assert provider.claim(forked) == "conflict"
    assert provider.claim(prepared) == "coalesced"
    assert provider.disk["claims"]["P"] == prepared.claim
    assert provider.disk["manifests"]["P"] == manifest


def test_migration_uses_protected_claim_and_manifest_not_tampered_mirrors():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    provider.seed_cover("retained-node-a", b"purge target")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    protected = provider._accepted_transition("P")
    assert provider.fence_and_drain("P")[0] == "fenced"

    provider.disk["claims"]["P"] = replace(
        prepared.claim,
        retirement_batch_commitment="00" * 32,
    )
    provider.disk["manifests"]["P"] = frozenset({"frontier-root"})

    assert provider.migrate(
        "P",
        "S",
        {"frontier-root"},
    ) == "retirement-manifest-mismatch"
    assert provider._accepted_transition("P") == protected
    assert provider.open_cover("frontier-root") == b"survivor"
    assert provider.open_cover("retained-node-a") == b"purge target"

    assert provider.migrate(
        "P",
        "S",
        protected.manifest,
    ) == "migrated"
    assert set(provider.disk["covers"]) == {"frontier-root"}


@pytest.mark.parametrize("replace_before_prepare", (True, False))
def test_next_transition_rejects_replacement_of_committed_staged_key(
    replace_before_prepare,
):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    first = FIXTURE["decision"]["transition_batches"][0]
    complete_transition(provider, first)
    committed_t_public = provider._accepted_claim("P").next_public
    second = FIXTURE["decision"]["transition_batches"][1]

    if not replace_before_prepare:
        assert provider.prepare_next("U") == "prepared"
    del provider._handles["T"]
    assert provider._generate("T") == "generated"
    assert provider.public_key("T") != committed_t_public

    if replace_before_prepare:
        assert provider.prepare_next("U") == "recursive-commitment-mismatch"
        assert "U" not in provider._handles
    else:
        replacement = prepared_transition(provider, second)
        assert replacement.successor_public != committed_t_public
        assert provider.claim(replacement) == "recursive-commitment-mismatch"
        assert provider.disk["claims"].get("S") is None


def test_replaced_genesis_handle_is_never_wrap_or_writer_eligible():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    assert provider.acquire_writer_lease("existing-writer", "P") == "accepted"
    original_public = provider.public_key("P")

    del provider._handles["P"]
    assert provider._generate("P") == "generated"
    assert provider.public_key("P") != original_public

    assert provider.wrap_eligible == set()
    assert provider.acquire_writer_lease("new-writer", "P") == "rejected"
    assert provider.commit_cover(
        "existing-writer",
        "forged-generation-cover",
        b"must not commit",
    ) == "rejected"
    assert provider.prepare_next("T") == "recursive-commitment-mismatch"


def test_replaced_finalized_handle_invalidates_wraps_and_existing_leases():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    complete_transition(provider, transition)
    assert provider.acquire_writer_lease("existing-writer", "S") == "accepted"
    committed_public = provider._accepted_claim("P").successor_public

    del provider._handles["S"]
    assert provider._generate("S") == "generated"
    assert provider.public_key("S") != committed_public

    assert provider.wrap_eligible == set()
    assert provider.acquire_writer_lease("new-writer", "S") == "rejected"
    assert provider.commit_cover(
        "existing-writer",
        "forged-generation-cover",
        b"must not commit",
    ) == "rejected"
    assert provider.finalize("P", "S") == "completion-evidence-required"


@pytest.mark.parametrize("rollback_resistant", (False, True))
@pytest.mark.parametrize("replace_at", ("fence", "migrate", "destroy"))
def test_transition_rejects_recreated_predecessor_even_without_survivors(
    rollback_resistant,
    replace_at,
):
    provider = ProviderModel(
        capacity=3,
        rollback_resistant=rollback_resistant,
    )
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"

    if replace_at != "fence":
        assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    if replace_at == "destroy":
        assert provider.migrate("P", "S", manifest) == "migrated"
    original_public = provider._generation_publics["P"]
    del provider._handles["P"]
    assert provider._generate("P") == "generated"
    assert provider.public_key("P") != original_public

    if replace_at == "fence":
        assert provider.fence_and_drain("P") == (
            "predecessor-key-mismatch",
            [],
        )
        assert provider.disk["fenced"] == set()
    elif replace_at == "migrate":
        assert provider.migrate(
            "P",
            "S",
            manifest,
        ) == "predecessor-key-mismatch"
        assert provider.disk["migrated"] == {}
    else:
        assert provider.destroy("P", "S") == "predecessor-key-mismatch"
    assert provider.disk["destroyed"] == {}
    assert provider.disk["promoted"] == {}


def test_recursive_schedule_uses_persisted_explicit_parent_claim_ref():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    first = FIXTURE["decision"]["transition_batches"][0]
    complete_transition(provider, first)
    claim = provider._accepted_claim("P")
    expected_ref = ParentClaimRef("P", transition_claim_id("P", claim))

    assert provider.disk["parent_claim_refs"]["S"] == expected_ref
    assert transition_claim_id("other-parent", claim) != expected_ref.claim_id

    provider.disk["parent_claim_refs"]["S"] = replace(
        expected_ref,
        claim_id="00" * 32,
    )
    assert provider.prepare_next("U") == "recursive-commitment-mismatch"
    assert "U" not in provider._handles


def test_unfinalized_predecessor_cannot_start_or_claim_next_transition():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    first = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, first)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert "S" not in provider.disk["finalized"]
    assert provider.wrap_eligible == set()

    assert provider.prepare_next("U") == "unfinalized-predecessor"
    assert "U" not in provider._handles

    assert provider._generate("U") == "generated"
    provider.disk["prepared_next"] = "U"
    second = prepared_transition(
        provider,
        FIXTURE["decision"]["transition_batches"][1],
    )
    assert provider.claim(second) == "unfinalized-predecessor"
    assert provider.disk["claims"].get("S") is None


def test_next_claim_requires_exact_completed_protected_position():
    provider = ProviderModel(capacity=4, rollback_resistant=True)
    first = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    first_prepared = prepared_transition(provider, first)
    assert provider.claim(first_prepared) == "accepted"

    # Forge every rollbackable projection of an S/T head without retiring P
    # or committing P's protected completion.
    provider.disk["destroyed"]["P"] = "S"
    provider.disk["promoted"]["P"] = first_prepared.claim
    provider.disk["active"] = "S"
    provider.disk["staged"] = "T"
    provider.disk["prepared_next"] = None
    provider.disk["finalized"].add("S")
    provider.disk["wrap_eligible"] = {"S"}
    provider.disk["parent_claim_refs"]["S"] = ParentClaimRef(
        "P",
        transition_claim_id("P", first_prepared.claim),
    )
    assert provider._hardware_floor == generation_index("P")
    assert provider._protected_retirements == {}
    assert provider._protected_completions == {}

    assert provider.prepare_next("U") == "recursive-commitment-mismatch"
    assert "U" not in provider._handles

    # Even if rollbackable preparation and the U allocation are also forged,
    # claim's protected CAS cannot advance from the false head.
    assert provider._generate("U") == "generated"
    provider.disk["prepared_next"] = "U"
    second = prepared_transition(
        provider,
        FIXTURE["decision"]["transition_batches"][1],
    )
    assert provider.claim(second) == "protected-position-mismatch"
    assert provider._protected_transitions.get("S") is None


@pytest.mark.parametrize(
    ("generation", "replace_handle"),
    (("T", False), ("S", True), ("T", True)),
)
def test_finalization_revalidates_both_committed_handles(
    generation, replace_handle
):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.promote(prepared) == "promoted-without-allocation"

    del provider._handles[generation]
    if replace_handle:
        assert provider._generate(generation) == "generated"
    assert provider.finalize("P", "S") == "completion-evidence-required"
    assert provider.wrap_eligible == set()


def test_finalization_revalidates_explicit_parent_claim_ref():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.promote(prepared) == "promoted-without-allocation"

    parent_ref = provider.disk["parent_claim_refs"].pop("S")
    assert provider.finalize("P", "S") == "completion-evidence-required"
    assert provider.wrap_eligible == set()

    provider.disk["parent_claim_refs"]["S"] = parent_ref
    assert provider.finalize("P", "S") == "finalized"
    assert provider.wrap_eligible == {"S"}


@pytest.mark.parametrize("completed_writes", range(1, 7))
def test_promotion_retry_replays_every_partial_projection(completed_writes):
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    assert provider.destroy("P", "S") == "destroyed"
    expected_parent_ref = ParentClaimRef(
        "P",
        transition_claim_id("P", prepared.claim),
    )
    handle_count = provider.handle_count

    # Model power loss after each successive durable write in the projection.
    if completed_writes >= 1:
        provider.disk["active"] = "S"
    if completed_writes >= 2:
        provider.disk["staged"] = "T"
    if completed_writes >= 3:
        provider.disk["prepared_next"] = None
    if completed_writes >= 4:
        provider.disk["wrap_eligible"] = set()
    if completed_writes >= 5:
        provider.disk["parent_claim_refs"]["S"] = expected_parent_ref
    if completed_writes >= 6:
        provider.disk["promoted"]["P"] = prepared.claim

    assert provider.promote(prepared) == "already-promoted"
    assert provider.handle_count == handle_count
    assert provider.active == "S"
    assert provider.staged == "T"
    assert provider.disk["prepared_next"] is None
    assert provider.disk["wrap_eligible"] == set()
    assert provider.disk["parent_claim_refs"]["S"] == expected_parent_ref
    assert provider.disk["promoted"]["P"] == prepared.claim
    assert provider.finalize("P", "S") == "finalized"
    assert provider.wrap_eligible == {"S"}


def test_forged_rollbackable_completion_cannot_finalize_before_retirement():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"

    provider.disk["destroyed"]["P"] = "S"
    provider.disk["promoted"]["P"] = prepared.claim
    provider.disk["active"] = "S"
    provider.disk["staged"] = "T"
    provider.disk["prepared_next"] = None
    provider.disk["wrap_eligible"] = set()
    provider.disk["parent_claim_refs"]["S"] = ParentClaimRef(
        "P",
        transition_claim_id("P", prepared.claim),
    )

    assert provider._hardware_floor == generation_index("P")
    assert "P" in provider._handles
    assert provider._protected_retirements == {}
    assert provider.finalize("P", "S") == "completion-evidence-required"
    assert "S" not in provider.disk["finalized"]
    assert provider.wrap_eligible == set()
    assert provider._protected_completions == {}

    # A legacy/corrupt floor advance without the exact protected retirement
    # record is not accepted as equivalent evidence.
    provider._hardware_floor = generation_index("S")
    del provider._handles["P"]
    assert provider.finalize("P", "S") == "completion-evidence-required"
    assert provider._protected_completions == {}
    assert provider.wrap_eligible == set()


def test_finalization_retry_replays_mirrors_after_protected_completion():
    class SimulatedPowerLoss(Exception):
        pass

    provider = ProviderModel(capacity=3, rollback_resistant=True)
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    assert provider.destroy("P", "S") == "destroyed"
    assert provider.promote(prepared) == "promoted-without-allocation"
    before_finalization = provider.snapshot()
    real_projection = provider._project_finalization

    def lose_power_between_mirrors(successor):
        provider.disk["finalized"].add(successor)
        assert provider.disk["wrap_eligible"] == set()
        raise SimulatedPowerLoss

    provider._project_finalization = lose_power_between_mirrors
    with pytest.raises(SimulatedPowerLoss):
        provider.finalize("P", "S")
    assert provider._protected_completions["P"] == (
        provider._protected_retirements["P"]
    )
    assert "S" in provider.disk["finalized"]
    assert provider.disk["wrap_eligible"] == set()

    assert provider.restore(before_finalization) == "restored"
    provider._project_finalization = real_projection
    assert "S" not in provider.disk["finalized"]
    assert provider.finalize("P", "S") == "already-finalized"
    assert provider.disk["finalized"] >= {"P", "S"}
    assert provider.wrap_eligible == {"S"}


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


def test_retirement_is_protected_before_physical_handle_cleanup():
    class SimulatedPowerLoss(Exception):
        pass

    provider = ProviderModel(capacity=3, rollback_resistant=True)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    before_destruction = provider.snapshot()
    real_delete = provider._delete_retired_handle

    def lose_power_before_physical_cleanup(predecessor):
        assert predecessor == "P"
        assert provider._hardware_floor == generation_index("S")
        with pytest.raises(CryptoError, match="hardware floor"):
            provider._usable_private("P")
        raise SimulatedPowerLoss

    provider._delete_retired_handle = lose_power_before_physical_cleanup
    with pytest.raises(SimulatedPowerLoss):
        provider.destroy("P", "S")
    assert "P" in provider._handles
    assert provider._hardware_floor == generation_index("S")
    assert provider.disk["destroyed"] == {}

    provider.restore(before_destruction)
    provider._delete_retired_handle = real_delete
    assert provider.reconcile_status() == "stale-snapshot-fail-closed"
    assert provider.destroy("P", "S") == "already-destroyed"
    assert "P" not in provider._handles
    assert provider.disk["destroyed"] == {"P": "S"}
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.finalize("P", "S") == "finalized"


@pytest.mark.parametrize("delete_before_power_loss", (False, True))
def test_lower_tier_destruction_intent_recovers_both_delete_boundaries(
    delete_before_power_loss,
):
    class SimulatedPowerLoss(Exception):
        pass

    provider = ProviderModel(capacity=3, rollback_resistant=False)
    provider.seed_cover("frontier-root", b"survivor")
    transition = FIXTURE["decision"]["transition_batches"][0]
    assert provider.prepare_next("T") == "prepared"
    prepared = prepared_transition(provider, transition)
    assert provider.claim(prepared) == "accepted"
    assert provider.fence_and_drain("P")[0] == "fenced"
    manifest = purge_targets_for_operations(prepared.operations)
    assert provider.migrate("P", "S", manifest) == "migrated"
    original_public = provider._generation_publics["P"]
    real_delete = provider._delete_retired_handle

    def lose_power_at_delete(predecessor):
        intent = provider.disk["destruction_intents"].get(predecessor)
        assert intent is not None
        assert intent.predecessor_public == original_public
        if delete_before_power_loss:
            real_delete(predecessor)
        raise SimulatedPowerLoss

    provider._delete_retired_handle = lose_power_at_delete
    with pytest.raises(SimulatedPowerLoss):
        provider.destroy("P", "S")
    assert ("P" not in provider._handles) is delete_before_power_loss
    assert provider.disk["destroyed"] == {}
    intent = provider.disk["destruction_intents"]["P"]
    assert intent.accepted_transition == provider._accepted_transition("P")
    assert intent.migration_proof == provider._accepted_migration("P")

    crash_snapshot = provider.snapshot()
    provider._delete_retired_handle = real_delete
    provider.restore(crash_snapshot)
    assert provider.destroy("P", "S") == "destroyed"
    assert "P" not in provider._handles
    assert provider.disk["destroyed"] == {"P": "S"}
    assert provider.promote(prepared) == "promoted-without-allocation"
    assert provider.finalize("P", "S") == "finalized"
    assert provider.open_cover("frontier-root") == b"survivor"


def test_rollback_resistant_restore_cannot_revive_p_or_fork_its_claim():
    provider = ProviderModel(capacity=3, rollback_resistant=True)
    deleted_secret = cover_fixture()["retained-node-a"]
    provider.seed_cover("retained-node-a", deleted_secret)
    assert provider.acquire_writer_lease(
        "stale-writer", "P"
    ) == "accepted"
    old_snapshot = provider.snapshot()

    transition = FIXTURE["decision"]["transition_batches"][0]
    prepared = complete_transition(provider, transition)
    provider.restore(old_snapshot)

    assert provider.reconcile_status() == "stale-snapshot-fail-closed"
    assert provider.wrap_eligible == set()
    assert provider.acquire_writer_lease("new-writer", "P") == "rejected"
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
    ]["maximum_default_tier"] == "hardware-isolated"
    assert platforms[
        "tpm-2-policy-nv-provider"
    ]["retirement_counter_available"] is True
    assert platforms[
        "tpm-2-policy-nv-provider"
    ]["protected_claim_digest_cas_required"] is True
    assert platforms[
        "tpm-2-policy-nv-provider"
    ]["conditional_tier"] == "rollback-resistant-after-reviewed-claim-cas"
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
        "protected claim-digest CAS",
        "normal-disk",
        "hardware-isolated",
        "rollback-resistant",
        "first-F-only mode is rejected",
        "new device is readmitted",
        "No allocation is permitted after P destruction",
    ):
        assert required in prose
