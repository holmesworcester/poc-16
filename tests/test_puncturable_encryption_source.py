"""Executable checks for the puncturable-encryption source contract.

These helpers deliberately model the frozen poc-10 byte contract and the
poc-16 lifecycle examples. They are test-only design models; later x1o beads
must test the runtime implementation against the same fixture.
"""

import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path

import pytest
from blake3 import blake3
from nacl import bindings
from nacl.exceptions import CryptoError


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "puncturable_encryption_v1.json"
CONTRACT_PATH = ROOT / "docs" / "PUNCTURABLE_ENCRYPTION_SOURCE.md"
FIXTURE = json.loads(FIXTURE_PATH.read_text())
UNIX_MINUTE_MS = 60_000


def unhex(value):
    return bytes.fromhex(value)


def u64(value):
    return value.to_bytes(8, "big")


def u16(value):
    return value.to_bytes(2, "big")


def keyed_hash(key, domain, info):
    return blake3(domain + b"\0" + info, key=key).digest()


def masked_prefix(prefix, depth):
    if not 0 <= depth <= 256:
        raise ValueError("prefix depth must be between 0 and 256")
    result = bytearray(prefix)
    byte_index, remaining_bits = divmod(depth, 8)
    if remaining_bits:
        result[byte_index] &= (0xFF << (8 - remaining_bits)) & 0xFF
        byte_index += 1
    result[byte_index:] = b"\0" * (32 - byte_index)
    return bytes(result)


def bit_at(prefix, depth):
    return (prefix[depth // 8] >> (7 - depth % 8)) & 1


def time_split_info(parent_start, parent_width, side, child_start, child_width):
    return (
        u64(parent_start)
        + u64(parent_width)
        + bytes([side])
        + u64(child_start)
        + u64(child_width)
    )


def trie_split_info(parent_depth, parent_prefix, side, child_depth, child_prefix):
    return (
        u16(parent_depth)
        + masked_prefix(parent_prefix, parent_depth)
        + bytes([side])
        + u16(child_depth)
        + masked_prefix(child_prefix, child_depth)
    )


def derive_trie_path(
    secret,
    domain,
    parent_depth,
    parent_prefix,
    child_depth,
    child_prefix,
):
    if not 0 <= parent_depth <= child_depth <= 256:
        raise ValueError("invalid trie depth interval")
    current_prefix = masked_prefix(parent_prefix, parent_depth)
    if current_prefix != masked_prefix(child_prefix, parent_depth):
        raise ValueError("child prefix is outside the parent prefix")

    for depth in range(parent_depth, child_depth):
        side = bit_at(child_prefix, depth)
        next_depth = depth + 1
        next_prefix = masked_prefix(child_prefix, next_depth)
        info = trie_split_info(
            depth,
            current_prefix,
            side,
            next_depth,
            next_prefix,
        )
        secret = keyed_hash(secret, domain, info)
        current_prefix = next_prefix
    return secret


def generate_frontier_root(random_bytes):
    secret = random_bytes(32)
    if len(secret) != 32:
        raise ValueError("frontier root RNG must return 32 bytes")
    return secret


def derive_root_to_leaf(kdf, authored_at_ms, coordinate):
    secret = unhex(kdf["root_secret"])
    start = kdf["root_time_start"]
    width = kdf["root_time_width"]
    time_bucket = authored_at_ms // UNIX_MINUTE_MS
    first_child = None
    time_domain = kdf["time_domain_ascii"].encode()
    trie_domain = kdf["trie_domain_ascii"].encode()

    while width > 1:
        child_width = width // 2
        midpoint = start + child_width
        side = int(time_bucket >= midpoint)
        child_start = midpoint if side else start
        info = time_split_info(start, width, side, child_start, child_width)
        secret = keyed_hash(secret, time_domain, info)
        first_child = first_child or secret
        start, width = child_start, child_width

    leaf = derive_trie_path(
        secret,
        trie_domain,
        0,
        bytes(32),
        256,
        coordinate,
    )
    return time_bucket, first_child, secret, leaf


def hkdf_sha256(input_key_material, salt, info, length=32):
    pseudorandom_key = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        output += previous
        counter += 1
    return output[:length]


def deterministic_wrap_info(common, vector):
    return b"".join(
        (
            unhex(common["workspace_id"]),
            u64(vector["authored_at_ms"]),
            unhex(common["signer_id"]),
            unhex(common["frontier_id"]),
            bytes([vector["kind"]]),
            unhex(vector["wrapped_secret_id"]),
            unhex(vector["wrapped_source_secret_id"]),
            unhex(vector["wrapped_tombstone_node_id"]),
            u64(vector["range_start"]),
            u64(vector["range_width"]),
            u16(vector["bit_depth"]),
            unhex(vector["event_id_prefix"]),
            unhex(common["recipient_key_id"]),
            unhex(common["recipient_public_key"]),
        )
    )


def wrap_associated_data(common, vector, sender_public_key):
    return b"".join(
        (
            bytes([common["type_tag"]]),
            unhex(common["workspace_id"]),
            unhex(common["frontier_id"]),
            bytes([vector["kind"]]),
            unhex(vector["wrapped_secret_id"]),
            unhex(vector["wrapped_source_secret_id"]),
            unhex(vector["wrapped_tombstone_node_id"]),
            u64(vector["range_start"]),
            u64(vector["range_width"]),
            u16(vector["bit_depth"]),
            unhex(vector["event_id_prefix"]),
            unhex(common["recipient_key_id"]),
            sender_public_key,
            unhex(common["signer_id"]),
        )
    )


def local_root_record(common, secret):
    return (
        bytes([common["local_root_type_tag"]])
        + unhex(common["workspace_id"])
        + unhex(common["frontier_id"])
        + secret
    )


def local_history_record(
    common,
    source_secret_id,
    range_start,
    range_width,
    bit_depth,
    prefix,
    tombstone_id,
    secret,
):
    return b"".join(
        (
            bytes([common["local_history_node_type_tag"]]),
            unhex(common["workspace_id"]),
            unhex(common["frontier_id"]),
            source_secret_id,
            u64(range_start),
            u64(range_width),
            u16(bit_depth),
            masked_prefix(prefix, bit_depth),
            tombstone_id,
            secret,
        )
    )


def materialized_time_bucket(common, kdf, authored_at_ms):
    secret = unhex(kdf["root_secret"])
    source_id = blake3(local_root_record(common, secret)).digest()
    time_bucket = authored_at_ms // UNIX_MINUTE_MS
    start = kdf["root_time_start"]
    width = kdf["root_time_width"]
    domain = kdf["time_domain_ascii"].encode()
    while width > 1:
        child_width = width // 2
        midpoint = start + child_width
        side = int(time_bucket >= midpoint)
        child_start = midpoint if side else start
        secret = keyed_hash(
            secret,
            domain,
            time_split_info(
                start,
                width,
                side,
                child_start,
                child_width,
            ),
        )
        source_id = blake3(
            local_history_record(
                common,
                source_id,
                child_start,
                child_width,
                0,
                bytes(32),
                bytes(32),
                secret,
            )
        ).digest()
        start, width = child_start, child_width
    return secret, source_id


def test_source_lineage_and_security_analysis_are_frozen():
    assert FIXTURE["schema"] == "poc-16.puncturable-encryption-source.v1"
    contract = CONTRACT_PATH.read_text()
    contract_prose = " ".join(contract.split())
    for repository, commits in FIXTURE["source_commits"].items():
        assert repository in contract
        for short_id, full_id in commits.items():
            assert full_id.startswith(short_id)
            assert len(full_id) == 40
            assert short_id in contract

    for required_section in (
        "## Vocabulary and ownership mapping",
        "## State and secret ownership",
        "## Adversary matrix",
        "## Availability and recovery tradeoffs",
        "## Intentional poc-16 deviations",
    ):
        assert required_section in contract

    for required_rule in (
        "Recipient ephemeral rotation is triggered by **key purge**",
        "`time_bucket = floor(authored_at_ms / 60_000)`",
        "Neither timestamps nor fact-id ranking selects a winner",
        "Nothing parks and no pending/wake state is created",
        "A permanent hardware root is not automatically safe",
        "Global suppression determines visibility",
    ):
        assert required_rule in contract_prose


def test_frontier_root_generation_and_prepared_retry_have_no_lookup_input():
    expected_root = unhex(FIXTURE["kdf"]["root_secret"])
    calls = []

    def injected_random_bytes(length):
        calls.append(length)
        return expected_root

    assert generate_frontier_root(injected_random_bytes) == expected_root
    assert calls == [32]

    preparation = FIXTURE["content_preparation"]
    assert len(unhex(preparation["initial"]["content_coordinate"])) == 32
    assert preparation["retry"] == preparation["initial"]
    assert preparation["lookup_inputs"] == []
    assert preparation["derived_local_artifact_authored_at_ms"] is None


def test_time_and_trie_split_vectors_recompute_exact_source_bytes():
    kdf = FIXTURE["kdf"]
    time_domain = kdf["time_domain_ascii"].encode()
    trie_domain = kdf["trie_domain_ascii"].encode()

    for vector in kdf["time_splits"]:
        info = time_split_info(
            vector["parent_start"],
            vector["parent_width"],
            vector["child_side"],
            vector["child_start"],
            vector["child_width"],
        )
        assert info == unhex(vector["info"])
        assert keyed_hash(
            unhex(vector["parent_secret"]), time_domain, info
        ) == unhex(vector["child_secret"])

    for vector in kdf["trie_splits"]:
        parent_prefix = unhex(vector["parent_prefix"])
        child_prefix = unhex(vector["child_prefix"])
        assert vector["child_depth"] == vector["parent_depth"] + 1
        assert masked_prefix(
            parent_prefix, vector["parent_depth"]
        ) == unhex(vector["masked_parent_prefix"])
        assert bit_at(child_prefix, vector["parent_depth"]) == vector["child_side"]
        info = trie_split_info(
            vector["parent_depth"],
            parent_prefix,
            vector["child_side"],
            vector["child_depth"],
            child_prefix,
        )
        assert info == unhex(vector["info"])
        assert keyed_hash(
            unhex(vector["parent_secret"]), trie_domain, info
        ) == unhex(vector["child_secret"])


def test_root_walk_reaches_each_frozen_content_leaf():
    kdf = FIXTURE["kdf"]
    for vector in kdf["root_to_leaf"]:
        time_bucket, first_child, bucket_secret, leaf_secret = derive_root_to_leaf(
            kdf,
            vector["authored_at_ms"],
            unhex(vector["content_coordinate"]),
        )
        assert time_bucket == vector["expected_time_bucket"]
        assert first_child == unhex(vector["first_time_child_secret"])
        assert bucket_secret == unhex(vector["bucket_secret"])
        assert leaf_secret == unhex(vector["leaf_secret"])


def test_fixed_bitwise_trie_path_is_independent_of_storage_compression():
    kdf = FIXTURE["kdf"]
    domain = kdf["trie_domain_ascii"].encode()
    for vector in kdf["root_to_leaf"]:
        coordinate = unhex(vector["content_coordinate"])
        _, _, bucket_secret, direct_leaf = derive_root_to_leaf(
            kdf,
            vector["authored_at_ms"],
            coordinate,
        )
        for retained_depth in (1, 12, 128, 255):
            retained_prefix = masked_prefix(coordinate, retained_depth)
            retained_secret = derive_trie_path(
                bucket_secret,
                domain,
                0,
                bytes(32),
                retained_depth,
                retained_prefix,
            )
            resumed_leaf = derive_trie_path(
                retained_secret,
                domain,
                retained_depth,
                retained_prefix,
                256,
                coordinate,
            )
            assert resumed_leaf == direct_leaf


@pytest.mark.parametrize("vector", FIXTURE["wrap_contract"]["vectors"])
def test_root_and_history_wrap_vectors_encrypt_and_open(vector):
    common = FIXTURE["wrap_contract"]
    secret = unhex(vector["secret"])
    root_secret = unhex(FIXTURE["kdf"]["root_secret"])
    root_id = blake3(local_root_record(common, root_secret)).digest()
    if vector["kind"] == 0:
        assert secret == root_secret
        assert unhex(vector["wrapped_secret_id"]) == root_id
    else:
        bucket_vector = next(
            candidate
            for candidate in FIXTURE["kdf"]["root_to_leaf"]
            if candidate["expected_time_bucket"] == vector["range_start"]
        )
        bucket_secret, bucket_id = materialized_time_bucket(
            common,
            FIXTURE["kdf"],
            bucket_vector["authored_at_ms"],
        )
        assert bucket_secret == unhex(bucket_vector["bucket_secret"])
        assert bucket_id == unhex(vector["wrapped_source_secret_id"])

        prefix = unhex(vector["event_id_prefix"])
        assert derive_trie_path(
            bucket_secret,
            FIXTURE["kdf"]["trie_domain_ascii"].encode(),
            0,
            bytes(32),
            vector["bit_depth"],
            prefix,
        ) == secret
        assert derive_trie_path(
            secret,
            FIXTURE["kdf"]["trie_domain_ascii"].encode(),
            vector["bit_depth"],
            prefix,
            256,
            unhex(bucket_vector["content_coordinate"]),
        ) == unhex(bucket_vector["leaf_secret"])
        tombstone_id = unhex(vector["wrapped_tombstone_node_id"])
        assert tombstone_id == bytes(32) or tombstone_id == bucket_id
        history_record = local_history_record(
            common,
            bucket_id,
            vector["range_start"],
            vector["range_width"],
            vector["bit_depth"],
            prefix,
            tombstone_id,
            secret,
        )
        assert blake3(history_record).digest() == unhex(
            vector["wrapped_secret_id"]
        )

    info = deterministic_wrap_info(common, vector)
    sender_private = keyed_hash(
        secret, common["sender_domain_ascii"].encode(), info
    )
    sender_public = bindings.crypto_scalarmult_base(sender_private)
    nonce = keyed_hash(
        secret, common["nonce_domain_ascii"].encode(), info
    )[: bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]

    assert sender_private == unhex(vector["sender_private_key"])
    assert sender_public == unhex(vector["sender_public_key"])
    assert nonce == unhex(vector["nonce"])

    recipient_public = unhex(common["recipient_public_key"])
    assert bindings.crypto_scalarmult_base(
        unhex(common["recipient_private_key"])
    ) == recipient_public
    sender_shared = bindings.crypto_scalarmult(sender_private, recipient_public)
    key = hkdf_sha256(
        sender_shared,
        common["purpose_ascii"].encode(),
        common["hkdf_info_ascii"].encode(),
    )
    aad = wrap_associated_data(common, vector, sender_public)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        secret, aad, nonce, key
    )

    assert key == unhex(vector["aead_key"])
    assert ciphertext == unhex(vector["ciphertext"])

    receiver_shared = bindings.crypto_scalarmult(
        unhex(common["recipient_private_key"]), sender_public
    )
    receiver_key = hkdf_sha256(
        receiver_shared,
        common["purpose_ascii"].encode(),
        common["hkdf_info_ascii"].encode(),
    )
    assert receiver_key == key
    assert bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, aad, nonce, receiver_key
    ) == secret
    with pytest.raises(CryptoError):
        bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad + b"\0", nonce, receiver_key
        )


RECOVERY_PATHS = (
    "shared_wrap_allowed",
    "sealed_to_generation",
    "retained_root_derivable",
)

TRANSITION_COMPLETION_FACTS = {
    "writer-fence-P-drained",
    "survivor-cover-migration-P-S",
    "predecessor-P-handle-destroyed",
    "transition-P-S-completion",
}


def purge_batch_result(batch):
    eligible = any(
        any(secret[path] for path in RECOVERY_PATHS)
        for secret in batch["secrets"]
    )
    return eligible, int(eligible)


def test_key_purge_rotates_once_from_causal_recovery_paths_not_observation():
    by_name = {case["name"]: case for case in FIXTURE["purge_batches"]}
    for case in by_name.values():
        eligible, rotations = purge_batch_result(case)
        assert eligible is case["expected_recovery_eligible"]
        assert rotations == case["expected_recipient_rotations"]

        observation_rewrite = deepcopy(case)
        for secret in observation_rewrite["secrets"]:
            secret["observed_local_wrap"] = not secret["observed_local_wrap"]
        assert purge_batch_result(observation_rewrite) == (eligible, rotations)

    delayed = by_name["later-history-node-with-delayed-remote-wrap"]
    delayed_secret = delayed["secrets"][0]
    assert delayed_secret["observed_local_wrap"] is False
    assert delayed_secret["remote_wrap_delivered_after_purge"] is True
    assert purge_batch_result(delayed) == (True, 1)
    assert purge_batch_result(by_name["batched-root-and-history-purge"]) == (
        True,
        1,
    )


class TransitionModel:
    def __init__(self, graph):
        self.graph = graph
        self.active = "P"
        self.claims = {}
        self.committed_successors = {}
        self.wrap_eligible = {"P"}

    def apply(self, attempt):
        predecessor = attempt["predecessor"]
        if attempt["action"] == "finalize":
            if predecessor != self.active or predecessor not in self.claims:
                return "rejected"
            successor = self.claims[predecessor][0]
            completion_fact = attempt.get("completion_fact")
            if completion_fact not in self.graph:
                return "blocked-until-completion-evidence"
            completion_closure = dependency_closure(
                self.graph, completion_fact
            )
            if not TRANSITION_COMPLETION_FACTS <= completion_closure:
                return "blocked-until-completion-evidence"
            finalization_fact = f"finalized-{successor}"
            if (
                finalization_fact not in self.graph
                or completion_fact
                not in dependency_closure(self.graph, finalization_fact)
            ):
                return "blocked-until-completion-evidence"
            self.active = successor
            self.wrap_eligible = {successor}
            return "finalized"

        claim = (
            attempt["successor"],
            attempt["next"],
            tuple(sorted(attempt["batch"])),
        )
        prior = self.claims.get(predecessor)
        if prior is not None:
            return "coalesced" if prior == claim else "conflict"
        if predecessor != self.active:
            return "blocked-until-P-finalized"
        committed_successor = self.committed_successors.get(predecessor)
        if (
            committed_successor is not None
            and attempt["successor"] != committed_successor
        ):
            return "conflict"
        self.claims[predecessor] = claim
        self.committed_successors[attempt["successor"]] = attempt["next"]
        return "accepted"


def test_recursive_transition_claims_conflict_by_refs_not_timestamp():
    graph = FIXTURE["recipient_transition"]["fact_graph"]
    model = TransitionModel(graph)
    results = []
    for attempt in FIXTURE["recipient_transition"]["claim_attempts"]:
        result = model.apply(attempt)
        results.append(result)
        assert result == attempt["expected"]
        if (
            attempt["action"] == "claim"
            and result == "accepted"
            and attempt["predecessor"] == model.active
        ):
            assert attempt["successor"] not in model.wrap_eligible

    assert results == [
        "accepted",
        "coalesced",
        "conflict",
        "conflict",
        "conflict",
        "blocked-until-P-finalized",
        "blocked-until-completion-evidence",
        "finalized",
        "coalesced",
        "conflict",
        "conflict",
        "accepted",
    ]
    assert model.active == "S"
    assert model.wrap_eligible == {"S"}
    assert model.claims == {
        "P": ("S", "T", ("operation-A",)),
        "S": ("T", "U", ("operation-X",)),
    }
    assert model.committed_successors == {"S": "T", "T": "U"}

    finalization_closure = dependency_closure(graph, "finalized-S")
    assert TRANSITION_COMPLETION_FACTS <= finalization_closure
    assert "operation-A" in finalization_closure
    assert "operation-X" not in finalization_closure


def dependencies(graph, fact_id):
    fact = graph[fact_id]
    return tuple(dict.fromkeys(fact["refs"] + fact["needs"]))


def dependency_closure(graph, root):
    result = set()

    def visit(fact_id):
        if fact_id in result:
            return
        result.add(fact_id)
        for dependency in dependencies(graph, fact_id):
            visit(dependency)

    visit(root)
    return result


def ingest_closed_pile(graph, pile, accepted):
    if not pile or any(fact_id not in graph for fact_id in pile):
        return "rejected", 0
    pile_set = set(pile)
    if len(pile_set) != len(pile):
        return "rejected", 0
    if any(
        not set(dependencies(graph, fact_id)) <= pile_set
        for fact_id in pile
    ):
        return "rejected", 0

    available = set()
    for fact_id in pile:
        if not set(dependencies(graph, fact_id)) <= available:
            return "rejected", 0
        available.add(fact_id)

    duplicates = len(pile_set & accepted)
    accepted.update(pile_set)
    return "accepted", duplicates


def test_transition_delivery_is_closed_atomic_and_never_parks():
    transition = FIXTURE["recipient_transition"]
    graph = transition["fact_graph"]
    reservation_closure = dependency_closure(
        graph, "reservation-P-S-T-A"
    )
    assert "operation-A" in reservation_closure
    assert "operation-X" not in reservation_closure

    for case in transition["delivery_cases"]:
        accepted = set()
        total_duplicates = 0
        rejected = False
        for pile in case["piles"]:
            before = set(accepted)
            result, duplicates = ingest_closed_pile(graph, pile, accepted)
            if result == "rejected":
                rejected = True
                assert accepted == before
                break
            total_duplicates += duplicates

        if case["expected"] == "rejected-no-side-effects":
            assert rejected
            assert accepted == set()
        else:
            assert not rejected
            assert "reservation-P-S-T-A" in accepted
        if case["expected"] == "accepted-idempotent-duplicate":
            assert total_duplicates > 0
        if case["expected"] == "accepted-operation-X-rebases-to-S":
            assert "operation-X" in accepted
            assert "operation-X" not in reservation_closure
            assert "operation-X-rebase-to-S" in accepted
            assert set(graph["operation-X-rebase-to-S"]["refs"]) == {
                "operation-X",
                "finalized-S",
            }
        if case["expected"] == "accepted-operation-X-remains-excluded":
            assert "operation-X" in accepted
            assert "operation-X" not in reservation_closure
            assert "operation-X-rebase-to-S" not in accepted
        if case["expected"] == "accepted-finalized":
            assert TRANSITION_COMPLETION_FACTS <= accepted
            assert "finalized-S" in accepted
        assert case["expected_parked"] == []


def test_closed_pile_order_is_independent_of_prior_acceptance():
    graph = FIXTURE["recipient_transition"]["fact_graph"]
    accepted = set()
    operation_pile = [
        "workspace-anchor",
        "reader-authority",
        "recipient-P",
        "operation-A",
    ]
    assert ingest_closed_pile(graph, operation_pile, accepted) == (
        "accepted",
        0,
    )
    before = set(accepted)
    malformed_reservation_pile = [
        "workspace-anchor",
        "reader-authority",
        "recipient-P",
        "successor-S-reservation",
        "next-T-commitment",
        "claim-P-S-T-A",
        "reservation-P-S-T-A",
        "operation-A",
    ]
    assert ingest_closed_pile(
        graph,
        malformed_reservation_pile,
        accepted,
    ) == ("rejected", 0)
    assert accepted == before


def topology_preserving_timestamp_rewrite(graph, timestamps):
    mapping = {
        fact_id: hashlib.sha256(
            f"{fact_id}:{timestamps[fact_id]}".encode()
        ).hexdigest()
        for fact_id in graph
    }
    rewritten = {}
    for fact_id, fact in graph.items():
        rewritten[mapping[fact_id]] = {
            **fact,
            "logical_id": fact_id,
            "refs": [mapping[dependency] for dependency in fact["refs"]],
            "needs": [mapping[dependency] for dependency in fact["needs"]],
        }
    return rewritten, mapping


def causal_batch_assignment(graph, claim_id, rebase_ids):
    claim = graph[claim_id]
    assert claim["kind"] == "transition-claim"
    assignment = {}
    for dependency in claim["refs"]:
        fact = graph[dependency]
        if fact.get("kind") == "purge-operation":
            assignment[fact["logical_id"]] = claim["predecessor"]

    for rebase_id in rebase_ids:
        rebase = graph[rebase_id]
        assert rebase["kind"] == "operation-rebase"
        operations = [
            graph[dependency]
            for dependency in rebase["refs"]
            if graph[dependency].get("kind") == "purge-operation"
        ]
        recipients = [
            graph[dependency]
            for dependency in rebase["refs"]
            if graph[dependency].get("kind") == "finalized-recipient"
        ]
        assert len(operations) == len(recipients) == 1
        assert recipients[0]["generation"] == rebase["generation"]
        assignment[operations[0]["logical_id"]] = rebase["generation"]
    return assignment


def test_timestamp_rewrites_cannot_change_batch_assignment():
    case = FIXTURE["recipient_transition"]["timestamp_assignment"]
    graph = FIXTURE["recipient_transition"]["fact_graph"]
    assert case["rewrites"][0] != case["rewrites"][1]
    assignments = []
    for timestamps in case["rewrites"]:
        assert set(timestamps) == set(graph)
        rewritten, mapping = topology_preserving_timestamp_rewrite(
            graph, timestamps
        )
        assignments.append(
            causal_batch_assignment(
                rewritten,
                mapping[case["batch_claim"]],
                [mapping[fact_id] for fact_id in case["rebase_facts"]],
            )
        )
    assert assignments == [
        case["expected_assignment"],
        case["expected_assignment"],
    ]


def replay_writer_race(case):
    current_generation = "P"
    active = {}
    prepared = {}
    fenced = set()
    committed = []
    scan = None
    migrated = False
    destroyed = set()
    post_fence_P_commits = []

    for step in case["steps"]:
        operation = step["op"]
        if operation == "lease":
            if (
                step["generation"] == current_generation
                and step["generation"] not in fenced
            ):
                active[step["writer"]] = step["generation"]
                result = "accepted"
            else:
                result = "rejected"
        elif operation == "prepare":
            if step["writer"] in active:
                prepared[step["writer"]] = step["record"]
                result = "accepted"
            else:
                result = "rejected"
        elif operation == "fence":
            fenced.add(step["generation"])
            aborted = sorted(
                writer
                for writer, generation in active.items()
                if generation == step["generation"]
            )
            for writer in aborted:
                active.pop(writer)
                prepared.pop(writer, None)
            result = "accepted-aborted-" + ",".join(aborted)
        elif operation == "commit":
            generation = active.get(step["writer"])
            if generation is None or generation in fenced:
                result = "rejected"
            else:
                committed.append((generation, step["record"]))
                if generation == "P" and "P" in fenced:
                    post_fence_P_commits.append(step["record"])
                result = "accepted"
        elif operation == "scan-survivors":
            assert not any(
                generation == step["generation"]
                for generation in active.values()
            )
            scan = [
                record
                for generation, record in committed
                if generation == step["generation"]
            ]
            result = scan
        elif operation == "migrate":
            assert scan is not None
            migrated = True
            result = "accepted"
        elif operation == "destroy":
            assert migrated
            destroyed.add(step["generation"])
            result = "accepted"
        elif operation == "promote":
            assert "P" in destroyed
            current_generation = step["generation"]
            result = "accepted"
        else:
            raise AssertionError(f"unknown writer-race operation: {operation}")
        assert result == step["expected"]

    return current_generation, post_fence_P_commits


def test_predecessor_writer_is_fenced_before_survivor_scan():
    case = FIXTURE["recipient_transition"]["writer_race"]
    generation, post_fence_commits = replay_writer_race(case)
    assert generation == case["expected_final_generation"]
    assert post_fence_commits == case["expected_post_fence_P_commits"]


def run_handle_transition(capacity):
    handles = ["P"]
    peak = list(handles)
    for handle in ("S", "T"):
        if len(handles) == capacity:
            return {
                "result": "capacity-failure-before-P-destruction",
                "live": handles,
                "peak": peak,
                "finalized": False,
            }
        handles.append(handle)
        if len(handles) > len(peak):
            peak = list(handles)

    handles.remove("P")
    return {
        "result": "success",
        "live": handles,
        "peak": peak,
        "finalized": True,
    }


def test_independent_non_exportable_rotation_requires_three_peak_handles():
    for case in FIXTURE["recipient_transition"]["handle_budgets"]:
        result = run_handle_transition(case["capacity"])
        assert result["result"] == case["expected"]
        assert result["live"] == case["expected_live_handles"]
        assert result["finalized"] is case["expected_finalized"]
        if "expected_peak_handles" in case:
            assert result["peak"] == case["expected_peak_handles"]
