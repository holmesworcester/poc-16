"""Pure codec and commitment tests for database-free upload sessions."""
import base64
from dataclasses import replace
import random

import pytest

from core.limits import MAX_OBJECT_BYTES, PAGE_BATCH
from deploy.upload_session import (
    InvalidUploadSession,
    MAX_RANGE_PROOF_BYTES,
    MAX_RANGE_PROOF_NODES,
    MAX_SESSION_BYTES,
    MAX_SESSION_OBJECTS,
    SessionKey,
    SessionState,
    SessionTokenCodec,
    TOKEN_BYTES,
    UploadLeaf,
    UploadManifest,
    UploadSessionPolicy,
    UploadVector,
    decode_range_proof,
    encode_range_proof,
    verify_range,
)


KEY = SessionKey("key00001", b"k" * 32, 0, 10**12)
POLICY = UploadSessionPolicy(
    "test-broker-v1",
    KEY.key_id,
    (KEY,),
    ttl_ms=600_000,
    max_ttl_ms=600_000,
    clock_skew_ms=1_000,
)


def leaf(number, size=None):
    return UploadLeaf(
        f"{number + 1:064x}",
        number % 29 if size is None else size,
    )


def state(manifest, *, next_index=0, issued_bytes=0, last=None):
    return SessionState(
        "a" * 64,
        "b" * 16,
        "c" * 32,
        manifest,
        UploadLeaf("d" * 64, 7),
        next_index,
        issued_bytes,
        last,
        100_000,
        700_000,
        KEY.key_id,
    )


def test_4096_leaf_vector_proves_random_bounded_contiguous_ranges():
    vector = UploadVector(tuple(leaf(index) for index in range(4_096)))
    rng = random.Random(0xA11CE)

    for _ in range(256):
        start = rng.randrange(len(vector.leaves))
        end = min(
            len(vector.leaves),
            start + rng.randint(1, PAGE_BATCH),
        )
        proof = vector.proof(start, end)
        assert len(proof) <= MAX_RANGE_PROOF_BYTES
        assert len(decode_range_proof(proof)) \
            <= MAX_RANGE_PROOF_NODES
        assert verify_range(
            vector.manifest,
            start,
            vector.leaves[start:end],
            proof,
        ) == vector.leaves[start:end]


@pytest.mark.parametrize("count", (1, 2, 3, 255, 256, 257))
def test_merkle_boundary_shapes_and_positions_are_unambiguous(count):
    vector = UploadVector(tuple(leaf(index) for index in range(count)))
    ranges = {
        (0, min(count, PAGE_BATCH)),
        (max(0, count - PAGE_BATCH), count),
    }
    for start, end in ranges:
        proof = vector.proof(start, end)
        verify_range(
            vector.manifest,
            start,
            vector.leaves[start:end],
            proof,
        )

    changed_size = tuple(vector.leaves)
    changed_size = (
        replace(changed_size[0], size=changed_size[0].size + 1),
        *changed_size[1:],
    )
    assert UploadVector(changed_size).manifest.root \
        != vector.manifest.root


def test_proof_codec_rejects_noncanonical_and_mutated_nodes():
    vector = UploadVector(tuple(leaf(index) for index in range(300)))
    start, end = 73, 291
    proof = vector.proof(start, end)
    mutations = []
    for offset in (0, 4, 5, len(proof) - 1):
        changed = bytearray(proof)
        changed[offset] ^= 1
        mutations.append(bytes(changed))
    mutations.extend((proof[:-1], proof + b"x", b"", b"not-a-proof"))

    for changed in mutations:
        with pytest.raises(InvalidUploadSession):
            verify_range(
                vector.manifest,
                start,
                vector.leaves[start:end],
                changed,
            )
    with pytest.raises(InvalidUploadSession):
        encode_range_proof(
            tuple(b"x" * 32 for _ in range(
                MAX_RANGE_PROOF_NODES + 1)))


@pytest.mark.parametrize(
    "leaves",
    (
        (UploadLeaf("a" * 64, 1), UploadLeaf("a" * 64, 2)),
        (UploadLeaf("b" * 64, 1), UploadLeaf("a" * 64, 1)),
        (UploadLeaf("A" * 64, 1),),
        (UploadLeaf("a" * 63, 1),),
        (UploadLeaf("a" * 64, -1),),
        (UploadLeaf("a" * 64, True),),
        (UploadLeaf("a" * 64, MAX_OBJECT_BYTES + 1),),
    ),
)
def test_vector_rejects_duplicates_ordering_and_invalid_leaves(leaves):
    with pytest.raises(InvalidUploadSession):
        UploadVector(leaves)


def test_empty_vector_has_one_canonical_commitment_and_no_range():
    first = UploadVector(())
    second = UploadVector(iter(()))

    assert first.manifest == second.manifest
    assert first.manifest.count == first.manifest.total_bytes == 0
    with pytest.raises(InvalidUploadSession):
        first.proof(0, 0)


def test_cursor_size_is_constant_at_empty_and_absolute_metadata_caps():
    codec = SessionTokenCodec(POLICY, "test-ingress-v1")
    empty = state(UploadVector(()).manifest)
    maximum = state(UploadManifest(
        "e" * 64,
        MAX_SESSION_OBJECTS,
        MAX_SESSION_BYTES - 7,
    ))

    empty_token = codec.encode(empty)
    maximum_token = codec.encode(maximum)
    assert len(empty_token) == len(maximum_token) == TOKEN_BYTES
    assert codec.decode(empty_token, 100_000) == empty
    assert codec.decode(maximum_token, 100_000) == maximum


def test_cursor_wire_is_unpadded_canonical_base64url():
    codec = SessionTokenCodec(POLICY, "test-ingress-v1")
    token = codec.encode(state(UploadVector(()).manifest))
    variants = (
        token + "=",
        token[:-1],
        "!" + token[1:],
        token.lower(),
    )

    for variant in variants:
        with pytest.raises(InvalidUploadSession):
            codec.decode(variant, 100_000)
    raw = base64.urlsafe_b64decode(
        token + "=" * (-len(token) % 4))
    assert base64.urlsafe_b64encode(
        raw).rstrip(b"=").decode() == token


@pytest.mark.parametrize(
    "change",
    (
        lambda value: replace(value, next_index=1),
        lambda value: replace(value, issued_bytes=1),
        lambda value: replace(value, last_digest="e" * 64),
        lambda value: replace(
            value, issued_at_ms=value.expires_at_ms),
        lambda value: replace(
            value, expires_at_ms=value.issued_at_ms),
        lambda value: replace(
            value,
            expires_at_ms=value.issued_at_ms + 600_001),
    ),
)
def test_cursor_encoder_refuses_impossible_progress(change):
    codec = SessionTokenCodec(POLICY, "test-ingress-v1")
    candidate = change(state(UploadVector(()).manifest))

    with pytest.raises(InvalidUploadSession):
        codec.encode(candidate)


def test_keyring_and_policy_inputs_are_finite_and_unambiguous():
    assert repr(KEY) == (
        "SessionKey(key_id='key00001', issue_from_ms=0, "
        "verify_until_ms=1000000000000)")
    assert "kkkk" not in repr(POLICY)
    with pytest.raises(ValueError):
        SessionKey("short", b"k" * 32, 0, 10)
    with pytest.raises(ValueError):
        SessionKey("key00001", b"short", 0, 10)
    with pytest.raises(ValueError):
        UploadSessionPolicy(
            "issuer",
            "key00001",
            (KEY, KEY),
        )
    with pytest.raises(ValueError):
        UploadSessionPolicy(
            "issuer",
            "missing1",
            (KEY,),
        )
    with pytest.raises(ValueError):
        replace(POLICY, max_bytes=0)
    with pytest.raises(ValueError):
        replace(POLICY, ttl_ms=POLICY.max_ttl_ms + 1)
