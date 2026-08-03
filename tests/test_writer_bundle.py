"""Portable writer bundles keep logical authority above physical packing."""
from dataclasses import replace
import json

import pytest

from core.close import (
    ClosedPileEvaluator,
    encode_signed_pile,
    make_signed_pile,
)
from core.crypto import h, keypair
from core.fact import canon
from core.limits import PayloadTooLarge
from core.writer_bundle import (
    InvalidWriterBundle,
    MAX_BUNDLE_DESCRIPTOR_BYTES,
    MAX_BUNDLE_PACK_BYTES,
    MAX_BUNDLE_PILES,
    PackSlice,
    WriterBundle,
    bundle_oid,
    decode_bundle,
    encode_bundle,
    extract_pile_bytes,
    pack_signed_piles,
    publication_rows,
    validate_prefix_extension,
    verify_pile_slice,
)
from core.writer_tree import MAX_WRITER_SEQUENCE
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact


def signed_piles():
    secret, device = keypair()
    root = workspace_fact(secret, device, "alice", 1)
    member = signature_fact(secret, device, root, 2)
    piles = tuple(
        encode_signed_pile(make_signed_pile(
            secret, root.fid, device, facts))
        for facts in ((root,), (root, member))
    )
    # The fixture itself proves these are not merely well-signed loose facts.
    evaluator = ClosedPileEvaluator(root.fid)
    assert all(evaluator.evaluate(raw, writer=device) for raw in piles)
    return secret, device, root, piles


def synthetic_bundle(*, count=1, first=1, pack_bytes=None):
    if pack_bytes is None:
        pack_bytes = count
    piles = tuple(
        h(index.to_bytes(8, "big")) for index in range(count))
    if count == 1:
        slices = (PackSlice(0, pack_bytes),)
    else:
        slices = tuple(PackSlice(index, 1) for index in range(count))
    return WriterBundle(
        h(b"workspace"),
        h(b"device"),
        first,
        first + count - 1,
        piles,
        h(b"pack"),
        pack_bytes,
        slices,
    )


def test_bundle_round_trip_binds_exact_publication_range_and_extracts_piles():
    _secret, device, root, raws = signed_piles()
    bundle, pack = pack_signed_piles(root.fid, device, 41, raws)
    encoded = encode_bundle(bundle)

    assert decode_bundle(
        encoded,
        workspace=root.fid,
        device=device,
        first=41,
        last=42,
        expected_oid=bundle_oid(bundle),
    ) == bundle
    assert publication_rows(bundle) == (
        (41, h(raws[0])),
        (42, h(raws[1])),
    )
    assert bundle.slices == (
        PackSlice(0, len(raws[0])),
        PackSlice(len(raws[0]), len(raws[1])),
    )
    assert extract_pile_bytes(bundle, pack, 41) == raws[0]
    assert extract_pile_bytes(bundle, pack, 42) == raws[1]

    for binding in (
            {"workspace": h(b"other workspace")},
            {"device": h(b"other device")},
            {"first": 40},
            {"last": 43}):
        with pytest.raises(InvalidWriterBundle):
            decode_bundle(encoded, **binding)


def test_tail_replacement_is_a_logical_prefix_proof_not_pack_trust():
    _secret, device, root, raws = signed_piles()
    accepted, accepted_pack = pack_signed_piles(
        root.fid, device, 9, raws[:1])
    candidate, candidate_pack = pack_signed_piles(
        root.fid, device, 9, raws)

    assert validate_prefix_extension(accepted, candidate) == (
        (10, h(raws[1])),)
    assert extract_pile_bytes(candidate, candidate_pack, 10) == raws[1]

    # A locator-only repack neither adds nor rewrites a logical publication.
    # Its bogus table is harmless because using it still verifies pile bytes.
    bogus_locator = replace(
        candidate,
        pack_oid=h(b"bogus physical object"),
        pack_bytes=2,
        slices=(PackSlice(0, 1), PackSlice(1, 1)),
    )
    assert validate_prefix_extension(candidate, bogus_locator) == ()
    with pytest.raises(InvalidWriterBundle, match="pack integrity"):
        extract_pile_bytes(bogus_locator, candidate_pack, 9)

    # Replacing a tail never grants deletion, reordering, or mutation.
    with pytest.raises(InvalidWriterBundle, match="rollback"):
        validate_prefix_extension(candidate, accepted)
    rewritten = replace(candidate, piles=tuple(reversed(candidate.piles)))
    with pytest.raises(InvalidWriterBundle, match="rewrote publication"):
        validate_prefix_extension(candidate, rewritten)

    for changed in (
            replace(candidate, workspace=h(b"foreign workspace")),
            replace(candidate, device=h(b"foreign device")),
            replace(candidate, first=10, last=11)):
        with pytest.raises(InvalidWriterBundle, match="binding changed"):
            validate_prefix_extension(candidate, changed)

    assert extract_pile_bytes(accepted, accepted_pack, 9) == raws[0]


@pytest.mark.parametrize("mutation", (
    lambda value: value["pack"]["table"][0].__setitem__(0, 1),
    lambda value: value["pack"]["table"][0].__setitem__(1, 0),
    lambda value: value["pack"]["table"].pop(),
    lambda value: value["pack"]["table"][0].__setitem__(0, True),
    lambda value: value["pack"].__setitem__("extra", 1),
))
def test_decode_rejects_corrupt_pack_tables(mutation):
    _secret, device, root, raws = signed_piles()
    bundle, _pack = pack_signed_piles(root.fid, device, 1, raws)
    value = json.loads(encode_bundle(bundle))
    mutation(value)

    with pytest.raises(InvalidWriterBundle):
        decode_bundle(canon(value))


def test_every_ranged_slice_is_hash_and_signature_checked():
    _secret, device, root, raws = signed_piles()
    bundle, pack = pack_signed_piles(root.fid, device, 1, raws)
    first = bundle.slices[0]

    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        verify_pile_slice(bundle, 1, raws[0][:-1])
    flipped = bytes([raws[0][0] ^ 1]) + raws[0][1:]
    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        verify_pile_slice(bundle, 1, flipped)
    with pytest.raises(InvalidWriterBundle, match="publication"):
        verify_pile_slice(bundle, 0, raws[0])

    # The complete physical object hash is checked when the whole concat pack
    # is available, independently of each inner pile identity.
    corrupt_pack = bytearray(pack)
    corrupt_pack[first.offset] ^= 1
    with pytest.raises(InvalidWriterBundle, match="pack integrity"):
        extract_pile_bytes(bundle, bytes(corrupt_pack), 1)

    # Even a table whose total and pack OID are internally consistent cannot
    # shift a boundary: the expected per-pile content hash catches it.
    shifted = replace(
        bundle,
        slices=(
            PackSlice(0, first.length + 1),
            PackSlice(first.length + 1, bundle.slices[1].length - 1),
        ),
    )
    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        extract_pile_bytes(shifted, pack, 1)


def test_a_hash_matching_slice_still_needs_a_valid_signed_pile():
    _secret, device, root, raws = signed_piles()
    value = json.loads(raws[0])
    value["signature"] = "0" * 128
    forged = canon(value)
    bundle = WriterBundle(
        root.fid,
        device,
        1,
        1,
        (h(forged),),
        h(forged),
        len(forged),
        (PackSlice(0, len(forged)),),
    )

    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        verify_pile_slice(bundle, 1, forged)


def test_pack_builder_rejects_a_foreign_writer_and_manifest_hash_corruption():
    _secret, device, root, raws = signed_piles()
    other_secret, other_device = keypair()
    foreign = encode_signed_pile(make_signed_pile(
        other_secret,
        root.fid,
        other_device,
        ClosedPileEvaluator(root.fid).evaluate(raws[0]).pile.facts,
    ))
    with pytest.raises(InvalidWriterBundle, match="pile binding"):
        pack_signed_piles(root.fid, device, 1, (foreign,))

    bundle, _pack = pack_signed_piles(root.fid, device, 1, raws)
    raw = encode_bundle(bundle)
    value = json.loads(raw)
    value["pack"]["oid"] = h(b"different pack")
    tampered = canon(value)
    assert decode_bundle(tampered).pack_oid == h(b"different pack")
    with pytest.raises(InvalidWriterBundle):
        decode_bundle(tampered, expected_oid=h(raw))


def test_exact_and_one_over_bundle_count_bounds_are_canonical():
    exact = synthetic_bundle(count=MAX_BUNDLE_PILES)
    raw = encode_bundle(exact)

    assert len(raw) <= MAX_BUNDLE_DESCRIPTOR_BYTES
    assert decode_bundle(raw) == exact

    piles = exact.piles + (h(b"one too many"),)
    slices = exact.slices + (PackSlice(MAX_BUNDLE_PILES, 1),)
    with pytest.raises(ValueError, match="descriptor"):
        WriterBundle(
            exact.workspace,
            exact.device,
            1,
            MAX_BUNDLE_PILES + 1,
            piles,
            h(b"larger pack"),
            MAX_BUNDLE_PILES + 1,
            slices,
        )

    _secret, device, root, signed = signed_piles()
    with pytest.raises(PayloadTooLarge, match="too many piles"):
        pack_signed_piles(
            root.fid, device, 1,
            (signed[0] for _ in range(MAX_BUNDLE_PILES + 1)),
        )


def test_exact_and_one_over_pack_range_and_descriptor_byte_bounds():
    exact_pack = synthetic_bundle(pack_bytes=MAX_BUNDLE_PACK_BYTES)
    assert decode_bundle(encode_bundle(exact_pack)) == exact_pack

    with pytest.raises(ValueError, match="descriptor"):
        replace(exact_pack, pack_bytes=MAX_BUNDLE_PACK_BYTES + 1)
    with pytest.raises(ValueError, match="slice"):
        PackSlice(0, MAX_BUNDLE_PACK_BYTES + 1)

    final = synthetic_bundle(first=MAX_WRITER_SEQUENCE)
    assert final.last == MAX_WRITER_SEQUENCE
    with pytest.raises(ValueError, match="descriptor"):
        WriterBundle(
            final.workspace,
            final.device,
            MAX_WRITER_SEQUENCE,
            MAX_WRITER_SEQUENCE + 1,
            (h(b"a"), h(b"b")),
            h(b"two bytes"),
            2,
            (PackSlice(0, 1), PackSlice(1, 1)),
        )

    with pytest.raises(InvalidWriterBundle):
        decode_bundle(b" " * MAX_BUNDLE_DESCRIPTOR_BYTES)
    with pytest.raises(PayloadTooLarge):
        decode_bundle(b" " * (MAX_BUNDLE_DESCRIPTOR_BYTES + 1))
