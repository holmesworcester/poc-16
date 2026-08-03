"""Logical writer history remains independent of optional physical packs."""
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
    BundlePack,
    InvalidWriterBundle,
    MAX_BUNDLE_DESCRIPTOR_BYTES,
    MAX_BUNDLE_PACK_BYTES,
    MAX_BUNDLE_PACK_TABLE_BYTES,
    MAX_BUNDLE_PILES,
    PackSlice,
    WriterBundle,
    bundle_oid,
    bundle_pack_oid,
    decode_bundle,
    decode_bundle_pack,
    encode_bundle,
    encode_bundle_pack,
    extract_pile_bytes,
    make_bundle,
    pack_bundle,
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
    raws = tuple(
        encode_signed_pile(make_signed_pile(
            secret, root.fid, device, facts))
        for facts in ((root,), (root, member))
    )
    evaluator = ClosedPileEvaluator(root.fid)
    assert all(evaluator.evaluate(raw, writer=device) for raw in raws)
    return secret, device, root, raws


def synthetic_bundle(count=1, first=1):
    return make_bundle(
        h(b"workspace"), h(b"device"), first,
        (h(index.to_bytes(8, "big")) for index in range(count)))


def synthetic_pack(bundle, *, pack_bytes=None):
    pack_bytes = len(bundle.piles) if pack_bytes is None else pack_bytes
    slices = (PackSlice(0, pack_bytes),) if len(bundle.piles) == 1 else tuple(
        PackSlice(index, 1) for index in range(len(bundle.piles)))
    return BundlePack(bundle_oid(bundle), h(b"pack"), pack_bytes, slices)


def test_logical_bundle_and_pack_locator_round_trip_separately():
    _secret, device, root, raws = signed_piles()
    bundle, locator, body = pack_signed_piles(root.fid, device, 41, raws)
    logical = encode_bundle(bundle)
    physical = encode_bundle_pack(locator)

    assert decode_bundle(
        logical,
        workspace=root.fid,
        device=device,
        first=41,
        last=42,
        expected_oid=bundle_oid(bundle),
    ) == bundle
    assert decode_bundle_pack(
        physical,
        expected_bundle=bundle_oid(bundle),
        expected_oid=bundle_pack_oid(locator),
    ) == locator
    assert b"pack" not in logical
    assert publication_rows(bundle) == (
        (41, h(raws[0])),
        (42, h(raws[1])),
    )
    assert extract_pile_bytes(bundle, locator, body, 41) == raws[0]
    assert extract_pile_bytes(bundle, locator, body, 42) == raws[1]

    for binding in (
            {"workspace": h(b"other workspace")},
            {"device": h(b"other device")},
            {"first": 40},
            {"last": 43}):
        with pytest.raises(InvalidWriterBundle):
            decode_bundle(logical, **binding)


def test_live_tail_prefix_extends_without_constructing_a_pack():
    _secret, device, root, raws = signed_piles()
    accepted = make_bundle(root.fid, device, 9, (h(raws[0]),))
    candidate = make_bundle(root.fid, device, 9, map(h, raws))

    assert validate_prefix_extension(accepted, candidate) == (
        (10, h(raws[1])),)
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


def test_repacking_changes_only_locator_identity_even_with_another_layout():
    _secret, device, root, raws = signed_piles()
    bundle, concat_locator, concat = pack_signed_piles(
        root.fid, device, 5, raws)
    logical_oid = bundle_oid(bundle)

    # A second physical object has a header, a gap, trailing bytes, and stores
    # the piles in reverse physical order. Its aligned table still indexes the
    # same logical publication order.
    header, gap, trailer = b"HEAD", b"gap", b"!"
    second_offset = len(header)
    first_offset = second_offset + len(raws[1]) + len(gap)
    repacked = header + raws[1] + gap + raws[0] + trailer
    repacked_locator = BundlePack(
        logical_oid,
        h(repacked),
        len(repacked),
        (
            PackSlice(first_offset, len(raws[0])),
            PackSlice(second_offset, len(raws[1])),
        ),
    )

    assert concat_locator.bundle_oid == repacked_locator.bundle_oid \
        == logical_oid
    assert concat_locator.pack_oid != repacked_locator.pack_oid
    assert bundle_oid(decode_bundle(encode_bundle(bundle))) == logical_oid
    assert extract_pile_bytes(bundle, concat_locator, concat, 5) == raws[0]
    assert extract_pile_bytes(bundle, repacked_locator, repacked, 5) == raws[0]
    assert extract_pile_bytes(bundle, repacked_locator, repacked, 6) == raws[1]


@pytest.mark.parametrize("mutation", (
    lambda value: value["table"][1].__setitem__(0, 0),
    lambda value: value["pack"].__setitem__("bytes", 1),
    lambda value: value.__setitem__("table", []),
    lambda value: value["table"][0].__setitem__(0, True),
    lambda value: value["pack"].__setitem__("extra", 1),
))
def test_pack_decoder_rejects_corrupt_or_overlapping_tables(mutation):
    _secret, device, root, raws = signed_piles()
    _bundle, locator, _body = pack_signed_piles(root.fid, device, 1, raws)
    value = json.loads(encode_bundle_pack(locator))
    mutation(value)

    with pytest.raises(InvalidWriterBundle):
        decode_bundle_pack(canon(value))


def test_locator_binding_range_hash_signature_and_complete_pack_are_checked():
    _secret, device, root, raws = signed_piles()
    bundle, locator, body = pack_signed_piles(root.fid, device, 1, raws)

    foreign = replace(locator, bundle_oid=h(b"another bundle"))
    with pytest.raises(InvalidWriterBundle, match="pack binding"):
        verify_pile_slice(bundle, foreign, 1, raws[0])
    missing_row = replace(locator, slices=locator.slices[:1])
    with pytest.raises(InvalidWriterBundle, match="pack binding"):
        verify_pile_slice(bundle, missing_row, 1, raws[0])
    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        verify_pile_slice(bundle, locator, 1, raws[0][:-1])
    flipped = bytes([raws[0][0] ^ 1]) + raws[0][1:]
    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        verify_pile_slice(bundle, locator, 1, flipped)
    with pytest.raises(InvalidWriterBundle, match="publication"):
        verify_pile_slice(bundle, locator, 0, raws[0])

    corrupt_body = bytearray(body)
    corrupt_body[0] ^= 1
    with pytest.raises(InvalidWriterBundle, match="pack integrity"):
        extract_pile_bytes(bundle, locator, bytes(corrupt_body), 1)

    first = locator.slices[0]
    shifted = replace(locator, slices=(
        PackSlice(0, first.length + 1),
        PackSlice(first.length + 1, locator.slices[1].length - 1),
    ))
    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        extract_pile_bytes(bundle, shifted, body, 1)


def test_a_hash_matching_range_still_needs_a_valid_signed_pile():
    _secret, device, root, raws = signed_piles()
    value = json.loads(raws[0])
    value["signature"] = "0" * 128
    forged = canon(value)
    bundle = make_bundle(root.fid, device, 1, (h(forged),))
    locator = BundlePack(
        bundle_oid(bundle), h(forged), len(forged),
        (PackSlice(0, len(forged)),))

    with pytest.raises(InvalidWriterBundle, match="pile integrity"):
        verify_pile_slice(bundle, locator, 1, forged)


def test_sealing_rejects_foreign_writer_wrong_order_and_oid_corruption():
    _secret, device, root, raws = signed_piles()
    bundle = make_bundle(root.fid, device, 1, map(h, raws))
    other_secret, other_device = keypair()
    foreign = encode_signed_pile(make_signed_pile(
        other_secret,
        root.fid,
        other_device,
        ClosedPileEvaluator(root.fid).evaluate(raws[0]).pile.facts,
    ))
    with pytest.raises(InvalidWriterBundle, match="pile binding"):
        pack_bundle(make_bundle(root.fid, device, 1, (h(foreign),)), (foreign,))
    with pytest.raises(InvalidWriterBundle, match="pile binding"):
        pack_bundle(bundle, tuple(reversed(raws)))

    locator, _body = pack_bundle(bundle, raws)
    logical = encode_bundle(bundle)
    physical = encode_bundle_pack(locator)
    with pytest.raises(InvalidWriterBundle):
        decode_bundle(logical, expected_oid=h(b"wrong logical object"))
    with pytest.raises(InvalidWriterBundle):
        decode_bundle_pack(
            physical, expected_oid=h(b"wrong locator object"))


def test_exact_and_one_over_logical_and_pack_table_count_bounds():
    exact = synthetic_bundle(MAX_BUNDLE_PILES)
    logical = encode_bundle(exact)
    locator = synthetic_pack(exact)
    physical = encode_bundle_pack(locator)

    assert len(logical) <= MAX_BUNDLE_DESCRIPTOR_BYTES
    assert len(physical) <= MAX_BUNDLE_PACK_TABLE_BYTES
    assert decode_bundle(logical) == exact
    assert decode_bundle_pack(physical) == locator

    with pytest.raises(PayloadTooLarge, match="too many piles"):
        make_bundle(
            exact.workspace, exact.device, 1,
            (h(index.to_bytes(8, "big"))
             for index in range(MAX_BUNDLE_PILES + 1)))
    with pytest.raises(ValueError, match="writer bundle pack"):
        BundlePack(
            bundle_oid(exact), h(b"larger pack"),
            MAX_BUNDLE_PILES + 1,
            locator.slices + (PackSlice(MAX_BUNDLE_PILES, 1),),
        )


def test_exact_and_one_over_pack_range_and_codec_byte_bounds():
    exact = synthetic_bundle()
    locator = synthetic_pack(exact, pack_bytes=MAX_BUNDLE_PACK_BYTES)
    assert decode_bundle_pack(encode_bundle_pack(locator)) == locator

    with pytest.raises(ValueError, match="writer bundle pack"):
        replace(locator, pack_bytes=MAX_BUNDLE_PACK_BYTES + 1)
    with pytest.raises(ValueError, match="slice"):
        PackSlice(0, MAX_BUNDLE_PACK_BYTES + 1)

    final = synthetic_bundle(first=MAX_WRITER_SEQUENCE)
    assert final.last == MAX_WRITER_SEQUENCE
    with pytest.raises(InvalidWriterBundle, match="descriptor"):
        make_bundle(
            final.workspace, final.device, MAX_WRITER_SEQUENCE,
            (h(b"a"), h(b"b")))

    with pytest.raises(InvalidWriterBundle):
        decode_bundle(b" " * MAX_BUNDLE_DESCRIPTOR_BYTES)
    with pytest.raises(PayloadTooLarge):
        decode_bundle(b" " * (MAX_BUNDLE_DESCRIPTOR_BYTES + 1))
    with pytest.raises(InvalidWriterBundle):
        decode_bundle_pack(b" " * MAX_BUNDLE_PACK_TABLE_BYTES)
    with pytest.raises(PayloadTooLarge):
        decode_bundle_pack(b" " * (MAX_BUNDLE_PACK_TABLE_BYTES + 1))
