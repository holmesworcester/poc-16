"""Source-local pack pages locate, but never authorize, writer history."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json

import pytest

from core.close import (
    ClosedPileEvaluator,
    KernelRejected,
    encode_signed_pile,
    make_signed_pile,
)
from core.crypto import h, keypair
from core.fact import canon
from core.limits import MAX_SEMANTIC_PILE_BYTES, PayloadTooLarge
from core.object_store import OutcomeUnknown
from core.store import FsStore
from core.writer_layout import (
    MAX_LAYOUT_PACK_BYTES,
    MAX_LAYOUT_PAGE_BYTES,
    WINDOW_PILES,
    InvalidWriterLayout,
    LayoutPage,
    PackPlacement,
    add_placements,
    build_pack,
    decode_layout_page,
    decode_layout_page_at,
    encode_layout_page,
    layout_page_key,
    parse_layout_page_key,
    placement_for,
    publish_placements,
    verify_pile_slice,
    verify_whole_pack,
    window_end,
    window_start,
)
from core.writer_tree import MAX_WRITER_SEQUENCE
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact
from tests.shared_bucket import ScriptedBucket


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


def fake_pack(first, count, tag=b"pack"):
    lengths = tuple(1 for _ in range(count))
    return PackPlacement(first, h(tag), count, lengths)


def test_window_arithmetic_and_keys_are_direct_and_canonical():
    workspace, device = h(b"workspace"), h(b"device")
    assert window_start(1) == window_start(WINDOW_PILES) == 1
    assert window_end(1) == WINDOW_PILES
    assert window_start(WINDOW_PILES + 1) == WINDOW_PILES + 1
    assert window_end(WINDOW_PILES + 1) == 2 * WINDOW_PILES
    final = window_start(MAX_WRITER_SEQUENCE)
    assert window_end(final) == MAX_WRITER_SEQUENCE

    key = layout_page_key(workspace, device, WINDOW_PILES + 1)
    assert parse_layout_page_key(key) == (
        workspace, device, WINDOW_PILES + 1)
    assert key.endswith("0000000000016385")

    for invalid in (
            f"layouts/{workspace}/{device}/16385",
            f"layouts/{workspace}/{device}/0000000000016384",
            f"layout/{workspace}/{device}/0000000000016385"):
        with pytest.raises(InvalidWriterLayout):
            parse_layout_page_key(invalid)
    with pytest.raises(ValueError):
        window_start(0)
    with pytest.raises(ValueError):
        layout_page_key(workspace, device, 2)


def test_page_round_trip_has_only_derived_ranges_and_allows_holes():
    workspace, device = h(b"workspace"), h(b"device")
    first = PackPlacement(2, h(b"first"), 5, (2, 3))
    second = PackPlacement(9, h(b"second"), 4, (4,))
    page = LayoutPage(workspace, device, 1, (first, second))
    raw = encode_layout_page(page)

    assert first.last == 3
    assert first.byte_range(2) == (0, 2)
    assert first.byte_range(3) == (2, 3)
    assert placement_for(page, 1) is None
    assert placement_for(page, 2) == first
    assert placement_for(page, 8) is None
    assert placement_for(page, 9) == second
    assert decode_layout_page(raw) == page
    assert decode_layout_page_at(
        layout_page_key(workspace, device, 1), raw) == page

    document = json.loads(raw)
    assert document["packs"] == [
        [2, first.pack_oid, 5, [2, 3]],
        [9, second.pack_oid, 4, [4]],
    ]
    assert not ({"last", "offsets", "piles", "signature", "generation",
                 "predecessor", "root", "timestamp"} & set(document))

    empty = LayoutPage(workspace, device, 1, ())
    assert decode_layout_page(encode_layout_page(empty)) == empty
    assert placement_for(empty, 1) is None


def test_layout_rejects_a_physical_pack_claiming_an_oversize_pile_slice():
    workspace, device = h(b"workspace"), h(b"device")
    raw = canon({
        "device": device,
        "format": "poc16-writer-layout-page-v1",
        "packs": [[
            1,
            h(b"hostile physical pack"),
            MAX_SEMANTIC_PILE_BYTES + 1,
            [MAX_SEMANTIC_PILE_BYTES + 1],
        ]],
        "start": 1,
        "workspace": workspace,
    })

    with pytest.raises(InvalidWriterLayout, match="layout encoding"):
        decode_layout_page(raw)


def test_real_signed_piles_build_verify_whole_and_verify_sparse_ranges():
    _secret, device, root, raws = signed_piles()
    placement, body = build_pack(root.fid, device, 10, raws)
    expected = tuple(map(h, raws))

    assert body == b"".join(raws)
    assert placement.first == 10
    assert placement.last == 11
    assert placement.pack_bytes == sum(map(len, raws))
    assert placement.lengths == tuple(map(len, raws))
    assert verify_whole_pack(
        placement, body, expected, root.fid, device) == raws

    offset, length = placement.byte_range(11)
    ranged = body[offset:offset + length]
    assert verify_pile_slice(
        placement, 11, ranged, expected[1], root.fid, device) == raws[1]


def test_pack_and_sparse_verification_reject_every_corrupt_binding():
    _secret, device, root, raws = signed_piles()
    placement, body = build_pack(root.fid, device, 1, raws)
    expected = tuple(map(h, raws))

    corrupt = bytearray(body)
    corrupt[0] ^= 1
    with pytest.raises(InvalidWriterLayout, match="pack integrity"):
        verify_whole_pack(
            placement, bytes(corrupt), expected, root.fid, device)
    with pytest.raises(InvalidWriterLayout, match="slice integrity"):
        verify_whole_pack(
            placement, body, tuple(reversed(expected)), root.fid, device)
    with pytest.raises(InvalidWriterLayout, match="pack integrity"):
        verify_whole_pack(
            placement, body, expected[:1], root.fid, device)

    first = placement.lengths[0]
    shifted = PackPlacement(
        1, placement.pack_oid, placement.pack_bytes,
        (first + 1, placement.lengths[1] - 1))
    with pytest.raises(InvalidWriterLayout, match="slice integrity"):
        verify_whole_pack(
            shifted, body, expected, root.fid, device)

    with pytest.raises(InvalidWriterLayout, match="slice integrity"):
        verify_pile_slice(
            placement, 1, raws[0][:-1], expected[0], root.fid, device)
    with pytest.raises(InvalidWriterLayout, match="slice integrity"):
        verify_pile_slice(
            placement, 1, raws[0], h(b"wrong pile"), root.fid, device)
    with pytest.raises(InvalidWriterLayout, match="pack sequence"):
        verify_pile_slice(
            placement, 0, raws[0], expected[0], root.fid, device)


def test_matching_hash_still_requires_the_signed_workspace_and_device():
    _secret, device, root, raws = signed_piles()
    value = json.loads(raws[0])
    value["signature"] = "0" * 128
    forged = canon(value)
    placement = PackPlacement(1, h(forged), len(forged), (len(forged),))

    with pytest.raises(InvalidWriterLayout, match="slice integrity"):
        verify_pile_slice(
            placement, 1, forged, h(forged), root.fid, device)

    other_secret, other_device = keypair()
    foreign = encode_signed_pile(make_signed_pile(
        other_secret,
        root.fid,
        other_device,
        ClosedPileEvaluator(root.fid).evaluate(raws[0]).pile.facts,
    ))
    with pytest.raises(InvalidWriterLayout, match="pile binding"):
        build_pack(root.fid, device, 1, (foreign,))


def test_layout_verifies_portable_bytes_but_does_not_claim_semantic_closure():
    secret, device, root, _raws = signed_piles()
    dangling = message_fact(
        root.fid, device, "general", "missing member authority", 9)
    raw = encode_signed_pile(make_signed_pile(
        secret, root.fid, device, (dangling,)))
    placement, body = build_pack(root.fid, device, 1, (raw,))

    assert verify_whole_pack(
        placement, body, (h(raw),), root.fid, device) == (raw,)
    with pytest.raises(KernelRejected, match="closed pile rejected"):
        ClosedPileEvaluator(root.fid).evaluate(raw, writer=device)


@pytest.mark.parametrize("mutation", (
    lambda value: value["packs"][0].__setitem__(2, 2),
    lambda value: value["packs"][1].__setitem__(0, 1),
    lambda value: value["packs"][0][3].__setitem__(0, True),
    lambda value: value["packs"][0].append("extra"),
    lambda value: value.__setitem__("extra", 1),
))
def test_page_decoder_rejects_length_overlap_and_shape_corruption(mutation):
    workspace, device = h(b"workspace"), h(b"device")
    page = LayoutPage(
        workspace, device, 1,
        (fake_pack(1, 1, b"one"), fake_pack(3, 1, b"three")))
    value = json.loads(encode_layout_page(page))
    mutation(value)

    with pytest.raises(InvalidWriterLayout):
        decode_layout_page(canon(value))


def test_add_rebase_fills_only_holes_and_is_idempotent():
    workspace, device = h(b"workspace"), h(b"device")
    first = fake_pack(1, 2, b"first")
    later = fake_pack(5, 2, b"later")
    base = LayoutPage(workspace, device, 1, (first,))

    updated = add_placements(base, (later,))
    assert base.placements == (first,)
    assert updated.placements == (first, later)
    assert add_placements(updated, (later,)) is not updated
    assert add_placements(updated, (later,)) == updated
    assert placement_for(updated, 3) is None

    racing = fake_pack(3, 2, b"racing")
    assert add_placements(updated, (racing,)).placements == (
        first, racing, later)

    conflict = fake_pack(2, 2, b"conflict")
    with pytest.raises(InvalidWriterLayout, match="overlap"):
        add_placements(updated, (conflict,))
    same_interval_other_body = fake_pack(1, 2, b"other body")
    with pytest.raises(InvalidWriterLayout, match="overlap"):
        add_placements(updated, (same_interval_other_body,))
    with pytest.raises(InvalidWriterLayout, match="overlap"):
        add_placements(base, (
            fake_pack(5, 2, b"a"), fake_pack(6, 2, b"b")))
    with pytest.raises(InvalidWriterLayout, match="overlap"):
        add_placements(
            updated, (fake_pack(WINDOW_PILES + 1, 1, b"foreign"),))


def test_concurrent_layout_publishers_rebase_disjoint_holes_without_clobber():
    workspace, device = h(b"workspace"), h(b"device")
    key = layout_page_key(workspace, device, 1)
    bucket = ScriptedBucket()
    alice, bob = bucket.handle("alice"), bucket.handle("bob")
    paused = bucket.pause("alice", "cas", key, when="before")
    first, later = fake_pack(1, 2, b"first"), fake_pack(5, 2, b"later")

    def publish(store, placement):
        return asyncio.run(publish_placements(
            store, workspace, device, 1, (placement,)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        delayed = pool.submit(publish, alice, first)
        paused.wait()
        winner = pool.submit(publish, bob, later)
        assert winner.result().placements == (later,)
        paused.release.set()
        assert delayed.result().placements == (first, later)

    page = decode_layout_page_at(key, alice.get(key))
    assert page.placements == (first, later)
    assert bucket.assert_valid_history()

    before = alice.get(key)
    with pytest.raises(InvalidWriterLayout, match="overlap"):
        publish(alice, fake_pack(2, 2, b"conflict"))
    assert alice.get(key) == before


def test_unknown_layout_cas_outcome_is_resolved_by_exact_reread(tmp_path):
    workspace, device = h(b"workspace"), h(b"device")
    store = FsStore(str(tmp_path / "store"))
    placement = fake_pack(1, 2, b"pack")

    class UnknownAfterCommit:
        def __init__(self):
            self.raised = False

        def get_bounded(self, key, maximum):
            return store.get_bounded(key, maximum)

        def read_versioned(self, key):
            return store.read_versioned(key)

        def cas(self, key, token, raw):
            result = store.cas(key, token, raw)
            if not self.raised:
                self.raised = True
                raise OutcomeUnknown("lost successful response")
            return result

    published = asyncio.run(publish_placements(
        UnknownAfterCommit(), workspace, device, 1, (placement,)))
    assert published.placements == (placement,)
    assert decode_layout_page_at(
        layout_page_key(workspace, device, 1),
        store.get(layout_page_key(workspace, device, 1)),
    ) == published


def test_pack_build_never_crosses_a_window_boundary():
    _secret, device, root, raws = signed_piles()
    final = window_end(1)
    placement, _body = build_pack(root.fid, device, final, raws[:1])
    assert placement.first == placement.last == final

    with pytest.raises(InvalidWriterLayout, match="crosses"):
        build_pack(root.fid, device, final, raws)
    crossing = fake_pack(final, 2, b"crossing")
    with pytest.raises(ValueError, match="overlap"):
        LayoutPage(root.fid, device, 1, (crossing,))


def test_exact_and_one_over_portable_pack_bounds():
    full, remainder = divmod(
        MAX_LAYOUT_PACK_BYTES, MAX_SEMANTIC_PILE_BYTES)
    lengths = (MAX_SEMANTIC_PILE_BYTES,) * full + (
        (remainder,) if remainder else ())
    exact = PackPlacement(
        1, h(b"exact pack"), MAX_LAYOUT_PACK_BYTES, lengths)
    assert exact.byte_range(exact.last) == (
        MAX_LAYOUT_PACK_BYTES - lengths[-1], lengths[-1])

    with pytest.raises(ValueError, match="placement"):
        replace(exact, pack_bytes=MAX_LAYOUT_PACK_BYTES + 1)
    with pytest.raises(ValueError, match="placement"):
        replace(exact, lengths=(MAX_SEMANTIC_PILE_BYTES + 1,))
    with pytest.raises(ValueError, match="placement"):
        replace(exact, lengths=(0,))


def test_exact_window_worst_case_fits_and_one_more_cannot_enter_page():
    # The previous full window keeps every sequence at maximum decimal width.
    start = window_start(MAX_WRITER_SEQUENCE) - WINDOW_PILES
    placements = tuple(
        PackPlacement(
            sequence,
            h(sequence.to_bytes(8, "big")),
            MAX_SEMANTIC_PILE_BYTES,
            (MAX_SEMANTIC_PILE_BYTES,),
        )
        for sequence in range(start, start + WINDOW_PILES)
    )
    page = LayoutPage(h(b"workspace"), h(b"device"), start, placements)
    raw = encode_layout_page(page)

    # Exact measured worst-shape ratchet for the compact v1 JSON codec.
    assert len(raw) == 1_736_934 < MAX_LAYOUT_PAGE_BYTES
    assert decode_layout_page(raw) == page
    with pytest.raises(ValueError, match="writer layout page"):
        LayoutPage(
            page.workspace,
            page.device,
            start,
            placements + (fake_pack(start + WINDOW_PILES, 1, b"over"),),
        )

    with pytest.raises(InvalidWriterLayout):
        decode_layout_page(b" " * MAX_LAYOUT_PAGE_BYTES)
    with pytest.raises(PayloadTooLarge):
        decode_layout_page(b" " * (MAX_LAYOUT_PAGE_BYTES + 1))


def test_pack_builder_bounds_an_untrusted_pile_iterator_before_work():
    _secret, device, root, raws = signed_piles()
    with pytest.raises(PayloadTooLarge, match="too many piles"):
        build_pack(
            root.fid,
            device,
            1,
            (raws[0] for _ in range(WINDOW_PILES + 1)),
        )
