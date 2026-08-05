"""Deterministic hostile-byte and authenticated-address protocol fuzzing."""
import random

import pytest

from core import merkle_map
from core.close import (
    ClosedPileEvaluator,
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
)
from core.crypto import h, load_sk
from core.limits import (
    MAX_SEMANTIC_PILE_BYTES,
    PayloadTooLarge,
    decode_json,
)
from core.pack_access import (
    InvalidPackAccess,
    ObjectOpen,
    PackOpen,
    ScopedRequest,
    confine_scoped_request,
    decode_object_open,
    decode_pack_open,
    decode_scoped_request,
    encode_object_open,
    encode_pack_open,
    encode_scoped_request,
)
from core.writer_head import (
    HeadSlot,
    WriterBinding,
    decode_head,
    decode_slot,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_slot_key,
    make_head,
    parse_head_slot_key,
    require_bound_head,
)
from core.writer_layout import (
    LayoutPage,
    decode_layout_page,
    decode_layout_page_at,
    encode_layout_page,
    layout_page_key,
    parse_layout_page_key,
)
from core.writer_tree import EMPTY_TREE
from facts.auth.workspace import workspace as workspace_fact


FUZZ_SEEDS = (
    0x00000000,
    0x00000001,
    0x00C0FFEE,
    0x5EEDFACE,
    0xFFFFFFFF,
)


def _mutants(raw, seed, maximum=64):
    """Replay a bounded set of truncation, extension, and bit-flip cases."""
    rng = random.Random(seed)
    positions = {0, len(raw) // 2, len(raw) - 1}
    if len(raw) > len(positions):
        positions.update(rng.sample(
            range(len(raw)), min(maximum, len(raw))))
    cases = [b"", raw + b" ", raw + b"\x00", b"\xff" + raw]
    cases.extend(raw[:at] for at in sorted(positions))
    for at in sorted(positions):
        changed = bytearray(raw)
        changed[at] ^= 1 << rng.randrange(8)
        cases.append(bytes(changed))
    return tuple(dict.fromkeys(cases))


def _assert_total_canonical_codec(label, raw, decode, encode, seed):
    value = decode(raw)
    assert encode(value) == raw, f"{label} rejected its canonical sample"
    for ordinal, mutant in enumerate(_mutants(raw, seed)):
        try:
            value = decode(mutant)
        except ValueError:
            continue
        assert encode(value) == mutant, (
            f"{label} accepted noncanonical bytes: "
            f"seed={seed:#x} case={ordinal} raw={mutant!r}"
        )


@pytest.mark.parametrize("seed", FUZZ_SEEDS)
def test_seeded_authenticated_wire_codecs_are_total_and_canonical(seed):
    secret = load_sk(f"{seed:064x}")
    device = secret.verify_key.encode().hex()
    root = workspace_fact(secret, device, "alice", 1)
    workspace = root.fid
    store = h(b"protocol-fuzz-store")

    pile_raw = encode_signed_pile(make_signed_pile(
        secret, workspace, device, (root,)))
    head = make_head(
        secret, workspace, device, device, 0, EMPTY_TREE, store)
    head_raw = encode_head(head)
    slot_raw = encode_slot(HeadSlot(
        workspace, device, h(head_raw), h(b"removal-root")))
    layout_raw = encode_layout_page(LayoutPage(
        workspace, device, 1, ()))
    oid = h(b"direct object")
    object_raw = encode_object_open(ObjectOpen("GET", oid, 4096))
    pack_raw = encode_pack_open(PackOpen("GET", oid, 4096, 17, 257))
    scoped_raw = encode_scoped_request(ScopedRequest(
        "GET", f"https://objects.invalid/pack/{oid}",
        (("range", "bytes=17-273"),), 50_000))

    codecs = (
        ("pile", pile_raw, decode_signed_pile, encode_signed_pile),
        ("head", head_raw, decode_head, encode_head),
        ("slot", slot_raw,
         lambda raw: decode_slot(raw, workspace=workspace, device=device),
         encode_slot),
        ("layout", layout_raw,
         lambda raw: decode_layout_page(
             raw, workspace=workspace, device=device, expected_start=1),
         encode_layout_page),
        ("object-open", object_raw, decode_object_open, encode_object_open),
        ("pack-open", pack_raw, decode_pack_open, encode_pack_open),
        ("scoped-request", scoped_raw,
         decode_scoped_request, encode_scoped_request),
    )
    for label, raw, decode, encode in codecs:
        _assert_total_canonical_codec(label, raw, decode, encode, seed)

    binding = WriterBinding(workspace, device, device, store)
    for ordinal, mutant in enumerate(_mutants(head_raw, seed)):
        try:
            decoded = decode_head(mutant)
        except ValueError:
            continue
        with pytest.raises(ValueError):
            require_bound_head(decoded, binding)
        assert mutant != head_raw, f"seed={seed:#x} case={ordinal}"

    evaluated = ClosedPileEvaluator(workspace).evaluate(
        pile_raw, writer=device)
    assert evaluated.pile.facts == (root,)
    with pytest.raises(ValueError):
        decode_signed_pile(pile_raw, workspace=h(b"foreign pile workspace"))
    with pytest.raises(ValueError):
        decode_signed_pile(pile_raw, writer=h(b"foreign pile writer"))


@pytest.mark.parametrize("seed", FUZZ_SEEDS)
def test_seeded_addresses_never_cross_workspace_or_writer_bindings(seed):
    workspace = h(b"address workspace")
    writer = h(b"address writer")
    foreign_workspace = h(b"foreign workspace")
    foreign_writer = h(b"foreign writer")
    slot = HeadSlot(
        workspace, writer, h(b"head"), h(b"removal"))
    slot_raw = encode_slot(slot)
    layout = LayoutPage(workspace, writer, 1, ())
    layout_raw = encode_layout_page(layout)
    keys = (
        (head_slot_key(workspace, writer), parse_head_slot_key,
         lambda value: head_slot_key(*value)),
        (layout_page_key(workspace, writer, 1), parse_layout_page_key,
         lambda value: layout_page_key(*value)),
    )

    for label, (key, parse, rebuild) in enumerate(keys):
        for ordinal, mutant in enumerate(_mutants(key.encode(), seed)):
            try:
                text = mutant.decode("ascii")
                parsed = parse(text)
            except (UnicodeError, ValueError):
                continue
            assert rebuild(parsed) == text, (
                f"address accepted alias: seed={seed:#x} "
                f"surface={label} case={ordinal}"
            )

    with pytest.raises(ValueError):
        decode_slot_at(
            head_slot_key(foreign_workspace, writer), slot_raw)
    with pytest.raises(ValueError):
        decode_slot_at(
            head_slot_key(workspace, foreign_writer), slot_raw)
    with pytest.raises(ValueError):
        decode_layout_page_at(
            layout_page_key(foreign_workspace, writer, 1), layout_raw)
    with pytest.raises(ValueError):
        decode_layout_page_at(
            layout_page_key(workspace, foreign_writer, 1), layout_raw)

    opened = PackOpen("GET", h(b"pack"), 4096, 17, 257)
    accepted = ScopedRequest(
        "GET", f"https://objects.invalid/pack/{opened.oid}",
        (("range", "bytes=17-273"),), 50_000)
    assert confine_scoped_request(opened, accepted, 49_000) == accepted
    foreign = ScopedRequest(
        "GET", f"https://objects.invalid/pack/{h(b'foreign pack')}",
        accepted.headers, accepted.expires_at_ms)
    with pytest.raises(InvalidPackAccess, match="pack key"):
        confine_scoped_request(opened, foreign, 49_000)


@pytest.mark.parametrize("seed", FUZZ_SEEDS)
def test_seeded_merkle_page_corruption_never_authenticates(seed):
    rows = [(f"key:{number:04d}", {"value": number})
            for number in range(96)]
    random.Random(seed).shuffle(rows)
    objects = {}

    def emit(raw):
        oid = h(raw)
        objects[oid] = raw
        return oid

    built = merkle_map.build(tuple(rows), h(b"fuzz map seed"), emit)
    for ordinal, oid in enumerate(sorted(objects)):
        raw = objects[oid]
        changed = bytearray(raw)
        changed[random.Random(seed ^ ordinal).randrange(len(changed))] ^= 1
        hostile = {**objects, oid: bytes(changed)}
        reader = merkle_map.Reader(
            built.root, h(b"fuzz map seed"), hostile.get,
            max_page_depth=built.page_depth,
            expected_count=built.count,
            expected_depth=built.page_depth)
        with pytest.raises(ValueError):
            reader.items(max_pages=max(1, 2 * built.count - 1))


def test_byte_ceilings_reject_before_json_allocation(monkeypatch):
    from core import limits

    calls = []

    def allocate(*_args, **_kwargs):
        calls.append("loads")
        raise AssertionError("oversized bytes reached JSON allocation")

    monkeypatch.setattr(limits.json, "loads", allocate)
    with pytest.raises(PayloadTooLarge):
        decode_json(b"x" * 65, 64, "fuzz envelope")
    with pytest.raises(ValueError, match="pile too large"):
        decode_signed_pile(b"x" * (MAX_SEMANTIC_PILE_BYTES + 1))
    assert calls == []
