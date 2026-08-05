"""Canonical signed-pile, writer-head, and per-device tree contract."""
import json
import tracemalloc

import pytest

from core.close import (
    ClosedPileEvaluator,
    InvalidPile,
    KernelRejected,
    SIGNED_PILE_FORMAT,
    SIGNED_PILE_SIGNATURE_DOMAIN,
    check_pile_bounds,
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from core.crypto import h, keypair, sign
from core.fact import Fact, canon
from core.limits import (
    MAX_DIRECT_OBJECT_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PILE_FACTS,
    MAX_PILE_JSON_VALUES,
    MAX_SEMANTIC_PILE_BYTES,
    MAX_WRITER_PACK_BYTES,
    MIN_HOSTED_MEMORY_BYTES,
    PayloadTooLarge,
    evaluator_peak_bound,
    evaluator_pile_byte_bound,
)
from core.writer_head import (
    HeadSlot,
    InvalidWriterHead,
    WriterBinding,
    decode_head,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    make_head,
    require_bound_head,
    validate_advance,
)
from core.writer_tree import (
    EMPTY_TREE,
    append_piles,
    build_tree,
    leaf_row,
    validate_extension,
)
from facts.auth.workspace import workspace as workspace_fact
from facts.auth.signature import signature as signature_fact
from facts.content.message import message as message_fact


def emit_into(objects):
    def emit(raw):
        oid = h(raw)
        objects.setdefault(oid, raw)
        return oid
    return emit


def signed_workspace_pile(name="alice"):
    secret, public = keypair()
    root = workspace_fact(secret, public, name, 1)
    pile = make_signed_pile(
        secret, root.fid, public, (root,))
    return secret, public, root, pile, encode_signed_pile(pile)


def canonical_padding_pile(target_bytes, secret, public, workspace):
    """Build an exact-size canonical pile without a protocol-sized fixture."""
    def encoded(padding):
        fact = Fact(
            "test_padding", 1, [], {"padding": "x" * padding}, workspace)
        return encode_signed_pile(make_signed_pile(
            secret, workspace, public, (fact,)))

    base = encoded(0)
    if target_bytes < len(base):
        raise ValueError("padding pile target")
    raw = encoded(target_bytes - len(base))
    assert len(raw) == target_bytes
    return raw


def test_signed_pile_is_the_same_canonical_push_and_pull_value():
    _secret, public, root, pile, raw = signed_workspace_pile()

    assert decode_signed_pile(
        raw, workspace=root.fid, writer=public) == pile
    evaluated = ClosedPileEvaluator(root.fid).evaluate(raw, writer=public)
    assert evaluated.pile == pile
    assert tuple(valid.fact.fid for valid in evaluated.judgment.valids) == (
        root.fid,)
    assert signed_pile_oid(raw) == h(raw)


def test_semantic_pile_ceiling_is_the_exact_hosted_memory_bound():
    assert MAX_SEMANTIC_PILE_BYTES == evaluator_pile_byte_bound(
        MIN_HOSTED_MEMORY_BYTES,
        MAX_PILE_JSON_VALUES,
        MAX_PILE_FACTS,
    )
    assert evaluator_peak_bound(
        MAX_SEMANTIC_PILE_BYTES,
        MAX_PILE_JSON_VALUES,
        MAX_PILE_FACTS,
    ) <= MIN_HOSTED_MEMORY_BYTES
    assert evaluator_peak_bound(
        MAX_SEMANTIC_PILE_BYTES + 1,
        MAX_PILE_JSON_VALUES,
        MAX_PILE_FACTS,
    ) > MIN_HOSTED_MEMORY_BYTES
    assert MAX_OBJECT_BYTES < MAX_SEMANTIC_PILE_BYTES \
        < MAX_DIRECT_OBJECT_BYTES == MAX_WRITER_PACK_BYTES


def test_canonical_pile_exact_bound_reaches_semantics_and_one_over_does_not(
        monkeypatch):
    from core import close as close_module

    secret, public = keypair()
    workspace = h(b"bounded canonical pile")
    target = 4 * 1024
    exact = canonical_padding_pile(target, secret, public, workspace)
    one_over = canonical_padding_pile(
        target + 1, secret, public, workspace)
    monkeypatch.setattr(
        close_module, "MAX_SEMANTIC_PILE_BYTES", target)
    evaluator = ClosedPileEvaluator(workspace, max_bytes=target)

    # The synthetic family is intentionally unknown: reaching kernel judgment
    # proves exact-bound canonical bytes passed every byte/codec check.
    with pytest.raises(KernelRejected, match="closed pile rejected"):
        evaluator.evaluate(exact, writer=public)
    with pytest.raises(InvalidPile, match="pile too large"):
        evaluator.evaluate(one_over, writer=public)


def test_pile_scanner_enforces_exact_fact_count_under_hostile_json_shapes():
    exact = b'{"decoy":"\\\"facts\\\":[0,0]","facts":[' \
        + b'0,' * (MAX_PILE_FACTS - 1) + b'0]}'
    check_pile_bounds(exact)

    one_over = b'{"decoy":[{"facts":[]}],"facts":[' \
        + b'0,' * MAX_PILE_FACTS + b'0]}'
    with pytest.raises(PayloadTooLarge, match="too many facts"):
        check_pile_bounds(one_over)

    # A noncanonical escaped root key must not bypass the pre-decode count.
    escaped_key = b'{"fa\\u0063ts":[' \
        + b'0,' * MAX_PILE_FACTS + b'0]}'
    with pytest.raises(PayloadTooLarge, match="too many facts"):
        check_pile_bounds(escaped_key)


def test_pile_scanner_bounds_nesting_and_json_values_before_decode(
        monkeypatch):
    from core import close as close_module

    decoded = False

    def forbidden_decode(*_args, **_kwargs):
        nonlocal decoded
        decoded = True
        raise AssertionError("untrusted graph was decoded")

    monkeypatch.setattr(close_module, "decode_json", forbidden_decode)
    hostile = b'[' * (MAX_PILE_JSON_VALUES + 1)
    with pytest.raises(PayloadTooLarge, match="too many JSON values"):
        check_pile_bounds(hostile)
    assert not decoded


def test_pile_scanner_streaming_memory_is_bounded_for_deep_input():
    depth = MAX_PILE_JSON_VALUES - 4
    hostile = b'{"facts":[' + b'[' * depth + b'0' \
        + b']' * depth + b']}'

    tracemalloc.start()
    try:
        check_pile_bounds(hostile)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The scanner retains only its bounded delimiter stack, never a decoded
    # object graph. This ceiling is deliberately far above the ~110 KiB
    # observed stack so ordinary allocator variation cannot make it flaky.
    assert peak < 2 * 1024 * 1024


def test_unsigned_predecessor_pile_has_no_decode_path():
    _secret, _public, root, _pile, _raw = signed_workspace_pile()
    predecessor = canon({
        "facts": [root.to_json()],
        "ws": root.fid,
    })

    with pytest.raises(InvalidPile, match="signed pile shape"):
        ClosedPileEvaluator(root.fid).evaluate(predecessor)


@pytest.mark.parametrize("change", ("signature", "writer", "workspace"))
def test_signed_pile_rejects_forged_outer_bindings(change):
    _secret, _public, _root, _pile, raw = signed_workspace_pile()
    value = json.loads(raw)
    value[change] = "0" * len(value[change])

    with pytest.raises(InvalidPile):
        decode_signed_pile(canon(value))


def test_signed_pile_rejects_noncanonical_and_nonclosed_content():
    secret, public, root, _pile, raw = signed_workspace_pile()
    with pytest.raises(InvalidPile):
        decode_signed_pile(raw + b" ")

    # The outer signature can authenticate publication but cannot make a fact
    # whose semantic dependencies are absent into a valid closure.
    dangling = message_fact(
        root.fid, public, "general", "missing authority", 2)
    nonclosed = encode_signed_pile(make_signed_pile(
        secret, root.fid, public, (dangling,)))
    with pytest.raises(KernelRejected, match="closed pile rejected"):
        ClosedPileEvaluator(root.fid).evaluate(nonclosed)


def test_signed_pile_rejects_duplicate_facts_even_when_outer_signature_valid():
    secret, public, root, _pile, _raw = signed_workspace_pile()
    document = {
        "facts": [root.to_json(), root.to_json()],
        "format": SIGNED_PILE_FORMAT,
        "workspace": root.fid,
        "writer": public,
    }
    raw = canon({
        **document,
        "signature": sign(secret, h(canon([
            SIGNED_PILE_SIGNATURE_DOMAIN,
            document,
        ]))),
    })

    with pytest.raises(InvalidPile, match="signed pile"):
        decode_signed_pile(raw)


def test_writer_head_and_slot_round_trip_without_predecessor_chain():
    secret, public, root, pile, _raw = signed_workspace_pile()
    objects = {}
    tree = append_piles(
        EMPTY_TREE,
        root.fid,
        public,
        (signed_pile_oid(pile),),
        objects.get,
        emit_into(objects),
    )
    store = h(b"registered-store")
    head = make_head(
        secret, root.fid, public, public, tree.count, tree, store)
    raw = encode_head(head)

    assert decode_head(raw) == head
    assert b"previous" not in raw
    binding = WriterBinding(root.fid, public, public, store)
    assert require_bound_head(head, binding) == head

    slot = HeadSlot(
        root.fid, public, head_oid(head), h(b"removal-root"))
    key = head_slot_key(root.fid, public)
    raw_slot = encode_slot(slot)
    assert b'"removal_root"' in raw_slot
    assert b'"authority_root"' not in raw_slot
    assert decode_slot_at(key, raw_slot) == slot


def test_head_and_tree_advance_compare_directly_to_last_accepted_root():
    secret, public, root, first_pile, _raw = signed_workspace_pile()
    objects = {}
    emit = emit_into(objects)
    first = append_piles(
        EMPTY_TREE, root.fid, public,
        (signed_pile_oid(first_pile),), objects.get, emit)
    second_fact = signature_fact(secret, public, root, 2)
    second_pile = make_signed_pile(
        secret, root.fid, public, (root, second_fact))
    second_oid = signed_pile_oid(second_pile)
    second = append_piles(
        first, root.fid, public, (second_oid,), objects.get, emit)
    store = h(b"store")
    binding = WriterBinding(root.fid, public, public, store)
    first_head = make_head(
        secret, root.fid, public, public, first.count, first, store)
    second_head = make_head(
        secret, root.fid, public, public, second.count, second, store)

    assert validate_advance(first_head, second_head, binding) == 1
    assert validate_extension(
        first, second, root.fid, public, objects.get) == (
            leaf_row(2, second_oid),)
    assert validate_advance(second_head, second_head, binding) == 0

    with pytest.raises(InvalidWriterHead, match="rollback"):
        validate_advance(second_head, first_head, binding)

    rewritten = build_tree(
        root.fid,
        public,
        (
            leaf_row(1, h(b"rewritten")),
            leaf_row(2, second_oid),
        ),
        emit,
    )
    hostile = make_head(
        secret, root.fid, public, public,
        rewritten.count, rewritten, store)
    with pytest.raises(InvalidWriterHead, match="fork"):
        validate_advance(second_head, hostile, binding)
    with pytest.raises(ValueError, match="rewrote accepted row"):
        validate_extension(
            first, rewritten, root.fid, public, objects.get)
