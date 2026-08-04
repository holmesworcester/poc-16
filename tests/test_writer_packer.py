"""The optional packer cannot alter or delay signed writer history."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import core.writer_layout as writer_layout_module
import core.writer_packer as writer_packer_module
from core.close import (
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from core.crypto import h, keypair
from core.limits import MAX_REPOSITORY_OBJECT_BYTES, PayloadTooLarge
from core.object_store import ABSENT, CREATED, EXISTS, OutcomeUnknown
from core.store import FsStore
from core.writer_layout import (
    MAX_LAYOUT_PACK_BYTES,
    WINDOW_PILES,
    InvalidWriterLayout,
    build_pack,
    decode_layout_page_at,
    encode_layout_page,
    layout_page_key,
)
from core.writer_packer import (
    DEFAULT_IDLE_MS,
    DEFAULT_PROMPT_PILES,
    LoosePile,
    PackingPolicy,
    WriterPacker,
)
from core.writer_repository import WriterLog
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from tests.shared_bucket import InjectedCrash, ScriptedBucket


def run(awaitable):
    return asyncio.run(awaitable)


def signed_world(count=4):
    secret, device = keypair()
    root = workspace_fact(secret, device, "alice", 1)
    raws = [encode_signed_pile(make_signed_pile(
        secret, root.fid, device, (root,)))]
    for ordinal in range(1, count):
        evidence = signature_fact(
            secret, device, root, ordinal + 1)
        raws.append(encode_signed_pile(make_signed_pile(
            secret, root.fid, device, (root, evidence))))
    return secret, device, root, tuple(raws)


def loose_rows(raws, first=1):
    return tuple(
        LoosePile(first + index, h(raw))
        for index, raw in enumerate(raws)
    )


def loose_objects(raws):
    return {"obj/" + h(raw): raw for raw in raws}


class PackSink:
    """Local create-only pack data plane with exact collision checking."""

    def __init__(self, store):
        self.store = store
        self.calls = []

    def establish(self, placement, chunks):
        chunks = tuple(chunks)
        body = b"".join(chunks)
        assert h(body) == placement.pack_oid
        assert len(body) == placement.pack_bytes
        key = "pack/" + placement.pack_oid
        result = self.store.put_if_absent(key, body)
        if result is EXISTS and self.store.get(key) != body:
            raise ValueError("pack collision")
        self.calls.append((placement, chunks, result))
        return result


class AsyncPackSink(PackSink):
    """Provider-shaped fake exercising the identical callback contract."""

    async def establish(self, placement, chunks):
        return super().establish(placement, chunks)


def packer_for(
        bucket, actor, root, device, *, policy=PackingPolicy(),
        sink_type=PackSink):
    store = bucket.handle(actor)
    sink = sink_type(store)

    def read_loose(oid):
        return store.get_bounded(
            "obj/" + oid, MAX_REPOSITORY_OBJECT_BYTES)

    return WriterPacker(
        root.fid,
        device,
        store,
        read_loose,
        sink.establish,
        policy=policy,
    ), sink, store


def test_count_byte_idle_and_force_are_local_sealing_policy():
    assert PackingPolicy() == PackingPolicy(
        MAX_LAYOUT_PACK_BYTES, DEFAULT_PROMPT_PILES, DEFAULT_IDLE_MS)

    _secret, device, root, raws = signed_world(3)
    rows = loose_rows(raws)
    bucket = ScriptedBucket(loose_objects(raws))
    packer, sink, store = packer_for(
        bucket, "count", root, device,
        policy=PackingPolicy(prompt_piles=2, idle_ms=1_000))

    assert run(packer.pack(
        rows[:1], now_ms=999, last_append_ms=500)) is None
    assert sink.calls == []
    assert store.get(layout_page_key(root.fid, device, 1)) is None

    packed = run(packer.pack(
        rows, now_ms=999, last_append_ms=500))
    assert packed.pile_oids == tuple(row.oid for row in rows[:2])
    assert packed.establishment is CREATED
    assert len(sink.calls) == 1

    # Pack create is the linearized precondition for advertising the page.
    pack_event = next(
        event for event in bucket.history
        if event.op == "put_if_absent" and event.key.startswith("pack/"))
    page_event = next(
        event for event in bucket.history
        if event.op == "cas" and event.key.startswith("layouts/"))
    assert pack_event.seq < page_event.seq

    for trigger in ("bytes", "idle", "force"):
        local = ScriptedBucket(loose_objects(raws[:1]))
        policy = PackingPolicy(
            prompt_bytes=(len(raws[0]) if trigger == "bytes"
                          else MAX_LAYOUT_PACK_BYTES),
            idle_ms=1_000,
        )
        candidate, candidate_sink, _store = packer_for(
            local, trigger, root, device, policy=policy)
        result = run(candidate.pack(
            rows[:1],
            now_ms=2_000,
            last_append_ms=(0 if trigger == "idle" else 1_500),
            force=trigger == "force",
        ))
        assert result is not None
        assert len(candidate_sink.calls) == 1


def test_existing_placements_bound_holes_and_retries_walk_forward():
    _secret, device, root, raws = signed_world(3)
    rows = loose_rows(raws)
    middle, middle_body = build_pack(
        root.fid, device, 2, raws[1:2])
    page_key = layout_page_key(root.fid, device, 1)
    from core.writer_layout import LayoutPage
    initial_page = LayoutPage(root.fid, device, 1, (middle,))
    bucket = ScriptedBucket({
        **loose_objects(raws),
        "pack/" + middle.pack_oid: middle_body,
        page_key: encode_layout_page(initial_page),
    })
    packer, sink, store = packer_for(bucket, "holes", root, device)

    # Sequence one seals without an idle/force signal because the established
    # sequence-two pack closes the hole on its right.
    first = run(packer.pack(
        rows, now_ms=100, last_append_ms=100))
    assert first.placement.first == first.placement.last == 1
    assert first.page.placements == (first.placement, middle)

    # The still-live suffix remains loose until explicitly sealed.
    assert run(packer.pack(
        rows, now_ms=100, last_append_ms=100)) is None
    final = run(packer.pack(
        rows, now_ms=100, last_append_ms=100, force=True))
    assert final.placement.first == final.placement.last == 3
    assert decode_layout_page_at(page_key, store.get(page_key)).placements \
        == (first.placement, middle, final.placement)
    assert len(sink.calls) == 2


def test_failure_before_or_during_pack_establishment_never_writes_layout():
    _secret, device, root, raws = signed_world(1)
    rows = loose_rows(raws)
    page_key = layout_page_key(root.fid, device, 1)
    bucket = ScriptedBucket(loose_objects(raws))
    store = bucket.handle("crash")

    def crash_read(_oid):
        raise InjectedCrash("before pack")

    never = WriterPacker(
        root.fid, device, store, crash_read,
        lambda _placement, _chunks: pytest.fail("pack was reached"))
    with pytest.raises(InjectedCrash, match="before pack"):
        run(never.pack(rows, now_ms=0, force=True))
    assert store.get(page_key) is None
    assert store.get("obj/" + rows[0].oid) == raws[0]

    class UnknownOnce(PackSink):
        def __init__(self, target):
            super().__init__(target)
            self.unknown = True

        def establish(self, placement, chunks):
            result = super().establish(placement, chunks)
            if self.unknown:
                self.unknown = False
                raise OutcomeUnknown("lost create acknowledgement")
            return result

    sink = UnknownOnce(store)
    retrying = WriterPacker(
        root.fid, device, store,
        lambda oid: store.get("obj/" + oid), sink.establish)
    with pytest.raises(OutcomeUnknown):
        run(retrying.pack(rows, now_ms=0, force=True))
    pack_key = "pack/" + sink.calls[0][0].pack_oid
    assert store.get(pack_key) is not None
    assert store.get(page_key) is None
    assert store.get("obj/" + rows[0].oid) == raws[0]

    retried = run(retrying.pack(rows, now_ms=0, force=True))
    assert retried.establishment is EXISTS
    assert sink.calls[0][0] == sink.calls[1][0] == retried.placement
    assert decode_layout_page_at(page_key, store.get(page_key)) \
        == retried.page


@pytest.mark.parametrize("when", ("before", "after"))
def test_crash_on_layout_cas_is_safe_and_idempotent(when):
    _secret, device, root, raws = signed_world(1)
    rows = loose_rows(raws)
    bucket = ScriptedBucket(loose_objects(raws))
    page_key = layout_page_key(root.fid, device, 1)
    bucket.crash("packer", "cas", page_key, when=when)
    packer, sink, store = packer_for(bucket, "packer", root, device)

    with pytest.raises(InjectedCrash):
        run(packer.pack(rows, now_ms=0, force=True))
    assert store.get("obj/" + rows[0].oid) == raws[0]
    assert store.get("pack/" + sink.calls[0][0].pack_oid) \
        == b"".join(sink.calls[0][1])
    assert (store.get(page_key) is not None) is (when == "after")

    retried = run(packer.pack(rows, now_ms=0, force=True))
    if when == "before":
        assert retried is not None
        assert retried.establishment is EXISTS
        assert len(sink.calls) == 2
    else:
        assert retried is None
        assert len(sink.calls) == 1
    assert decode_layout_page_at(page_key, store.get(page_key)).placements
    assert bucket.assert_valid_history()


def test_unknown_after_layout_commit_is_resolved_without_second_pack():
    _secret, device, root, raws = signed_world(1)
    rows = loose_rows(raws)
    bucket = ScriptedBucket(loose_objects(raws))
    page_key = layout_page_key(root.fid, device, 1)
    gate = bucket.pause("packer", "cas", page_key, when="after")
    gate.error = OutcomeUnknown("lost layout acknowledgement")
    gate.release.set()
    packer, sink, store = packer_for(bucket, "packer", root, device)

    packed = run(packer.pack(rows, now_ms=0, force=True))
    assert packed.page == decode_layout_page_at(
        page_key, store.get(page_key))
    assert len(sink.calls) == 1
    assert run(packer.pack(rows, now_ms=0, force=True)) is None
    assert len(sink.calls) == 1


@pytest.mark.parametrize("overlap", (False, True))
def test_competing_packers_rebase_disjoint_runs_and_reject_overlap(overlap):
    _secret, device, root, raws = signed_world(2)
    bucket = ScriptedBucket(loose_objects(raws))
    page_key = layout_page_key(root.fid, device, 1)
    delayed_gate = bucket.pause(
        "delayed", "cas", page_key, when="before")
    delayed, delayed_sink, store = packer_for(
        bucket, "delayed", root, device)
    winner, winner_sink, _ = packer_for(
        bucket, "winner", root, device)
    delayed_rows = loose_rows(raws[:1], 1)
    # The overlap is two honest snapshots of one append-only writer: the
    # delayed packer saw sequence one, while the winner also saw sequence two.
    winner_rows = loose_rows(raws, 1) if overlap \
        else loose_rows(raws[1:2], 2)

    def attempt(packer, rows):
        return run(packer.pack(rows, now_ms=0, force=True))

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(attempt, delayed, delayed_rows)
        delayed_gate.wait()
        won = pool.submit(attempt, winner, winner_rows).result()
        delayed_gate.release.set()
        if overlap:
            with pytest.raises(InvalidWriterLayout, match="overlap"):
                pending.result()
        else:
            delayed_result = pending.result()

    page = decode_layout_page_at(page_key, store.get(page_key))
    if overlap:
        assert page.placements == (won.placement,)
        # The losing immutable pack is a harmless orphan; both signed loose
        # piles remain independently fetchable fallback.
        assert len(delayed_sink.calls) == len(winner_sink.calls) == 1
        assert all(store.get("obj/" + h(raw)) == raw for raw in raws)
    else:
        assert page.placements == (
            delayed_result.placement, won.placement)
    assert bucket.assert_valid_history()


def test_window_and_signed_writer_binding_fail_before_publication():
    _secret, device, root, raws = signed_world(2)
    bucket = ScriptedBucket(loose_objects(raws))
    packer, sink, store = packer_for(bucket, "bounds", root, device)

    crossing = (
        LoosePile(WINDOW_PILES, h(raws[0])),
        LoosePile(WINDOW_PILES + 1, h(raws[1])),
    )
    with pytest.raises(InvalidWriterLayout, match="contiguous window"):
        run(packer.pack(crossing, now_ms=0, force=True))
    with pytest.raises(InvalidWriterLayout, match="contiguous window"):
        run(packer.pack((
            LoosePile(1, h(raws[0])), LoosePile(3, h(raws[1]))),
            now_ms=0, force=True))

    foreign_secret, foreign_device = keypair()
    foreign = encode_signed_pile(make_signed_pile(
        foreign_secret, root.fid, foreign_device,
        (root,)))
    foreign_oid = h(foreign)
    foreign_bucket = ScriptedBucket({"obj/" + foreign_oid: foreign})
    foreign_packer, foreign_sink, foreign_store = packer_for(
        foreign_bucket, "foreign", root, device)
    with pytest.raises(InvalidWriterLayout, match="pile binding"):
        run(foreign_packer.pack(
            (LoosePile(1, foreign_oid),), now_ms=0, force=True))
    assert sink.calls == foreign_sink.calls == []
    assert store.get(layout_page_key(root.fid, device, 1)) is None
    assert foreign_store.get(layout_page_key(root.fid, device, 1)) is None


def test_loose_pile_read_enforces_exact_named_pile_bound(monkeypatch):
    _secret, device, root, raws = signed_world(1)
    rows = loose_rows(raws)

    exact_bucket = ScriptedBucket(loose_objects(raws))
    exact, exact_sink, _store = packer_for(
        exact_bucket, "exact", root, device)
    monkeypatch.setattr(
        writer_packer_module, "MAX_PILE_BYTES", len(raws[0]))
    assert run(exact.pack(rows, now_ms=0, force=True)) is not None
    assert len(exact_sink.calls) == 1

    over_bucket = ScriptedBucket(loose_objects(raws))
    over, over_sink, over_store = packer_for(
        over_bucket, "over", root, device)
    monkeypatch.setattr(
        writer_packer_module, "MAX_PILE_BYTES", len(raws[0]) - 1)
    with pytest.raises(PayloadTooLarge, match="loose pile too large"):
        run(over.pack(rows, now_ms=0, force=True))
    assert over_sink.calls == []
    assert over_store.get(layout_page_key(root.fid, device, 1)) is None


def test_aggregate_pack_capacity_seals_exact_and_one_over_without_big_data(
        monkeypatch):
    _secret, device, root, raws = signed_world(2)
    rows = loose_rows(raws)
    exact_bytes = sum(map(len, raws))
    monkeypatch.setattr(
        writer_layout_module, "MAX_LAYOUT_PACK_BYTES", exact_bytes)
    monkeypatch.setattr(
        writer_packer_module, "MAX_LAYOUT_PACK_BYTES", exact_bytes)

    exact_bucket = ScriptedBucket(loose_objects(raws))
    exact, _sink, _store = packer_for(
        exact_bucket,
        "exact-capacity",
        root,
        device,
        policy=PackingPolicy(prompt_bytes=exact_bytes),
    )
    packed = run(exact.pack(rows, now_ms=0))
    assert packed.placement.pack_bytes == exact_bytes
    assert packed.pile_oids == tuple(row.oid for row in rows)

    one_under = exact_bytes - 1
    monkeypatch.setattr(
        writer_layout_module, "MAX_LAYOUT_PACK_BYTES", one_under)
    monkeypatch.setattr(
        writer_packer_module, "MAX_LAYOUT_PACK_BYTES", one_under)
    over_bucket = ScriptedBucket(loose_objects(raws))
    over, _sink, over_store = packer_for(
        over_bucket,
        "one-over-capacity",
        root,
        device,
        policy=PackingPolicy(prompt_bytes=one_under),
    )
    split = run(over.pack(rows, now_ms=0))
    assert split.placement.pack_bytes == len(raws[0]) < one_under
    assert split.pile_oids == (rows[0].oid,)
    assert over_store.get("obj/" + rows[1].oid) == raws[1]


def test_reference_pack_sink_refuses_unverified_exists():
    _secret, device, root, raws = signed_world(1)
    placement, _body = build_pack(root.fid, device, 1, raws)

    class WrongIncumbent:
        @staticmethod
        def put_if_absent(_key, _body):
            return EXISTS

        @staticmethod
        def get(_key):
            return b"different incumbent"

    sink = PackSink(WrongIncumbent())
    with pytest.raises(ValueError, match="pack collision"):
        sink.establish(placement, raws)
    assert sink.calls == []


@pytest.mark.parametrize("sink_type", (PackSink, AsyncPackSink))
def test_full_peer_and_provider_shaped_sinks_share_one_interface(sink_type):
    _secret, device, root, raws = signed_world(1)
    bucket = ScriptedBucket(loose_objects(raws))
    packer, sink, _store = packer_for(
        bucket, sink_type.__name__, root, device, sink_type=sink_type)

    packed = run(packer.pack(
        loose_rows(raws), now_ms=0, force=True))
    assert packed.establishment is CREATED
    assert len(sink.calls) == 1


def test_packing_preserves_real_writer_head_tree_and_all_loose_objects(
        tmp_path):
    async def scenario():
        secret, device, root, _raws = signed_world(1)
        store = FsStore(str(tmp_path / "writer"))
        writer = WriterLog(
            root.fid, device, device, h(b"store binding"), secret, store)

        prepared = await writer.prepare(((root,),))
        await writer.establish(prepared)
        assert store.list("layouts/") == []
        before_objects = {
            key: store.get(key) for key in store.list("obj/")}
        before_head = prepared.head
        pile_oid = signed_pile_oid(prepared.piles[0])
        sink = PackSink(store)
        packer = WriterPacker(
            root.fid,
            device,
            store,
            lambda oid: store.get("obj/" + oid),
            sink.establish,
        )

        packed = await packer.pack(
            (LoosePile(1, pile_oid),), now_ms=0, force=True)
        assert packed.pile_oids == (pile_oid,)
        assert prepared.head == before_head
        assert {
            key: store.get(key) for key in store.list("obj/")
        } == before_objects
        assert store.get("obj/" + pile_oid) == before_objects[
            "obj/" + pile_oid]

        # Exact retry observes layout coverage and performs no second create.
        assert await packer.pack(
            (LoosePile(1, pile_oid),), now_ms=0, force=True) is None
        assert len(sink.calls) == 1

    run(scenario())

    source = Path(__file__).parents[1] / "core" / "writer_repository.py"
    writer_source = source.read_text(encoding="utf-8")
    assert "writer_packer" not in writer_source
    assert "writer_layout" not in writer_source
