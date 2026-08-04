"""Black-box per-device repository behavior in normal and cloud modes."""
import asyncio

import pytest

from core.close import (
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from core.crypto import h, keypair
from core.fact import canon
from core.limits import MAX_FACT_BYTES, MAX_REPOSITORY_OBJECT_BYTES
from core.object_store import ABSENT
from core.store import FsStore
from core.writer_head import (
    HeadSlot,
    WriterBinding,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    make_head,
    writer_store_binding,
)
from core.writer_repository import (
    FactConsumer,
    HeadGrant,
    OpaqueHeadGate,
    OwnerPublisher,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from core.writer_tree import EMPTY_TREE, append_piles
from facts.auth.device import device as device_fact
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact


def run(awaitable):
    return asyncio.run(awaitable)


def world():
    secret, public = keypair()
    root = workspace_fact(secret, public, "alice", 1)
    device = device_fact(root.fid, public, "laptop", 2)
    device_signature = signature_fact(secret, public, device, 2)
    return secret, public, root, device_signature, device


def proof_for(
        secret, public, root, device_signature, device, proposed_head,
        base_head=None):
    request = head_request(
        root.fid, public, public, base_head,
        proposed_head, 1_000, 3)
    request_signature = signature_fact(
        secret, public, request, 3)
    return encode_signed_pile(make_signed_pile(
        secret,
        root.fid,
        public,
        (root, device_signature, device, request_signature, request),
    ))


def binding_for(workspace, public, store_binding):
    def resolve(candidate_workspace, device, _authority_root, _candidate):
        assert candidate_workspace == workspace
        if device != public:
            return None
        return WriterBinding(
            workspace, public, public, store_binding)
    return resolve


def test_writer_binding_proof_reads_current_form_offers(monkeypatch):
    """A retained source tag cannot hide its current writer authority."""
    from types import SimpleNamespace

    import facts
    from core.close import ClosedPileEvaluator
    from core.fact import CurrentFact, Fact, current_fact
    from core import writer_repository
    from facts._policy import FamilyPolicy

    workspace = "0" * 64
    secret, writer = keypair()
    source = Fact(
        "test_writer_member.v0", 1, [],
        {"legacy_writer": writer}, workspace)
    current = Fact(
        "test_writer_member", 1,
        [["offer", "member", writer, writer]],
        {"writer": writer}, workspace)

    def reextract(candidate):
        if candidate != source:
            raise ValueError("synthetic writer source")
        return current

    family = SimpleNamespace(
        TAG=current.t,
        POLICY=FamilyPolicy(),
        DURABLE=True,
        needs=lambda _fact: (),
        validate=lambda fact, _context: current_fact(fact) == current,
        reextract=reextract,
    )
    real_family_for = facts.family_for
    monkeypatch.setattr(
        facts,
        "family_for",
        lambda tag: family if tag in {source.t, current.t}
        else real_family_for(tag),
    )
    raw = encode_signed_pile(make_signed_pile(
        secret, workspace, writer, (source,)))

    evaluated = ClosedPileEvaluator(workspace).evaluate(raw, writer=writer)

    assert evaluated.judgment.valids[0].fact == source
    assert source.offers() == []
    assert isinstance(facts.hydrate(source), CurrentFact)
    assert writer_repository._require_writer_proof(
        evaluated, writer, writer) is None


def test_same_writer_objects_converge_through_normal_and_opaque_cloud_modes(
        tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        store_binding = h(b"writer-store")
        authority_root = h(b"current-authority")
        writer_store = FsStore(str(tmp_path / "writer"))
        cloud_store = FsStore(str(tmp_path / "cloud"))
        normal_store = FsStore(str(tmp_path / "normal-receiver"))
        cloud_receiver_store = FsStore(str(tmp_path / "cloud-receiver"))

        writer = WriterLog(
            root.fid,
            public,
            public,
            store_binding,
            secret,
            writer_store,
        )
        prepared = await writer.prepare(((
            root, device_signature, device),))
        await writer.establish(prepared)

        proof = proof_for(
            secret, public, root, device_signature,
            device, prepared.head_oid)
        writer_gate = OpaqueHeadGate(
            writer_store,
            mechanical_head_authorizer(root.fid, authority_root, 10))
        cloud_gate = OpaqueHeadGate(
            cloud_store,
            mechanical_head_authorizer(root.fid, authority_root, 10))

        assert (await writer_gate.advance(
            proof, prepared.head_oid)).status == "applied"
        await writer.establish(prepared, cloud_store)
        assert (await cloud_gate.advance(
            proof, prepared.head_oid)).status == "applied"

        normal_consumer = FactConsumer(root.fid)
        cloud_consumer = FactConsumer(root.fid)
        resolve = binding_for(root.fid, public, store_binding)
        normal = RepositoryMirror(
            root.fid, normal_store, resolve, normal_consumer)
        via_cloud = RepositoryMirror(
            root.fid, cloud_receiver_store, resolve, cloud_consumer)

        normal_result = await normal.sync_from(writer_store)
        cloud_result = await via_cloud.sync_from(cloud_store)

        assert normal_result.errors == cloud_result.errors == ()
        assert normal_result.changed == cloud_result.changed == 1
        assert normal_result.piles == cloud_result.piles == 1
        assert normal_consumer.fact_ids() == cloud_consumer.fact_ids()
        assert set(normal_consumer.fact_ids()) == {
            root.fid, device_signature.fid, device.fid}
        assert normal_store.get(
            f"heads/{root.fid}/{public}") == cloud_receiver_store.get(
                f"heads/{root.fid}/{public}")

        # Equal directories are a no-op and fetch no pile for semantic work.
        again = await via_cloud.sync_from(cloud_store)
        assert again.changed == again.piles == again.facts == 0

    run(scenario())


def test_owner_publisher_diffs_then_advances_cloud_head_last(tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        store_binding = h(b"owner-publisher-store")
        authority_root = h(b"owner-publisher-authority")
        local = FsStore(str(tmp_path / "local"))
        cloud = FsStore(str(tmp_path / "cloud"))
        receiver = FsStore(str(tmp_path / "receiver"))
        binding = WriterBinding(
            root.fid, public, public, store_binding)
        writer = WriterLog(
            root.fid, public, public, store_binding, secret, local)
        local_gate = OpaqueHeadGate(
            local,
            mechanical_head_authorizer(
                root.fid, authority_root, 10),
        )
        cloud_gate = OpaqueHeadGate(
            cloud,
            mechanical_head_authorizer(
                root.fid, authority_root, 10),
        )

        async def advance(proof, proposed):
            return await cloud_gate.advance(proof, proposed)

        def make_proof(base, proposed):
            return proof_for(
                secret,
                public,
                root,
                device_signature,
                device,
                proposed,
                base,
            )

        publisher = OwnerPublisher(
            root.fid,
            public,
            binding,
            local,
            cloud,
            make_proof,
            advance,
        )

        first = await writer.prepare(((root, device_signature, device),))
        await writer.establish(first)
        assert (await local_gate.advance(
            make_proof(None, first.head_oid), first.head_oid
        )).status == "applied"
        published = await publisher.publish()
        assert (published.status, published.piles) == ("applied", 1)
        first_objects = set(cloud.list("obj"))
        key = head_slot_key(root.fid, public)
        assert decode_slot_at(key, cloud.get(key)).head == first.head_oid

        item = message_fact(
            root.fid, public, "general", "incremental", 20)
        item_signature = signature_fact(secret, public, item, 20)
        second = await writer.prepare(((*first.piles[0].facts,
                                        item_signature, item),))
        await writer.establish(second)
        assert (await local_gate.advance(
            make_proof(first.head_oid, second.head_oid), second.head_oid
        )).status == "applied"
        advanced = await publisher.publish()
        assert (advanced.status, advanced.piles) == ("applied", 1)
        assert first_objects < set(cloud.list("obj"))
        assert decode_slot_at(key, cloud.get(key)).head == second.head_oid

        noop = await publisher.publish()
        assert (noop.status, noop.objects, noop.piles) == ("noop", 0, 0)

        consumer = FactConsumer(root.fid)
        mirrored = await RepositoryMirror(
            root.fid,
            receiver,
            binding_for(root.fid, public, store_binding),
            consumer,
        ).sync_from(cloud)
        assert mirrored.errors == ()
        assert mirrored.piles == 2
        assert item.fid in consumer.fact_ids()

    run(scenario())


def test_two_device_roots_advance_without_a_shared_content_cas(tmp_path):
    async def scenario():
        alice = world()
        bob = world()
        # Both devices publish into one workspace for this storage-level race;
        # binding/auth fixtures deliberately keep semantic identities separate.
        workspace = alice[2].fid
        store = FsStore(str(tmp_path / "cloud"))
        authority_root = h(b"authority")
        proposals = []
        for ordinal, values in enumerate((alice, bob), 1):
            _secret, public, _root, _sig, _device = values
            raw_head = f"head-{ordinal}".encode()
            head = h(raw_head)
            store.put_if_absent("obj/" + head, raw_head)
            proposals.append((
                public, head))

        async def authorize(proof, head):
            device = proof.decode()
            return HeadGrant(
                workspace, device, None, head, authority_root)

        gate = OpaqueHeadGate(store, authorize)
        outcomes = await asyncio.gather(*(
            gate.advance(device.encode(), head)
            for device, head in proposals
        ))
        assert [outcome.status for outcome in outcomes] == [
            "applied", "applied"]
        assert len(store.list(f"heads/{workspace}")) == 2

    run(scenario())


def test_cloud_requires_the_opaque_head_object_then_trusts_its_bytes(tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        authority_root = h(b"authority")
        cloud = FsStore(str(tmp_path / "cloud"))
        receiver = FsStore(str(tmp_path / "receiver"))
        forged_head = h(b"missing opaque head")
        proof = proof_for(
            secret, public, root, device_signature, device, forged_head)
        # The mechanical gate rejects head-before-object ordering without
        # opening or decoding writer-controlled bytes.
        with pytest.raises(ValueError, match="head object is missing"):
            await OpaqueHeadGate(
                cloud,
                mechanical_head_authorizer(
                    root.fid, authority_root, 10)).advance(
                        proof, forged_head)
        assert cloud.get(f"heads/{root.fid}/{public}") is None

        # Existence is not content admission: an opaque malformed head is
        # accepted by the cloud and rejected only by a consuming peer.
        cloud.put_if_absent("obj/" + forged_head, b"missing opaque head")
        result = await OpaqueHeadGate(
            cloud,
            mechanical_head_authorizer(
                root.fid, authority_root, 10)).advance(proof, forged_head)
        assert result.status == "applied"

        consumer = FactConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            receiver,
            binding_for(root.fid, public, h(b"store")),
            consumer,
        )
        synced = await mirror.sync_from(cloud)
        assert synced.changed == synced.piles == synced.facts == 0
        assert len(synced.errors) == 1
        assert synced.errors[0][0] == f"heads/{root.fid}/{public}"
        assert consumer.fact_ids() == ()

    run(scenario())


def test_invalid_closed_pile_never_reaches_a_writer_tree(tmp_path):
    async def scenario():
        secret, public, root, _device_signature, _device = world()
        writer = WriterLog(
            root.fid, public, public, h(b"store"), secret,
            FsStore(str(tmp_path / "writer")))
        dangling = message_fact(
            root.fid, public, "general", "no member closure", 9)
        try:
            await writer.prepare(((dangling,),))
        except Exception as error:
            assert "closed pile rejected" in str(error)
        else:
            raise AssertionError("nonclosed writer pile was accepted")

    run(scenario())


def test_bad_late_pile_admits_nothing_from_the_candidate_head(tmp_path):
    """A multi-pile candidate is one semantic acceptance transaction."""
    async def scenario():
        secret, public, root, device_signature, device = world()
        source = FsStore(str(tmp_path / "hostile-source"))
        receiver = FsStore(str(tmp_path / "receiver"))
        store_binding = h(b"store")
        good = make_signed_pile(
            secret, root.fid, public,
            (root, device_signature, device))
        dangling = message_fact(
            root.fid, public, "general", "missing member", 9)
        bad = make_signed_pile(
            secret, root.fid, public, (dangling,))
        raw_piles = tuple(map(encode_signed_pile, (good, bad)))
        objects = {
            signed_pile_oid(raw): raw for raw in raw_piles
        }

        def emit(raw):
            oid = h(raw)
            objects[oid] = raw
            return oid

        tree = append_piles(
            EMPTY_TREE, root.fid, public,
            tuple(signed_pile_oid(raw) for raw in raw_piles),
            objects.get, emit)
        candidate = make_head(
            secret, root.fid, public, public,
            tree.count, tree, store_binding)
        candidate_raw = encode_head(candidate)
        candidate_oid = head_oid(candidate_raw)
        objects[candidate_oid] = candidate_raw
        for oid, raw in objects.items():
            source.put_if_absent("obj/" + oid, raw)
        key = head_slot_key(root.fid, public)
        source.cas(key, ABSENT, encode_slot(HeadSlot(
            root.fid, public, candidate_oid, h(b"authority"))))

        consumer = FactConsumer(root.fid)
        result = await RepositoryMirror(
            root.fid,
            receiver,
            binding_for(root.fid, public, store_binding),
            consumer,
        ).sync_from(source)

        assert result.changed == result.piles == result.facts == 0
        assert result.errors and "closed pile rejected" in result.errors[0][1]
        assert consumer.fact_ids() == ()
        assert receiver.get(key) is None
        assert receiver.get("obj/" + signed_pile_oid(raw_piles[0])) is None

    run(scenario())


def test_projection_crash_after_slot_cas_replays_from_durable_head(tmp_path):
    class FailOnceConsumer(FactConsumer):
        def __init__(self, workspace):
            super().__init__(workspace)
            self.fail = True

        def commit(self, batch, *, device, head):
            if self.fail:
                self.fail = False
                raise OSError("simulated projection crash")
            return super().commit(batch, device=device, head=head)

    async def scenario():
        secret, public, root, device_signature, device = world()
        source = FsStore(str(tmp_path / "source"))
        receiver = FsStore(str(tmp_path / "receiver"))
        binding = writer_store_binding(root.fid, public)
        log = WriterLog(
            root.fid, public, public, binding, secret, source)
        probe = message_fact(
            root.fid, public, "general", "", 3)
        padding = MAX_FACT_BYTES - len(canon(probe.to_json()))
        message = message_fact(
            root.fid, public, "general", "x" * padding, 3)
        message_signature = signature_fact(
            secret, public, message, 3)
        update = await log.prepare(((
            root, device_signature, device,
            message_signature, message),))
        assert len(encode_signed_pile(update.piles[0])) \
            > MAX_REPOSITORY_OBJECT_BYTES
        await log.establish(update)
        await log.establish(update)
        gate = OpaqueHeadGate(
            source,
            mechanical_head_authorizer(
                root.fid, h(b"authority"), 10),
        )
        await gate.advance(
            proof_for(
                secret, public, root, device_signature,
                device, update.head_oid),
            update.head_oid,
        )

        consumer = FailOnceConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            receiver,
            binding_for(root.fid, public, binding),
            consumer,
        )
        with pytest.raises(OSError, match="projection crash"):
            await mirror.sync_from(source)

        key = head_slot_key(root.fid, public)
        assert decode_slot_at(key, receiver.get(key)).head == update.head_oid
        assert consumer.projected_head(public) is None
        assert consumer.fact_ids() == ()

        repaired = await mirror.sync_from(source)
        assert repaired.errors == ()
        assert repaired.changed == 0
        assert repaired.piles == 1
        assert consumer.projected_head(public) == update.head_oid
        assert set(consumer.fact_ids()) == {
            root.fid, device_signature.fid, device.fid,
            message_signature.fid, message.fid}

    run(scenario())
