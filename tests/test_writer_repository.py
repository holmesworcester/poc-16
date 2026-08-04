"""Black-box per-device repository behavior in normal and cloud modes."""
import asyncio

import facts
import pytest

from core.close import (
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from core.crypto import h, keypair
from core.fact import canon
from core.limits import (
    MAX_CONTROL_PILE_BYTES,
    MAX_FACT_BYTES,
    MAX_SEMANTIC_PILE_BYTES,
    MAX_REPOSITORY_OBJECT_BYTES,
    PayloadTooLarge,
)
from core.object_store import ABSENT, STALE, OutcomeUnknown
from core.removal_state import RecipientRemovalState
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
    open_accepted_pile,
)
from tests.util import mechanical_head_authorizer
from core.writer_tree import EMPTY_TREE, WriterTree, append_piles
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
        proposed_head, 1_000, b"mechanical removal path", 3)
    request_signature = signature_fact(
        secret, public, request, 3)
    return encode_signed_pile(make_signed_pile(
        secret,
        root.fid,
        public,
        (root, device_signature, device, request_signature, request),
    ))


def binding_for(workspace, public, store_binding):
    def resolve(candidate_workspace, device, _removal_root, _candidate):
        assert candidate_workspace == workspace
        if device != public:
            return None
        return WriterBinding(
            workspace, public, public, store_binding)
    return resolve


async def _accepted_history(path, store_type=FsStore):
    secret, public, root, device_signature, device = world()
    store = store_type(str(path))
    binding = writer_store_binding(root.fid, public)
    log = WriterLog(
        root.fid, public, public, binding, secret, store)
    closures = []
    for timestamp, text in ((10, "first"), (11, "second")):
        item = message_fact(
            root.fid, public, "general", text, timestamp)
        item_signature = signature_fact(
            secret, public, item, timestamp)
        closures.append((
            root, device_signature, device, item_signature, item))
    update = await log.prepare(closures)
    await log.establish(update)
    gate = OpaqueHeadGate(
        store,
        mechanical_head_authorizer(root.fid, h(b"removal root")),
    )
    outcome = await gate.advance(
        proof_for(
            secret, public, root, device_signature,
            device, update.head_oid),
        update.head_oid,
        100,
    )
    assert outcome.status == "applied"
    return store, secret, public, root, update


def _install_candidate(
        path, secret, workspace, device, pile_oid, *,
        head_secret=None, head_workspace=None, head_device=None, tree=None,
        pile_raw=None):
    """Install one hostile mechanically advertised candidate for open tests."""
    store = FsStore(str(path))
    if pile_raw is not None:
        store.put_if_absent("obj/" + pile_oid, pile_raw)
    if tree is None:
        pages = {}

        def emit(raw):
            oid = h(raw)
            pages[oid] = raw
            return oid

        tree = append_piles(
            EMPTY_TREE, workspace, device, (pile_oid,), None, emit)
        for oid, raw in pages.items():
            store.put_if_absent("obj/" + oid, raw)
    candidate = make_head(
        secret if head_secret is None else head_secret,
        workspace if head_workspace is None else head_workspace,
        device if head_device is None else head_device,
        device,
        tree.count,
        tree,
        writer_store_binding(workspace, device),
    )
    raw = encode_head(candidate)
    oid = head_oid(raw)
    store.put_if_absent("obj/" + oid, raw)
    key = head_slot_key(workspace, device)
    store.cas(key, ABSENT, encode_slot(HeadSlot(
        workspace, device, oid, h(b"authority"))))
    return store


def test_open_accepted_pile_reads_one_exact_historical_leaf(tmp_path):
    class PointOnlyStore(FsStore):
        def __init__(self, root):
            super().__init__(root)
            self.pile_reads = []

        def list_page(self, *_args, **_kwargs):
            raise AssertionError("accepted pile lookup must not LIST")

        def copy_pile_object(self, oid, maximum, write):
            self.pile_reads.append(oid)
            return super().copy_pile_object(oid, maximum, write)

    async def scenario():
        store, _secret, public, root, update = await _accepted_history(
            tmp_path / "accepted", PointOnlyStore)
        store.pile_reads.clear()

        raw = await open_accepted_pile(
            store, root.fid, public, 1)

        assert raw == encode_signed_pile(update.piles[0])
        assert decode_signed_pile(
            raw, workspace=root.fid, writer=public) == update.piles[0]
        assert store.pile_reads == [update.pile_oids[0]]

    run(scenario())


def test_open_accepted_pile_rejects_forged_identity_and_sequence(tmp_path):
    async def scenario():
        store, _secret, public, root, _update = await _accepted_history(
            tmp_path / "accepted")
        for workspace, device, sequence in (
                (h(b"other workspace"), public, 1),
                (root.fid, h(b"other device"), 1),
                (root.fid, public, 0),
                (root.fid, public, 3)):
            with pytest.raises(ValueError):
                await open_accepted_pile(
                    store, workspace, device, sequence)

    run(scenario())


def test_open_accepted_pile_authenticates_head_tree_oid_and_outer_pile(
        tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        good = encode_signed_pile(make_signed_pile(
            secret, root.fid, public,
            (root, device_signature, device)))
        good_oid = signed_pile_oid(good)

        attacker_secret, attacker = keypair()
        forged_head = _install_candidate(
            tmp_path / "head", secret, root.fid, public, good_oid,
            head_secret=attacker_secret, pile_raw=good)
        with pytest.raises(ValueError, match="authority binding"):
            await open_accepted_pile(
                forged_head, root.fid, public, 1)

        for name, fields in (
                ("workspace", {"head_workspace": h(b"other workspace")}),
                ("device", {"head_device": attacker})):
            rebound_head = _install_candidate(
                tmp_path / name, secret, root.fid, public, good_oid,
                pile_raw=good, **fields)
            with pytest.raises(ValueError, match="authority binding"):
                await open_accepted_pile(
                    rebound_head, root.fid, public, 1)

        missing_tree = _install_candidate(
            tmp_path / "tree", secret, root.fid, public, good_oid,
            tree=WriterTree(h(b"missing tree"), 1, 1), pile_raw=good)
        with pytest.raises(ValueError, match="object integrity"):
            await open_accepted_pile(
                missing_tree, root.fid, public, 1)

        missing_oid = _install_candidate(
            tmp_path / "oid", secret, root.fid, public,
            h(b"missing pile"))
        with pytest.raises(ValueError, match="pile integrity"):
            await open_accepted_pile(
                missing_oid, root.fid, public, 1)

        hostile = encode_signed_pile(make_signed_pile(
            attacker_secret, root.fid, attacker,
            (root, device_signature, device)))
        hostile_oid = signed_pile_oid(hostile)
        forged_pile = _install_candidate(
            tmp_path / "pile", secret, root.fid, public,
            hostile_oid, pile_raw=hostile)
        with pytest.raises(ValueError, match="signed pile binding"):
            await open_accepted_pile(
                forged_pile, root.fid, public, 1)

    run(scenario())


def test_open_accepted_pile_enforces_the_explicit_streaming_byte_bound(
        tmp_path):
    async def scenario():
        store, _secret, public, root, update = await _accepted_history(
            tmp_path / "accepted")
        raw = encode_signed_pile(update.piles[0])

        assert await open_accepted_pile(
            store, root.fid, public, 1,
            max_bytes=len(raw)) == raw
        assert await open_accepted_pile(
            store, root.fid, public, 1,
            max_bytes=MAX_CONTROL_PILE_BYTES) == raw

        with pytest.raises(PayloadTooLarge, match="exceeds byte limit"):
            await open_accepted_pile(
                store, root.fid, public, 1,
                max_bytes=len(raw) - 1)
        with pytest.raises(ValueError, match="byte limit"):
            await open_accepted_pile(
                store, root.fid, public, 1,
                max_bytes=MAX_SEMANTIC_PILE_BYTES + 1)

    run(scenario())


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
        removal_root = h(b"current-removal-root")
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
            mechanical_head_authorizer(root.fid, removal_root))
        cloud_gate = OpaqueHeadGate(
            cloud_store,
            mechanical_head_authorizer(root.fid, removal_root))

        assert (await writer_gate.advance(
            proof, prepared.head_oid, 10)).status == "applied"
        await writer.establish(prepared, cloud_store)
        assert (await cloud_gate.advance(
            proof, prepared.head_oid, 10)).status == "applied"

        normal_consumer = FactConsumer(root.fid)
        cloud_consumer = FactConsumer(root.fid)
        normal_removals = RecipientRemovalState(
            root.fid, normal_store)
        cloud_removals = RecipientRemovalState(
            root.fid, cloud_receiver_store)
        resolve = binding_for(root.fid, public, store_binding)
        normal = RepositoryMirror(
            root.fid,
            normal_store,
            resolve,
            normal_consumer,
            control_state=normal_removals,
        )
        via_cloud = RepositoryMirror(
            root.fid,
            cloud_receiver_store,
            resolve,
            cloud_consumer,
            control_state=cloud_removals,
        )

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


def test_accepting_mirror_composes_recipient_removal_state(tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        source = FsStore(str(tmp_path / "source"))
        target = FsStore(str(tmp_path / "target"))
        binding = writer_store_binding(root.fid, public)
        writer = WriterLog(
            root.fid, public, public, binding, secret, source)
        update = await writer.prepare(((root, device_signature, device),))
        await writer.establish(update)
        async def authorize(_proof, proposed, _trusted_now):
            return HeadGrant(
                root.fid,
                public,
                None,
                proposed,
                h(b"source removal"),
            )

        assert (await OpaqueHeadGate(
            source, authorize,
        ).advance(b"proof", update.head_oid, 10)).status == "applied"

        consumer = FactConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            target,
            binding_for(root.fid, public, binding),
            consumer,
        )
        result = await mirror.sync_from(source)

        assert result.errors == ()
        assert result.changed == result.piles == 1
        assert target.get(head_slot_key(root.fid, public)) is not None
        pin = await mirror.control_state.pin()
        assert pin is not None
        proof = await pin.proof(facts.principal_sid("member", public))
        assert pin.verify(
            facts.principal_sid("member", public), proof,
        )["state"] == "clear"
        assert root.fid in consumer.fact_ids()

    run(scenario())


def test_listed_but_invisible_pending_head_is_delayed_not_corrupt(tmp_path):
    async def scenario():
        workspace = h(b"pending workspace")
        device = h(b"pending device")
        store = FsStore(str(tmp_path / "recipient"))
        mirror = RepositoryMirror(
            workspace,
            store,
            lambda *_args: None,
            None,
        )
        assert await mirror._sync_slot(
            store,
            head_slot_key(workspace, device),
            ABSENT,
        ) == (0, 0, False)

    run(scenario())


@pytest.mark.parametrize(("failure", "visible", "expected"), (
    ("stale", "proposed", "noop"),
    ("unknown", "proposed", "applied"),
    ("stale", "base", "retryable"),
    ("unknown", "base", "retryable"),
    ("stale", "winner", "conflict"),
    ("unknown", "winner", "conflict"),
))
def test_head_cas_reread_distinguishes_success_retry_and_conflict(
        tmp_path, failure, visible, expected):
    class RacedStore(FsStore):
        armed = False
        replacement = None

        def cas(self, key, token, value):
            if not self.armed:
                return super().cas(key, token, value)
            self.armed = False
            if self.replacement is not None:
                assert super().cas(key, token, self.replacement) is not STALE
            if failure == "unknown":
                raise OutcomeUnknown("lost head CAS response")
            return STALE

    async def scenario():
        _secret, device, root, _device_signature, _device = world()
        store = RacedStore(str(tmp_path / f"{failure}-{visible}"))
        removal_root = h(b"head reconciliation removal root")
        base = h(b"accepted base head")
        proposed = h(b"proposed next head")
        winner = h(b"competing next head")
        for oid, raw in (
                (base, b"accepted base head"),
                (proposed, b"proposed next head"),
                (winner, b"competing next head")):
            store.put_if_absent("obj/" + oid, raw)
        key = head_slot_key(root.fid, device)
        assert store.cas(key, ABSENT, encode_slot(HeadSlot(
            root.fid, device, base, removal_root))) is not STALE
        proposed_slot = HeadSlot(
            root.fid, device, proposed, removal_root)
        winner_slot = HeadSlot(
            root.fid, device, winner, removal_root)
        store.replacement = {
            "base": None,
            "proposed": encode_slot(proposed_slot),
            "winner": encode_slot(winner_slot),
        }[visible]
        store.armed = True

        result = await OpaqueHeadGate(
            store, lambda *_args: None).advance_grant(HeadGrant(
                root.fid, device, base, proposed, removal_root))

        assert result.status == expected
        assert result.slot.head == (
            winner if expected == "conflict" else proposed)

    run(scenario())


def test_head_with_missing_required_base_is_terminal_conflict(tmp_path):
    async def scenario():
        _secret, device, root, _device_signature, _device = world()
        store = FsStore(str(tmp_path / "missing-required-base"))
        proposed_raw = b"proposed after missing base"
        proposed = h(proposed_raw)
        store.put_if_absent("obj/" + proposed, proposed_raw)

        result = await OpaqueHeadGate(
            store, lambda *_args: None).advance_grant(HeadGrant(
                root.fid,
                device,
                h(b"missing base"),
                proposed,
                h(b"removal root"),
            ))

        assert result.status == "conflict"

    run(scenario())


@pytest.mark.parametrize("failure", ("stale", "unknown"))
def test_head_create_failure_rereads_absent_as_retryable(tmp_path, failure):
    class AbsentStore(FsStore):
        def cas(self, _key, _token, _value):
            if failure == "unknown":
                raise OutcomeUnknown("lost absent head CAS response")
            return STALE

    async def scenario():
        _secret, device, root, _device_signature, _device = world()
        store = AbsentStore(str(tmp_path / f"absent-{failure}"))
        proposed_raw = b"first proposed head"
        proposed = h(proposed_raw)
        store.put_if_absent("obj/" + proposed, proposed_raw)

        result = await OpaqueHeadGate(
            store, lambda *_args: None).advance_grant(HeadGrant(
                root.fid,
                device,
                None,
                proposed,
                h(b"removal root"),
            ))

        assert result.status == "retryable"

    run(scenario())


def test_owner_publisher_diffs_then_advances_cloud_head_last(tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        store_binding = h(b"owner-publisher-store")
        removal_root = h(b"owner-publisher-removal-root")
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
                root.fid, removal_root),
        )
        cloud_gate = OpaqueHeadGate(
            cloud,
            mechanical_head_authorizer(
                root.fid, removal_root),
        )

        async def advance(proof, proposed):
            return await cloud_gate.advance(proof, proposed, 10)

        controls = []

        async def apply_control(raw, writer):
            controls.append((signed_pile_oid(raw), writer))
            return type("Applied", (), {"status": "applied"})()

        permitted = {}

        async def issue_permit(proof, proposed, control_piles):
            permit = h(proof + proposed.encode()).encode()
            permitted[permit] = proof, proposed, control_piles
            return permit

        async def commit_permit(permit, proposed):
            expected_proof, expected_head, expected_piles = permitted[permit]
            assert proposed == expected_head
            for raw in expected_piles:
                result = await apply_control(raw, public)
                assert result.status in {"applied", "noop"}
            return await advance(expected_proof, proposed)

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
            issue_permit,
            commit_permit,
            advance,
        )

        first = await writer.prepare(((root, device_signature, device),))
        await writer.establish(first)
        assert (await local_gate.advance(
            make_proof(None, first.head_oid), first.head_oid, 10
        )).status == "applied"
        published = await publisher.publish()
        assert (published.status, published.piles) == ("applied", 1)
        assert controls == [(first.pile_oids[0], public)]
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
            make_proof(first.head_oid, second.head_oid), second.head_oid, 10
        )).status == "applied"
        advanced = await publisher.publish()
        assert (advanced.status, advanced.piles) == ("applied", 1)
        # The second original leaf deliberately mixes ordinary content with
        # repeated control dependencies, so it is not a control application.
        assert controls == [(first.pile_oids[0], public)]
        assert first_objects < set(cloud.list("obj"))
        assert decode_slot_at(key, cloud.get(key)).head == second.head_oid

        noop = await publisher.publish()
        assert (noop.status, noop.objects, noop.piles) == ("noop", 0, 0)

        consumer = FactConsumer(root.fid)
        removals = RecipientRemovalState(root.fid, receiver)
        mirrored = await RepositoryMirror(
            root.fid,
            receiver,
            binding_for(root.fid, public, store_binding),
            consumer,
            control_state=removals,
        ).sync_from(cloud)
        assert mirrored.errors == ()
        assert mirrored.piles == 2
        assert item.fid in consumer.fact_ids()

    run(scenario())


def test_owner_publisher_retries_control_before_head_without_a_cursor(
        tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        store_binding = h(b"control-before-head-store")
        removal_root = h(b"control-before-head-removal")
        local = FsStore(str(tmp_path / "local"))
        cloud = FsStore(str(tmp_path / "cloud"))
        binding = WriterBinding(
            root.fid, public, public, store_binding)
        writer = WriterLog(
            root.fid, public, public, store_binding, secret, local)
        update = await writer.prepare(((root, device_signature, device),))
        await writer.establish(update)
        local_gate = OpaqueHeadGate(
            local, mechanical_head_authorizer(root.fid, removal_root))
        assert (await local_gate.advance(
            proof_for(
                secret, public, root, device_signature,
                device, update.head_oid),
            update.head_oid,
            10,
        )).status == "applied"
        cloud_gate = OpaqueHeadGate(
            cloud, mechanical_head_authorizer(root.fid, removal_root))
        attempts = []

        async def apply_control(raw, writer_id):
            attempts.append((signed_pile_oid(raw), writer_id))
            return type("Result", (), {
                "status": "applied" if len(attempts) > 1 else "retryable",
            })()

        async def advance(proof, proposed):
            return await cloud_gate.advance(proof, proposed, 10)

        held_permit = b"held exact control-head permit"
        held_proof = None
        issues = 0
        commits = []
        pauses = []

        async def retry_pause(attempt):
            pauses.append(attempt)

        async def issue_permit(proof, proposed, control_piles):
            nonlocal held_proof, issues
            issues += 1
            held_proof = proof, proposed, control_piles
            return held_permit

        async def commit_permit(permit, proposed):
            commits.append(permit)
            assert permit == held_permit
            proof, expected_head, expected_piles = held_proof
            assert proposed == expected_head
            for raw in expected_piles:
                applied = await apply_control(raw, public)
                if applied.status == "retryable":
                    return applied
            return await advance(proof, proposed)

        publisher = OwnerPublisher(
            root.fid,
            public,
            binding,
            local,
            cloud,
            lambda base, proposed: proof_for(
                secret, public, root, device_signature,
                device, proposed, base),
            issue_permit,
            commit_permit,
            advance,
            retry_pause,
        )
        published = await publisher.publish()
        assert published.status == "applied"
        key = head_slot_key(root.fid, public)
        assert decode_slot_at(key, cloud.get(key)).head == update.head_oid
        assert issues == 1
        assert len(commits) == 2
        assert commits[0] is commits[1] is held_permit
        assert pauses == [0]
        assert attempts == [
            (update.pile_oids[0], public),
            (update.pile_oids[0], public),
        ]

    run(scenario())


def test_owner_publisher_stops_on_same_base_competing_control_head(
        tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        binding = WriterBinding(
            root.fid, public, public, h(b"competing publisher store"))
        removal_root = h(b"competing publisher removal root")
        local = FsStore(str(tmp_path / "competing-local"))
        cloud = FsStore(str(tmp_path / "competing-cloud"))
        writer = WriterLog(
            root.fid,
            public,
            public,
            binding.store,
            secret,
            local,
        )
        update = await writer.prepare(((root, device_signature, device),))
        await writer.establish(update)
        proof = proof_for(
            secret,
            public,
            root,
            device_signature,
            device,
            update.head_oid,
        )
        assert (await OpaqueHeadGate(
            local,
            mechanical_head_authorizer(root.fid, removal_root),
        ).advance(proof, update.head_oid, 10)).status == "applied"

        cloud_gate = OpaqueHeadGate(
            cloud,
            mechanical_head_authorizer(root.fid, removal_root),
        )
        winner_raw = b"same-base competing head"
        winner = h(winner_raw)
        issues = []
        commits = []

        async def issue_permit(
                exact_proof, proposed, control_piles):
            issues.append((exact_proof, proposed, control_piles))
            return b"one exact losing permit"

        async def commit_permit(permit, proposed):
            commits.append((permit, proposed))
            cloud.put_if_absent("obj/" + winner, winner_raw)
            won = await cloud_gate.advance_grant(HeadGrant(
                root.fid,
                public,
                None,
                winner,
                removal_root,
            ))
            assert won.status == "applied"
            return await cloud_gate.advance(issues[0][0], proposed, 10)

        def retry_pause(_attempt):
            raise AssertionError("terminal conflict was retried")

        published = await OwnerPublisher(
            root.fid,
            public,
            binding,
            local,
            cloud,
            lambda _base, _proposed: proof,
            issue_permit,
            commit_permit,
            lambda *_args: None,
            retry_pause,
        ).publish()

        assert published.status == "conflict"
        assert len(issues) == len(commits) == 1
        assert commits[0][0] == b"one exact losing permit"
        slot = decode_slot_at(
            head_slot_key(root.fid, public),
            cloud.get(head_slot_key(root.fid, public)),
        )
        assert slot.head == winner

    run(scenario())


def test_two_device_roots_advance_without_a_shared_content_cas(tmp_path):
    async def scenario():
        alice = world()
        bob = world()
        # Both devices publish into one workspace for this storage-level race;
        # binding/auth fixtures deliberately keep semantic identities separate.
        workspace = alice[2].fid
        store = FsStore(str(tmp_path / "cloud"))
        removal_root = h(b"removal root")
        proposals = []
        for ordinal, values in enumerate((alice, bob), 1):
            _secret, public, _root, _sig, _device = values
            raw_head = f"head-{ordinal}".encode()
            head = h(raw_head)
            store.put_if_absent("obj/" + head, raw_head)
            proposals.append((
                public, head))

        async def authorize(proof, head, _trusted_now):
            device = proof.decode()
            return HeadGrant(
                workspace, device, None, head, removal_root)

        gate = OpaqueHeadGate(store, authorize)
        outcomes = await asyncio.gather(*(
            gate.advance(device.encode(), head, 10)
            for device, head in proposals
        ))
        assert [outcome.status for outcome in outcomes] == [
            "applied", "applied"]
        assert len(store.list(f"heads/{workspace}")) == 2

    run(scenario())


def test_cloud_requires_the_opaque_head_object_then_trusts_its_bytes(tmp_path):
    async def scenario():
        secret, public, root, device_signature, device = world()
        removal_root = h(b"removal root")
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
                    root.fid, removal_root)).advance(
                        proof, forged_head, 10)
        assert cloud.get(f"heads/{root.fid}/{public}") is None

        # Existence is not content admission: an opaque malformed head is
        # accepted by the cloud and rejected only by a consuming peer.
        cloud.put_if_absent("obj/" + forged_head, b"missing opaque head")
        result = await OpaqueHeadGate(
            cloud,
            mechanical_head_authorizer(
                root.fid, removal_root)).advance(proof, forged_head, 10)
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
                root.fid, h(b"removal root")),
        )
        await gate.advance(
            proof_for(
                secret, public, root, device_signature,
                device, update.head_oid),
            update.head_oid,
            10,
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
