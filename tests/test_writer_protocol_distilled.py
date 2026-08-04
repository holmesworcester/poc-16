"""Distilled POC-10/17 black-box tests for per-device writer trees."""
import asyncio

from core.close import (
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
    signed_pile_oid,
)
from core.crypto import h, keypair
from core.fact import decode
from core.store import FsStore
from core.writer_head import (
    WriterBinding,
    decode_slot_at,
    head_slot_key,
    head_slot_prefix,
)
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from facts.auth.device import device as device_fact
from facts.auth.device_invite import device_invite
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message as message_fact


def run(awaitable):
    return asyncio.run(awaitable)


class ReadTracingFsStore(FsStore):
    """A real filesystem store that records bounded protocol reads."""

    def __init__(self, root):
        super().__init__(root)
        self.bounded_reads = []
        self.pile_reads = []

    def get_bounded(self, key, max_bytes):
        self.bounded_reads.append(key)
        return super().get_bounded(key, max_bytes)

    def copy_pile_object(self, oid, max_bytes, write):
        self.pile_reads.append("obj/" + oid)
        return super().copy_pile_object(oid, max_bytes, write)

    def clear_reads(self):
        self.bounded_reads.clear()
        self.pile_reads.clear()


def primary_authority(name="alice"):
    secret, public = keypair()
    root = workspace_fact(secret, public, name, 1)
    device = device_fact(root.fid, public, "primary", 2)
    device_signature = signature_fact(secret, public, device, 2)
    return secret, public, root, (
        root, device_signature, device)


def message_closure(secret, writer, owner, authority, text, timestamp):
    root = authority[0]
    message = message_fact(
        root.fid, writer, "general", text, timestamp, owner=owner)
    message_signature = signature_fact(
        secret, writer, message, timestamp)
    return (*authority, message_signature, message)


def authority_proof(
        secret, writer, owner, authority, proposed_head, *,
        base_head=None, timestamp=100):
    root = authority[0]
    request = head_request(
        root.fid,
        writer,
        owner,
        base_head,
        proposed_head,
        1_000_000,
        b"mechanical removal path",
        timestamp,
    )
    request_signature = signature_fact(
        secret, writer, request, timestamp)
    return encode_signed_pile(make_signed_pile(
        secret,
        root.fid,
        writer,
        (*authority, request_signature, request),
    ))


def resolver(bindings, removal_root):
    def resolve(
            workspace, device, candidate_removal_root, _candidate):
        binding = bindings.get(device)
        if candidate_removal_root != removal_root \
                or binding is None \
                or binding.workspace != workspace:
            return None
        return binding
    return resolve


def message_texts(consumer):
    return {
        fact.body["text"]
        for fid in consumer.fact_ids()
        if (fact := decode(consumer.fact_bytes(fid))).t == "msg"
    }


def test_same_device_stale_base_race_has_one_winner_and_retryable_loser(
        tmp_path):
    async def scenario():
        secret, writer, root, authority = primary_authority()
        store_binding = h(b"same-device-store")
        removal_root = h(b"current-removal-root")
        source = FsStore(str(tmp_path / "source"))
        log = WriterLog(
            root.fid, writer, writer, store_binding, secret, source)
        gate = OpaqueHeadGate(
            source,
            mechanical_head_authorizer(
                root.fid, removal_root),
        )

        initial = await log.prepare((authority,))
        await log.establish(initial)
        initial_result = await gate.advance(
            authority_proof(
                secret, writer, writer, authority,
                initial.head_oid, timestamp=101),
            initial.head_oid,
            10,
        )
        assert initial_result.status == "applied"

        closures = (
            message_closure(
                secret, writer, writer, authority, "left", 200),
            message_closure(
                secret, writer, writer, authority, "right", 201),
        )
        # Both candidates read the same accepted slot before either publishes.
        candidates = (
            await log.prepare((closures[0],)),
            await log.prepare((closures[1],)),
        )
        assert candidates[0].base_head == candidates[1].base_head \
            == initial.head_oid
        for candidate in candidates:
            await log.establish(candidate)

        outcomes = await asyncio.gather(*(
            gate.advance(
                authority_proof(
                    secret,
                    writer,
                    writer,
                    authority,
                    candidate.head_oid,
                    base_head=candidate.base_head,
                    timestamp=210 + ordinal,
                ),
                candidate.head_oid,
                10,
            )
            for ordinal, candidate in enumerate(candidates)
        ))
        statuses = tuple(outcome.status for outcome in outcomes)
        assert sorted(statuses) == ["applied", "retryable"]

        winner = statuses.index("applied")
        loser = 1 - winner
        key = head_slot_key(root.fid, writer)
        winning_head = candidates[winner].head_oid
        assert decode_slot_at(key, source.get(key)).head == winning_head

        # Replaying the stale proposal cannot overwrite the winning slot.
        stale_again = await gate.advance(
            authority_proof(
                secret,
                writer,
                writer,
                authority,
                candidates[loser].head_oid,
                base_head=candidates[loser].base_head,
                timestamp=220,
            ),
            candidates[loser].head_oid,
            10,
        )
        assert stale_again.status == "retryable"
        assert decode_slot_at(key, source.get(key)).head == winning_head

        # Retry means rebase, not force: the losing closure appends after the
        # winner and both publications become visible through ordinary sync.
        rebased = await log.prepare((closures[loser],))
        assert rebased.base_head == winning_head
        await log.establish(rebased)
        applied = await gate.advance(
            authority_proof(
                secret,
                writer,
                writer,
                authority,
                rebased.head_oid,
                base_head=rebased.base_head,
                timestamp=230,
            ),
            rebased.head_oid,
            10,
        )
        assert applied.status == "applied"

        consumer = FactConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            FsStore(str(tmp_path / "receiver")),
            resolver({
                writer: WriterBinding(
                    root.fid, writer, writer, store_binding),
            }, removal_root),
            consumer,
        )
        synced = await mirror.sync_from(source)
        assert synced.errors == ()
        assert synced.changed == 1
        assert synced.piles == 3
        assert message_texts(consumer) == {"left", "right"}

    run(scenario())


def test_duplicate_sync_is_noop_and_warm_append_fetches_only_new_pile(
        tmp_path):
    async def scenario():
        secret, writer, root, authority = primary_authority()
        store_binding = h(b"warm-writer-store")
        removal_root = h(b"current-removal-root")
        source = ReadTracingFsStore(str(tmp_path / "source"))
        receiver = FsStore(str(tmp_path / "receiver"))
        log = WriterLog(
            root.fid, writer, writer, store_binding, secret, source)
        gate = OpaqueHeadGate(
            source,
            mechanical_head_authorizer(
                root.fid, removal_root),
        )
        consumer = FactConsumer(root.fid)
        mirror = RepositoryMirror(
            root.fid,
            receiver,
            resolver({
                writer: WriterBinding(
                    root.fid, writer, writer, store_binding),
            }, removal_root),
            consumer,
        )

        initial = await log.prepare((authority,))
        await log.establish(initial)
        proof = authority_proof(
            secret, writer, writer, authority,
            initial.head_oid, timestamp=101)
        assert (await gate.advance(
            proof, initial.head_oid, 10)).status == "applied"
        initial_pile_oid = signed_pile_oid(initial.piles[0])

        cold = await mirror.sync_from(source)
        assert cold.errors == ()
        assert cold.changed == cold.piles == 1
        accepted_facts = consumer.fact_ids()

        # The publisher and receiver both treat exact duplicates as no-ops.
        assert (await gate.advance(
            proof, initial.head_oid, 10)).status == "noop"
        source.clear_reads()
        duplicate = await mirror.sync_from(source)
        assert duplicate.changed == duplicate.piles == duplicate.facts == 0
        assert consumer.fact_ids() == accepted_facts
        assert f"obj/{initial_pile_oid}" not in source.bounded_reads

        closure = message_closure(
            secret, writer, writer, authority, "warm append", 200)
        update = await log.prepare((closure,))
        await log.establish(update)
        assert (await gate.advance(
            authority_proof(
                secret,
                writer,
                writer,
                authority,
                update.head_oid,
                base_head=update.base_head,
                timestamp=201,
            ),
            update.head_oid,
            10,
        )).status == "applied"
        new_pile_oid = signed_pile_oid(update.piles[0])
        source.clear_reads()

        warm = await mirror.sync_from(source)
        assert warm.errors == ()
        assert warm.changed == warm.piles == 1
        assert message_texts(consumer) == {"warm append"}
        # RBSR may fetch the new head and changed Merkle pages, but semantic
        # consumption fetches exactly the new indivisible closed pile.
        assert source.pile_reads.count(f"obj/{new_pile_oid}") == 1
        assert f"obj/{initial_pile_oid}" not in source.pile_reads

        raw = source.get(f"obj/{new_pile_oid}")
        fetched = decode_signed_pile(
            raw, workspace=root.fid, writer=writer)
        assert tuple(fact.fid for fact in fetched.facts) == tuple(
            fact.fid for fact in closure)

    run(scenario())


def test_shuffled_device_publication_orders_converge_by_paginated_directory(
        tmp_path):
    async def scenario():
        owner_secret, owner, root, primary = primary_authority()
        removal_root = h(b"directory-removal-root")
        entries = []

        primary_binding = WriterBinding(
            root.fid, owner, owner, h(b"primary-store"))
        entries.append((
            owner_secret, owner, primary, primary_binding,
        ))
        for ordinal in range(1, 4):
            secret, device = keypair()
            grant = device_invite(
                root.fid,
                owner,
                device,
                f"sibling-{ordinal}",
                10 + ordinal,
            )
            grant_signature = signature_fact(
                owner_secret, owner, grant, 10 + ordinal)
            authority = (*primary, grant_signature, grant)
            entries.append((
                secret,
                device,
                authority,
                WriterBinding(
                    root.fid,
                    device,
                    owner,
                    h(f"sibling-store-{ordinal}".encode()),
                ),
            ))

        # Prepare once, then publish identical immutable updates to two stores
        # in deliberately different insertion orders.
        prepared = []
        for ordinal, (secret, device, authority, binding) in enumerate(entries):
            local = FsStore(str(tmp_path / f"writer-{ordinal}"))
            log = WriterLog(
                root.fid,
                device,
                owner,
                binding.store,
                secret,
                local,
            )
            update = await log.prepare((authority,))
            prepared.append((log, update, secret, device, authority, binding))

        canonical = sorted(prepared, key=lambda item: item[3])
        orders = (
            (canonical[2], canonical[0], canonical[3], canonical[1]),
            tuple(reversed(canonical)),
        )
        bindings = {entry[3]: entry[5] for entry in prepared}
        consumers = []
        receiver_stores = []

        for cloud_ordinal, order in enumerate(orders):
            cloud = FsStore(str(tmp_path / f"cloud-{cloud_ordinal}"))
            for proof_ordinal, (
                    log, update, secret, device, authority, _binding,
                    ) in enumerate(order):
                await log.establish(update, cloud)
                gate = OpaqueHeadGate(
                    cloud,
                    mechanical_head_authorizer(
                        root.fid, removal_root),
                )
                result = await gate.advance(
                    authority_proof(
                        secret,
                        device,
                        owner,
                        authority,
                        update.head_oid,
                        timestamp=100 + proof_ordinal,
                    ),
                    update.head_oid,
                    10,
                )
                assert result.status == "applied"

            # One-key pages force the whole directory cursor path. FsStore's
            # canonical listing erases insertion order, as a provider may.
            consumer = FactConsumer(root.fid)
            receiver_store = FsStore(
                str(tmp_path / f"receiver-{cloud_ordinal}"))
            mirror = RepositoryMirror(
                root.fid,
                receiver_store,
                resolver(bindings, removal_root),
                consumer,
            )
            result = await mirror.sync_from(cloud, page_limit=1)
            assert result.errors == ()
            assert result.listed == result.changed == result.piles == 4
            assert cloud.list(head_slot_prefix(root.fid)) == sorted(
                head_slot_key(root.fid, device) for device in bindings)
            consumers.append(consumer)
            receiver_stores.append(receiver_store)

        assert consumers[0].fact_ids() == consumers[1].fact_ids()
        assert receiver_stores[0].list(
            head_slot_prefix(root.fid)) == receiver_stores[1].list(
                head_slot_prefix(root.fid))
        for key in receiver_stores[0].list(head_slot_prefix(root.fid)):
            assert receiver_stores[0].get(key) == receiver_stores[1].get(key)

    run(scenario())
