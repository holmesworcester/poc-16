"""Distilled POC-10/17 black-box scenarios over the target core surface."""
import asyncio

from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.fact import decode
from core.store import FsStore
from core.writer_head import WriterBinding
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


def authority_proof(
        secret, writer, owner, root, authority_closure, proposed_head, ts,
        base_head=None):
    request = head_request(
        root.fid, writer, owner, base_head,
        proposed_head, 1_000_000, ts)
    signed = signature_fact(secret, writer, request, ts)
    return encode_signed_pile(make_signed_pile(
        secret,
        root.fid,
        writer,
        (*authority_closure, signed, request),
    ))


def test_three_peer_relay_offline_catchup_and_second_device(tmp_path):
    async def scenario():
        alice_secret, alice = keypair()
        bob_secret, bob = keypair()
        root = workspace_fact(alice_secret, alice, "workspace", 1)
        primary = device_fact(root.fid, alice, "alice-phone", 2)
        primary_sig = signature_fact(
            alice_secret, alice, primary, 2)
        sibling = device_invite(
            root.fid, alice, alice, bob, "alice-laptop", 3)
        sibling_sig = signature_fact(
            alice_secret, alice, sibling, 3)
        authority = (
            root, primary_sig, primary, sibling_sig, sibling)

        alice_store = FsStore(str(tmp_path / "alice"))
        bob_store = FsStore(str(tmp_path / "bob"))
        carol_store = FsStore(str(tmp_path / "carol"))
        authority_root = h(b"current-authority")
        authorize = mechanical_head_authorizer(
            root.fid, authority_root, 10)
        bindings = {
            alice: WriterBinding(
                root.fid, alice, alice, h(b"alice-store")),
            bob: WriterBinding(
                root.fid, bob, alice, h(b"bob-store")),
        }

        def binding_for(workspace, device, _authority_root, _candidate):
            binding = bindings.get(device)
            return binding if binding is not None \
                and binding.workspace == workspace else None

        # Alice publishes the authority closure and a message in one complete
        # leaf. Bob has no connection to Carol yet.
        alice_message = message_fact(
            root.fid, alice, "general", "from alice", 10)
        alice_message_sig = signature_fact(
            alice_secret, alice, alice_message, 10)
        alice_log = WriterLog(
            root.fid, alice, alice, bindings[alice].store,
            alice_secret, alice_store)
        alice_update = await alice_log.prepare(((*authority,
            alice_message_sig, alice_message),))
        await alice_log.establish(alice_update)
        await OpaqueHeadGate(alice_store, authorize).advance(
            authority_proof(
                alice_secret, alice, alice, root,
                (root, primary_sig, primary),
                alice_update.head_oid, 20),
            alice_update.head_oid,
        )

        # Bob consumes Alice before it can relay Alice onward.
        bob_consumer = FactConsumer(root.fid)
        bob_mirror = RepositoryMirror(
            root.fid, bob_store, binding_for, bob_consumer)
        first = await bob_mirror.sync_from(alice_store)
        assert first.changed == first.piles == 1
        assert first.errors == ()

        # Bob is Alice's second device: a separate root and mutable slot, but
        # the same durable owner. It authors while Carol remains offline.
        bob_message = message_fact(
            root.fid, bob, "general", "from second device", 30,
            owner=alice)
        bob_message_sig = signature_fact(
            bob_secret, bob, bob_message, 30)
        bob_log = WriterLog(
            root.fid, bob, alice, bindings[bob].store,
            bob_secret, bob_store)
        bob_update = await bob_log.prepare(((*authority,
            bob_message_sig, bob_message),))
        await bob_log.establish(bob_update)
        await OpaqueHeadGate(bob_store, authorize).advance(
            authority_proof(
                bob_secret, bob, alice, root, authority,
                bob_update.head_oid, 31),
            bob_update.head_oid,
        )

        # Carol connects only to Bob. Bob relays Alice's original accepted
        # head/tree/pile alongside its own; no A-C connection or combined log.
        carol_consumer = FactConsumer(root.fid)
        carol = RepositoryMirror(
            root.fid, carol_store, binding_for, carol_consumer)
        relayed = await carol.sync_from(bob_store)
        assert relayed.listed == relayed.changed == relayed.piles == 2
        assert relayed.errors == ()
        messages = {
            fact.body["text"]
            for fid in carol_consumer.fact_ids()
            if (fact := decode(carol_consumer.fact_bytes(fid))).t == "msg"
        }
        assert messages == {"from alice", "from second device"}

        # Alice appends while Carol is offline. Bob's warm RBSR fetches just
        # that new leaf; Carol then obtains it through the same Bob relay.
        late = message_fact(
            root.fid, alice, "general", "offline catchup", 40)
        late_sig = signature_fact(alice_secret, alice, late, 40)
        late_update = await alice_log.prepare((
            (root, late_sig, late),))
        await alice_log.establish(late_update)
        await OpaqueHeadGate(alice_store, authorize).advance(
            authority_proof(
                alice_secret, alice, alice, root,
                (root, primary_sig, primary),
                late_update.head_oid, 41, late_update.base_head),
            late_update.head_oid,
        )
        warm = await bob_mirror.sync_from(alice_store)
        assert warm.changed == warm.piles == 1
        catchup = await carol.sync_from(bob_store)
        assert catchup.changed == catchup.piles == 1
        assert "offline catchup" in {
            decode(carol_consumer.fact_bytes(fid)).body.get("text")
            for fid in carol_consumer.fact_ids()
        }

    run(scenario())


def test_workspace_directory_prefixes_do_not_cross(tmp_path):
    async def scenario():
        shared = FsStore(str(tmp_path / "shared"))
        receivers = []
        expected = []
        for ordinal in (1, 2):
            secret, public = keypair()
            root = workspace_fact(secret, public, f"ws-{ordinal}", ordinal)
            device = device_fact(root.fid, public, "device", ordinal + 2)
            device_sig = signature_fact(
                secret, public, device, ordinal + 2)
            binding = WriterBinding(
                root.fid, public, public,
                h(f"store-{ordinal}".encode()))
            local = FsStore(str(tmp_path / f"writer-{ordinal}"))
            log = WriterLog(
                root.fid, public, public, binding.store, secret, local)
            update = await log.prepare(((root, device_sig, device),))
            await log.establish(update, shared)
            request = authority_proof(
                secret, public, public, root,
                (root, device_sig, device), update.head_oid, 20)
            authorize = mechanical_head_authorizer(
                root.fid, h(f"auth-{ordinal}".encode()), 10)
            await OpaqueHeadGate(shared, authorize).advance(
                request, update.head_oid)
            consumer = FactConsumer(root.fid)
            receiver = RepositoryMirror(
                root.fid,
                FsStore(str(tmp_path / f"receiver-{ordinal}")),
                lambda workspace, device_key, _authority, _candidate,
                wanted=binding: wanted if (
                    workspace, device_key) == (
                        wanted.workspace, wanted.device) else None,
                consumer,
            )
            receivers.append(receiver)
            expected.append((root, consumer))

        for receiver, (root, consumer) in zip(receivers, expected):
            result = await receiver.sync_from(shared)
            assert result.listed == result.changed == result.piles == 1
            assert root.fid in consumer.fact_ids()
            assert all(
                decode(consumer.fact_bytes(fid)).ws in {None, root.fid}
                for fid in consumer.fact_ids())

    run(scenario())
