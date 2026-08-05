"""Full-peer SQL is a disposable sink behind the core writer consumer."""
import asyncio

import facts
import pytest

from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.fact import encode
from core.store import FsStore
from core.writer_head import WriterBinding, writer_store_binding
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from tests.util import mechanical_head_authorizer
from facts.auth.device import device as device_fact
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from facts.auth.workspace import workspace as workspace_fact
from full_peer.sql_store import SqlStore


def test_sql_fact_reads_reject_foreign_and_corrupt_rows(tmp_path):
    first_secret, first_public = keypair()
    first = workspace_fact(first_secret, first_public, "first", 1)
    second_secret, second_public = keypair()
    second = workspace_fact(second_secret, second_public, "second", 1)
    projection = SqlStore.open(str(tmp_path / "projection.db"), first.fid)

    projection.db.execute(
        "INSERT INTO facts(fid, blob) VALUES(?, ?)",
        (second.fid, encode(second)),
    )
    projection.db.execute(
        "INSERT INTO facts(fid, blob) VALUES(?, ?)",
        (first.fid, b"not canonical fact bytes"),
    )
    projection.db.commit()

    with pytest.raises(ValueError, match="integrity"):
        projection.fact_of(second.fid)
    with pytest.raises(ValueError):
        projection.fact_of(first.fid)


def test_sql_checkpoint_restart_and_wipe_replay_the_accepted_tree(tmp_path):
    async def scenario():
        secret, public = keypair()
        root = workspace_fact(secret, public, "alice", 1)
        device = device_fact(root.fid, public, "laptop", 2)
        device_signature = signature_fact(secret, public, device, 2)
        binding = writer_store_binding(root.fid, public)
        removal_root = h(b"removal root")
        source = FsStore(str(tmp_path / "source"))
        local = FsStore(str(tmp_path / "local"))
        database = str(tmp_path / "projection.db")

        log = WriterLog(
            root.fid, public, public, binding, secret, source)
        update = await log.prepare(((
            root, device_signature, device),))
        await log.establish(update)
        request = head_request(
            root.fid, public, public, None,
            update.head_oid, 1_000, h(b"mechanical removal path"), 3)
        request_signature = signature_fact(
            secret, public, request, 3)
        proof = encode_signed_pile(make_signed_pile(
            secret,
            root.fid,
            public,
            (root, device_signature, device,
             request_signature, request),
        ))
        assert (await OpaqueHeadGate(
            source,
            mechanical_head_authorizer(
                root.fid, removal_root)).advance(
                proof, update.head_oid, 10)).status == "applied"

        def binding_for(
                workspace, writer, selected_removal, _candidate):
            if (workspace, writer, selected_removal) != (
                    root.fid, public, removal_root):
                return None
            return WriterBinding(
                root.fid, public, public, binding)

        projection = SqlStore.open(database, root.fid)
        consumer = FactConsumer(root.fid, projection)
        mirror = RepositoryMirror(
            root.fid, local, binding_for, consumer)
        first = await mirror.sync_from(source)
        assert first.errors == ()
        assert projection.projected_head(public) == update.head_oid
        assert projection.fact_of(root.fid) == root
        projection.db.close()

        # An ordinary restart preserves the transactional projection stamp.
        projection = SqlStore.open(database, root.fid)
        restarted = RepositoryMirror(
            root.fid, local, binding_for,
            FactConsumer(root.fid, projection),
        )
        unchanged = await restarted.sync_from(source)
        assert unchanged.changed == unchanged.piles == unchanged.facts == 0

        # Deleting/reinitializing SQL changes no accepted protocol state. The
        # same core mirror replays the locally accepted tree from an empty
        # per-writer checkpoint; it does not ask the remote for old piles.
        projection.reset()
        rebuilt = await restarted.sync_from(source)
        assert rebuilt.errors == ()
        assert rebuilt.changed == 0
        assert rebuilt.piles == 1
        assert projection.projected_head(public) == update.head_oid
        assert projection.fact_of(root.fid) == root
        projection.db.close()

    asyncio.run(scenario())


def test_full_peer_projection_rebuild_never_republishes_writer_state(
        tmp_path):
    from full_peer.node import FullPeer

    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    message = facts.content.message.post(
        node, workspace, "general", "stable", ts=2)
    store = node.store(workspace)
    before = {
        key: store.get(key)
        for key in store.list("")
    }

    node.rebuild(workspace)

    assert node.fact_of(workspace, message).fid == message
    assert {
        key: store.get(key)
        for key in store.list("")
    } == before
    with pytest.raises(ValueError, match="never rebuilt"):
        node.rebuild(workspace, republish=True)
