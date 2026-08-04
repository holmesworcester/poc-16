"""A removed writer may deliver only its locally accepted terminal head."""

from contextlib import ExitStack

import facts
import pytest

from core import peer_capability
from core.access import ControlHeadRetry
from core.crypto import h, keypair
from core.writer_head import (
    HeadSlot,
    InvalidWriterHead,
    decode_head,
    decode_slot_at,
    encode_head,
    encode_slot,
    head_oid,
    head_slot_key,
    make_head,
)
from facts.auth.device import bind
from facts.auth.device_invite import grant
from facts.auth.device_removal import remove
from full_peer import sync as sync_module
from full_peer.node import FullPeer
from full_peer.walk import Peer

from .test_full_peer_writer_http_contract import _forest_fixture, _serve


def _slot(peer, workspace, device):
    key = head_slot_key(workspace, device)
    return decode_slot_at(key, peer.store(workspace).get(key))


def _enroll_secondary(alice, workspace):
    owner = alice.identity_id(workspace)
    bind(alice, workspace, "alice-primary")
    secret, device = keypair()
    alice.keychain.add_identity(secret)
    grant(alice, workspace, owner, device, "alice-secondary")
    return owner, secret, device


def _start_secondary_writer(alice, workspace, device):
    alice.bind_identity(workspace, device)
    facts.content.message.post(
        alice, workspace, "general", "before device removal", ts=40)


def test_terminal_device_head_survives_restart_and_exact_permit_retry(
        tmp_path, monkeypatch):
    workspace, alice, bob, carol = _forest_fixture(tmp_path)

    with ExitStack() as stack:
        full_url, _ = stack.enter_context(_serve(
            bob, sync_profile=peer_capability.FULL))
        hosted_url, _ = stack.enter_context(_serve(
            carol, sync_profile=peer_capability.OWNER))

        # Enroll the direct member at each recipient before that member binds
        # a secondary writer. This is the ordinary first-contact bootstrap.
        sync_module.sync(alice, workspace, full_url)
        sync_module.sync(alice, workspace, hosted_url)
        _owner, _secret, device = _enroll_secondary(alice, workspace)
        sync_module.sync(alice, workspace, full_url)
        sync_module.sync(alice, workspace, hosted_url)
        _start_secondary_writer(alice, workspace, device)

        # Establish the ordinary predecessor at both recipients. The hosted
        # peer receives only this dialer's writer; the full peer uses gossip.
        sync_module.sync(alice, workspace, full_url)
        sync_module.sync(alice, workspace, hosted_url)
        predecessor = _slot(alice, workspace, device).head
        assert _slot(bob, workspace, device).head == predecessor
        assert _slot(carol, workspace, device).head == predecessor

        remove(alice, workspace, device)
        terminal = _slot(alice, workspace, device).head
        assert terminal != predecessor
        assert alice.local_writer_binding(workspace) is None

        # Lose all process-local authoring/publication objects before the
        # terminal turn. Only the signed accepted repository and keychain live.
        alice.sql(workspace).db.close()
        restarted = FullPeer(alice.dir)
        assert restarted.identity_id(workspace) == device
        assert restarted.local_writer_binding(workspace) is None

        access = carol.access_gate(workspace)
        original_commit = access.commit_head_permit
        commit_attempts = 0

        async def lose_first_result(head_gate, permit, proposed, secret):
            nonlocal commit_attempts
            commit_attempts += 1
            result = await original_commit(
                head_gate, permit, proposed, secret)
            if commit_attempts == 1:
                raise ControlHeadRetry("lost terminal commit result")
            return result

        monkeypatch.setattr(
            access, "commit_head_permit", lose_first_result)
        requests = []

        class CountingPeer(Peer):
            def _http(self, method, path, data=None, *args, **kwargs):
                requests.append((method, path, data))
                return super()._http(
                    method, path, data, *args, **kwargs)

        async def no_delay(_attempt):
            return None

        monkeypatch.setattr(sync_module, "Peer", CountingPeer)
        monkeypatch.setattr(
            sync_module, "_control_head_retry_pause", no_delay)

        sync_module.sync(restarted, workspace, hosted_url)
        assert _slot(carol, workspace, device).head == terminal
        commits = [
            body for method, path, body in requests
            if (method, path) == (
                "POST", f"/head/{terminal}/commit")
        ]
        assert commit_attempts == 2
        assert len(commits) == 2 and commits[0] == commits[1]
        assert sum(
            (method, path) == ("POST", f"/head/{terminal}/permit")
            for method, path, _body in requests
        ) == 1

        # The normal all-writer mirror accepts that same signed terminal head.
        # It does not need or gain a second publication implementation.
        sync_module.sync(restarted, workspace, full_url)
        assert _slot(bob, workspace, device).head == terminal

    with pytest.raises(ValueError):
        facts.content.message.post(
            restarted, workspace, "general", "after device removal", ts=50)
    assert _slot(restarted, workspace, device).head == terminal


def test_missing_live_binding_does_not_publish_an_ordinary_head(
        tmp_path, monkeypatch):
    workspace, alice, _bob, carol = _forest_fixture(tmp_path)

    with _serve(
            carol, sync_profile=peer_capability.OWNER) as (url, _secret):
        sync_module.sync(alice, workspace, url)
        _owner, _secret, device = _enroll_secondary(alice, workspace)
        sync_module.sync(alice, workspace, url)
        _start_secondary_writer(alice, workspace, device)
        ordinary = _slot(alice, workspace, device).head
        monkeypatch.setattr(
            alice, "local_writer_binding", lambda _workspace: None)
        with pytest.raises(ValueError, match="terminal publication binding"):
            sync_module.sync(alice, workspace, url)

    assert carol.store(workspace).get(
        head_slot_key(workspace, device)) is None
    assert _slot(alice, workspace, device).head == ordinary


@pytest.mark.parametrize("forged_field", ("owner", "store"))
def test_terminal_fallback_rejects_signed_forged_binding(
        tmp_path, monkeypatch, forged_field):
    workspace, alice, _bob, _carol = _forest_fixture(tmp_path)
    owner, secret, device = _enroll_secondary(alice, workspace)
    _start_secondary_writer(alice, workspace, device)
    remove(alice, workspace, device)

    store = alice.store(workspace)
    key = head_slot_key(workspace, device)
    slot = _slot(alice, workspace, device)
    accepted = decode_head(store.get("obj/" + slot.head))
    forged = make_head(
        secret,
        workspace,
        device,
        h(b"forged owner") if forged_field == "owner" else owner,
        accepted.sequence,
        accepted.tree,
        h(b"forged store") if forged_field == "store" else accepted.store,
    )
    raw = encode_head(forged)
    oid = head_oid(raw)
    store.put_if_absent("obj/" + oid, raw)
    store._replace(key, encode_slot(HeadSlot(
        workspace, device, oid, slot.removal_root, slot.permit)))

    monkeypatch.setattr(
        alice, "local_writer_binding", lambda _workspace: None)
    monkeypatch.setattr(
        sync_module, "historical_owner",
        lambda _node, _workspace, _device: owner)

    with pytest.raises(InvalidWriterHead):
        sync_module._local_publication_binding(alice, workspace)
