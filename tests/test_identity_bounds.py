"""Identity-family display fields share one UTF-8 byte ceiling."""

import pytest

from core.crypto import keypair
from core.fact import Fact
from core.kernel import drain
from facts.auth._display import MAX_DISPLAY_BYTES
from facts.auth.device import device
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace


def _rebody(item, **changes):
    return Fact(
        item.t,
        item.ts,
        item.atoms,
        {**item.body, **changes},
        item.ws,
    )


def _signed(secret, public, item):
    return signature(secret, public, item, item.ts)


def test_identity_display_facts_use_one_utf8_byte_bound():
    exact = "é" * 127 + "a"
    oversized = exact + "b"
    assert len(exact.encode()) == MAX_DISPLAY_BYTES
    assert len(oversized.encode()) == MAX_DISPLAY_BYTES + 1

    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, exact, 1)
    hostile_root = _rebody(root, name=oversized)
    assert drain((root,), root.fid).ok
    assert not drain((hostile_root,), hostile_root.fid).ok
    with pytest.raises(ValueError, match="display"):
        workspace(founder_secret, founder, oversized, 1)

    invite_secret, invite_public = keypair()
    invitation = user_invite(root.fid, founder, invite_public, 2)
    invitation_signature = _signed(
        founder_secret, founder, invitation)
    member_secret, member = keypair()
    joined = user(invitation, invite_secret, member, exact, 3)
    joined_signature = _signed(member_secret, member, joined)
    user_base = (root, invitation_signature, invitation)
    assert drain(user_base + (joined_signature, joined), root.fid).ok
    hostile_user = _rebody(joined, name=oversized)
    assert not drain(user_base + (
        _signed(member_secret, member, hostile_user),
        hostile_user,
    ), root.fid).ok
    with pytest.raises(ValueError, match="display"):
        user(invitation, invite_secret, member, oversized, 3)

    primary = device(root.fid, founder, exact, 4)
    primary_signature = _signed(founder_secret, founder, primary)
    device_base = (root, primary_signature, primary)
    assert drain(device_base, root.fid).ok
    hostile_device = _rebody(primary, label=oversized)
    assert not drain((
        root,
        _signed(founder_secret, founder, hostile_device),
        hostile_device,
    ), root.fid).ok
    with pytest.raises(ValueError, match="display"):
        device(root.fid, founder, oversized, 4)

    _, sibling = keypair()
    granted = device_invite(
        root.fid, founder, sibling, exact, 5)
    assert drain(device_base + (
        _signed(founder_secret, founder, granted),
        granted,
    ), root.fid).ok
    hostile_grant = _rebody(granted, label=oversized)
    assert not drain(device_base + (
        _signed(founder_secret, founder, hostile_grant),
        hostile_grant,
    ), root.fid).ok
    with pytest.raises(ValueError, match="display"):
        device_invite(root.fid, founder, sibling, oversized, 5)
