"""ACTIVE rejection-path codec and exact-point privacy contracts."""

import asyncio
import pytest

from core.crypto import h
from core.limits import MAX_REMOVAL_PATH_SCOPES
from core.removal_path import RemovalPath, decode, encode
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.removal_tree import RemovalTree


def run(awaitable):
    return asyncio.run(awaitable)


def test_exact_caller_points_round_trip_without_neighbor_state(tmp_path):
    workspace = h(b"path workspace")
    own = (
        scoped_id("member", h(b"owner")),
        scoped_id("device", h(b"device")),
    )
    hidden_sid = scoped_id("member", h(b"hidden"))
    hidden_action = h(b"hidden removal")
    state = RemovalTree(workspace, FsStore(tmp_path / "store"))
    assert run(state.apply(tuple(
        (sid, suppression_slot()) for sid in own
    ) + ((hidden_sid, suppression_slot(hidden_action)),))).status == "applied"
    pin = run(state.pin())

    proofs = run(pin.proofs(sorted(own)))
    raw = encode(RemovalPath(workspace, pin.root_oid, proofs))
    opened = decode(raw)

    assert tuple(sid for sid, _proof in opened.proofs) == tuple(sorted(own))
    assert hidden_sid.encode() not in raw
    assert hidden_action.encode() not in raw
    assert tuple(
        pin.verify(sid, proof) for sid, proof in opened.proofs
    ) == (suppression_slot(), suppression_slot())


def test_codec_rejects_one_over_scope_bound_before_encoding():
    workspace = h(b"bound workspace")
    rows = tuple(
        (scoped_id("member", h(str(index).encode())), b"proof")
        for index in range(MAX_REMOVAL_PATH_SCOPES + 1)
    )
    with pytest.raises(ValueError, match="removal path"):
        RemovalPath(workspace, h(b"tip"), rows)
