"""Self-confined removal-path codec and verification contracts."""

import asyncio
import json

import pytest

from core.crypto import h
from core.limits import MAX_REMOVAL_PATH_SCOPES, PayloadTooLarge
from core.removal_path import (
    ProofRefreshRequired,
    RemovalDenied,
    build,
    decode,
    encode,
    verify_clear,
)
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.suppression_tree import SuppressionTree


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
    state = SuppressionTree(workspace, FsStore(tmp_path / "store"))
    assert run(state.apply(tuple(
        (sid, suppression_slot()) for sid in own
    ) + ((hidden_sid, suppression_slot(hidden_action)),))).status == "applied"
    pin = run(state.pin())

    raw = encode(run(build(pin, reversed(own))))
    opened = decode(raw)

    assert tuple(sid for sid, _proof in opened.proofs) == tuple(sorted(own))
    assert hidden_sid.encode() not in raw
    assert hidden_action.encode() not in raw
    assert verify_clear(pin, raw, own) is True


def test_stale_active_missing_extra_and_relabelled_paths_fail_closed(tmp_path):
    workspace = h(b"binding workspace")
    sid = scoped_id("member", h(b"member"))
    state = SuppressionTree(workspace, FsStore(tmp_path / "store"))
    assert run(state.apply(((sid, suppression_slot()),))).status == "applied"
    stale = run(state.pin())
    stale_raw = encode(run(build(stale, (sid,))))

    assert run(state.apply((
        (sid, suppression_slot(h(b"removal"))),
    ))).status == "applied"
    current = run(state.pin())
    with pytest.raises(ProofRefreshRequired):
        verify_clear(current, stale_raw, (sid,))

    active_raw = encode(run(build(current, (sid,))))
    with pytest.raises(RemovalDenied):
        verify_clear(current, active_raw, (sid,))
    with pytest.raises(ValueError, match="scope set"):
        verify_clear(current, active_raw, ())
    with pytest.raises(ValueError, match="scope set"):
        verify_clear(current, active_raw, (sid, scoped_id("device", h(b"x"))))

    document = json.loads(active_raw)
    document["workspace"] = h(b"other workspace")
    with pytest.raises(ValueError):
        verify_clear(current, json.dumps(
            document, sort_keys=True, separators=(",", ":")).encode(), (sid,))


def test_scope_bound_stops_lazy_input_before_any_private_read(tmp_path):
    workspace = h(b"bound workspace")
    state = SuppressionTree(workspace, FsStore(tmp_path / "store"))
    sid = scoped_id("member", h(b"member"))
    assert run(state.apply(((sid, suppression_slot()),))).status == "applied"
    pin = run(state.pin())
    consumed = []

    def one_over():
        for index in range(MAX_REMOVAL_PATH_SCOPES + 100):
            consumed.append(index)
            yield scoped_id("member", h(str(index).encode()))

    with pytest.raises(PayloadTooLarge, match="too many"):
        run(build(pin, one_over()))
    assert consumed == list(range(MAX_REMOVAL_PATH_SCOPES + 1))
