"""Real admission, steady lookup, refresh, and rejection-path tests."""

import asyncio

import pytest

from core.access import AccessGate, LookupActive, LookupRefresh
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.removal_path import decode as decode_path
from core.object_store import REMOVAL_ROOT_KEY
from core.removal_state import RecipientRemovalState
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.writer_head import writer_store_binding
from core.writer_repository import WriterLog
from facts.auth._access import lookup_claim
from facts.auth.head_request import head_request
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.message import message


def run(awaitable):
    return asyncio.run(awaitable)


class TracingStore(FsStore):
    """Count authoritative reads without changing the store contract."""

    def __init__(self, root):
        super().__init__(root)
        self.reads = []

    def read_versioned(self, key):
        self.reads.append(("read_versioned", key))
        return super().read_versioned(key)

    def read_versioned_if_changed(self, key, token):
        self.reads.append(("read_versioned_if_changed", key))
        return super().read_versioned_if_changed(key, token)

    def get_bounded(self, key, maximum):
        self.reads.append(("get_bounded", key))
        return super().get_bounded(key, maximum)


def world():
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, "workspace", 1)
    invite_secret, invite_public = keypair()
    invited = user_invite(root.fid, founder, invite_public, 2)
    invited_sig = signature(founder_secret, founder, invited, 2)
    member_secret, member = keypair()
    joined = user(invited, invite_secret, member, "member", 3)
    joined_sig = signature(member_secret, member, joined, 3)
    return (
        root,
        member_secret,
        member,
        (root, invited_sig, invited, joined_sig, joined),
    )


def signed(secret, writer, root, facts_):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, facts_))


def access_proof(
        secret, member, root, membership=(), basis="", *, exp=1_000,
        owner=None):
    owner = member if owner is None else owner
    item = request(root.fid, member, owner, "sync", exp, basis, 5)
    if basis:
        return signed(secret, member, root, (item,))
    item_sig = signature(secret, member, item, 5)
    return signed(
        secret, member, root, (*membership, item_sig, item))


def head_proof(
        secret, member, root, membership, basis, proposed, *, owner=None):
    owner = member if owner is None else owner
    item = head_request(
        root.fid, member, owner, None, proposed, 1_000, basis, 6)
    return signed(secret, member, root, (item,))


def test_admission_is_evaluated_once_then_lookup_and_head_use_outer_signature(
        tmp_path):
    root, secret, member, membership = world()
    store = FsStore(tmp_path / "store")
    gate = AccessGate(root.fid, store)

    admitted = run(gate.authorize_access(
        access_proof(secret, member, root, membership), 10))
    assert admitted[:2] == (member, "sync")
    tip = admitted[2]
    assert run(gate.state.pin()).root_oid == tip

    # The steady request contains only the ephemeral request fact. Its outer
    # signed-pile signature is the device binding; no admission chain is
    # re-presented or drained.
    assert run(gate.authorize_access(
        access_proof(secret, member, root, basis=tip), 10,
    )) == (member, "sync", tip)

    content = message(root.fid, member, "general", "ordinary", 7)
    content_signature = signature(secret, member, content, 7)
    writer = WriterLog(
        root.fid,
        member,
        member,
        writer_store_binding(root.fid, member),
        secret,
        store,
    )
    update = run(writer.prepare((
        (*membership, content_signature, content),
    )))
    run(writer.establish(update))
    grant = run(gate.authorize_head(
        head_proof(
            secret, member, root, membership, tip, update.head_oid),
        update.head_oid,
        10,
    ))
    assert (grant.workspace, grant.device, grant.head, grant.removal_root) == (
        root.fid, member, update.head_oid, tip)


def test_stale_clear_refreshes_but_active_returns_own_path_and_tip(tmp_path):
    root, secret, member, membership = world()
    gate = AccessGate(root.fid, FsStore(tmp_path / "store"))
    old_tip = run(gate.authorize_access(
        access_proof(secret, member, root, membership), 10))[2]

    assert run(gate.state.tree.apply(((
        scoped_id("member", h(b"unrelated")), suppression_slot()),
    ))).status == "applied"
    with pytest.raises(LookupRefresh) as refresh:
        run(gate.authorize_access(
            access_proof(secret, member, root, basis=old_tip), 10))
    assert refresh.value.tip == run(gate.state.pin()).root_oid

    assert run(gate.state.tree.apply(((
        scoped_id("member", member),
        suppression_slot(h(b"remove member"))),
    ))).status == "applied"
    with pytest.raises(LookupActive) as denied:
        run(gate.authorize_access(
            access_proof(
                secret, member, root, basis=refresh.value.tip), 10))
    rejection = decode_path(denied.value.path)
    identity = lookup_claim(member, member)
    assert denied.value.tip == rejection.root
    assert tuple(sid for sid, _proof in rejection.proofs) == identity.scopes


def test_known_device_cannot_relabel_itself_as_another_clear_member(tmp_path):
    root, secret, member, membership = world()
    gate = AccessGate(root.fid, FsStore(tmp_path / "store"))
    tip = run(gate.authorize_access(
        access_proof(secret, member, root, membership), 10))[2]
    _other_secret, other = keypair()
    assert run(gate.state.tree.apply((
        (scoped_id("member", other), suppression_slot()),
    ))).status == "applied"

    # The member and device cells alone are insufficient. The exact
    # subject:<device>:<owner> admission row is absent, so this is UNKNOWN.
    assert run(gate.authorize_access(access_proof(
        secret, member, root, basis=tip, owner=other), 10)) is None


def test_active_row_rejects_even_before_subject_ever_admits_here(tmp_path):
    """An ACTIVE row is itself the recipient's historical admission record."""
    root, secret, member, _membership = world()
    gate = AccessGate(root.fid, FsStore(tmp_path / "store"))
    member_sid = scoped_id("member", member)
    assert run(gate.state.tree.apply(((
        member_sid, suppression_slot(h(b"remove before first mint"))),
    ))).status == "applied"

    with pytest.raises(LookupActive) as denied:
        run(gate.authorize_access(
            access_proof(secret, member, root), 10))
    path = decode_path(denied.value.path)
    assert tuple(sid for sid, _proof in path.proofs) == (member_sid,)
    assert path.root == denied.value.tip


def test_cold_and_warm_lookup_each_verify_one_signature_and_walk_no_nodes(
        tmp_path, monkeypatch):
    """A cold gate fetches the materialized root; a warm gate uses its cache.

    Both turns still validate the live root with exactly one versioned read,
    and neither performs a provider read for a Patricia node.
    """
    import core.close as close

    root, secret, member, membership = world()
    store = TracingStore(tmp_path / "store")
    admitted_by = AccessGate(root.fid, store)
    tip = run(admitted_by.authorize_access(
        access_proof(secret, member, root, membership), 10))[2]
    proof = access_proof(secret, member, root, basis=tip)

    original_verify = close.verify
    verified = []

    def counted_verify(*args):
        verified.append(args)
        return original_verify(*args)

    monkeypatch.setattr(close, "verify", counted_verify)
    cold = AccessGate(root.fid, store)
    for turn, expected_cache_entries in enumerate((1, 1)):
        store.reads.clear()
        verified.clear()
        assert run(cold.authorize_access(proof, 10)) == (
            member, "sync", tip)
        assert len(verified) == 1
        assert store.reads.count(("read_versioned", REMOVAL_ROOT_KEY)) == 1
        assert store.reads.count((
            "read_versioned_if_changed", REMOVAL_ROOT_KEY)) == turn
        assert not any(
            operation == "get_bounded" and key.startswith("removal-node/")
            for operation, key in store.reads)
        assert len(cold._lookup_cache) == expected_cache_entries


def test_three_recipients_fold_permuted_control_facts_to_one_tip_and_judgment(
        tmp_path):
    """Control arrival order cannot change CLEAR/ACTIVE lookup decisions."""
    # Construct two independently signed, competing removals of the same
    # member. The ACI cell must select the same immutable action in either
    # arrival order.
    from tests.test_removal_state import signed as control_signed
    from tests.test_removal_state import world as control_world
    from facts.auth.removal import removal

    value = control_world()
    controls = []
    for ts in (7, 8):
        item = removal(
            value.root.fid, value.founder, value.member, ts)
        item_sig = signature(
            value.founder_secret, value.founder, item, ts)
        controls.append(control_signed(
            value.founder_secret,
            value.founder,
            value.root,
            (*value.membership, item_sig, item),
        ))

    tips = []
    decisions = []
    for index, order in enumerate(((0, 1), (1, 0), (0, 1))):
        store = FsStore(tmp_path / f"recipient-{index}")
        state = RecipientRemovalState(value.root.fid, store)
        assert run(state.bootstrap(control_signed(
            value.founder_secret,
            value.founder,
            value.root,
            (value.root,),
        ))).status == "applied"
        assert run(state.bootstrap(control_signed(
            value.member_secret,
            value.member,
            value.root,
            value.membership,
        ))).status == "applied"
        for selected in order:
            assert run(state.apply_control(
                controls[selected], value.founder)).status in {
                    "applied", "noop"}

        gate = AccessGate(value.root.fid, store)
        tip = run(state.pin()).root_oid
        assert run(gate.authorize_access(access_proof(
            value.founder_secret,
            value.founder,
            value.root,
            basis=tip,
        ), 10)) == (value.founder, "sync", tip)
        with pytest.raises(LookupActive) as active:
            run(gate.authorize_access(access_proof(
                value.member_secret,
                value.member,
                value.root,
                basis=tip,
            ), 10))
        path = decode_path(active.value.path)
        tips.append(tip)
        decisions.append((
            active.value.tip,
            tuple(sid for sid, _proof in path.proofs),
        ))

    assert len(set(tips)) == 1
    assert len(set(decisions)) == 1
