"""Running OPEN/ISSUE/FINALIZE boundary for direct upload sessions."""
import asyncio
import base64
from dataclasses import fields, replace
import json
import random

import facts
import pytest

from core.close import encode_pile
from core.crypto import h
from core.limits import MAX_OBJECT_BYTES, MAX_PILE_BYTES, PAGE_BATCH
from full_peer.node import FullPeer
from core.staged_intent import staging_key
from core.http import AsyncFromSyncReader, HttpGate
from deploy.upload_broker import (
    AuthorizedPut,
    MAX_CAPABILITY_DOCUMENT_BYTES,
    MAX_CAPABILITY_HEADERS,
    MAX_CAPABILITY_HEADER_NAME_BYTES,
    MAX_CAPABILITY_HEADER_VALUE_BYTES,
    MAX_CAPABILITY_QUERY_BYTES,
    MAX_CAPABILITY_URL_BYTES,
    UploadBroker,
    UploadUnavailable,
    encode_finalize,
    encode_issue,
    encode_open,
    finalize_document,
    issue_document,
    open_document,
)
from deploy.upload_wire import (
    MAX_ISSUE_RESPONSE_BYTES,
    FinalizedUpload,
    IssuedUpload,
    OpenedUpload,
    UploadCapability,
)
from deploy import upload_session as session_codec
from deploy.upload_session import (
    InvalidUploadSession,
    MAX_SESSION_BYTES,
    MAX_SESSION_OBJECTS,
    SessionKey,
    TOKEN_BYTES,
    UploadLeaf,
    UploadManifest,
    UploadSessionPolicy,
    UploadVector,
)
from facts.auth import request
from .util import add_member


NOW = 100_000
SESSION = bytes.fromhex("d" * 32)
OLD_KEY = SessionKey("key00001", b"k" * 32, 0, 10**12)
NEW_KEY = SessionKey("key00002", b"n" * 32, 0, 10**12)


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


class RecordingSigner:
    provider_binding = "test-ingress-v1"

    def __init__(self, clock, lifetime_ms=60_000):
        self.clock = clock
        self.lifetime_ms = lifetime_ms
        self.puts = []

    def sign(self, put):
        assert isinstance(put, AuthorizedPut)
        self.puts.append(put)
        return UploadCapability(
            "PUT",
            "https://uploads.example/" + put.key + "?signed=1",
            (
                ("content-length", str(put.size)),
                ("content-type", put.content_type),
                ("if-none-match", "*"),
                ("x-checksum-sha256", put.digest),
            ),
            min(self.clock() + self.lifetime_ms, put.not_after_ms),
        )


def policy(
        *, active_key_id="key00001", keys=(OLD_KEY,),
        ttl_ms=600_000, max_ttl_ms=600_000,
        max_bytes=MAX_SESSION_BYTES):
    return UploadSessionPolicy(
        "test-broker-v1",
        active_key_id,
        keys,
        ttl_ms=ttl_ms,
        max_ttl_ms=max_ttl_ms,
        clock_skew_ms=1_000,
        max_bytes=max_bytes,
    )


def world(
        tmp_path, *, session_policy=None, signer=None, clock=None,
        nonce=lambda count: SESSION if count == 16 else b""):
    clock = clock or Clock()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    public = node.identity_id(workspace)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    signer = signer or RecordingSigner(clock)
    session_policy = session_policy or policy()
    broker = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace,
        signer,
        clock,
        session_policy,
        nonce=nonce,
    )
    return (
        node, workspace, public[:16], proof, clock, signer,
        session_policy, broker,
    )


def leaf(number, size=None):
    return UploadLeaf(
        f"{number + 1:064x}",
        number % 31 + 1 if size is None else size,
    )


def pile(raw=b"closed pile"):
    return UploadLeaf(h(raw), len(raw))


def open_session(broker, proof, vector, pile_leaf=None):
    return asyncio.run(broker.open(
        proof, vector.manifest, pile_leaf or pile()))


def restarted(broker, *, signer=None, session_policy=None, workspace=None):
    return UploadBroker(
        broker.store,
        workspace or broker.workspace,
        signer or broker.signer,
        broker.now,
        session_policy or broker.session_policy,
        nonce=lambda count: SESSION if count == 16 else b"",
        max_mint_fetches=broker.max_mint_fetches,
        max_mint_fetch_bytes=broker.max_mint_fetch_bytes,
    )


def grant_keys(result):
    if isinstance(result, IssuedUpload):
        return tuple(
            grant.capability.url.split("uploads.example/", 1)[1].split(
                "?", 1)[0]
            for grant in result.objects
        )
    assert isinstance(result, FinalizedUpload)
    return (
        result.pile.capability.url.split("uploads.example/", 1)[1].split(
            "?", 1)[0],
    )


def gateway_call(gateway, workspace, proof):
    body = json.dumps({
        "pile": base64.b64encode(proof).decode(),
        "ws": workspace,
    }).encode()
    return asyncio.run(gateway.handle(
        "POST", "/mint", {"ws": workspace}, {}, body))


def test_open_issues_nothing_and_zero_object_finalize_is_pile_only(
        tmp_path):
    (
        _, workspace, member, proof, _, signer, _, broker,
    ) = world(tmp_path)
    vector = UploadVector(())

    opened = open_session(broker, proof, vector)

    assert isinstance(opened, OpenedUpload)
    assert opened.session == "d" * 32
    assert len(opened.cursor) == TOKEN_BYTES
    assert signer.puts == []
    final = broker.finalize(opened.cursor)
    assert final.cursor == opened.cursor
    assert [put.object_class for put in signer.puts] == ["pile"]
    assert signer.puts[0].key == staging_key(
        workspace, member, opened.session, "pile", pile().digest)
    assert json.loads(encode_open(opened)) == open_document(opened)
    assert json.loads(encode_finalize(final)) == finalize_document(final)


def test_4096_object_random_batches_restart_fork_replay_and_convergence(
        tmp_path):
    (
        _, workspace, member, proof, _, signer, _, broker,
    ) = world(tmp_path)
    vector = UploadVector(tuple(leaf(index) for index in range(4_096)))
    pile_leaf = pile(b"one exact publication intent")
    opened = open_session(broker, proof, vector, pile_leaf)
    seen_tokens = {opened.cursor}
    seen_keys = set()

    # Two partitions of the same prefix converge byte-for-byte because the
    # cursor carries only the committed prefix, not request history.
    first = broker.issue(
        opened.cursor, 0, vector.leaves[:37], vector.proof(0, 37))
    wider = broker.issue(
        opened.cursor, 0, vector.leaves[:113], vector.proof(0, 113))
    first_then_rest = broker.issue(
        first.cursor, 37, vector.leaves[37:113],
        vector.proof(37, 113))
    assert first_then_rest.cursor == wider.cursor
    seen_tokens.update((
        first.cursor, wider.cursor, first_then_rest.cursor))
    seen_keys.update(grant_keys(first))
    seen_keys.update(grant_keys(wider))
    seen_keys.update(grant_keys(first_then_rest))

    cursor = wider.cursor
    index = 113
    rng = random.Random(0x517A7E)
    lost_response_checked = False
    latest_cursor_reissue_checked = False
    while index < len(vector.leaves):
        end = min(
            len(vector.leaves),
            index + rng.randint(1, PAGE_BATCH),
        )
        old_cursor = cursor
        result = broker.issue(
            old_cursor,
            index,
            vector.leaves[index:end],
            vector.proof(index, end),
        )
        assert len(result.objects) == end - index
        assert len(encode_issue(result)) <= MAX_ISSUE_RESPONSE_BYTES
        seen_tokens.add(result.cursor)
        seen_keys.update(grant_keys(result))

        if not lost_response_checked:
            # A process dies after signing but before returning. A cold broker
            # with only the retained old cursor mints the same exact keys and
            # reaches the identical next cursor.
            retry = restarted(broker).issue(
                old_cursor,
                index,
                vector.leaves[index:end],
                vector.proof(index, end),
            )
            assert retry.cursor == result.cursor
            assert grant_keys(retry) == grant_keys(result)
            lost_response_checked = True

        cursor = result.cursor
        if not latest_cursor_reissue_checked:
            # Unknown provider completion can also be retried later from the
            # latest cursor. The cursor does not roll back, and the broker
            # returns fresh authority for only the already committed keys.
            replay = restarted(broker).issue(
                cursor,
                index,
                vector.leaves[index:end],
                vector.proof(index, end),
            )
            assert replay.cursor == cursor
            assert grant_keys(replay) == grant_keys(result)
            seen_keys.update(grant_keys(replay))
            latest_cursor_reissue_checked = True
        index = end

    final = restarted(broker).finalize(cursor)
    replayed_final = restarted(broker).finalize(cursor)
    assert final.cursor == replayed_final.cursor == cursor
    assert grant_keys(final) == grant_keys(replayed_final)
    seen_keys.update(grant_keys(final))

    expected = {
        staging_key(
            workspace, member, opened.session, "obj", item.digest)
        for item in vector.leaves
    }
    expected.add(staging_key(
        workspace, member, opened.session, "pile", pile_leaf.digest))
    assert seen_keys == expected
    assert len(seen_keys) == len(vector.leaves) + 1
    assert {len(token) for token in seen_tokens} == {TOKEN_BYTES}

    # A completely different valid partition reaches the same final cursor.
    alternate = opened.cursor
    for start in range(0, len(vector.leaves), PAGE_BATCH):
        end = min(start + PAGE_BATCH, len(vector.leaves))
        alternate = restarted(broker).issue(
            alternate,
            start,
            vector.leaves[start:end],
            vector.proof(start, end),
        ).cursor
    assert alternate == cursor
    assert {put.key for put in signer.puts} == expected
    assert sum(put.object_class == "pile" for put in signer.puts) == 2


def test_lost_cursor_starts_a_new_confined_session_without_server_state(
        tmp_path):
    nonces = iter((b"a" * 16, b"b" * 16))
    (
        _, workspace, member, proof, _, signer, _, broker,
    ) = world(tmp_path, nonce=lambda count: next(nonces))
    vector = UploadVector((leaf(0), leaf(1)))

    abandoned = open_session(broker, proof, vector)
    replacement = open_session(broker, proof, vector)
    assert abandoned.session != replacement.session
    assert signer.puts == []

    first = broker.issue(
        abandoned.cursor, 0, vector.leaves[:1],
        vector.proof(0, 1))
    retried = broker.issue(
        replacement.cursor, 0, vector.leaves[:1],
        vector.proof(0, 1))
    assert set(grant_keys(first)) == {
        staging_key(
            workspace, member, abandoned.session,
            "obj", vector.leaves[0].digest),
    }
    assert set(grant_keys(retried)) == {
        staging_key(
            workspace, member, replacement.session,
            "obj", vector.leaves[0].digest),
    }


def test_absolute_session_caps_are_checked_without_issuing_maximum(
        tmp_path):
    _, _, _, proof, _, signer, _, broker = world(tmp_path)
    pile_leaf = UploadLeaf("e" * 64, 1)
    at_limit = UploadManifest(
        "a" * 64,
        MAX_SESSION_OBJECTS,
        MAX_SESSION_BYTES - pile_leaf.size,
    )

    opened = asyncio.run(broker.open(proof, at_limit, pile_leaf))
    state = broker.tokens.decode(opened.cursor, NOW)
    assert state.manifest == at_limit
    assert signer.puts == []

    for over_limit in (
            replace(at_limit, count=MAX_SESSION_OBJECTS + 1),
            replace(at_limit, total_bytes=MAX_SESSION_BYTES + 1),
            replace(at_limit, total_bytes=MAX_SESSION_BYTES),
    ):
        with pytest.raises(
                InvalidUploadSession, match="OPEN metadata"):
            asyncio.run(broker.open(proof, over_limit, pile_leaf))

    with pytest.raises(ValueError, match="session policy"):
        policy(max_bytes=MAX_SESSION_BYTES + 1)

    # Substitute small limits to exercise N/N+1 and total/pile arithmetic
    # through a complete session rather than allocating 65,536 capabilities.
    bounded = policy(max_bytes=100)
    small_broker = restarted(broker, session_policy=bounded)
    vector = UploadVector(tuple(leaf(index, 20) for index in range(4)))
    opened = open_session(
        small_broker, proof, vector, UploadLeaf("f" * 64, 20))
    issued = small_broker.issue(
        opened.cursor, 0, vector.leaves, vector.proof(0, 4))
    assert small_broker.finalize(issued.cursor)
    for invalid in (replace(vector.manifest, total_bytes=81),):
        with pytest.raises(InvalidUploadSession):
            asyncio.run(small_broker.open(
                proof, invalid, UploadLeaf("f" * 64, 20)))


def test_range_proofs_reject_mutation_ordering_gaps_and_overlap(tmp_path):
    _, _, _, proof, _, _, _, broker = world(tmp_path)
    vector = UploadVector(tuple(leaf(index) for index in range(300)))
    opened = open_session(broker, proof, vector)
    proof_0_16 = vector.proof(0, 16)

    mutations = (
        (0, vector.leaves[:15], vector.proof(0, 15) + b"x"),
        (0, vector.leaves[:15], vector.proof(0, 16)),
        (0, vector.leaves[:16] + (vector.leaves[16],), proof_0_16),
        (0, (
            replace(vector.leaves[0], digest="f" * 64),
            *vector.leaves[1:16],
        ), proof_0_16),
        (0, (
            replace(vector.leaves[0], size=vector.leaves[0].size + 1),
            *vector.leaves[1:16],
        ), proof_0_16),
        (0, (
            vector.leaves[1],
            vector.leaves[0],
            *vector.leaves[2:16],
        ), proof_0_16),
        (0, (
            vector.leaves[0],
            vector.leaves[0],
            *vector.leaves[2:16],
        ), proof_0_16),
    )
    for start, leaves, merkle_proof in mutations:
        with pytest.raises(InvalidUploadSession):
            broker.issue(
                opened.cursor, start, leaves, merkle_proof)

    with pytest.raises(InvalidUploadSession, match="gap"):
        broker.issue(
            opened.cursor, 16, vector.leaves[16:32],
            vector.proof(16, 32))

    first = broker.issue(
        opened.cursor, 0, vector.leaves[:16], proof_0_16)
    with pytest.raises(InvalidUploadSession, match="partial overlap"):
        broker.issue(
            first.cursor, 8, vector.leaves[8:24],
            vector.proof(8, 24))
    covered = broker.issue(
        first.cursor, 4, vector.leaves[4:12],
        vector.proof(4, 12))
    assert covered.cursor == first.cursor
    assert len(covered.objects) == 8


def test_broker_enforces_sorted_unique_order_across_batch_boundaries(
        tmp_path):
    _, _, _, proof, _, _, _, broker = world(tmp_path)
    high = UploadLeaf("f" * 64, 1)
    low = UploadLeaf("1" * 64, 1)
    first_hash = session_codec._leaf_hash(0, high)
    second_hash = session_codec._leaf_hash(1, low)
    tree_root = session_codec._node_hash(
        1, first_hash, second_hash)
    manifest = UploadManifest(
        session_codec._wrapped_root(2, 2, 1, tree_root),
        2,
        2,
    )
    opened = asyncio.run(broker.open(proof, manifest, pile()))
    first_proof = session_codec.encode_range_proof((second_hash,))
    second_proof = session_codec.encode_range_proof((first_hash,))

    first = broker.issue(
        opened.cursor, 0, (high,), first_proof)
    with pytest.raises(InvalidUploadSession, match="ordering"):
        broker.issue(first.cursor, 1, (low,), second_proof)


def _manifest_with_total(vector, total_bytes):
    return UploadManifest(
        session_codec._wrapped_root(
            len(vector.leaves),
            total_bytes,
            len(vector._levels) - 1,
            vector._levels[-1][0],
        ),
        len(vector.leaves),
        total_bytes,
    )


@pytest.mark.parametrize("delta", (-1, 1))
def test_committed_root_cannot_lie_about_total_bytes(tmp_path, delta):
    _, _, _, proof, _, signer, _, broker = world(tmp_path)
    vector = UploadVector(tuple(leaf(index) for index in range(8)))
    declared = vector.manifest.total_bytes + delta
    committed_lie = _manifest_with_total(vector, declared)
    opened = asyncio.run(broker.open(proof, committed_lie, pile()))

    with pytest.raises(InvalidUploadSession, match="byte quota"):
        broker.issue(
            opened.cursor, 0, vector.leaves, vector.proof(0, 8))
    assert signer.puts == []


def test_object_and_pile_byte_limits_are_independently_enforced(tmp_path):
    _, _, _, proof, _, _, _, broker = world(tmp_path)
    with pytest.raises(InvalidUploadSession):
        UploadVector((UploadLeaf("a" * 64, MAX_OBJECT_BYTES + 1),))
    with pytest.raises(InvalidUploadSession, match="OPEN metadata"):
        asyncio.run(broker.open(
            proof,
            UploadVector(()).manifest,
            UploadLeaf("b" * 64, MAX_PILE_BYTES + 1),
        ))


def _mutate_token(token, offset):
    raw = bytearray(base64.urlsafe_b64decode(
        token + "=" * (-len(token) % 4)))
    raw[offset] ^= 1
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.mark.parametrize(
    "offset",
    (
        0,    # magic
        4,    # version
        5,    # key id
        13,   # issuer
        45,   # provider
        77,   # workspace
        109,  # member
        117,  # session
        133,  # vector root
        165,  # count
        169,  # total bytes
        177,  # pile digest
        209,  # pile size
        217,  # next index
        221,  # issued bytes
        229,  # last digest
        261,  # issued time
        269,  # expiry
        -1,   # MAC
    ),
)
def test_every_cursor_authority_field_and_mac_is_authenticated(
        tmp_path, offset):
    _, _, _, proof, _, _, _, broker = world(tmp_path)
    opened = open_session(
        broker, proof, UploadVector((leaf(0),)))

    with pytest.raises(InvalidUploadSession, match="cursor"):
        broker.tokens.decode(_mutate_token(opened.cursor, offset), NOW)


def test_cursor_binds_issuer_provider_and_workspace_even_with_same_key(
        tmp_path):
    _, _, _, proof, clock, _, session_policy, broker = world(tmp_path)
    opened = open_session(
        broker, proof, UploadVector((leaf(0),)))

    other_issuer = replace(
        session_policy, issuer="other-broker-v1")
    with pytest.raises(InvalidUploadSession):
        restarted(
            broker, session_policy=other_issuer).tokens.decode(
                opened.cursor, clock())

    other_signer = RecordingSigner(clock)
    other_signer.provider_binding = "other-provider-v1"
    with pytest.raises(InvalidUploadSession):
        restarted(
            broker, signer=other_signer).tokens.decode(
                opened.cursor, clock())

    foreign_workspace = restarted(broker, workspace="e" * 64)
    with pytest.raises(
            InvalidUploadSession, match="cursor workspace"):
        foreign_workspace.issue(
            opened.cursor, 0, (leaf(0),),
            UploadVector((leaf(0),)).proof(0, 1))


def test_two_phase_key_rotation_and_default_ttl_change_survive_restart(
        tmp_path):
    clock = Clock()
    initial = policy(
        active_key_id="key00001",
        keys=(OLD_KEY, NEW_KEY),
        ttl_ms=500_000,
        max_ttl_ms=600_000,
    )
    (
        _, _, _, proof, _, _, _, broker,
    ) = world(tmp_path, clock=clock, session_policy=initial)
    vector = UploadVector((leaf(0),))
    old = open_session(broker, proof, vector)
    assert broker.tokens.decode(old.cursor, clock()).key_id == "key00001"

    rolling = policy(
        active_key_id="key00002",
        keys=(OLD_KEY, NEW_KEY),
        ttl_ms=120_000,
        max_ttl_ms=600_000,
    )
    updated = restarted(broker, session_policy=rolling)
    issued = updated.issue(
        old.cursor, 0, vector.leaves, vector.proof(0, 1))
    assert issued.next_index == 1
    new = asyncio.run(updated.open(proof, vector.manifest, pile()))
    assert updated.tokens.decode(new.cursor, clock()).key_id == "key00002"

    new_only = policy(
        active_key_id="key00002",
        keys=(NEW_KEY,),
        ttl_ms=120_000,
        max_ttl_ms=600_000,
    )
    with pytest.raises(InvalidUploadSession, match="cursor"):
        restarted(
            broker, session_policy=new_only).tokens.decode(
                old.cursor, clock())


def test_expiry_is_fixed_and_key_window_must_cover_session_plus_skew(
        tmp_path):
    clock = Clock()
    short = policy(ttl_ms=100, max_ttl_ms=100)
    signer = RecordingSigner(clock)
    (
        _, _, _, proof, _, _, _, broker,
    ) = world(
        tmp_path, clock=clock, signer=signer,
        session_policy=short)
    vector = UploadVector((leaf(0),))
    opened = open_session(broker, proof, vector)

    clock.value = opened.expires_at_ms - 1
    result = broker.issue(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1))
    assert result.expires_at_ms == opened.expires_at_ms
    assert result.objects[0].capability.expires_at_ms \
        == opened.expires_at_ms
    assert signer.puts[0].not_after_ms == opened.expires_at_ms
    clock.value = opened.expires_at_ms
    with pytest.raises(InvalidUploadSession, match="cursor"):
        broker.finalize(result.cursor)

    too_short = SessionKey(
        "key00003", b"z" * 32, 0,
        NOW + short.ttl_ms + short.clock_skew_ms - 1)
    unusable = replace(
        short, active_key_id="key00003", keys=(too_short,))
    blocked = restarted(broker, session_policy=unusable)
    clock.value = NOW
    with pytest.raises(
            UploadUnavailable, match="insufficient lifetime"):
        asyncio.run(blocked.open(proof, vector.manifest, pile()))


def test_removal_staleness_is_exactly_one_cold_resumable_lease(tmp_path):
    """OPEN observes removal; an already-open lease only observes its expiry."""
    clock = Clock()
    node = FullPeer(str(tmp_path / "node"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    founder = node.identity_id(workspace)
    bob_secret, bob, _ = add_member(
        node, workspace, "bob", ts=10)
    node.keychain.add_identity(bob_secret)
    node.bind_identity(workspace, bob)
    proof = encode_pile(request.payload(
        node, workspace, "upload", NOW + 60_000, NOW))
    signer = RecordingSigner(clock)
    lease_policy = policy(ttl_ms=100, max_ttl_ms=100)
    broker = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace,
        signer,
        clock,
        lease_policy,
        nonce=lambda count: SESSION if count == 16 else b"",
    )
    vector = UploadVector((leaf(0), leaf(1)))
    opened = open_session(broker, proof, vector)
    in_flight = broker.issue(
        opened.cursor, 0, vector.leaves[:1], vector.proof(0, 1))

    # The current root changes while one exact PUT is in flight. A new OPEN
    # sees that removal and fails, but the old cursor is a deliberately bounded
    # bearer lease rather than a broker-side membership record.
    node.bind_identity(workspace, founder)
    facts.auth.removal.evict(node, workspace, bob)
    with pytest.raises(InvalidUploadSession, match="authorization"):
        asyncio.run(broker.open(proof, vector.manifest, pile()))

    class NoRepositoryReads:
        async def get_bounded(self, _key, _maximum):
            raise AssertionError("ISSUE/FINALIZE rechecked repository state")

    def cold():
        return UploadBroker(
            NoRepositoryReads(),
            workspace,
            signer,
            clock,
            lease_policy,
            nonce=lambda count: SESSION if count == 16 else b"",
        )

    # Lost ISSUE responses may be retried through cold instances. Both
    # instances can only sign the exact precommitted staging address.
    clock.value = opened.expires_at_ms - 1
    retried = cold().issue(
        opened.cursor, 0, vector.leaves[:1], vector.proof(0, 1))
    issued = cold().issue(
        in_flight.cursor, 1, vector.leaves[1:], vector.proof(1, 2))
    finalized = cold().finalize(issued.cursor)
    assert retried.cursor == in_flight.cursor
    assert grant_keys(retried) == grant_keys(in_flight)
    assert in_flight.expires_at_ms == issued.expires_at_ms \
        == finalized.expires_at_ms \
        == opened.expires_at_ms
    grants = (*in_flight.objects, *issued.objects, finalized.pile)
    assert all(
        grant.capability.expires_at_ms <= opened.expires_at_ms
        for grant in grants
    )
    assert all(
        put.not_after_ms == opened.expires_at_ms for put in signer.puts)
    assert all(
        put.key.startswith(
            f"ingress/v1/workspaces/{workspace}/")
        and "/root" not in put.key
        and "/applier/" not in put.key
        for put in signer.puts
    )

    # The lease uses a half-open time interval. Neither retry nor pile
    # finalization can stretch it by one millisecond.
    for trusted_now in (
            opened.expires_at_ms, opened.expires_at_ms + 1):
        clock.value = trusted_now
        with pytest.raises(InvalidUploadSession, match="cursor"):
            cold().issue(
                opened.cursor, 0, vector.leaves[:1], vector.proof(0, 1))
        with pytest.raises(InvalidUploadSession, match="cursor"):
            cold().finalize(issued.cursor)


class StaticSigner:
    provider_binding = RecordingSigner.provider_binding

    def __init__(self, capability):
        self.capability = capability

    def sign(self, _put):
        return self.capability


@pytest.mark.parametrize(
    "capability",
    (
        UploadCapability(
            "PUT",
            "https://uploads.example/obj?" + (
                "q" * (MAX_CAPABILITY_QUERY_BYTES + 1)),
            (), NOW + 1),
        UploadCapability(
            "PUT",
            "https://uploads.example/" + (
                "x" * MAX_CAPABILITY_URL_BYTES),
            (), NOW + 1),
        UploadCapability(
            "PUT", "https://uploads.example/obj",
            tuple(
                (f"x-{index:02d}", "v")
                for index in range(MAX_CAPABILITY_HEADERS + 1)),
            NOW + 1),
        UploadCapability(
            "PUT", "https://uploads.example/obj",
            (("x" * (MAX_CAPABILITY_HEADER_NAME_BYTES + 1), "v"),),
            NOW + 1),
        UploadCapability(
            "PUT", "https://uploads.example/obj",
            (("x-test", "v" * (
                MAX_CAPABILITY_HEADER_VALUE_BYTES + 1)),),
            NOW + 1),
        UploadCapability(
            "GET", "https://uploads.example/obj", (), NOW + 1),
        UploadCapability(
            "PUT", "http://uploads.example/obj", (), NOW + 1),
        UploadCapability(
            "PUT", "https://uploads.example/obj", (), NOW),
        UploadCapability(
            "PUT", "https://uploads.example/obj", (),
            NOW + 600_001),
    ),
)
def test_provider_signer_output_is_bounded_and_session_scoped(
        tmp_path, capability):
    _, _, _, proof, _, _, _, broker = world(tmp_path)
    vector = UploadVector((leaf(0),))
    opened = open_session(broker, proof, vector)
    hostile = restarted(broker, signer=StaticSigner(capability))

    with pytest.raises(UploadUnavailable):
        hostile.issue(
            opened.cursor, 0, vector.leaves, vector.proof(0, 1))


def test_response_documents_have_no_credentials_or_semantic_path_input(
        tmp_path):
    _, _, _, proof, _, _, _, broker = world(tmp_path)
    vector = UploadVector((leaf(0),))
    opened = open_session(broker, proof, vector)
    issued = broker.issue(
        opened.cursor, 0, vector.leaves, vector.proof(0, 1))
    final = broker.finalize(issued.cursor)

    assert {field.name for field in fields(UploadLeaf)} == {
        "digest", "size"}
    assert {field.name for field in fields(UploadManifest)} == {
        "root", "count", "total_bytes"}
    assert {field.name for field in fields(UploadCapability)} == {
        "method", "url", "headers", "expires_at_ms"}
    assert "signed=1" not in repr(
        issued.objects[0].capability)
    assert len(encode_issue(issued)) <= MAX_ISSUE_RESPONSE_BYTES
    assert len(json.dumps(
        issue_document(issued)["objects"][0]["put"],
        sort_keys=True, separators=(",", ":")).encode()) \
        <= MAX_CAPABILITY_DOCUMENT_BYTES
    encoded = b"".join((
        encode_open(opened),
        encode_issue(issued),
        encode_finalize(final),
    )).decode().lower()
    for forbidden in (
            "secret_access_key", "session_token", "\"list\"",
            "\"delete\"", "\"root\""):
        assert forbidden not in encoded


def test_upload_purpose_is_accepted_only_by_upload_broker(tmp_path):
    (
        node, workspace, _, upload_proof, _, signer, _, broker,
    ) = world(tmp_path)
    gateway = HttpGate(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, b"s" * 32, lambda: NOW)
    sync_proof = encode_pile(request.payload(
        node, workspace, "sync", NOW + 60_000, NOW))
    vector = UploadVector(())

    assert gateway_call(gateway, workspace, upload_proof).status == 403
    assert gateway_call(gateway, workspace, sync_proof).status == 200
    with pytest.raises(InvalidUploadSession, match="authorization"):
        asyncio.run(broker.open(
            sync_proof, vector.manifest, pile()))
    assert open_session(broker, upload_proof, vector)
    assert signer.puts == []


def test_broker_distinguishes_provider_failure_from_bad_proof(tmp_path):
    (
        node, workspace, _, proof, clock, signer, session_policy, _,
    ) = world(tmp_path)
    vector = UploadVector(())

    class WholeOnly:
        gets = 0

        async def get(self, _key):
            self.gets += 1
            raise AssertionError("whole-object fallback was used")

    whole_only = WholeOnly()
    with pytest.raises(ValueError, match="upload broker dependency"):
        UploadBroker(
            whole_only, workspace, signer, clock, session_policy)
    assert whole_only.gets == 0

    class Failing:
        async def get_bounded(self, _key, _maximum):
            raise OSError("injected provider outage")

    broker = UploadBroker(
        Failing(), workspace, signer, clock, session_policy)
    with pytest.raises(UploadUnavailable, match="root unavailable"):
        asyncio.run(broker.open(proof, vector.manifest, pile()))

    foreign = FullPeer(str(tmp_path / "foreign"))
    foreign_workspace = facts.auth.workspace.create(foreign, "mallory", ts=1)
    foreign_root = foreign.store(foreign_workspace).get("root")

    class ForeignRoot:
        async def get_bounded(self, key, _maximum):
            return foreign_root if key == "root" else None

    misbound = UploadBroker(
        ForeignRoot(), workspace, signer, clock, session_policy)
    with pytest.raises(UploadUnavailable, match="root unavailable"):
        asyncio.run(misbound.open(proof, vector.manifest, pile()))

    healthy = UploadBroker(
        AsyncFromSyncReader(node.store(workspace)),
        workspace, signer, clock, session_policy)
    with pytest.raises(InvalidUploadSession, match="authorization"):
        asyncio.run(healthy.open(
            b"not a proof", vector.manifest, pile()))
