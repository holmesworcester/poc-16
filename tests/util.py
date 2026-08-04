"""Test helpers: author facts directly (bypassing HTTP) to build fixtures."""
import asyncio
import base64
import json
import os
import random
import tempfile

import facts

from core import http, peer_capability
from core.close import (
    close,
    decode_signed_pile,
    encode_signed_pile,
    make_signed_pile,
)
from core.crypto import h, keypair, load_sk
from core.fact import workspace_of
from facts.auth.device_invite import device_invite
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.message import message
from core.kernel import resolve_deps
from core.writer_repository import FactConsumer, HeadGrant
from core.writer_head import head_slot_prefix
from full_peer.node import FullPeer, now_ms


_FIXTURE_SIGNER = load_sk("01" * 32)


def mechanical_head_authorizer(workspace, authority_root, trusted_now=0):
    """Test-only semantic bypass for exercising the mechanical head CAS.

    Authority behavior is covered through ``AuthorityRepository`` tests. Lower
    writer-tree/store tests need only a typed grant that preserves the exact
    request's device, base, and proposed head without retaining the retired
    production AuthorityGate.
    """
    async def authorize(raw, proposed_head):
        pile = decode_signed_pile(raw, workspace=workspace)
        requests = [fact for fact in pile.facts if fact.t == "head_request"]
        if len(requests) != 1:
            return None
        request = requests[0]
        body = request.body
        if pile.writer != body.get("device") \
                or body.get("head") != proposed_head \
                or body.get("exp", -1) < trusted_now:
            return None
        return HeadGrant(
            workspace,
            body["device"],
            body.get("base_head") or None,
            proposed_head,
            authority_root,
        )
    return authorize


def signed_pile_bytes(facts, *, workspace=None, secret=None):
    """Encode one real signed wire pile for protocol-independent fixtures."""
    facts = tuple(facts)
    if workspace is None:
        if not facts:
            raise ValueError("pile workspace")
        workspace = workspace_of(facts[0])
    secret = _FIXTURE_SIGNER if secret is None else secret
    writer = secret.verify_key.encode().hex()
    return encode_signed_pile(make_signed_pile(
        secret, workspace, writer, facts))


def signed_pile_facts(raw, workspace=None, writer=None):
    """Decode the sole signed wire format and return its ordered facts."""
    return list(decode_signed_pile(
        raw, workspace=workspace, writer=writer).facts)


def invoke_mint_value(node, workspace, value):
    gate = http.HttpGate(
        http.AsyncFromSyncReader(node.store(workspace)),
        workspace,
        b"mint-test-secret" * 2,
        now_ms,
        sync_profile=peer_capability.FULL,
        max_mint_fetches=http.MAX_MINT_FETCHES,
        max_mint_fetch_bytes=http.MAX_MINT_FETCH_BYTES,
    )
    response = asyncio.run(gate.handle(
        "POST", "/mint", {"ws": workspace}, {},
        json.dumps(value).encode(),
    ))
    body = json.loads(response.body) if response.body else None
    return gate, (response.status, body)


def invoke_mint(node, workspace, pile):
    return invoke_mint_value(node, workspace, {
        "ws": workspace,
        "pile": base64.b64encode(pile).decode(),
    })


def suppression_world(path, initial_secret=None):
    """A valid set with targets and PRODUCTION deletions
    (facts/content/delete.py via facts.content.delete.remove), authored in one fixed order."""
    node = FullPeer(str(path), initial_secret=initial_secret)
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    targets = [
        facts.content.message.post(
            node, workspace, f"channel-{ordinal % 2}",
            f"message-{ordinal}", ts=10 + ordinal)
        for ordinal in range(8)
    ]
    attachment = send_bytes(
        node, workspace, "suppression.bin",
        b"attachment-cascade-" * 4096, channel="channel-0", ts=30)
    deletions = [
        facts.content.delete.remove(node, workspace, targets[ordinal], ts=100 + ordinal)
        for ordinal in (1, 4, 6)
    ]
    deletions.append(facts.content.delete.remove(node, workspace, attachment, ts=110))
    return node, workspace, targets, deletions


def replay_random(source, workspace, destination, seed):
    """Consume the same valid set under a random partition and order."""
    rng = random.Random(seed)
    shuffled = all_fids(source, workspace)
    rng.shuffle(shuffled)
    position = 0
    while position < len(shuffled):
        for _pile in range(rng.randint(1, 3)):
            take = rng.randint(1, 5)
            chunk = shuffled[position:position + take]
            position += take
            if chunk:
                deliver(
                    destination, workspace,
                    closed_subset(source, workspace, chunk))
    return destination


def query_state(node, workspace=None):
    """Canonical public query state over the disposable SQL projection."""
    if workspace is None:
        known = node.workspaces() or list(node._sql)
        if len(known) != 1:
            raise ValueError("query_state needs one workspace")
        workspace = known[0]
    queries = (
        ("admins", facts.auth.admin.admins),
        ("devices", facts.auth.device.devices),
        ("files", facts.content.file.files),
        ("members", facts.auth.user.members),
        ("messages", facts.content.message.messages),
    )
    return tuple(
        (
            name,
            tuple(json.dumps(row, sort_keys=True) for row in query(
                node, workspace)),
        )
        for name, query in queries
    )


def compiled_repository(node, workspace, objects=None):
    """Compile current projected facts into an explicit test-only snapshot.

    The writer-log FullPeer deliberately has no aggregate content root. Tests
    for pure RepositoryReader queries construct that disposable value
    explicitly instead of reviving ``FullPeer.reader``.
    """
    from core.repository_snapshot import compile_snapshot

    with node.lock:
        projection = node.sql(workspace)
        compiled = compile_snapshot(workspace, {
            fid: projection.fact_of(fid)
            for fid in projection.fact_ids()
        })
    target = {} if objects is None else objects
    target.update(compiled.objects)
    return compiled.root, target


def visible_fids(node, workspace):
    """Eligible facts not masked by their explicit suppression ids."""
    with node.lock:
        return {
            fid
            for fid in node.sql(workspace).fact_ids()
            if not node.suppressed(workspace, node.fact_of(workspace, fid))
        }


def add_member(
        n, ws, name, ts=None, inviter=None, member_identity=None,
        invite_identity=None):
    """Add a user through an existing member and return ``(sk, pk, user)``.

    ``inviter`` defaults to the workspace founder. The two ``*_identity``
    arguments pin otherwise-random keys in replayable adversarial fixtures.
    The user follows ``ts`` by one tick.
    """
    inviter_sk, inviter_pk = inviter or n.identity(ws)
    with n.lock:
        member_source = n.sql(ws).resolve_offer("member", inviter_pk)
        if member_source is None:
            raise ValueError("inviter is not a workspace member")
        member_ts = n.fact_of(ws, member_source).ts
    invite_ts = max(now_ms(), member_ts + 1) if ts is None else ts
    if invite_ts <= member_ts:
        raise ValueError("invite timestamp must follow the inviter's membership")
    user_ts = invite_ts + 1
    isk, ipk = invite_identity or keypair()
    inv = user_invite(ws, inviter_pk, ipk, invite_ts)
    si = signature(inviter_sk, inviter_pk, inv, invite_ts)
    bsk, bpk = member_identity or keypair()
    joined = user(inv, isk, bpk, name, user_ts)
    joined_sig = signature(bsk, bpk, joined, user_ts)
    deps = {inv.fid: [si.fid, member_source], si.fid: [],
            joined.fid: [inv.fid, joined_sig.fid], joined_sig.fid: []}
    n.ingest_new(ws, [si, inv, joined_sig, joined], deps)
    return bsk, bpk, joined


def author_msg(n, ws, sk, pk, text, ts=None, chan="general"):
    """A message from an arbitrary member key, via the ordinary ingress."""
    ts = ts or now_ms()
    f = message(ws, pk, chan, text, ts)
    s = signature(sk, pk, f, ts)
    deps = {f.fid: [s.fid, member_src(n, ws, pk)], s.fid: []}
    n.ingest_new(ws, [s, f], deps)
    return f


def member_src(n, ws, pk):
    with n.lock:
        return n.sql(ws).resolve_offer("member", pk)


def inject_device_claim(
        node, workspace, owner_secret, owner, target, label, ts):
    """Author one owner-signed claim past command duplicate checks."""
    item = device_invite(workspace, owner, target, label, ts)
    signed = signature(owner_secret, owner, item, ts)
    node.ingest_new(
        workspace,
        [signed, item],
        {
            signed.fid: [],
            item.fid: [
                signed.fid,
                node.sql(workspace).resolve_offer(
                    "member", owner, owner),
                node.sql(workspace).resolve_offer(
                    "device_key", owner, owner),
            ],
        },
    )
    return item


def closed_subset(n, ws, fids):
    """close() an arbitrary subset out of a node's index — a valid pile."""
    with n.lock:
        context = n.sql(ws)
        facts = close([n.fact_of(ws, fid) for fid in fids],
                      lambda fid: resolve_deps(
                          n.fact_of(ws, fid), context) or [],
                      lambda fid: n.fact_of(ws, fid))
    return signed_pile_bytes(facts, workspace=ws)


def deliver(dst, ws, pile_bytes):
    """Consume one already-authenticated signed pile through common core."""
    pile = decode_signed_pile(pile_bytes, workspace=ws)
    return FactConsumer(ws, dst.sql(ws)).consume(
        pile_bytes, writer=pile.writer)


def all_fids(n, ws):
    with n.lock:
        facts = [
            n.fact_of(ws, fid)
            for fid in n.sql(ws).fact_ids()
        ]
    return [fact.fid for fact in sorted(facts, key=lambda fact: fact.key)]


def writer_slots(node, workspace):
    """Exact accepted writer-slot bytes for a realistic mutation ratchet."""
    store = node.store(workspace)
    return tuple(
        (key, store.get(key))
        for key in store.list(head_slot_prefix(workspace))
    )


def send_bytes(node, workspace, name, data, channel="general", ts=None):
    """Test adapter for the path-only attachment authoring seam."""
    handle, path = tempfile.mkstemp(prefix="poc-16-test-")
    try:
        with os.fdopen(handle, "wb") as spool:
            spool.write(data)
        return facts.content.file.send(
            node, workspace, channel, path, name=name, ts=ts)
    finally:
        os.unlink(path)
