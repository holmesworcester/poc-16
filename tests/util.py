"""Test helpers: author facts directly (bypassing HTTP) to build fixtures."""
import random

from tinyp2p import cmds, facts
from tinyp2p.close import close, encode_pile
from tinyp2p.crypto import h, keypair
from tinyp2p.fact import Fact
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.content.message import message
from tinyp2p.kernel import resolve_deps
from tinyp2p.node import Node, now_ms
from tinyp2p.suppression import TARGET, atom, is_deletion


def channel_delete(target, channel, ts):
    """Synthetic valid single-target deletion used by suppression laws."""
    return Fact(
        "channel_delete", ts,
        [atom(channel, deletion=True), ["ref", TARGET, target]], {})


class DeletionFamily:
    TAG = "channel_delete"
    TABLES = ()
    DURABLE = True

    @staticmethod
    def needs(fact):
        return ()

    @staticmethod
    def validate(fact, context):
        try:
            ((name, target),) = fact.refs()
            channel = fact.atoms[0][2]
        except (IndexError, TypeError, ValueError):
            return False
        row = context.db.execute(
            "SELECT t FROM facts WHERE fid=?", (target,)).fetchone()
        return name == TARGET and is_deletion(fact) \
            and row is not None and row[0] != DeletionFamily.TAG \
            and fact == channel_delete(target, channel, fact.ts)

    @staticmethod
    def global_rows(fact):
        return ()

    @staticmethod
    def blob_refs(fact):
        return ()

    @staticmethod
    def materialize(db, workspace, valid):
        return None


def suppression_world(path, monkeypatch):
    """A valid set with targets and deletions, authored in one fixed order."""
    monkeypatch.setitem(facts.ROUTES, DeletionFamily.TAG, DeletionFamily)
    node = Node(str(path))
    workspace = cmds.create(node, "alice", ts=1)
    targets = [
        cmds.post(
            node, workspace, f"channel-{ordinal % 2}",
            f"message-{ordinal}", ts=10 + ordinal)
        for ordinal in range(8)
    ]
    deletions = []
    for ordinal in (1, 4, 6):
        target = node.fact_of(workspace, targets[ordinal])
        deletion = channel_delete(
            target.fid, target.body["chan"], 100 + ordinal)
        node.ingest_new(
            workspace, [deletion], {deletion.fid: [target.fid]})
        deletions.append(deletion.fid)
    return node, workspace, targets, deletions


def replay_random(source, workspace, destination, seed):
    """Deliver the same valid set under a random partition/order/batching."""
    rng = random.Random(seed)
    shuffled = all_fids(source, workspace)
    rng.shuffle(shuffled)
    position = batch = 0
    while position < len(shuffled):
        for pile in range(rng.randint(1, 3)):
            take = rng.randint(1, 5)
            chunk = shuffled[position:position + take]
            position += take
            if chunk:
                deliver(
                    destination, workspace,
                    closed_subset(source, workspace, chunk),
                    member=f"seed{seed}batch{batch}pile{pile}")
        destination.turn(workspace)
        batch += 1
    return destination


def projection_state(node):
    """Canonical logical app state, excluding the history cursor."""
    names = [
        name for (name,) in node.app.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
            "AND name != 'cursors' ORDER BY name")
    ]
    state = []
    for name in names:
        columns = node.app.execute(f"PRAGMA table_info({name})").fetchall()
        order = ",".join(str(index) for index in range(1, len(columns) + 1))
        state.append(
            (name, tuple(node.app.execute(
                f"SELECT * FROM {name} ORDER BY {order}"))))
    return tuple(state)


def add_member(
        n, ws, name, ts=None, inviter=None, member_identity=None):
    """Add a user through an existing member and return ``(sk, pk, user)``.

    ``inviter`` is that member's ``(sk, pk)`` identity and defaults to the
    workspace founder. ``member_identity`` can pin the joining key in
    adversarial fixtures. ``ts`` is the invite timestamp; the user follows
    one tick later so every delegation edge is strictly forward in time.
    """
    inviter_sk, inviter_pk = inviter or n.identity(ws)
    with n.lock:
        from tinyp2p.kernel import offer_src
        member_source = offer_src(n.idx(ws), "member", inviter_pk)
        if member_source is None:
            raise ValueError("inviter is not a workspace member")
        member_ts = n.fact_of(ws, member_source).ts
    invite_ts = max(now_ms(), member_ts + 1) if ts is None else ts
    if invite_ts <= member_ts:
        raise ValueError("invite timestamp must follow the inviter's membership")
    user_ts = invite_ts + 1
    isk, ipk = keypair()
    inv = user_invite(inviter_pk, ipk, invite_ts)
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
    f = message(pk, chan, text, ts)
    s = signature(sk, pk, f, ts)
    deps = {f.fid: [s.fid, member_src(n, ws, pk)], s.fid: []}
    n.ingest_new(ws, [s, f], deps)
    return f


def member_src(n, ws, pk):
    from tinyp2p.kernel import offer_src
    with n.lock:
        return offer_src(n.idx(ws), "member", pk)


def closed_subset(n, ws, fids):
    """close() an arbitrary subset out of a node's index — a valid pile."""
    with n.lock:
        idx = n.idx(ws)
        facts = close([n.fact_of(ws, fid) for fid in fids],
                      lambda fid: resolve_deps(n.fact_of(ws, fid), idx) or [],
                      lambda fid: n.fact_of(ws, fid))
    return encode_pile(facts)


def deliver(dst, ws, pile_bytes, member="feed7feed7feed7f"):
    dst.store(ws).put(f"pile/{member}/{h(pile_bytes)}", pile_bytes)


def all_fids(n, ws):
    return [fid for (fid,) in n.idx(ws).execute("SELECT fid FROM facts ORDER BY ts, fid")]
