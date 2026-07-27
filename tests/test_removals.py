"""Contract for the grow-only removal index (docs/REMOVALS.md).

Section and invariant numbers cite docs/REMOVALS.md; the remaining
skeletons land with oyd.4 (retraction) and oyd.7 (production family).
"""
import pytest

import facts

import core.manifest as manifest
import core.removals as removals
import core.shape as shape
import core.sync as sync_module
from core import cmds
from core.crypto import h, keypair, load_sk
from core.fact import Fact, canon
from core.node import Node
from core.suppression import TARGET, atom, is_deletion
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.message import message

from .util import (
    DeletionFamily,
    add_member,
    all_fids,
    channel_delete,
    channel_kill,
    closed_subset,
    deliver,
    inject_device_claim,
    member_src,
    multi_group_post,
    suppression_world,
)

SKELETON = pytest.mark.skip(reason="skeleton: contract only, body unwritten")


def victim_key(*victims):
    """The author chokepoint's key lookup: span from the actual victim."""
    keys = {fact.fid: shape.key(fact) for fact in victims}
    return keys.__getitem__


def surfaced(node, ws, fid):
    """Whether ``fid`` is materialized in E (app.db projected)."""
    return node.app.execute(
        "SELECT 1 FROM projected WHERE ws=? AND src=?",
        (ws, fid)).fetchone() is not None


class KillFamily(DeletionFamily):
    """Synthetic valid KILL family: death marker, NO TARGET ref — the §2
    kill kind, admissible so entry-strictly-before-victim is testable."""
    TAG = "channel_kill"

    @staticmethod
    def validate(fact, context):
        try:
            channel = fact.atoms[0][2]
        except (IndexError, TypeError):
            return False
        return not fact.refs() and fact == channel_kill(channel, fact.ts)


def local_peer(source):
    """A Peer over ``source``'s store for a full local sync."""
    class LocalPeer:
        def __init__(self, node, ws, url):
            self.node, self.ws = node, ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            return (source.store(self.ws).get("root"),
                    source.store(self.ws).etag("root"))

        def obj(self, oid):
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            return tuple(
                source.store(self.ws).get("obj/" + oid) for oid in oids)

        def put_pile(self, raw):
            pytest.fail("destination unexpectedly pushed")

    return LocalPeer


def test_point_entry_sorts_to_victim_position():
    """A single-target removal's span is exactly its victim's key (§2)."""
    early = message("pk", "general", "hello", 1)
    late = message("pk", "general", "world", 9)
    kill_early = removals.entry(
        channel_delete(early.fid, "general", 20), victim_key(early))
    kill_late = removals.entry(
        channel_delete(late.fid, "general", 10), victim_key(late))

    assert (kill_early.lo, kill_early.hi) == (shape.key(early),) * 2
    # deletion order is irrelevant: entries sit at their victims' positions
    assert sorted(
        [kill_late, kill_early], key=removals.entry_key) \
        == [kill_early, kill_late]


def test_channel_kill_sorts_to_head():
    """A kill spans ("", "~") and sorts before every point entry (§2)."""
    victim = message("pk", "general", "hello", 1)
    kill = removals.entry(
        channel_kill("general", 9), victim_key())  # no victim lookup at all
    point = removals.entry(
        channel_delete(victim.fid, "general", 9), victim_key(victim))

    assert (kill.lo, kill.hi) == removals.HEAD
    assert sorted([point, kill], key=removals.entry_key) == [kill, point]


def test_overlapping_returns_head_plus_slice_only():
    """Evaluating [a, b] reads the head and the [a, b] points, nothing else
    (§3.1); sorting is the skipping mechanism, no per-key probing."""
    victims = [message("pk", "general", f"m{ts}", ts) for ts in range(1, 5)]
    points = [
        removals.entry(
            channel_delete(fact.fid, "general", 9), victim_key(fact))
        for fact in victims
    ]
    kill = removals.entry(channel_kill("general", 9), victim_key())
    entries = [points[2], kill, points[0], points[3], points[1]]  # any order

    a, b = shape.key(victims[1]), shape.key(victims[2])
    assert removals.overlapping(entries, a, b) == (kill, points[1], points[2])
    # the head rides along even when the slice is empty
    assert removals.overlapping(entries, "9" * 15, "~") == (kill,)


def test_span_never_under_approximates():
    """fid embedded in a point span must match the target ref or admission
    rejects; the author chokepoint derives spans from the victim (I6)."""
    victim = message("pk", "general", "hello", 1)
    mate = message("pk", "general", "world", 2)
    point = channel_delete(victim.fid, "general", 9)
    honest = removals.entry(point, victim_key(victim))
    kill = channel_kill("general", 9)

    assert removals.admit(honest, point)
    assert removals.admit(removals.entry(kill, victim_key()), kill)
    routed_elsewhere = removals.Entry(
        shape.key(mate), shape.key(mate), point.fid)  # span misses victim
    widened = removals.Entry(honest.lo, shape.key(mate), point.fid)
    narrowed_kill = removals.Entry(
        shape.key(victim), shape.key(victim), kill.fid)  # hides victims
    for lie in (routed_elsewhere, widened):
        assert not removals.admit(lie, point)
    assert not removals.admit(narrowed_kill, kill)

    # Right fid, lying ts: passes the syntactic gate by design — "a deleter
    # who lies anyway only neuters their own deletion" (REMOVALS.md I6).
    # The span can never route to the victim's real key, so the lie is inert.
    liar = removals.Entry(
        shape.key_parts(999_999, victim.fid),
        shape.key_parts(999_999, victim.fid), point.fid)
    assert removals.admit(liar, point)
    assert removals.overlapping(
        [liar], shape.key(victim), shape.key(victim)) == ()


def test_point_deletion_never_suppresses_channel_mates():
    """REGRESSION (§2): a point removal of m1 reaches exactly m1 — never
    channel-mate m2. This fails against scalar suppkey equality AND against
    any form where a point's death marker feeds the group clause: both
    messages share the channel group, so either defect deletes m2 (the I6
    under-approximation, span (K,K) routing to one key)."""
    m1 = message("pk", "general", "hello", 1)
    m2 = message("pk", "general", "world", 2)
    point = channel_delete(m1.fid, "general", 3)

    assert removals.applies(point, m1)
    assert not removals.applies(point, m2)


def test_multi_group_fact_reachable_by_every_declared_group():
    """MULTI-GROUP (§2): membership is a SET. A fact in {chan, author} is
    reached by a kill of either group, not by a kill of a third, and a
    point removal of it reaches it alone."""
    fact = multi_group_post("general", "alice", "hi", 1)
    twin = multi_group_post("general", "alice", "again", 2)

    assert removals.applies(channel_kill("general", 3), fact)
    assert removals.applies(channel_kill("author/alice", 3), fact)
    assert not removals.applies(channel_kill("elsewhere", 3), fact)
    point = channel_delete(fact.fid, "general", 3)
    assert removals.applies(point, fact)
    assert not removals.applies(point, twin)


def test_predicate_never_suppresses_removals():
    """not is_deletion(f) is a correctness requirement (I2): removals are
    never victims and write no supp rows, so no removal — point or kill —
    can retract another, and the index cannot self-annihilate."""
    victim = message("pk", "general", "hello", 1)
    kill = channel_kill("general", 5)
    other_kill = channel_kill("general", 6)
    point_at_kill = channel_delete(kill.fid, "general", 7)

    assert removals.applies(kill, victim)  # the group clause is live...
    assert not removals.applies(kill, kill)  # ...but never against removals
    assert not removals.applies(other_kill, kill)
    assert not removals.applies(point_at_kill, kill)


def test_exactly_one_death_marker_admission_rule():
    """0 or 2+ death markers reject at admission instead of silently
    collapsing to no marker (I3)."""
    victim = message("pk", "general", "hello", 1)
    unmarked = Fact("channel_delete", 9, [["ref", TARGET, victim.fid]], {})
    twice = Fact(
        "channel_delete", 9,
        [atom("a", deletion=True), atom("b", deletion=True),
         ["ref", TARGET, victim.fid]], {})

    for bad in (unmarked, twice):
        assert not is_deletion(bad)
        with pytest.raises(ValueError, match="not a removal"):
            removals.entry(bad, victim_key(victim))
        assert not removals.admit(
            removals.Entry(*removals.HEAD, bad.fid), bad)


def test_encode_decode_roundtrip_and_fingerprint():
    """Canonical sorted encoding round-trips; fingerprint over entry keys is
    the set identity published beside the pile oid (I4)."""
    victim = message("pk", "general", "hello", 1)
    point = channel_delete(victim.fid, "general", 9)
    kill = channel_kill("general", 9)
    entries = [
        removals.entry(point, victim_key(victim)),
        removals.entry(kill, victim_key()),
    ]
    closure = [point, kill, victim]

    emitted = []
    oid = removals.encode(entries, closure, emitted.append)
    (raw,) = emitted
    assert h(raw) == oid
    assert oid == removals.encode(  # canonical: input order never shows
        list(reversed(entries)), list(reversed(closure)), lambda raw: None)
    decoded, refs = removals.decode(raw)
    assert decoded == tuple(sorted(entries, key=removals.entry_key))
    assert refs == tuple(sorted(shape.key(fact) for fact in closure))
    assert removals.fingerprint(entries) \
        == removals.fingerprint(reversed(entries))
    assert removals.fingerprint(entries) != removals.fingerprint(entries[:1])


def _crafted_root(source, workspace, entries, refs):
    """The source's root with its removals slot swapped for a crafted
    index pile; returns ``(root bytes, {oid: raw})``."""
    raw = canon({
        "entries": [list(e) for e in sorted(entries, key=removals.entry_key)],
        "refs": sorted(refs),
    })
    _, globals_, man, _ = manifest.decode_root(
        source.store(workspace).get("root"))
    root = manifest.encode_root(
        workspace, globals_, man,
        {"oid": h(raw), "fp": removals.fingerprint(entries)})
    return root, {h(raw): raw}


def test_poisoned_entry_does_not_block_the_index(tmp_path, monkeypatch):
    """Admission is per entry: one bad entry rejects alone, never
    pile-atomically with the rest of the removal history (I3)."""
    source, workspace, _, deletions = suppression_world(
        tmp_path / "source", monkeypatch,
        initial_secret=load_sk(f"{1:064x}"))
    destination = Node(str(tmp_path / "destination"))
    survivors = set(all_fids(source, workspace)) - set(deletions)
    deliver(
        destination, workspace,
        closed_subset(source, workspace, survivors))
    destination.turn(workspace)

    src = source.store(workspace)
    slot = manifest.decode_root(src.get("root"))[3]
    honest, refs = removals.decode(src.get("obj/" + slot["oid"]))
    ghost = "d" * 64  # a removal whose closure resolves to nothing
    poisoned = removals.Entry("", "~", ghost)
    root, crafted = _crafted_root(
        source, workspace, [*honest, poisoned],
        [*refs, shape.key_parts(300, ghost)])

    def fetch(oid):
        return crafted.get(oid) or src.get("obj/" + oid)

    fetch.many = lambda oids: tuple(fetch(oid) for oid in oids)
    admitted = sync_module.pull_removals(
        destination, workspace, root, fetch)

    assert {entry.fid for entry in admitted} == set(deletions)
    assert poisoned not in admitted
    for fid in deletions:  # the honest history landed despite the poison
        assert destination.fact_of(workspace, fid) is not None


def test_removal_before_victim_retracts_on_arrival(tmp_path, monkeypatch):
    """Retroactive retraction plus forward mask: a victim admitted after its
    removal never surfaces in E (§3.3), observed BETWEEN sync legs, not
    just at the end. Forward: sync's index leg lands the entry (and the
    removal's closure — the target is a hard dep, so entry and victim can
    never be pulled further apart than one leg) before the fact leg; the
    victim logs '+' and '-' in one transaction, the pump nets to
    retracted, and a trace at every leg boundary — after the index leg,
    at each fact-pile delivery — never sees the victim in E. Retro: a
    replica that already materialized the victim retracts it the moment
    the index leg completes (node.apply_removals via sync.pull_removals),
    before the fact leg pulls a single pile, and it never resurfaces.
    Mask: a KILL's victim authored AFTER the index synced arrives in a
    turn admitting no removal at all — the entry alone, via the admission
    consult, keeps it out of E (the point legs cannot pin this hook: a
    point removal's victim always rides its removal's own closure)."""
    source, workspace, targets, deletions = suppression_world(
        tmp_path / "source", monkeypatch,
        initial_secret=load_sk(f"{1:064x}"))
    dead = {targets[ordinal] for ordinal in (1, 4, 6)}
    monkeypatch.setattr(sync_module, "Peer", local_peer(source))

    trace = []  # (node, leg, per-victim E flags) at every leg boundary
    watch = sorted(dead)  # the victims the trace observes
    index_leg, fact_pull = sync_module.pull_removals, sync_module.pull

    def spy(tag, real):
        def wrapped(n, ws, *rest):
            out = real(n, ws, *rest)
            trace.append((n, tag, [surfaced(n, ws, fid) for fid in watch]))
            return out
        return wrapped

    monkeypatch.setattr(
        sync_module, "pull_removals", spy("index", index_leg))
    monkeypatch.setattr(sync_module, "pull", spy("pile", fact_pull))

    forward = Node(str(tmp_path / "forward"))  # neither removal nor victim
    deliver(forward, workspace, closed_subset(
        source, workspace,
        set(all_fids(source, workspace)) - dead - set(deletions)))
    forward.turn(workspace)
    sync_module.sync(forward, workspace, "local://source")
    for fid in dead:
        assert forward.fact_of(workspace, fid) is not None  # in V...
        ops = [op for (op,) in forward.idx(workspace).execute(
            "SELECT op FROM log WHERE fid=? ORDER BY seq", (fid,))]
        assert ops[:1] == ["+"] and "-" in ops  # '+' then '-', one turn
        assert not surfaced(forward, workspace, fid)  # ...never in E
    mine = [(tag, flags) for n, tag, flags in trace if n is forward]
    assert "index" in {tag for tag, _ in mine}  # the boundary was observed
    assert not any(flag for _, flags in mine for flag in flags)  # never in E
    assert forward.store(workspace).get("root") \
        == source.store(workspace).get("root")

    retro = Node(str(tmp_path / "retro"))  # victims materialized first
    deliver(retro, workspace, closed_subset(
        source, workspace,
        set(all_fids(source, workspace)) - set(deletions)))
    retro.turn(workspace)
    assert all(surfaced(retro, workspace, fid) for fid in dead)
    trace.clear()
    sync_module.sync(retro, workspace, "local://source")
    mine = [(tag, flags) for n, tag, flags in trace if n is retro]
    start = next(i for i, (tag, _) in enumerate(mine) if tag == "index")
    assert not any(  # retracted the moment the index leg completes, and
        flag for _, flags in mine[start:] for flag in flags)  # for good
    for fid in dead:
        assert not surfaced(retro, workspace, fid)  # retracted on arrival
    assert all_fids(retro, workspace) == all_fids(source, workspace)

    # Entry strictly BEFORE victim: sync the kill's entry first, author its
    # victim after, pull the victim's range last — the arriving turn admits
    # no removal, so only the admission-consult mask stands between the
    # victim and E.
    monkeypatch.setitem(facts.ROUTES, KillFamily.TAG, KillFamily)
    kill = channel_kill("channel-0", 150)
    source.ingest_new(workspace, [kill], {kill.fid: []})
    sync_module.sync(forward, workspace, "local://source")  # index first
    assert forward.fact_of(workspace, kill.fid) is not None
    late = cmds.post(source, workspace, "channel-0", "posthumous", ts=700)
    assert not surfaced(source, workspace, late)  # masked at the author too
    watch.append(late)
    trace.clear()
    sync_module.sync(forward, workspace, "local://source")  # victim's range
    assert forward.fact_of(workspace, late) is not None  # in V...
    ops = [op for (op,) in forward.idx(workspace).execute(
        "SELECT op FROM log WHERE fid=? ORDER BY seq", (late,))]
    assert ops[:1] == ["+"] and "-" in ops  # masked in its arriving turn
    assert not surfaced(forward, workspace, late)  # ...never in E
    assert not any(
        flag for n, _, flags in trace if n is forward for flag in flags)


def test_prune_restore_keeps_removals(tmp_path, monkeypatch):
    """Quarantining a victim quarantines its removal too — the target is a
    hard dep, the prune cascade — yet the index stays grow-only even
    locally (I1): the entry rides the published slot through the quarantine
    window (and an index rebuild inside it), and suppression HOLDS at every
    step — E excludes the victim before the cascade, inside the window,
    after the rebuild, and after restore."""
    monkeypatch.setitem(facts.ROUTES, DeletionFamily.TAG, DeletionFamily)
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "root", ts=1)
    root_secret, root_pk = node.identity(workspace)
    q_secret, q, _ = add_member(node, workspace, "q", ts=10)
    short_secret, short, _ = add_member(
        node, workspace, "short", inviter=(q_secret, q), ts=20)
    deep_secret, deep, _ = add_member(node, workspace, "d1", ts=30)
    for ordinal, name in enumerate(("d2", "d3", "deep")):
        deep_secret, deep, _ = add_member(
            node, workspace, name, inviter=(deep_secret, deep),
            ts=40 + 10 * ordinal)
    for secret, public, label in (
            (short_secret, short, "short-primary"),
            (deep_secret, deep, "deep-primary")):
        node.keychain.add_identity(secret)
        node.bind_identity(workspace, public)
        cmds.bind_device(node, workspace, label)
    target_secret, target = keypair()
    node.keychain.add_identity(target_secret)
    inject_device_claim(
        node, workspace, deep_secret, deep, deep, target, "from-deep", 200)
    node.bind_identity(workspace, target)
    _, child = keypair()
    victim = inject_device_claim(
        node, workspace, target_secret, target, deep, child, "child", 201)

    removal = channel_delete(victim.fid, "devices", 300)
    node.ingest_new(workspace, [removal], {removal.fid: [victim.fid]})
    entry = removals.entry(removal, victim_key(victim))
    assert not surfaced(node, workspace, victim.fid)
    assert entry in node.removal_entries(workspace)

    # The cascade: the short claim orphans the victim; the removal follows.
    inject_device_claim(
        node, workspace, short_secret, short, short, target,
        "from-short", 400)
    st = node.store(workspace)
    for fid in (victim.fid, removal.fid):
        assert node.fact_of(workspace, fid) is None
        assert st.has("quarantine/" + fid)
    # ...yet the entry keeps riding the published slot (grow-only), and
    # suppression holds inside the window: the victim stays out of E.
    assert entry in node.removal_entries(workspace)
    assert not surfaced(node, workspace, victim.fid)
    assert node.app.execute(
        "SELECT 1 FROM devices WHERE ws=? AND pk=?",
        (workspace, child)).fetchone() is None
    slot = manifest.decode_root(st.get("root"))[3]
    published, _ = removals.decode(st.get("obj/" + slot["oid"]))
    assert entry in published

    # An index rebuild inside the window re-derives from the store and must
    # not drop the entry: it lives in the slot object, not in idx.db rows.
    node.idx(workspace).executescript(
        "DELETE FROM facts; DELETE FROM offers; DELETE FROM proofs; "
        "DELETE FROM globals; DELETE FROM meta;")
    node.idx(workspace).commit()
    node.rebuild(workspace)
    assert node.fact_of(workspace, victim.fid) is None
    assert entry in node.removal_entries(workspace)
    assert not surfaced(node, workspace, victim.fid)  # E still excludes it

    # Restore: a direct rejoin shortens the deep proof; victim and removal
    # come back together and suppression still holds.
    invite_secret, invite_public = keypair()
    invitation = user_invite(root_pk, invite_public, 500)
    invitation_sig = signature(root_secret, root_pk, invitation, 500)
    rejoined = user(invitation, invite_secret, deep, "deep-direct", 501)
    rejoined_sig = signature(deep_secret, deep, rejoined, 501)
    node.ingest_new(
        workspace,
        [invitation_sig, invitation, rejoined_sig, rejoined], {
            invitation_sig.fid: [],
            invitation.fid: [
                invitation_sig.fid, member_src(node, workspace, root_pk)],
            rejoined_sig.fid: [],
            rejoined.fid: [invitation.fid, rejoined_sig.fid],
        })
    assert node.fact_of(workspace, victim.fid) == victim
    assert node.fact_of(workspace, removal.fid) == removal
    assert entry in node.removal_entries(workspace)
    assert not surfaced(node, workspace, victim.fid)
    assert node.app.execute(
        "SELECT 1 FROM devices WHERE ws=? AND pk=?",
        (workspace, child)).fetchone() is None


def test_e_is_the_v_minus_s_fold(tmp_path, monkeypatch):
    """The E = V∖S fold guard (was test_suppression_proof.effective, kept
    beside I2's contracts): the projected set equals the pure fold
    {f ∈ V : is_deletion(f) or no valid removal applies to f} — removals
    themselves stay in E, and S is exactly the applies() fold, kills and
    points alike."""
    monkeypatch.setitem(facts.ROUTES, KillFamily.TAG, KillFamily)
    node, ws, targets, _ = suppression_world(tmp_path / "node", monkeypatch)
    kill = channel_kill("channel-0", 300)
    node.ingest_new(ws, [kill], {kill.fid: []})

    valid = [node.fact_of(ws, fid) for fid in all_fids(node, ws)]
    deletions = [f for f in valid if is_deletion(f)]
    s = {
        f.fid for f in valid
        if not is_deletion(f)  # I2 is the frame: removals never leave E
        and any(removals.applies(r, f) for r in deletions)
    }
    e = {f.fid for f in valid} - s

    assert {d.fid for d in deletions} <= e  # deletions sit in E themselves
    assert set(targets) & s  # the fold really suppressed content...
    assert set(targets) & e  # ...and really spared the rest
    assert {
        src for (src,) in node.app.execute(
            "SELECT src FROM projected WHERE ws=?", (ws,))
    } == e


def test_fact_tree_fingerprints_unchanged_by_removal(tmp_path, monkeypatch):
    """Admitting a removal changes its OWN home leaf and the index slot —
    never a victim's leaf (I5 in one-store terms): no other range's leaf
    byte, key, or sibling moves, so cold ranges stay cold and the
    root-etag short-circuit keeps meaning "nothing to do"."""
    monkeypatch.setitem(facts.ROUTES, DeletionFamily.TAG, DeletionFamily)
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice", ts=1)
    first = cmds.post(node, workspace, "general", "m100", ts=100)
    ts, cuts = 101, 0
    while cuts < 2:  # several home leaves, so a cold range is real
        cuts += shape.boundary(cmds.post(
            node, workspace, "general", f"m{ts}", ts=ts))
        ts += 1
    st = node.store(workspace)
    fetch = lambda oid: st.get("obj/" + oid)
    man, slot = manifest.decode_root(st.get("root"))[2:]
    before = manifest.decode(fetch(man), fetch)
    victim = node.fact_of(workspace, first)
    home = manifest.locate(before, shape.key(victim))
    assert home != before[-1]  # the victim's range is genuinely elsewhere
    assert slot == {"oid": "", "fp": ""}

    deletion = channel_delete(victim.fid, "general", ts + 1000)
    node.ingest_new(workspace, [deletion], {deletion.fid: [victim.fid]})

    man, slot = manifest.decode_root(st.get("root"))[2:]
    after = manifest.decode(fetch(man), fetch)
    assert home in after  # victim's leaf: same sep, pile bytes, sibling
    assert manifest.locate(after, shape.key(deletion)) != home
    assert set(before) - set(after) <= {before[-1]}  # only the removal's
    assert slot["oid"] and slot["fp"]  # own tail leaf and the index moved


def test_sync_fetches_removals_before_fact_ranges(tmp_path, monkeypatch):
    """One index fetch ahead of the fact walk replaces the SUPP leg and
    close_deletions range augmentation (§5)."""
    source, workspace, targets, _ = suppression_world(
        tmp_path / "source", monkeypatch,
        initial_secret=load_sk(f"{1:064x}"))
    target = source.fact_of(workspace, targets[0])
    deletion = channel_delete(target.fid, target.body["chan"], 500)
    source.ingest_new(workspace, [deletion], {deletion.fid: [target.fid]})
    unsynced = [
        cmds.post(source, workspace, "general", f"late {i}", ts=600 + i)
        for i in range(4)
    ]
    destination = Node(str(tmp_path / "destination"))
    existing = set(all_fids(source, workspace)) \
        - {deletion.fid} - set(unsynced)
    deliver(
        destination, workspace,
        closed_subset(source, workspace, existing))
    destination.turn(workspace)

    order = []

    class LocalPeer:
        def __init__(self, node, ws, url):
            self.node, self.ws = node, ws
            self.cache = node.sync_cache.setdefault((ws, url), {})

        def root(self, etag=None):
            raw = source.store(self.ws).get("root")
            return raw, source.store(self.ws).etag("root")

        def obj(self, oid):
            order.append(oid)
            return source.store(self.ws).get("obj/" + oid)

        def objs(self, oids):
            order.extend(oids)
            return tuple(
                source.store(self.ws).get("obj/" + oid) for oid in oids)

        def put_pile(self, raw):
            pytest.fail("destination unexpectedly pushed")

    monkeypatch.setattr(sync_module, "Peer", LocalPeer)
    sync_module.sync(destination, workspace, "local://source")

    src = source.store(workspace)
    _, _, man, slot = manifest.decode_root(src.get("root"))
    fetch = lambda oid: src.get("obj/" + oid)
    leaves = {
        entry.leaf for entry in manifest.decode(fetch(man), fetch)}
    fact_fetches = [
        position for position, oid in enumerate(order) if oid in leaves]
    assert fact_fetches  # the fact leg really pulled home leaves
    assert order.index(slot["oid"]) < min(fact_fetches)
    assert destination.fact_of(workspace, deletion.fid) == deletion
    assert all_fids(destination, workspace) == all_fids(source, workspace)


@SKELETON
def test_production_deletion_family():
    """facts/content/delete.py is registered in content.MODULES; its author
    command derives channel and span from the actual victim (I6); admitting
    one retracts the victim's projected row and lands one index entry —
    the first non-monkeypatched deletion end to end (REMOVALS.md §8)."""
