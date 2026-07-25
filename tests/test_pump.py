"""Acceptance laws for the cursored projection pump."""
from types import SimpleNamespace

import pytest

from tinyp2p import cmds, facts
from tinyp2p.close import decode_pile
from tinyp2p.crypto import keypair
from tinyp2p.fact import Fact
from tinyp2p.kernel import Valid
from tinyp2p.node import Node, now_ms
from tinyp2p.pump import pump, retract
from tinyp2p.suppression import atom

from .util import add_member, all_fids, closed_subset, deliver


@pytest.fixture
def world(tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    message = cmds.post(node, workspace, "general", "hello")
    return node, workspace, message


# ---- exactly-once (poc-16-808.5) ---------------------------------------------

def test_pump_twice_is_noop(world):
    """Second pump with no new log rows changes nothing."""
    node, workspace, _ = world
    before = tuple(node.app.iterdump())

    assert pump(node, workspace) == 0
    assert tuple(node.app.iterdump()) == before
    assert node.app.execute(
        "SELECT seq FROM cursors WHERE ws=? AND projector='app'",
        (workspace,),
    ).fetchone()[0] == node.idx(workspace).execute(
        "SELECT MAX(seq) FROM log").fetchone()[0]


def test_pump_crash_resume(tmp_path, monkeypatch):
    """Kill between any two rows: rerun continues cleanly — row application
    and cursor advance share ONE transaction; no handler needs
    INSERT OR IGNORE to survive it."""
    from tinyp2p import node as runtime

    monkeypatch.setattr(runtime, "pump", lambda *args: 0)
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    cmds.post(node, workspace, "general", "first")
    cmds.post(node, workspace, "general", "second")
    monkeypatch.setattr(runtime, "pump", pump)
    materialize = facts.materialize
    calls = 0

    def crash(app, ws, valid):
        nonlocal calls
        materialize(app, ws, valid)
        calls += 1
        if calls == 2:
            raise RuntimeError("projector crash")

    monkeypatch.setattr(facts, "materialize", crash)
    with pytest.raises(RuntimeError, match="projector crash"):
        pump(node, workspace)

    assert node.app.execute("SELECT COUNT(*) FROM members").fetchone()[0] == 0
    assert node.app.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0
    assert node.app.execute("SELECT COUNT(*) FROM cursors").fetchone()[0] == 0

    monkeypatch.setattr(facts, "materialize", materialize)
    rows = node.idx(workspace).execute(
        "SELECT COUNT(*) FROM log").fetchone()[0]
    node.idx(workspace).close()
    node.app.close()
    resumed = Node(node.dir)

    assert rows > 0
    assert pump(resumed, workspace) == 0
    assert [item["text"] for item in cmds.msgs(resumed, workspace)] \
        == ["first", "second"]


def test_restart_discards_index_ahead_of_root(tmp_path, monkeypatch):
    """A crash after merge cannot publish facts the root does not contain."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    root = node.store(workspace).get("root")
    root_etag = node.store(workspace).etag("root")

    def crash(*args, **kwargs):
        raise RuntimeError("before root")

    monkeypatch.setattr(node, "commit", crash)
    with pytest.raises(RuntimeError, match="before root"):
        cmds.post(node, workspace, "general", "not published")
    assert node.idx(workspace).execute(
        "SELECT v FROM meta WHERE k='root'").fetchone() == (root_etag,)
    assert node.idx(workspace).execute(
        "SELECT COUNT(*) FROM facts WHERE t='message'").fetchone() == (0,)
    assert cmds.msgs(node, workspace) == []
    assert node.store(workspace).list("pile/")

    node.idx(workspace).close()
    node.app.close()
    resumed = Node(node.dir)
    assert resumed.store(workspace).get("root") == root
    assert cmds.msgs(resumed, workspace) == []

    resumed.turn(workspace)
    assert [item["text"] for item in cmds.msgs(resumed, workspace)] \
        == ["not published"]


def test_restart_resumes_rows_after_root_publish(tmp_path, monkeypatch):
    """A published root with an unadvanced cursor is pumped on startup."""
    from tinyp2p import node as runtime

    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")

    def crash(*args, **kwargs):
        raise RuntimeError("after root")

    monkeypatch.setattr(runtime, "pump", crash)
    with pytest.raises(RuntimeError, match="after root"):
        cmds.post(node, workspace, "general", "committed")
    assert cmds.msgs(node, workspace) == []

    monkeypatch.setattr(runtime, "pump", pump)
    node.idx(workspace).close()
    node.app.close()
    resumed = Node(node.dir)
    assert [item["text"] for item in cmds.msgs(resumed, workspace)] \
        == ["committed"]
    assert pump(resumed, workspace) == 0


def test_restart_recovers_interrupted_rebuild(tmp_path, monkeypatch):
    """The destructive rebuild step invalidates its root stamp atomically."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    cmds.post(node, workspace, "general", "survives")
    root = node.store(workspace).get("root")

    def crash(*args, **kwargs):
        raise RuntimeError("during rebuild")

    monkeypatch.setattr(node, "merge", crash)
    with pytest.raises(RuntimeError, match="during rebuild"):
        node.rebuild(workspace)
    assert node.idx(workspace).execute(
        "SELECT 1 FROM meta WHERE k='root'").fetchone() is None

    node.idx(workspace).close()
    node.app.close()
    resumed = Node(node.dir)
    assert resumed.store(workspace).get("root") == root
    assert [item["text"] for item in cmds.msgs(resumed, workspace)] \
        == ["survives"]


def test_reproject_marker_survives_restart(world, monkeypatch):
    """A commit-only restore remains durable until the next pump."""
    node, workspace, restored = world
    monkeypatch.setattr(
        node, "_update_proofs",
        lambda *args: (set(), {restored}),
    )
    node.commit(workspace)

    marker = node.idx(workspace).execute(
        "SELECT CAST(v AS INT) FROM meta WHERE k='reproject'"
    ).fetchone()[0]
    assert marker == node.idx(workspace).execute(
        "SELECT MAX(seq) FROM log").fetchone()[0]

    clear = facts.clear
    cleared = []

    def track_clear(app, ws):
        cleared.append(ws)
        clear(app, ws)

    monkeypatch.setattr(facts, "clear", track_clear)
    node.idx(workspace).close()
    node.app.close()
    resumed = Node(node.dir)

    assert cleared == [workspace]
    assert pump(resumed, workspace) == 0


@pytest.mark.parametrize("historical_minus", (False, True))
def test_missing_cursor_rebuilds(world, monkeypatch, historical_minus):
    """Unknown app state folds the effective set, never replays history."""
    node, workspace, target = world
    if historical_minus:
        node.idx(workspace).execute(
            "INSERT INTO log(op, fid) VALUES('-', ?)", (target,))
        node.idx(workspace).commit()
    node.app.execute(
        "DELETE FROM cursors WHERE ws=?", (workspace,))
    node.app.commit()

    clear = facts.clear
    cleared = []

    def track_clear(app, ws):
        cleared.append(ws)
        clear(app, ws)

    monkeypatch.setattr(facts, "clear", track_clear)
    node._reproject.clear()
    assert pump(node, workspace) > 0
    assert cleared == [workspace]
    assert [item["text"] for item in cmds.msgs(node, workspace)] == ["hello"]


@pytest.mark.parametrize("boundary", ("live", "retry", "restart", "rebuild"))
def test_pump_preserves_order_for_dependent_updates(
        tmp_path, monkeypatch, boundary):
    """Same-batch UPDATEs follow their member across every replay boundary."""
    from tinyp2p import node as runtime

    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice")
    clock = [source.fact_of(workspace, workspace).ts]

    def tick():
        clock[0] += 10
        return clock[0]

    monkeypatch.setattr(runtime, "now_ms", tick)
    for ordinal in range(64):
        _, target, joined = add_member(
            source, workspace, f"member-{ordinal}", ts=tick())
        granted = cmds.grant_admin(source, workspace, target)
        removed = cmds.evict(source, workspace, target)
        if granted < joined.fid and removed < joined.fid:
            break
    else:
        raise AssertionError("could not construct reverse fid order")

    pile = closed_subset(source, workspace, all_fids(source, workspace))
    expected = [fact.fid for fact in decode_pile(pile)[0]]
    peer = Node(str(tmp_path / "peer"))
    peer.add_workspace(workspace, "alice", peers=[])
    peer.rebuild(workspace)
    deliver(peer, workspace, pile)

    def crash(*args, **kwargs):
        raise RuntimeError(boundary)

    if boundary == "retry":
        commit = peer.commit
        monkeypatch.setattr(peer, "commit", crash)
        with pytest.raises(RuntimeError, match=boundary):
            peer.turn(workspace)
        monkeypatch.setattr(peer, "commit", commit)
        peer.turn(workspace)
    elif boundary == "restart":
        monkeypatch.setattr(runtime, "pump", crash)
        with pytest.raises(RuntimeError, match=boundary):
            peer.turn(workspace)
        monkeypatch.setattr(runtime, "pump", pump)
        peer.idx(workspace).close()
        peer.app.close()
        peer = Node(peer.dir)
    else:
        peer.turn(workspace)
        if boundary == "rebuild":
            peer.rebuild(workspace)

    admitted = [
        fid for op, fid in peer.idx(workspace).execute(
            "SELECT op, fid FROM log ORDER BY seq")
        if op == "+"
    ]
    if boundary != "rebuild":
        assert admitted == expected
    assert admitted.index(joined.fid) < admitted.index(granted)
    assert admitted.index(joined.fid) < admitted.index(removed)
    projected = next(
        row for row in cmds.members(peer, workspace)
        if row["pk"] == target)
    assert projected["role"] == "admin"
    assert projected["evicted"] is True


def test_minus_follows_plus(world, monkeypatch):
    """A deletion refs its target, so −t appears after +t in every legal
    stream node.merge appends."""
    node, workspace, target = world
    deletion = Fact(
        "channel_delete", now_ms(),
        [atom("general", deletion=True), ["ref", "target", target]],
        {},
    )
    monkeypatch.setitem(
        facts.ROUTES, deletion.t,
        SimpleNamespace(DURABLE=True),
    )

    node.merge(workspace, [Valid(deletion, (target,))])

    rows = node.idx(workspace).execute(
        "SELECT seq, op, fid FROM log "
        "WHERE fid IN (?, ?) ORDER BY seq",
        (target, deletion.fid),
    ).fetchall()
    target_plus = next(seq for seq, op, fid in rows
                       if op == "+" and fid == target)
    deletion_plus = next(seq for seq, op, fid in rows
                         if op == "+" and fid == deletion.fid)
    target_minus = next(seq for seq, op, fid in rows
                        if op == "-" and fid == target)

    assert target_plus < deletion_plus < target_minus


# ---- the contract (poc-16-808.6) ----------------------------------------------

def test_every_projector_row_carries_src(world):
    """Every family-declared projector table is keyed by producing fact."""
    node, _, _ = world
    tables = {"projected"} | {
        table for module in facts.MODULES for table in module.TABLES
    }
    for table in tables:
        columns = {
            name: primary
            for _, name, _, _, _, primary in node.app.execute(
                f"PRAGMA table_info({table})")
        }
        assert columns.get("src", 0) > 0


def test_generic_retraction_by_src(tmp_path):
    """pump.retract deletes a fact's rows across the family's tables; no
    per-family retraction code exists."""
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    cmds.bind_device(node, workspace, "phone")
    _, laptop = keypair()
    source = cmds.grant_device(
        node, workspace, node.identity_id(workspace), laptop, "laptop")
    assert node.app.execute(
        "SELECT COUNT(*) FROM member_rows WHERE src=?", (source,)
    ).fetchone() == (1,)
    assert node.app.execute(
        "SELECT COUNT(*) FROM device_rows WHERE src=?", (source,)
    ).fetchone() == (1,)

    node.idx(workspace).execute(
        "INSERT INTO log(op, fid) VALUES('-', ?)", (source,))
    node.idx(workspace).commit()
    assert pump(node, workspace) == 1

    assert node.app.execute(
        "SELECT COUNT(*) FROM projected WHERE src=?", (source,)
    ).fetchone() == (0,)
    assert node.app.execute(
        "SELECT COUNT(*) FROM member_rows WHERE src=?", (source,)
    ).fetchone() == (0,)
    assert node.app.execute(
        "SELECT COUNT(*) FROM device_rows WHERE src=?", (source,)
    ).fetchone() == (0,)
    assert all(row["pk"] != laptop for row in cmds.members(node, workspace))
    assert node.app.execute(
        "SELECT COUNT(*) FROM devices WHERE ws=? AND pk=?",
        (workspace, laptop),
    ).fetchone() == (0,)

    # Aggregate views retain all candidates, so deleting a winner exposes the
    # runner-up without family-specific repair code.
    candidates = (("a" * 64, 1, "first"), ("b" * 64, 2, "second"))
    for src, rank, label in candidates:
        node.app.execute(
            "INSERT INTO projected VALUES(?,?,?,?)",
            (workspace, src, "device_invite", rank))
        node.app.execute(
            "INSERT INTO device_rows VALUES(?,?,?,?,?)",
            (workspace, src, laptop, "runner-up", label))
        node.app.execute(
            "INSERT INTO member_rows VALUES(?,?,?,?,?)",
            (workspace, src, "runner-up", label, "device"))
    assert node.app.execute(
        "SELECT source FROM devices WHERE pk='runner-up'"
    ).fetchone() == (candidates[0][0],)
    assert node.app.execute(
        "SELECT src FROM members WHERE pk='runner-up'"
    ).fetchone() == (candidates[0][0],)
    retract(node.app, workspace, candidates[0][0])
    assert node.app.execute(
        "SELECT source FROM devices WHERE pk='runner-up'"
    ).fetchone() == (candidates[1][0],)
    assert node.app.execute(
        "SELECT src FROM members WHERE pk='runner-up'"
    ).fetchone() == (candidates[1][0],)


def test_handlers_contain_no_suppression_logic():
    """AST check: no materialize handler reads S, removals, or evicted state
    — suppression reaches app.db only as pump '−' rows."""
    for module in facts.MODULES:
        names = module.materialize.__code__.co_names
        assert "retract" not in names
        assert "victims" not in names


def test_removal_join_confluence(tmp_path):
    """The known bug (SIMPLIFY.md §5): removal before join in delivery order
    still yields evicted=1 in the members view — insert-only removals row +
    view, not UPDATE."""
    source = Node(str(tmp_path / "source"))
    workspace = cmds.create(source, "alice", ts=1)
    _, target, joined = add_member(source, workspace, "bob", ts=2)
    removed = cmds.evict(source, workspace, target)
    piles = (
        closed_subset(source, workspace, [joined.fid]),
        closed_subset(source, workspace, [removed]),
    )

    observations = []
    for name, order in (("join-first", piles), ("removal-first", piles[::-1])):
        peer = Node(str(tmp_path / name))
        for pile in order:
            deliver(peer, workspace, pile)
            peer.turn(workspace)
        observations.append(next(
            member for member in cmds.members(peer, workspace)
            if member["pk"] == target))

    assert observations[0] == observations[1]
    assert observations[0]["evicted"] is True


# ---- THE theorem (poc-16-808.7) ------------------------------------------------

@pytest.mark.skip(reason="poc-16-808.7")
def test_fold_pm_over_d_equals_fold_over_e():
    """Live: fold± over random delivery orders of D. Rebuild: fold over E in
    canonical order. Identical app.db (dump compare), for every world in the
    suppression corpus."""
    raise NotImplementedError


@pytest.mark.skip(reason="poc-16-808.7")
def test_rebuild_fires_zero_retractions():
    """Replay computes S first (T_supp / the root), folds over E: the '−'
    path never runs; the retraction counter stays 0."""
    raise NotImplementedError
