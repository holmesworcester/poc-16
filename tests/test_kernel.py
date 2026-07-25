"""Adversarial kernel tests: the judge rejects what it must, whole units."""
import pytest

from tinyp2p.crypto import keypair, sign
from tinyp2p.fact import Fact
from tinyp2p.facts.auth.removal import removal
from tinyp2p.facts.auth.request import request
from tinyp2p.facts.auth.signature import signature
from tinyp2p.facts.auth.user import user
from tinyp2p.facts.auth.user_invite import user_invite
from tinyp2p.facts.auth.workspace import workspace
from tinyp2p.facts.content.message import message
from tinyp2p.kernel import Global, drain, evaluate, validate
from tinyp2p.node import now_ms


@pytest.fixture
def anchor_chain():
    sk, pk = keypair()
    g = workspace(sk, pk, "alice", now_ms())
    return sk, pk, g


def judge(facts, anchor, g=None):
    return validate(facts, anchor) if g is None else evaluate(facts, anchor, g)


def test_genesis_and_msg(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    s = signature(sk, pk, m, ts)
    assert judge([g, s, m], g.fid)


def test_wrong_anchor_rejects(anchor_chain):
    """Workspace scope: a foreign genesis rejects inside the predicate."""
    sk, pk, g = anchor_chain
    assert not judge([g], "0" * 64)


def test_bad_sig_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    other_sk, _ = keypair()
    forged = Fact("signature", ts, [["offer", "author", m.fid, pk]],
                  {"sig": sign(other_sk, m.fid)})
    assert not judge([g, forged, m], g.fid)


def test_nonmember_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    m = message(epk, "c", "intruder", ts)
    s = signature(esk, epk, m, ts)
    assert not judge([g, s, m], g.fid)


def test_unresolved_ref_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    dangling = Fact("user", ts, [["ref", ts, "f" * 64], ["offer", "member", pk]],
                    {"name": "x", "pk": pk, "countersig": "00"})
    assert not judge([g, dangling], g.fid)


def test_offer_smuggling_rejects(anchor_chain):
    """A msg cannot mint auth offers: family offer names are closed."""
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    evil = Fact("msg", ts, [["offer", "admin", epk]],
                {"pk": pk, "chan": "c", "text": "x"})
    s = signature(sk, pk, evil, ts)
    assert not judge([g, s, evil], g.fid)


def test_all_or_nothing(anchor_chain):
    """A valid fact sinks with its bad batch; it returns on the next walk."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    good = message(pk, "c", "good", ts)
    sg = signature(sk, pk, good, ts)
    esk, epk = keypair()
    bad = message(epk, "c", "bad", ts)
    sb = signature(esk, epk, bad, ts)
    result = drain([g, sg, good, sb, bad], g.fid)
    assert not result.ok and result.valids == ()


def test_evict_needs_admin(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    isk, ipk = keypair()
    inv = user_invite(pk, ipk, ts)
    si = signature(sk, pk, inv, ts)
    bsk, bpk = keypair()
    j = user(inv, isk, bpk, "bob", ts)
    sj = signature(bsk, bpk, j, ts)
    ev = removal(bpk, pk, ts)  # bob (mere member) tries to evict alice
    se = signature(bsk, bpk, ev, ts)
    assert judge([g, si, inv, sj, j], g.fid)
    assert not judge([g, si, inv, sj, j, se, ev], g.fid)


def test_removal_gates_requests_only(anchor_chain):
    """Validity is globals-blind; only the ephemeral family reads removal."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "still valid", ts)
    s = signature(sk, pk, m, ts)
    rq = request(pk, "sync", ts + 9999, ts)
    sr = signature(sk, pk, rq, ts)
    globals_ = {Global("removal", pk)}
    assert validate([g, s, m], g.fid)                  # persistent: globals-blind
    assert not judge([g, sr, rq], g.fid, g=globals_)   # ephemeral: refused
    assert judge([g, sr, rq], g.fid, g=set())


def test_drain_emits_removal_global_only(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    ev = removal(pk, pk, ts)
    se = signature(sk, pk, ev, ts)
    result = drain([g, se, ev], g.fid)
    assert result.ok
    assert result.globals == {Global("removal", pk)}
    assert isinstance(validate([g, se, ev], g.fid), bool)


def test_order_matters_seen_set(anchor_chain):
    """The seen-set rule: providers must precede dependents in the stream."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = message(pk, "c", "hi", ts)
    s = signature(sk, pk, m, ts)
    assert not judge([g, m, s], g.fid)  # sig after its dependent: unmet need
