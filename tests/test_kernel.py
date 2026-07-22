"""Adversarial kernel tests: the judge rejects what it must, whole units."""
import pytest

from tinyp2p import fact as F
from tinyp2p.crypto import keypair
from tinyp2p.kernel import kernel
from tinyp2p.node import now_ms


@pytest.fixture
def anchor_chain():
    sk, pk = keypair()
    g = F.genesis(sk, pk, "alice", now_ms())
    return sk, pk, g


def judge(facts, anchor, g=None):
    ok, valids, removed = kernel(facts, anchor, globals_=g)
    return ok


def test_genesis_and_msg(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = F.msg(pk, "c", "hi", ts)
    s = F.sig_for(sk, pk, m, ts)
    assert judge([g, s, m], g.fid)


def test_wrong_anchor_rejects(anchor_chain):
    """Workspace scope: a foreign genesis rejects inside the predicate."""
    sk, pk, g = anchor_chain
    assert not judge([g], "0" * 64)


def test_bad_sig_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = F.msg(pk, "c", "hi", ts)
    other_sk, other_pk = keypair()
    forged = F.Fact("sig", ts, [["offer", "author", m.fid, pk]],
                    {"sig": F.sign(other_sk, m.fid)})
    assert not judge([g, forged, m], g.fid)


def test_nonmember_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    m = F.msg(epk, "c", "intruder", ts)
    s = F.sig_for(esk, epk, m, ts)
    assert not judge([g, s, m], g.fid)


def test_unresolved_ref_rejects(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    dangling = F.Fact("join", ts, [["ref", ts, "f" * 64], ["offer", "member", pk]],
                      {"name": "x", "pk": pk, "countersig": "00"})
    assert not judge([g, dangling], g.fid)


def test_offer_smuggling_rejects(anchor_chain):
    """A msg cannot mint auth offers: family offer names are closed."""
    sk, pk, g = anchor_chain
    esk, epk = keypair()
    ts = now_ms()
    evil = F.Fact("msg", ts, [["offer", "admin", epk]], {"pk": pk, "chan": "c", "text": "x"})
    s = F.sig_for(sk, pk, evil, ts)
    assert not judge([g, s, evil], g.fid)


def test_all_or_nothing(anchor_chain):
    """A valid fact sinks with its bad batch; it returns on the next walk."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    good = F.msg(pk, "c", "good", ts)
    sg = F.sig_for(sk, pk, good, ts)
    esk, epk = keypair()
    bad = F.msg(epk, "c", "bad", ts)
    sb = F.sig_for(esk, epk, bad, ts)
    ok, valids, _ = kernel([g, sg, good, sb, bad], g.fid)
    assert not ok and valids == []


def test_evict_needs_admin(anchor_chain):
    sk, pk, g = anchor_chain
    ts = now_ms()
    isk, ipk = keypair()
    inv = F.invite(pk, ipk, ts)
    si = F.sig_for(sk, pk, inv, ts)
    bsk, bpk = keypair()
    j = F.join(inv, isk, bpk, "bob", ts)
    sj = F.sig_for(bsk, bpk, j, ts)
    ev = F.evict(bpk, pk, ts)  # bob (mere member) tries to evict alice
    se = F.sig_for(bsk, bpk, ev, ts)
    assert judge([g, si, inv, sj, j], g.fid)
    assert not judge([g, si, inv, sj, j, se, ev], g.fid)


def test_removal_gates_requests_only(anchor_chain):
    """Validity is globals-blind; only the ephemeral family reads removal."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = F.msg(pk, "c", "still valid", ts)
    s = F.sig_for(sk, pk, m, ts)
    rq = F.req(pk, "sync", ts + 9999, ts)
    sr = F.sig_for(sk, pk, rq, ts)
    removal = {pk}
    assert judge([g, s, m], g.fid, g=removal)          # persistent: globals-blind
    assert not judge([g, sr, rq], g.fid, g=removal)    # ephemeral: refused
    assert judge([g, sr, rq], g.fid, g=set())


def test_order_matters_seen_set(anchor_chain):
    """The seen-set rule: providers must precede dependents in the stream."""
    sk, pk, g = anchor_chain
    ts = now_ms()
    m = F.msg(pk, "c", "hi", ts)
    s = F.sig_for(sk, pk, m, ts)
    assert not judge([g, m, s], g.fid)  # sig after its dependent: unmet need
