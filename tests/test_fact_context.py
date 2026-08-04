"""Differential contract for database-free and SQL fact relationship reads."""

import facts

from .util import signed_pile_facts
from core.crypto import keypair
from core.fact import Fact, encode
from core.fact_index import index_rows
from core.kernel import MemoryContext, accepts, resolve_edges
from core.limits import (
    MAX_REGISTERED_FACT_ROUTES,
    MAX_REGISTERED_FACT_ROWS,
    MAX_REGISTERED_SUPPRESSION_ROUTES,
)
from full_peer.node import FullPeer, now_ms
from full_peer.sql_store import SqlStore

from .util import add_member, all_fids, closed_subset, send_bytes


def project(path, workspace, corpus):
    context = SqlStore.open(str(path), workspace)
    for fact in corpus:
        context.db.execute(
            "INSERT OR IGNORE INTO facts VALUES(?,?)",
            (fact.fid, encode(fact)),
        )
        context.db.executemany(
            "INSERT OR IGNORE INTO fact_index VALUES(?,?,?,?)",
            index_rows(fact),
        )
    context.db.commit()
    return context


def admit(context, fact):
    edges = resolve_edges(fact, context, strict=True)
    assert edges is not None
    assert accepts(fact, edges, context, strict=True)
    depth = context.depth(tuple(edge.fid for edge in edges))
    assert depth is not None
    context.admit(fact, depth, edges)
    return edges


def test_offer_resolution_matrix_matches_for_exact_and_open_sources(tmp_path):
    workspace = "0" * 64
    offered = (
        Fact("signature", 1, [["offer", "route", "key"]], {}, workspace),
        Fact(
            "signature", 2,
            [["offer", "route", "key", "owner"]], {}, workspace),
        Fact(
            "signature", 3,
            [["offer", "route", "other", "owner"]], {}, workspace),
    )
    sql = project(tmp_path / "matrix.db", workspace, offered)
    memory = MemoryContext(workspace)
    reverse = MemoryContext(workspace)
    for fact in offered:
        memory.admit(fact, 0, ())
    for fact in reversed(offered):
        reverse.admit(fact, 0, ())

    missing = "f" * 64
    for source in (None, missing, *(fact.fid for fact in offered)):
        for a1 in (None, "", "owner", "missing"):
            query = ("route", "key", a1, source)
            expected = sql.resolve_offer(*query)
            assert memory.resolve_offer(*query) == expected
            assert reverse.resolve_offer(*query) == expected

    owner = offered[1]
    assert memory.resolve_offer(
        "route", "key", None, owner.fid) == owner.fid
    assert memory.resolve_offer(
        "route", "key", "", owner.fid) is None
    assert memory.resolve_offer(
        "route", "key", "owner", owner.fid) == owner.fid
    sql.db.close()


def test_every_family_accepts_against_the_same_complete_context(tmp_path):
    node = FullPeer(str(tmp_path / "peer"))
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    facts.auth.device.bind(node, workspace, "phone")

    member = add_member(node, workspace, "bob")[1]
    facts.auth.admin.grant(node, workspace, member)
    sibling_secret, sibling = keypair()
    node.keychain.add_identity(sibling_secret)
    facts.auth.device_invite.grant(
        node, workspace, node.pk, sibling, "laptop")
    timestamp = now_ms()
    _, push_node = keypair()
    facts.auth.push_endpoint.register(
        node,
        workspace,
        "1" * 64,
        push_node,
        "android",
        "poc16.mobile",
        "production",
        facts.auth.push_endpoint.encode_sealed_target(b"x" * 49),
        ts=timestamp,
    )
    facts.content.notification_preference.set_global(
        node, workspace, "all", ts=timestamp + 1)

    message = facts.content.message.post(
        node, workspace, "general", "context contract", ts=timestamp + 2)
    send_bytes(
        node, workspace, "context.bin", b"context",
        ts=timestamp + 3)
    facts.content.delete.remove(
        node, workspace, message, ts=timestamp + 4)
    facts.auth.device_removal.remove(node, workspace, sibling)
    facts.auth.removal.evict(node, workspace, member)
    ephemeral = facts.auth.request.payload(
        node, workspace, "sync", timestamp + 10_000, timestamp + 6,
        removal_path=b"[]")
    historical = facts.auth.removal_path_request.payload(
        node, workspace, timestamp + 10_000, timestamp + 6)
    head = facts.auth.head_request.head_request(
        workspace,
        node.pk,
        node.pk,
        None,
        "2" * 64,
        timestamp + 10_000,
        b"[]",
        timestamp + 7,
    )
    head_signature = facts.auth.signature.signature(
        node.sk, node.pk, head, timestamp + 7)

    durable = signed_pile_facts(
        closed_subset(node, workspace, all_fids(node, workspace)),
        workspace,
    )
    corpus, seen = list(durable), {fact.fid for fact in durable}
    corpus.extend(fact for fact in ephemeral if fact.fid not in seen)
    seen.update(fact.fid for fact in corpus)
    corpus.extend(fact for fact in historical if fact.fid not in seen)
    corpus.extend((head_signature, head))
    assert {fact.t for fact in corpus} == set(facts.FAMILIES)
    routes = {
        fact.t: (
            len(fact.refs()),
            len(fact.offers()),
            len(facts.current_scopes(fact)),
            len(facts.action_sids(fact)),
            2 + len(index_rows(fact))
            + len(facts.current_scopes(fact) | facts.action_sids(fact)),
        )
        for fact in corpus
    }
    assert routes == {
        "admin": (0, 1, 1, 0, 7),
        "file_slice": (1, 1, 1, 0, 8),
        "delete": (1, 0, 0, 1, 6),
        "device": (0, 2, 2, 0, 10),
        "device_invite": (0, 2, 2, 0, 10),
        "device_removal": (0, 1, 0, 1, 6),
        "evict": (0, 1, 0, 1, 6),
        "file_bao": (0, 1, 1, 0, 7),
        "head_request": (0, 0, 0, 0, 4),
        "msg": (0, 0, 1, 0, 6),
        "notification_preference": (0, 2, 1, 0, 8),
        "push_endpoint": (0, 1, 3, 0, 11),
        "removal_path_request": (0, 0, 0, 0, 4),
        "req": (0, 0, 0, 0, 4),
        "signature": (0, 1, 0, 0, 5),
        "user": (1, 1, 1, 0, 8),
        "user_invite": (0, 1, 0, 0, 5),
        "workspace": (0, 2, 1, 0, 8),
    }
    assert max(row[-1] for row in routes.values()) \
        == MAX_REGISTERED_FACT_ROUTES
    assert max(
        1 + len(index_rows(fact))
        for fact in corpus
    ) == MAX_REGISTERED_FACT_ROWS
    assert max(
        len(facts.current_scopes(fact) | facts.action_sids(fact))
        for fact in corpus
    ) == MAX_REGISTERED_SUPPRESSION_ROUTES

    memory = MemoryContext(workspace)
    for fact in corpus:
        if not memory.has_fact(fact.fid):
            admit(memory, fact)
    sql = project(tmp_path / "complete.db", workspace, corpus)

    for fact in corpus:
        memory_edges = resolve_edges(fact, memory, strict=True)
        sql_edges = resolve_edges(fact, sql, strict=True)
        assert memory_edges == sql_edges
        assert accepts(fact, memory_edges, memory, strict=True)
        assert accepts(fact, sql_edges, sql, strict=True)
        assert memory.fact_of(fact.fid) == sql.fact_of(fact.fid)
        for name in {name for name, _, _ in fact.offers()}:
            assert memory.offers_from(fact.fid, name) \
                == sql.offers_from(fact.fid, name)
    sql.db.close()
