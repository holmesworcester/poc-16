"""Raw-free, content-addressed witnesses for running-kernel admission.

One proof root is a complete historical witness produced by one real
``drain`` judgment.  Its nodes bind durable facts to the exact named edges in
that judgment, and each edge pins the matching parent node.  Fact bytes live
in the candidate snapshot instead of being copied into proofs.

A candidate may acquire more than one valid historical witness.  Catalog
selection is a separate min-join over complete root oids; nodes inside one
witness deliberately do not have to equal the independently selected witness
for the same parent candidate.
"""
from dataclasses import dataclass

import facts

from .btreap import MAX_PAGE_BYTES, MAX_PAGE_DEPTH
from .crypto import h
from .fact import canon, encode as encode_fact
from .kernel import ResolvedEdge, drain, valid_resolved_edges
from .limits import (
    MAX_CLOSURE_FACTS,
    MAX_OBJECT_BYTES,
    MAX_PILE_BYTES,
    MAX_RESOLVED_EDGES,
    decode_json,
)
from .object_store import verified_object
from .shape import valid_fid

SCHEMA = "admission-proof-v1"
MAX_PROOF_EDGES = MAX_RESOLVED_EDGES
MAX_PROOF_NODES = MAX_CLOSURE_FACTS
MAX_PROOF_DEPTH = MAX_CLOSURE_FACTS
MAX_PROOF_FETCHES = MAX_PROOF_NODES * (MAX_PAGE_DEPTH + 2)
MAX_PROOF_INTRINSIC_BYTES = 6 * MAX_PILE_BYTES
MAX_PROOF_BYTES = (
    MAX_PROOF_INTRINSIC_BYTES
    + MAX_PROOF_NODES * MAX_PAGE_DEPTH * MAX_PAGE_BYTES
)


@dataclass(frozen=True)
class ProofNode:
    workspace: str
    fid: str
    edges: tuple


@dataclass(frozen=True)
class VerifiedProof:
    facts: tuple
    valids: tuple
    proofs: tuple
    fetches: int
    bytes: int


@dataclass
class VerificationBudget:
    """One budget shared by proof nodes, fact bytes, and cold object reads."""

    fetches: int = 0
    bytes: int = 0
    fetch_limit: int | None = None
    byte_limit: int | None = None

    def _limits(self):
        return (
            MAX_PROOF_FETCHES
            if self.fetch_limit is None else self.fetch_limit,
            MAX_PROOF_BYTES
            if self.byte_limit is None else self.byte_limit,
        )

    def charge(self, raw, *, fetches=1):
        if not isinstance(raw, bytes) or type(fetches) is not int \
                or fetches < 0:
            raise ValueError("admission proof budget input")
        self.fetches += fetches
        self.bytes += len(raw)
        fetch_limit, byte_limit = self._limits()
        if self.fetches > fetch_limit:
            raise ValueError("admission proof fetch budget")
        if self.bytes > byte_limit:
            raise ValueError("admission proof byte budget")

    def charge_io(self, fetches, byte_count):
        """Charge already-read cold objects without retaining their bytes."""
        if type(fetches) is not int or fetches < 0 \
                or type(byte_count) is not int or byte_count < 0:
            raise ValueError("admission proof budget input")
        self.fetches += fetches
        self.bytes += byte_count
        fetch_limit, byte_limit = self._limits()
        if self.fetches > fetch_limit:
            raise ValueError("admission proof fetch budget")
        if self.bytes > byte_limit:
            raise ValueError("admission proof byte budget")


def encode(workspace, fid, edges):
    """Encode one checked proof node; ``edges`` include parent proof oids."""
    if not valid_fid(workspace) or not valid_fid(fid):
        raise ValueError("admission proof identity")
    plain = []
    resolved = []
    for edge in edges:
        if not isinstance(edge, (list, tuple)) or len(edge) != 4:
            raise ValueError("admission proof edge")
        role, parent, kind, proof = edge
        if not valid_fid(proof):
            raise ValueError("admission parent proof")
        plain.append([role, parent, kind, proof])
        resolved.append(ResolvedEdge(role, parent, kind))
    if len(plain) > MAX_PROOF_EDGES:
        raise ValueError("admission proof edge budget")
    deps = tuple(edge.fid for edge in resolved)
    if not valid_resolved_edges(deps, tuple(resolved)):
        raise ValueError("admission proof edges")
    return canon({
        "edges": plain,
        "fid": fid,
        "schema": SCHEMA,
        "workspace": workspace,
    })


def decode(raw):
    value = decode_json(raw, MAX_OBJECT_BYTES, "admission proof")
    if not isinstance(value, dict) or set(value) != {
            "edges", "fid", "schema", "workspace"} \
            or value.get("schema") != SCHEMA:
        raise ValueError("admission proof shape")
    raw_edges = value["edges"]
    if not isinstance(raw_edges, list):
        raise ValueError("admission proof shape")
    canonical = encode(
        value["workspace"], value["fid"], raw_edges)
    if canonical != raw:
        raise ValueError("admission proof encoding")
    return ProofNode(
        value["workspace"],
        value["fid"],
        tuple(tuple(edge) for edge in raw_edges),
    )


def build(workspace, valids, emit):
    """Emit the path-sharing proof DAG for one complete kernel judgment."""
    proof_by_fid, closure_by_fid, depth_by_fid = {}, {}, {}
    proof_bytes, fact_bytes = {}, {}
    for receipt in valids:
        family = facts.family_for(receipt.fact.t)
        if family is None or not family.DURABLE:
            continue
        edges = []
        for edge in receipt.edges:
            parent = proof_by_fid.get(edge.fid)
            if parent is None:
                raise ValueError("durable admission has unproved parent")
            edges.append((edge.role, edge.fid, edge.kind, parent))
        raw = encode(workspace, receipt.fact.fid, edges)
        oid = h(raw)
        closure = {receipt.fact.fid}
        for edge in receipt.edges:
            closure.update(closure_by_fid[edge.fid])
        depth = 1 + max(
            (depth_by_fid[edge.fid] for edge in receipt.edges),
            default=0,
        )
        proof_bytes[receipt.fact.fid] = len(raw)
        fact_bytes[receipt.fact.fid] = len(encode_fact(receipt.fact))
        intrinsic_bytes = sum(
            proof_bytes[source] + fact_bytes[source]
            for source in closure
        )
        if len(closure) > MAX_PROOF_NODES:
            raise ValueError("admission proof node budget")
        if depth > MAX_PROOF_DEPTH:
            raise ValueError("admission proof depth budget")
        if 2 * len(closure) > MAX_PROOF_FETCHES:
            raise ValueError("admission proof fetch budget")
        if intrinsic_bytes > MAX_PROOF_INTRINSIC_BYTES:
            raise ValueError("admission proof byte budget")
        emitted = emit(raw)
        if emitted is not None and emitted != oid:
            raise ValueError("admission proof emitter changed identity")
        proof_by_fid[receipt.fact.fid] = oid
        closure_by_fid[receipt.fact.fid] = frozenset(closure)
        depth_by_fid[receipt.fact.fid] = depth
    return proof_by_fid


def verify(
        workspace, fid, proof_oid, fact_of, fetch, *,
        budget=None, fact_reads_metered=False):
    """Follow one rooted proof DAG and rerun the actual kernel over its facts."""
    if not valid_fid(workspace) or not valid_fid(fid) \
            or not valid_fid(proof_oid):
        raise ValueError("admission proof identity")
    nodes, by_fid, state, order = {}, {}, {}, []
    budget = VerificationBudget() if budget is None else budget
    if not isinstance(budget, VerificationBudget):
        raise TypeError("admission proof budget")
    stack = [(proof_oid, False, 1)]
    while stack:
        oid, expanded, depth = stack.pop()
        # Check every edge path, including one that rejoins a node already
        # verified through a shallower route. Otherwise a diamond can hide a
        # path one or more levels beyond the advertised depth bound.
        if depth > MAX_PROOF_DEPTH:
            raise ValueError("admission proof depth budget")
        if expanded:
            state[oid] = 2
            order.append(oid)
            continue
        if state.get(oid) == 1:
            raise ValueError("admission proof cycle")
        if state.get(oid) == 2:
            continue
        if len(nodes) >= MAX_PROOF_NODES:
            raise ValueError("admission proof node budget")
        raw = verified_object(oid, fetch)
        budget.charge(raw)
        node = decode(raw)
        if node.workspace != workspace:
            raise ValueError("admission proof workspace")
        previous = by_fid.setdefault(node.fid, oid)
        if previous != oid:
            raise ValueError("admission proof fid fork")
        nodes[oid] = node
        state[oid] = 1
        stack.append((oid, True, depth))
        for _, parent_fid, _, parent_oid in reversed(node.edges):
            stack.append((parent_oid, False, depth + 1))

    if nodes[proof_oid].fid != fid:
        raise ValueError("admission proof root")
    stream = []
    for oid in order:
        fact = fact_of(nodes[oid].fid)
        if fact is None or fact.fid != nodes[oid].fid:
            raise ValueError("admission proof fact")
        if not fact_reads_metered:
            budget.charge(encode_fact(fact))
        stream.append(fact)
    judgment = drain(stream, workspace)
    if not judgment.ok or len(judgment.valids) != len(stream):
        raise ValueError("admission proof kernel rejection")
    receipts = {receipt.fact.fid: receipt for receipt in judgment.valids}
    for node in nodes.values():
        receipt = receipts.get(node.fid)
        expected = tuple(
            ResolvedEdge(role, parent, kind)
            for role, parent, kind, _ in node.edges
        )
        if any(
                nodes[parent_oid].fid != parent_fid
                for _, parent_fid, _, parent_oid in node.edges):
            raise ValueError("admission proof parent identity")
        if receipt is None or tuple(receipt.edges) != expected:
            raise ValueError("admission proof edge judgment")
    return VerifiedProof(
        tuple(stream),
        judgment.valids,
        tuple((nodes[oid].fid, oid) for oid in order),
        budget.fetches,
        budget.bytes,
    )
