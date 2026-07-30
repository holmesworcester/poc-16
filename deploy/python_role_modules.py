"""Exact database-free Python source closures for deployed read roles."""


REPOSITORY_READER_CORE_MODULES = (
    "__init__.py",
    "admission_proof.py",
    "bao.py",
    "candidate_archive.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "grants.py",
    "http_body.py",
    "indexes.py",
    "ingress.py",
    "kernel.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "peer_capability.py",
    "repository_reader.py",
    "repository_snapshot.py",
    "settlement.py",
    "shape.py",
    "snapshot.py",
    "suppression.py",
    "worker.py",
)

UPLOAD_BROKER_CORE_MODULES = (
    *REPOSITORY_READER_CORE_MODULES,
    "staged_intent.py",
)
