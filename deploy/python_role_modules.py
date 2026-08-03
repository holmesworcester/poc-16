"""Exact database-free Python source closures for deployed read roles."""


REPOSITORY_READER_CORE_MODULES = (
    "__init__.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "grants.py",
    "http.py",
    "http_body.py",
    "indexes.py",
    "ingress.py",
    "kernel.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "pack_access.py",
    "peer_capability.py",
    "repository_reader.py",
    "repository_snapshot.py",
    "shape.py",
    "snapshot.py",
    "suppression.py",
    "validated_set.py",
    "worker.py",
    "writer_head.py",
    "writer_tree.py",
)

# The public hosted gateway reads the writer forest and also owns the two
# bounded control mutations: authority-root publication and owner-confined
# writer-head CAS.  This is the exact database-free import closure for that
# role; the retired detached upload/applier deployments are not included.
HOSTED_GATE_CORE_MODULES = tuple(dict.fromkeys((
    *REPOSITORY_READER_CORE_MODULES,
    "authority.py",
    "repository_applier.py",
    "writer_repository.py",
)))

UPLOAD_BROKER_CORE_MODULES = (
    *REPOSITORY_READER_CORE_MODULES,
)
