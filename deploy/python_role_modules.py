"""Exact database-free Python source closures for deployed read roles."""


_HTTP_REPOSITORY_CORE_MODULES = (
    "__init__.py",
    "close.py",
    "crypto.py",
    "fact.py",
    "fact_index.py",
    "grants.py",
    "http.py",
    "http_body.py",
    "limits.py",
    "merkle_map.py",
    "object_store.py",
    "pack_access.py",
    "peer_capability.py",
    "removal_path.py",
    "shape.py",
    "suppression.py",
    "removal_tree.py",
    "writer_head.py",
    "writer_tree.py",
)

# The public hosted gateway reads the writer forest and owns only private
# recipient-removal projection plus owner-confined writer-head CAS.  This is
# the exact database-free import closure for that role; no shared aggregate
# repository or detached compiler deployment is included.
HOSTED_GATE_CORE_MODULES = (
    *_HTTP_REPOSITORY_CORE_MODULES,
    "access.py",
    "head_permit.py",
    "kernel.py",
    "removal_state.py",
    "writer_repository.py",
)
