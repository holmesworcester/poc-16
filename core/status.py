"""Read-only local host status for the daemon control plane."""
from .crypto import h
from .fact_index import STATE_INDEX


def describe(node):
    """Describe local presentation and operational state without fact policy."""
    out = {"pk": node.pk, "member": node.member, "workspaces": {}}
    with node.lock:
        for workspace, entry in node.keyring["workspaces"].items():
            database = node.idx(workspace)
            root = node.store(workspace).get("root")
            out["workspaces"][workspace] = {
                "root": h(root) if root is not None else None,
                "facts": database.execute(
                    "SELECT COUNT(*) FROM fact_index "
                    "WHERE kind=? AND k0='eligible'",
                    (STATE_INDEX,),
                ).fetchone()[0],
                "admitted": database.execute(
                    "SELECT COUNT(*) FROM facts").fetchone()[0],
                "peers": entry["peers"],
                "name": entry["name"],
                "identity": entry["identity"],
                "ingress_failures": node.ingress_failures(workspace),
                "ingress_attempt_failures":
                    node.ingress_attempt_failures(workspace),
                "sync_failures": node.sync_failures(workspace),
            }
    return out
