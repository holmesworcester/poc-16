"""Read-only local host status for the daemon control plane."""
from core.crypto import h
from core.limits import MAX_ROOT_BYTES


def describe(node, notifications=None):
    """Describe local presentation and operational state without fact policy."""
    out = {"pk": node.pk, "member": node.member, "workspaces": {}}
    with node.lock:
        for workspace, entry in node.keyring["workspaces"].items():
            node._sync_sql(workspace)
            database = node.idx(workspace)
            root = node.store(workspace).get_bounded(
                "root", MAX_ROOT_BYTES)
            out["workspaces"][workspace] = {
                "root": h(root) if root is not None else None,
                "facts": database.execute(
                    "SELECT COUNT(*) FROM facts",
                ).fetchone()[0],
                "peers": entry["peers"],
                "name": entry["name"],
                "identity": entry["identity"],
                "iroh_connections":
                    node.peer_connection_status(workspace),
                "ingress_failures": node.ingress_failures(workspace),
                "ingress_attempt_failures":
                    node.ingress_attempt_failures(workspace),
                "sync_failures": node.sync_failures(workspace),
            }
    if notifications is not None:
        out["notifications"] = notifications.status()
    return out
