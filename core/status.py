"""Read-only local host status for the daemon control plane."""
from .crypto import h
from .limits import MAX_ROOT_BYTES


def describe(node):
    """Describe local presentation and operational state without fact policy."""
    out = {"pk": node.pk, "member": node.member, "workspaces": {}}
    with node.lock:
        for workspace, entry in node.keyring["workspaces"].items():
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
                "ingress_failures": node.ingress_failures(workspace),
                "ingress_attempt_failures":
                    node.ingress_attempt_failures(workspace),
                "sync_failures": node.sync_failures(workspace),
            }
    return out
