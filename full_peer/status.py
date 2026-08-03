"""Read-only local host status for the daemon control plane."""
from core.crypto import h
from core.fact import canon
from core.limits import PAGE_BATCH
from core.object_store import Versioned
from core.writer_head import (
    decode_slot_at,
    head_slot_prefix,
)


def _writer_state(node, workspace):
    """Return deterministic accepted and projected per-writer checkpoints."""
    store = node.store(workspace)
    prefix = head_slot_prefix(workspace)
    cursor = None
    accepted = []
    while True:
        page = store.list_page(prefix, cursor, PAGE_BATCH)
        for key in page.keys:
            opened = store.read_versioned(key)
            if not isinstance(opened, Versioned):
                raise ValueError("listed writer slot disappeared")
            slot = decode_slot_at(key, opened.value)
            accepted.append((
                slot.device, slot.head, slot.authority_root))
        if page.cursor is None:
            break
        cursor = page.cursor
    accepted.sort()
    projected = dict(node.idx(workspace).execute(
        "SELECT device, head_oid FROM projected_heads ORDER BY device"))
    writers = []
    for device, head, authority_root in accepted:
        writers.append({
            "authority_root": authority_root,
            "device": device,
            "head": head,
            "projected_head": projected.pop(device, None),
        })
    return (
        h(canon(["poc16-status-writer-forest-v1", accepted])),
        writers,
        projected,
    )


def describe(node, notifications=None):
    """Describe local presentation and operational state without fact policy."""
    out = {"pk": node.pk, "member": node.member, "workspaces": {}}
    with node.lock:
        for workspace in sorted(node.keyring["workspaces"]):
            entry = node.keyring["workspaces"][workspace]
            node._ensure_projection(workspace)
            database = node.idx(workspace)
            fingerprint, writers, projection_only = _writer_state(
                node, workspace)
            out["workspaces"][workspace] = {
                "facts": database.execute(
                    "SELECT COUNT(*) FROM facts",
                ).fetchone()[0],
                "forest_fingerprint": fingerprint,
                "writers": writers,
                "projection_only": projection_only,
                "peers": entry["peers"],
                "name": entry["name"],
                "identity": entry["identity"],
                "iroh_connections":
                    node.peer_connection_status(workspace),
                "sync_failures": node.sync_failures(workspace),
            }
    if notifications is not None:
        out["notifications"] = notifications.status()
    return out
