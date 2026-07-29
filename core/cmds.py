"""Stable command façade over auth and content fact families.

Family modules own authoring and query assembly. This root module remains the
small control-plane API used by the daemon and tests.
"""
from facts.auth.user import accept as join, members
from facts.auth.user_invite import make as make_invite
from facts.auth.workspace import create
from facts.auth.admin import admins, grant as grant_admin
from facts.auth.device import bind as bind_device, devices
from facts.auth.device_invite import grant as grant_device
from facts.auth.removal import evict
from facts.content.delete import remove
from facts.content.file import bytes_for as file_bytes
from facts.content.file import files, save as save_file, send as send_file
from facts.content.message import messages as msgs
from facts.content.message import post


def status(node):
    out = {"pk": node.pk, "member": node.member, "workspaces": {}}
    with node.lock:
        for workspace, entry in node.keyring["workspaces"].items():
            out["workspaces"][workspace] = {
                "root": node.store(workspace).etag("root"),
                "facts": node.idx(workspace).execute(
                    "SELECT COUNT(*) FROM proofs").fetchone()[0],
                "admitted": node.idx(workspace).execute(
                    "SELECT COUNT(*) FROM facts").fetchone()[0],
                "peers": entry["peers"], "name": entry["name"],
                "identity": entry["identity"],
                "ingress_failures": node.ingress_failures(workspace),
                "sync_failures": node.sync_failures(workspace),
            }
    return out
