"""facts/auth/join.py — invite redemption and workspace membership."""
import base64
import json
import urllib.request

from ...close import encode_pile
from ...crypto import box_decrypt, h, kdf, load_sk, sign, verify
from ...fact import Fact, from_json
from . import invite, signature

TAG = "join"


# SHAPE
def join(invite_fact, invite_sk, pk, name, ts):
    atoms = [["ref", invite_fact.ts, invite_fact.fid], ["offer", "member", pk]]
    return Fact(TAG, ts, atoms,
                {"name": name, "pk": pk, "countersig": sign(invite_sk, pk)})


# NEEDS
def needs(f):
    return (("author", f.fid, f.body.get("pk", "")),)


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"name", "pk", "countersig"} or len(f.refs()) != 1:
            return False
        if f.offers() != [("member", f.body["pk"], "")]:
            return False
        ref_ts, ref_fid = f.refs()[0]
        invited = ctx.offers_from(ref_fid, "invitee")
        if len(invited) != 1:
            return False
        invite_pk = invited[0][0]
        shaped = Fact(TAG, f.ts,
                      [["ref", ref_ts, ref_fid], ["offer", "member", f.body["pk"]]],
                      dict(f.body))
        return f == shaped and verify(invite_pk, f.body["pk"], f.body["countersig"])
    except Exception:
        return False


# MODE
DURABLE = True


def global_rows(f):
    return ()


def blob_refs(f):
    return ()


# MATERIALIZE
def materialize(db, workspace, valid):
    body = valid.fact.body
    db.execute("INSERT OR IGNORE INTO members VALUES(?,?,?,?,0)",
               (workspace, body["pk"], body["name"], "member"))


# COMMANDS — accepting a workspace establishes its local keyring anchor.
def accept(node, link, name):
    """Redeem a self-contained invite, then push the authored join."""
    from ...node import now_ms
    from ...walk import walk

    link_data = json.loads(base64.urlsafe_b64decode(link))
    url, workspace = link_data["u"], link_data["ws"]
    seed = bytes.fromhex(link_data["s"])
    encrypted = urllib.request.urlopen(
        f"{url}/invite/{kdf(seed, 'id').hex()}?ws={workspace}", timeout=15).read()
    blob = json.loads(box_decrypt(kdf(seed, "key"), encrypted))
    bootstrap = [from_json(item) for item in blob["pile"]]
    invitation = [fact for fact in bootstrap if fact.t == invite.TAG][-1]
    ts = now_ms()
    member = join(invitation, load_sk(blob["isk"]), node.pk, name, ts)
    sig = signature.signature(node.sk, node.pk, member, ts)
    node.add_workspace(workspace, name, peers=[url])
    pile = encode_pile(bootstrap + [sig, member])  # bootstrap is already closed/topo
    node.store(workspace).put(f"pile/{node.member}/{h(pile)}", pile)
    node.turn(workspace)
    walk(node, workspace, url)
    return workspace


# QUERIES
def members(node, workspace):
    with node.lock:
        rows = node.app.execute(
            "SELECT pk, name, role, evicted FROM members WHERE ws=? ORDER BY name",
            (workspace,)).fetchall()
    return [{"pk": pk, "name": name, "role": role, "evicted": bool(evicted)}
            for pk, name, role, evicted in rows]
