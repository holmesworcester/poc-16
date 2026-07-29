"""facts/auth/user.py — invite redemption and workspace membership."""
import base64
import json
import urllib.request

from core.close import encode_pile
from core.crypto import box_decrypt, h, kdf, load_sk, sign, verify
from core.fact import Fact, Need, from_json
from .._policy import FamilyPolicy, Self, SidOffer, author_selectors
from . import signature, user_invite

TAG = "user"
TABLES = ("member_rows",)
POLICY = FamilyPolicy(
    suppression=(Self(),),
    principal_offers=(SidOffer("member", "member"),),
)


# SHAPE
def user(invite_fact, invite_sk, pk, name, ts):
    atoms = author_selectors(POLICY, {}) + [
        ["ref", "invite", invite_fact.fid], ["offer", "member", pk]]
    return Fact(TAG, ts, atoms,
                {"name": name, "pk": pk, "countersig": sign(invite_sk, pk)})


# NEEDS
def needs(f):
    return (Need("author", "author", f.fid, f.body.get("pk", "")),)


# VALIDATE
def validate(f, ctx):
    try:
        if set(f.body) != {"name", "pk", "countersig"} or len(f.refs()) != 1:
            return False
        if f.offers() != [("member", f.body["pk"], "")]:
            return False
        ref_role, ref_fid = f.refs()[0]
        if ref_role != "invite":
            return False
        invited = ctx.offers_from(ref_fid, "invitee")
        if len(invited) != 1:
            return False
        invite_pk = invited[0][0]
        shaped = Fact(TAG, f.ts,
                      author_selectors(POLICY, {}) + [
                       ["ref", "invite", ref_fid],
                       ["offer", "member", f.body["pk"]]],
                      dict(f.body))
        return f == shaped and verify(invite_pk, f.body["pk"], f.body["countersig"])
    except Exception:
        return False


# MODE
DURABLE = True


# MATERIALIZE
def materialize(db, workspace, valid):
    fact, body = valid.fact, valid.fact.body
    db.execute(
        "INSERT INTO member_rows VALUES(?,?,?,?,?)",
        (workspace, fact.fid, body["pk"], body["name"], "member"))


# COMMANDS — accepting a workspace establishes its local keyring anchor.
def accept(node, link, name):
    """Redeem a self-contained invite, then push the authored join."""
    from core.node import now_ms
    from core.sync import sync

    link_data = json.loads(base64.urlsafe_b64decode(link))
    url, workspace = link_data["u"], link_data["ws"]
    seed = bytes.fromhex(link_data["s"])
    encrypted = urllib.request.urlopen(
        f"{url}/invite/{kdf(seed, 'id').hex()}?ws={workspace}", timeout=15).read()
    blob = json.loads(box_decrypt(kdf(seed, "key"), encrypted))
    bootstrap = [from_json(item) for item in blob["pile"]]
    invitation = [
        fact for fact in bootstrap if fact.t == user_invite.TAG][-1]
    ts = now_ms()
    secret, public = node.identity()
    member = user(invitation, load_sk(blob["isk"]), public, name, ts)
    sig = signature.signature(secret, public, member, ts)
    node.add_workspace(
        workspace, name, peers=[url], identity=node.keychain.default_id())
    pile = encode_pile(bootstrap + [sig, member])  # bootstrap is already closed/topo
    node.store(workspace).put(f"pile/{node.member_for(workspace)}/{h(pile)}", pile)
    node.turn(workspace)
    sync(node, workspace, url)
    return workspace


# QUERIES
def members(node, workspace):
    with node.lock:
        rows = node.app.execute(
            "SELECT pk, name, role, evicted FROM members WHERE ws=? ORDER BY name",
            (workspace,)).fetchall()
    return [{"pk": pk, "name": name, "role": role, "evicted": bool(evicted)}
            for pk, name, role, evicted in rows]
