"""facts/auth/user.py — invite redemption and workspace membership."""
import base64
import json
import urllib.request

from core.close import decode_pile, encode_pile
from core.crypto import box_decrypt, kdf, load_sk, sign, verify
from core.fact import Fact, Need, workspace_of
from core import suppression_state
from core.suppression import scoped_id
from .._policy import FamilyPolicy, Self, SidOffer, author_selectors
from . import signature, user_invite

TAG = "user"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    principal_offers=(SidOffer("member", "member"),),
)


# SHAPE
def user(invite_fact, invite_sk, pk, name, ts):
    atoms = author_selectors(POLICY, {}) + [
        ["ref", "invite", invite_fact.fid], ["offer", "member", pk]]
    return Fact(TAG, ts, atoms,
                {"name": name, "pk": pk, "countersig": sign(invite_sk, pk)},
                workspace_of(invite_fact))


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
                      dict(f.body), f.ws)
        return f == shaped and verify(invite_pk, f.body["pk"], f.body["countersig"])
    except Exception:
        return False


# MODE
DURABLE = True


# COMMANDS — accepting a workspace establishes its local keyring anchor.
def accept(node, link, name):
    """Redeem a self-contained invite, then push the authored join."""
    from core.kernel import drain
    from core.ingress import stage_pile
    from core.node import now_ms
    from core.sync import sync

    link_data = json.loads(base64.urlsafe_b64decode(link))
    url, workspace = link_data["u"], link_data["ws"]
    seed = bytes.fromhex(link_data["s"])
    encrypted = urllib.request.urlopen(
        f"{url}/invite/{kdf(seed, 'id').hex()}?ws={workspace}", timeout=15).read()
    blob = json.loads(box_decrypt(kdf(seed, "key"), encrypted))
    if not isinstance(blob, dict) or set(blob) != {"pile", "isk", "ws"} \
            or blob.get("ws") != workspace:
        raise ValueError("invite workspace")
    bootstrap, _ = decode_pile(
        base64.b64decode(blob["pile"], validate=True), workspace)
    judgment = drain(bootstrap, workspace)
    invitations = [
        valid.fact for valid in judgment.valids
        if valid.fact.t == user_invite.TAG
    ]
    if not judgment.ok or len(invitations) != 1:
        raise ValueError("invite bootstrap")
    invitation = invitations[0]
    ts = now_ms()
    secret, public = node.identity()
    member = user(invitation, load_sk(blob["isk"]), public, name, ts)
    sig = signature.signature(secret, public, member, ts)
    node.add_workspace(
        workspace, name, peers=[url], identity=node.keychain.default_id())
    pile = encode_pile(
        bootstrap + [sig, member],
        workspace=workspace,
    )  # bootstrap is already closed/topo
    stage_pile(node.store(workspace), node.member_for(workspace), pile)
    node.turn(workspace)
    sync(node, workspace, url)
    return workspace


# QUERIES
def members(node, workspace):
    """Assemble the roster from current ``member`` and ``admin`` offers."""
    with node.lock:
        candidates = {}
        role_order = {"admin": 0, "member": 1, "device": 2}
        for rank, fact in node.select_ranked(workspace, "member"):
            body = fact.body
            if fact.t == "workspace":
                row = body.get("pk"), body.get("name"), "admin"
            elif fact.t == TAG:
                row = body.get("pk"), body.get("name"), "member"
            elif fact.t == "device_invite":
                row = body.get("device"), body.get("label"), "device"
            else:
                continue
            public, name, role = row
            choice = (role_order[role], rank, fact.fid)
            if public and name and (
                    public not in candidates
                    or choice < candidates[public][0]):
                candidates[public] = (choice, name, role)

        admins = {
            public
            for fact in node.select(workspace, "admin")
            for name, public, _ in fact.offers()
            if name == "admin"
        }
        rows = [
            {
                "pk": public,
                "name": name,
                "role": "admin" if public in admins else role,
                "evicted": suppression_state.active(
                    node.idx(workspace), scoped_id("member", public)),
            }
            for public, (_, name, role) in candidates.items()
        ]
    return sorted(rows, key=lambda row: (row["name"], row["pk"]))


CLI = {"auth.user.join": accept, "auth.user.list": members}
