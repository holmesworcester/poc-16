"""facts/auth/user.py — invite redemption and workspace membership."""
import base64
import json
import urllib.request

from core.close import decode_pile
from core.crypto import box_decrypt, kdf, load_sk, sign, verify
from core.fact import Fact, Need, workspace_of
from core.http_body import read_bounded
from core.limits import MAX_INVITE_BYTES
from core.suppression import scoped_id
from .._policy import FamilyPolicy, Self, SidOffer, author_selectors
from . import signature, user_invite
from ._display import display

TAG = "user"
POLICY = FamilyPolicy(
    authority_resident=True,
    suppression=(Self(),),
    principal_offers=(SidOffer("member", "member"),),
)


# SHAPE
def user(invite_fact, invite_sk, pk, name, ts):
    name = display(name)
    atoms = author_selectors(POLICY, {}) + [
        ["ref", "invite", invite_fact.fid], ["offer", "member", pk, pk]]
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
        if f.offers() != [("member", f.body["pk"], f.body["pk"])]:
            return False
        ref_role, ref_fid = f.refs()[0]
        if ref_role != "invite":
            return False
        invited = ctx.offers_from(ref_fid, "invitee")
        if len(invited) != 1:
            return False
        invite_pk = invited[0][0]
        name = display(f.body["name"])
        shaped = Fact(TAG, f.ts,
                      author_selectors(POLICY, {}) + [
                       ["ref", "invite", ref_fid],
                       ["offer", "member", f.body["pk"], f.body["pk"]]],
                      {**f.body, "name": name}, f.ws)
        return f == shaped and verify(invite_pk, f.body["pk"], f.body["countersig"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS — accepting a workspace establishes its local keyring anchor.
def accept(node, link, name):
    """Redeem a self-contained invite and commit the authored join locally."""
    from core.kernel import drain

    link_data = json.loads(base64.urlsafe_b64decode(link))
    if not isinstance(link_data, dict):
        raise ValueError("invite link")
    if set(link_data) == {"u", "ws", "s"}:
        peer = link_data["u"]  # legacy URL-only envelope
    elif set(link_data) == {"p", "ws", "s"}:
        peer = link_data["p"]
    else:
        raise ValueError("invite link")
    workspace = link_data["ws"]
    seed = bytes.fromhex(link_data["s"])
    retained = False
    try:
        url = node.resolve_peer(workspace, peer)
        response = urllib.request.urlopen(
            f"{url}/invite/{kdf(seed, 'id').hex()}?ws={workspace}",
            timeout=15,
        )
        try:
            encrypted = read_bounded(
                response, MAX_INVITE_BYTES, "invite response")
        finally:
            response.close()
        blob = json.loads(box_decrypt(kdf(seed, "key"), encrypted))
        if not isinstance(blob, dict) or set(blob) != {"pile", "isk", "ws"} \
                or blob.get("ws") != workspace:
            raise ValueError("invite workspace")
        bootstrap = decode_pile(
            base64.b64decode(blob["pile"], validate=True), workspace)
        judgment = drain(bootstrap, workspace)
        invitations = [
            valid.fact for valid in judgment.valids
            if valid.fact.t == user_invite.TAG
        ]
        if not judgment.ok or len(invitations) != 1:
            raise ValueError("invite bootstrap")
        invitation = invitations[0]
        ts = node.now_ms()
        secret, public = node.identity()
        member = user(invitation, load_sk(blob["isk"]), public, name, ts)
        sig = signature.signature(secret, public, member, ts)
        node.add_workspace(
            workspace, name, peers=[peer],
            identity=node.keychain.default_id())
        retained = True
        # The bootstrap is already closed/topological; PileSender owns the one
        # outbound wire encoding before the shared receiving boundary.
        pile = node.sender(workspace).pack(bootstrap + [sig, member])
        node.receive_pile(
            workspace, node.member_for(workspace), pile)
        return workspace
    finally:
        if not retained:
            node.release_peer(workspace, peer)


# QUERIES
def members(node, workspace):
    """Assemble the roster from current ``member`` and ``admin`` offers."""
    with node.lock:
        candidates = {}
        role_order = {"admin": 0, "member": 1, "device": 2}
        # The roster is historical presentation: keep removed identities
        # visible and report their current liveness in ``evicted`` below.
        for fact in node.select(
                workspace, "member", include_suppressed=True):
            body = fact.body
            if fact.t == "workspace":
                row = (
                    body.get("pk"), body.get("name"), "admin",
                    body.get("pk"))
            elif fact.t == TAG:
                row = (
                    body.get("pk"), body.get("name"), "member",
                    body.get("pk"))
            elif fact.t == "device_invite":
                row = (
                    body.get("device"), body.get("label"), "device",
                    body.get("user"))
            else:
                continue
            public, name, role, owner = row
            choice = (role_order[role], fact.fid)
            if public and name and owner and (
                    public not in candidates
                    or choice < candidates[public][0]):
                candidates[public] = (choice, name, role, owner)

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
                "evicted": node.suppression_active(
                    workspace, scoped_id("member", owner)),
            }
            for public, (_, name, role, owner) in candidates.items()
        ]
    return sorted(rows, key=lambda row: (row["name"], row["pk"]))


CLI = {"auth.user.join": accept, "auth.user.list": members}
