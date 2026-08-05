"""facts/auth/user.py — invite redemption and workspace membership."""
import base64

from core.close import decode_signed_pile
from core.crypto import box_decrypt, kdf, load_sk, sign, verify
from core.fact import Fact, Need, workspace_of
from core.limits import (
    MAX_INVITE_ARTIFACT_BYTES,
    MAX_INVITE_BYTES,
    MAX_INVITE_LINK_BYTES,
    PayloadTooLarge,
    decode_json,
)
from core.suppression import scoped_id
from .._policy import FamilyPolicy, SidOffer, author_selectors
from . import signature, user_invite
from ._display import display

TAG = "user"
POLICY = FamilyPolicy(
    control_fact=True,
    principal_offers=(SidOffer("member", "member"),),
    clear_offers=(SidOffer("member", "device"),),
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
    """Accept an inline invite and home its signed closure in this writer."""
    from facts import semantic_evaluation
    from core.kernel import drain

    if not isinstance(link, str):
        raise ValueError("invite link")
    try:
        encoded = link.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("invite link") from error
    if len(encoded) > MAX_INVITE_LINK_BYTES:
        raise PayloadTooLarge("invite link too large")
    try:
        artifact = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invite link") from error
    if base64.urlsafe_b64encode(artifact) != encoded:
        raise ValueError("invite link")
    link_data = decode_json(
        artifact, MAX_INVITE_ARTIFACT_BYTES, "invite artifact")
    if not isinstance(link_data, dict):
        raise ValueError("invite link")
    if set(link_data) != {"b", "p", "s", "ws"}:
        raise ValueError("invite link")
    peer = link_data["p"]
    workspace = link_data["ws"]
    if not all(
            isinstance(link_data[name], str)
            for name in ("b", "s", "ws")):
        raise ValueError("invite link")
    try:
        seed = bytes.fromhex(link_data["s"])
        encrypted = base64.b64decode(link_data["b"], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invite link") from error
    if len(seed) != 32:
        raise ValueError("invite link")
    if link_data["s"] != seed.hex() \
            or link_data["b"] != base64.b64encode(encrypted).decode():
        raise ValueError("invite link")
    if len(encrypted) > MAX_INVITE_BYTES:
        raise PayloadTooLarge("invite too large")
    retained = False
    try:
        blob = decode_json(
            box_decrypt(kdf(seed, "key"), encrypted),
            MAX_INVITE_BYTES,
            "invite plaintext",
        )
        if not isinstance(blob, dict) or set(blob) != {"pile", "isk", "ws"} \
                or blob.get("ws") != workspace:
            raise ValueError("invite workspace")
        bootstrap = decode_signed_pile(
            base64.b64decode(blob["pile"], validate=True), workspace).facts
        judgment = drain(bootstrap, workspace)
        if not judgment.ok:
            raise ValueError("invite bootstrap")
        valids, _current_bootstrap = semantic_evaluation(
            judgment, bootstrap)
        invitations = [
            valid.fact for valid in valids
            if valid.fact.t == user_invite.TAG
        ]
        if len(invitations) != 1:
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
        # The bootstrap is already closed and topological.  The local writer
        # publishes that exact closure as one signed writer-tree leaf; network
        # reconciliation subsequently exchanges the same portable leaf.
        node.publish_closed(workspace, (tuple(bootstrap) + (sig, member),))
        return workspace
    finally:
        if not retained:
            node.release_peer(workspace, peer)


# QUERIES
def members(node, workspace):
    """Assemble direct members and their explicitly owned devices."""
    with node.lock:
        candidates = {}
        role_order = {"admin": 0, "member": 1, "device": 2}
        # The roster is historical presentation: keep removed identities
        # visible and report their current liveness in ``evicted`` below.
        providers = {
            fact.fid: fact
            for kind in ("member", "device_key")
            for fact in node.select(
                workspace, kind, include_suppressed=True)
        }
        for fact in providers.values():
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
            owner
            for fact in node.select(workspace, "admin")
            for name, owner, _ in fact.offers()
            if name == "admin"
        }
        rows = [
            {
                "pk": public,
                "name": name,
                "role": "admin" if owner in admins else role,
                "evicted": node.suppression_active(
                    workspace, scoped_id("member", owner)),
            }
            for public, (_, name, role, owner) in candidates.items()
        ]
    return sorted(rows, key=lambda row: (row["name"], row["pk"]))


CLI = {"auth.user.join": accept, "auth.user.list": members}
