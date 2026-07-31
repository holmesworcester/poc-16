"""facts/content/message.py — a member-signed channel message."""
from core.fact import Fact, Need
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Self,
    author_selectors,
)
from .._commands import (
    direct_upload,
    member_source,
    publish,
)
from ..auth import signature

TAG = "msg"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="owner",
)


# SHAPE
def message(workspace, pk, channel, text, ts, owner=None):
    owner = pk if owner is None else owner
    return Fact(
        TAG, ts, author_selectors(POLICY, {}),
        {"pk": pk, "owner": owner, "chan": channel, "text": text}, workspace,
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    owner = f.body.get("owner", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk, owner),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "owner", "chan", "text"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == message(
                f.ws, body["pk"], body["chan"], body["text"], f.ts,
                body["owner"])
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _author(node, workspace, channel, text, ts):
    timestamp = node.now_ms() if ts is None else ts
    secret, public = node.identity(workspace)
    _, owner = member_source(node, workspace, public)
    if owner is None:
        raise ValueError("publishing identity is not a workspace member")
    item = message(
        workspace, public, channel, text, timestamp, owner)
    return item, signature.signature(secret, public, item, timestamp)


def post(node, workspace, channel, text, ts=None):
    item, signed = _author(node, workspace, channel, text, ts)
    return publish(node, workspace, item, signed)


def upload(
        node, workspace, channel, text, broker_url, provider_origin,
        ts=None):
    """Author one message and send its closed pile directly to ingress."""
    item, signed = _author(node, workspace, channel, text, ts)
    public = item.body["pk"]
    member, _ = member_source(
        node, workspace, public, item.body["owner"])
    if member is None:
        raise ValueError("publishing identity is not a workspace member")
    deps = {item.fid: [signed.fid, member], signed.fid: []}
    builder = node.start_upload(workspace)
    try:
        source = builder.finish(node.sender(workspace).pile(
            [signed, item], deps))
    except BaseException:
        builder.discard()
        raise
    return {"fid": item.fid, **direct_upload(
        node, workspace, source, broker_url, provider_origin)}


# QUERIES
def messages(node, workspace, channel=None):
    from ..auth.user import members

    with node.lock:
        names = {row["pk"]: row["name"] for row in members(node, workspace)}
        selected = [
            fact for fact in node.by_type(workspace, TAG)
            if channel is None or fact.body["chan"] == channel
        ]
    return [
        {
            "chan": fact.body["chan"],
            "from": names.get(fact.body["pk"], fact.body["pk"][:8]),
            "text": fact.body["text"],
            "ts": fact.ts,
            "fid": fact.fid,
        }
        for fact in sorted(selected, key=lambda fact: (fact.ts, fact.fid))
    ]


CLI = {
    "content.message.list": messages,
    "content.message.post": post,
    "content.message.upload": upload,
}
