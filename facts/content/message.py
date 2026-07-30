"""facts/content/message.py — a member-signed channel message."""
from core.fact import Fact, Need
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Self,
    author_selectors,
)
from .._commands import (
    offer_source,
    publish,
    upload_builder,
    upload_source,
)
from ..auth import signature

TAG = "msg"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_edge="member",
)


# SHAPE
def message(workspace, pk, channel, text, ts):
    return Fact(
        TAG, ts, author_selectors(POLICY, {}),
        {"pk": pk, "chan": channel, "text": text}, workspace,
    )


# NEEDS
def needs(f):
    pk = f.body.get("pk", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == {"pk", "chan", "text"} \
            and all(isinstance(body[key], str) for key in body) \
            and f == message(
                f.ws, body["pk"], body["chan"], body["text"], f.ts)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _author(node, workspace, channel, text, ts):
    from core.node import now_ms

    timestamp = now_ms() if ts is None else ts
    secret, public = node.identity(workspace)
    item = message(workspace, public, channel, text, timestamp)
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
    member = offer_source(node, workspace, "member", public)
    if member is None:
        raise ValueError("publishing identity is not a workspace member")
    deps = {item.fid: [signed.fid, member], signed.fid: []}
    builder = upload_builder(node, workspace)
    try:
        source = builder.finish(node.sender(workspace).pile(
            [signed, item], deps))
    except BaseException:
        builder.discard()
        raise
    return {"fid": item.fid, **upload_source(
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
