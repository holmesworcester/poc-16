"""facts/content/message.py — a member-signed channel message."""
from core.fact import Fact, Need
from core.shape import valid_fid
from .._notification import NotificationTrigger
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
MAX_MENTIONS = 32
POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="owner",
)


# SHAPE
def _mentions(values):
    try:
        values = tuple(sorted(set(values)))
    except TypeError as error:
        raise ValueError("message mentions") from error
    if len(values) > MAX_MENTIONS \
            or not all(valid_fid(value) for value in values):
        raise ValueError("message mentions")
    return values


def message(workspace, pk, channel, text, ts, owner=None, mentions=()):
    owner = pk if owner is None else owner
    mentions = _mentions(mentions)
    body = {"pk": pk, "owner": owner, "chan": channel, "text": text}
    if mentions:
        body["mentions"] = list(mentions)
    return Fact(
        TAG, ts, author_selectors(POLICY, {}),
        body, workspace,
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
        return set(body) in (
                {"pk", "owner", "chan", "text"},
                {"pk", "owner", "chan", "text", "mentions"},
            ) \
            and all(isinstance(body[key], str)
                    for key in ("pk", "owner", "chan", "text")) \
            and f == message(
                f.ws, body["pk"], body["chan"], body["text"], f.ts,
                body["owner"], body.get("mentions", ()))
    except (KeyError, IndexError, TypeError, ValueError):
        return False


# MODE
DURABLE = True


# COMMANDS
def _author(node, workspace, channel, text, ts, mentions=()):
    timestamp = node.now_ms() if ts is None else ts
    secret, public = node.identity(workspace)
    _, owner = member_source(node, workspace, public)
    if owner is None:
        raise ValueError("publishing identity is not a workspace member")
    item = message(
        workspace, public, channel, text, timestamp, owner, mentions)
    return item, signature.signature(secret, public, item, timestamp)


def post(node, workspace, channel, text, ts=None, mentions=()):
    item, signed = _author(
        node, workspace, channel, text, ts, mentions)
    return publish(node, workspace, item, signed)


def upload(
        node, workspace, channel, text, broker_url, provider_origin,
        ts=None, mentions=()):
    """Author one message and send its closed pile directly to ingress."""
    item, signed = _author(
        node, workspace, channel, text, ts, mentions)
    public = item.body["pk"]
    member, _ = member_source(
        node, workspace, public, item.body["owner"])
    if member is None:
        raise ValueError("publishing identity is not a workspace member")
    deps = {item.fid: [signed.fid, member], signed.fid: []}
    source = node.create_upload(
        workspace, node.sender(workspace).pile([signed, item], deps))
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
            "mentions": list(fact.body.get("mentions", ())),
            "ts": fact.ts,
            "fid": fact.fid,
        }
        for fact in sorted(selected, key=lambda fact: (fact.ts, fact.fid))
    ]


def notification_trigger(fact):
    """Return checked routing metadata; display text is never parsed."""
    body = fact.body
    return NotificationTrigger(
        kind=TAG,
        channel=body["chan"],
        mentions=tuple(body.get("mentions", ())),
    )


CLI = {
    "content.message.list": messages,
    "content.message.post": post,
    "content.message.upload": upload,
}
