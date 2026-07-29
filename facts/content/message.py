"""facts/content/message.py — a member-signed channel message."""
from core.fact import Fact, Need
from .._policy import (
    DELETE_SELF,
    FamilyPolicy,
    Self,
    author_selectors,
)
from .._commands import publish
from ..auth import signature

TAG = "msg"
POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_edge="member",
    authorization_guards=("member",),
)


# SHAPE
def message(pk, channel, text, ts):
    return Fact(
        TAG, ts, author_selectors(POLICY, {}),
        {"pk": pk, "chan": channel, "text": text},
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
            and f == message(body["pk"], body["chan"], body["text"], f.ts)
    except Exception:
        return False


# MODE
DURABLE = True


# COMMANDS
def post(node, workspace, channel, text, ts=None):
    from core.node import now_ms

    ts = now_ms() if ts is None else ts
    secret, public = node.identity(workspace)
    item = message(public, channel, text, ts)
    return publish(node, workspace, item,
                   signature.signature(secret, public, item, ts))


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


CLI = {"content.message.post": post, "content.message.list": messages}
