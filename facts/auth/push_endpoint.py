"""facts/auth/push_endpoint.py — a sealed mobile installation target."""
import base64
import re

from nacl import bindings
from nacl.exceptions import CryptoError

from core.crypto import seal_to, unseal
from core.fact import Fact, Need
from core.shape import valid_fid
from .._commands import member_source, offer_source
from .._policy import DELETE_SELF, FamilyPolicy, Self, author_selectors
from . import signature


TAG = "push_endpoint"
ENDPOINT_OFFER = "notification.endpoint"
PLATFORMS = frozenset(("android", "apple"))
MAX_APPLICATION_BYTES = 256
MAX_ENVIRONMENT_BYTES = 64
MAX_SEALED_TARGET_BYTES = 4096
MIN_SEALED_TARGET_BYTES = 49
MAX_TARGET_BYTES = MAX_SEALED_TARGET_BYTES - 48
MAX_ACTIVE_ENDPOINTS = 32
_APPLICATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ENVIRONMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BODY_FIELDS = {
    "application",
    "environment",
    "installation",
    "owner",
    "pk",
    "platform",
    "push_node",
    "sealed_target",
}

POLICY = FamilyPolicy(
    suppression=(Self(),),
    direct_targets=DELETE_SELF,
    owner_field="owner",
    authority_liveness_guards=("member", "device_liveness"),
)


# SHAPE
def _application(value):
    if not isinstance(value, str) \
            or _APPLICATION_RE.fullmatch(value) is None \
            or len(value.encode("ascii")) > MAX_APPLICATION_BYTES:
        raise ValueError("push application")
    return value


def _environment(value):
    if not isinstance(value, str) \
            or _ENVIRONMENT_RE.fullmatch(value) is None \
            or len(value.encode("ascii")) > MAX_ENVIRONMENT_BYTES:
        raise ValueError("push environment")
    return value


def _platform(value):
    if value not in PLATFORMS:
        raise ValueError("push platform")
    return value


def _identity(value, label):
    if not valid_fid(value):
        raise ValueError(label)
    return value


def _push_node(value):
    value = _identity(value, "push node public key")
    try:
        bindings.crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(value))
    except Exception as error:
        raise ValueError("push node public key") from error
    return value


def encode_sealed_target(value):
    if not isinstance(value, bytes) \
            or not MIN_SEALED_TARGET_BYTES <= len(value) \
            <= MAX_SEALED_TARGET_BYTES:
        raise ValueError("sealed push target")
    return base64.b64encode(value).decode("ascii")


def decode_sealed_target(value):
    if not isinstance(value, str) \
            or len(value) > 4 * ((MAX_SEALED_TARGET_BYTES + 2) // 3):
        raise ValueError("sealed push target")
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, UnicodeError, ValueError) as error:
        raise ValueError("sealed push target") from error
    if not MIN_SEALED_TARGET_BYTES <= len(raw) <= MAX_SEALED_TARGET_BYTES \
            or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("sealed push target")
    return raw


def checked_target(value):
    if not isinstance(value, str) or not value.isascii() or not value \
            or len(value) > MAX_TARGET_BYTES \
            or any(not 0x21 <= ord(character) <= 0x7e
                   for character in value):
        raise ValueError("FCM installation target")
    return value


def seal_target(push_node_public, target):
    try:
        return encode_sealed_target(seal_to(
            push_node_public, checked_target(target).encode("ascii")))
    except (TypeError, ValueError) as error:
        raise ValueError("push node public key") from error


def open_target(push_node_secret, sealed):
    try:
        return checked_target(
            unseal(
                push_node_secret,
                decode_sealed_target(sealed),
            ).decode("ascii"))
    except (CryptoError, TypeError, UnicodeError, ValueError) as error:
        raise ValueError("invalid sealed FCM target") from error


def push_endpoint(
        workspace, pk, owner, installation, push_node, platform,
        application, environment, sealed_target, ts):
    pk = _identity(pk, "push endpoint device")
    owner = _identity(owner, "push endpoint owner")
    installation = _identity(installation, "push installation")
    push_node = _push_node(push_node)
    platform = _platform(platform)
    application = _application(application)
    environment = _environment(environment)
    decode_sealed_target(sealed_target)
    return Fact(
        TAG,
        ts,
        author_selectors(POLICY, {}) + [
            ["offer", ENDPOINT_OFFER, owner, installation],
        ],
        {
            "application": application,
            "environment": environment,
            "installation": installation,
            "owner": owner,
            "pk": pk,
            "platform": platform,
            "push_node": push_node,
            "sealed_target": sealed_target,
        },
        workspace,
    )


# NEEDS
def needs(f):
    body = f.body
    pk = body.get("pk", "")
    owner = body.get("owner", "")
    return (
        Need("author", "author", f.fid, pk),
        Need("member", "member", pk, owner),
        Need("device", "device_key", pk, owner),
        # The complete address above proves ownership. This second view of the
        # same provider contributes device:<pk> to continuing liveness rather
        # than incorrectly treating the owning user as the installation.
        Need("device_liveness", "device_key", pk),
    )


# VALIDATE
def validate(f, ctx):
    try:
        body = f.body
        return set(body) == _BODY_FIELDS \
            and f == push_endpoint(
                f.ws,
                body["pk"],
                body["owner"],
                body["installation"],
                body["push_node"],
                body["platform"],
                body["application"],
                body["environment"],
                body["sealed_target"],
                f.ts,
            )
    except (KeyError, IndexError, TypeError, UnicodeError, ValueError):
        return False


# MODE
DURABLE = True


def _authority(node, workspace, public):
    member, owner = member_source(node, workspace, public)
    if member is None:
        raise ValueError("local identity is not a workspace member")
    device = offer_source(
        node, workspace, "device_key", public, owner)
    if device is None:
        raise ValueError("local identity is not an enrolled device")
    return member, device, owner


def _current(node, workspace, owner, installation):
    return tuple(
        fact for fact in node.select(
            workspace, ENDPOINT_OFFER, owner, installation)
        if fact.t == TAG
    )


# COMMANDS
def register(
        node, workspace, installation, push_node, platform, application,
        environment, sealed_target, ts=None):
    """Register canonical base64 ciphertext; never accept a raw FCM token."""
    secret, public = node.identity(workspace)
    with node.lock:
        member, device, owner = _authority(node, workspace, public)
        if _current(node, workspace, owner, installation):
            raise ValueError("push installation is already registered")
        timestamp = node.now_ms() if ts is None else ts
        item = push_endpoint(
            workspace,
            public,
            owner,
            installation,
            push_node,
            platform,
            application,
            environment,
            sealed_target,
            timestamp,
        )
        signed = signature.signature(secret, public, item, timestamp)
        node.ingest_new(
            workspace,
            [signed, item],
            {
                signed.fid: (),
                item.fid: (signed.fid, member, device),
            },
        )
        return item.fid


def replace(node, workspace, endpoint, push_node, sealed_target, ts=None):
    """Publish one target and suppress every observed installation sibling."""
    from .. import _policy
    from ..content import delete as deletion

    secret, public = node.identity(workspace)
    with node.lock:
        old = node.fact_of(workspace, endpoint)
        if old is None or old.t != TAG or node.suppressed(workspace, old):
            raise ValueError("no active push endpoint")
        member, device, owner = _authority(node, workspace, public)
        if old.body["owner"] != owner:
            raise ValueError("push endpoint belongs to another user")
        siblings = _current(
            node, workspace, owner, old.body["installation"])
        if old not in siblings:
            raise ValueError("no active push endpoint")
        if len(siblings) > MAX_ACTIVE_ENDPOINTS:
            raise ValueError("too many concurrent push endpoints")
        timestamp = node.now_ms() if ts is None else ts
        body = old.body
        item = push_endpoint(
            workspace,
            public,
            owner,
            body["installation"],
            push_node,
            body["platform"],
            body["application"],
            body["environment"],
            sealed_target,
            timestamp,
        )
        if item.fid == old.fid:
            raise ValueError("push endpoint replacement is unchanged")
        item_signature = signature.signature(
            secret, public, item, timestamp)
        news = [item_signature, item]
        deps = {
            item_signature.fid: (),
            item.fid: (item_signature.fid, member, device),
        }
        for sibling in siblings:
            removal = deletion.delete(
                workspace, public, sibling.key,
                _policy.OWNER, timestamp, owner)
            removal_signature = signature.signature(
                secret, public, removal, timestamp)
            news.extend((removal_signature, removal))
            deps[removal_signature.fid] = ()
            deps[removal.fid] = (
                removal_signature.fid, sibling.fid, member)
        node.ingest_new(workspace, news, deps)
        return item.fid


def remove(node, workspace, endpoint, ts=None):
    from ..content import delete as deletion

    return deletion.remove(node, workspace, endpoint, ts)


# QUERIES
def endpoints(node, workspace, owner=None, installation=None):
    rows = []
    with node.lock:
        for fact in node.by_type(workspace, TAG):
            body = fact.body
            if owner is not None and body["owner"] != owner \
                    or installation is not None \
                    and body["installation"] != installation:
                continue
            rows.append(fact)
    return [
        {
            "application": fact.body["application"],
            "device": fact.body["pk"],
            "environment": fact.body["environment"],
            "fid": fact.fid,
            "installation": fact.body["installation"],
            "owner": fact.body["owner"],
            "platform": fact.body["platform"],
            "push_node": fact.body["push_node"],
            "ts": fact.ts,
        }
        for fact in sorted(rows, key=lambda value: (
            value.body["owner"],
            value.body["application"],
            value.body["environment"],
            value.body["installation"],
            value.fid,
        ))
    ]


CLI = {
    "auth.push_endpoint.list": endpoints,
    "auth.push_endpoint.register": register,
    "auth.push_endpoint.remove": remove,
    "auth.push_endpoint.replace": replace,
}
