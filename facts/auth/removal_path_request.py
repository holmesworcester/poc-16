"""Historical membership request for one self-confined removal path."""

from core.fact import Fact
from core.shape import valid_fid
from .._policy import FamilyPolicy
from . import _access


TAG = "removal_path_request"
POLICY = FamilyPolicy()
DURABLE = False


def removal_path_request(workspace, device, owner, exp, ts):
    return Fact(
        TAG, ts, [],
        {"device": device, "owner": owner, "exp": exp},
        workspace,
    )


def needs(fact):
    return _access.needs(fact)


def validate(fact, _ctx):
    try:
        body = fact.body
        return set(body) == {"device", "owner", "exp"} \
            and valid_fid(body["device"]) \
            and valid_fid(body["owner"]) \
            and type(body["exp"]) is int \
            and fact == removal_path_request(
                fact.ws, body["device"], body["owner"],
                body["exp"], fact.ts)
    except (KeyError, TypeError, ValueError):
        return False


def authorize_path(valid, stream, writer, trusted_now):
    if valid.fact.t != TAG or valid.fact.body["exp"] < trusted_now:
        return None
    return _access.claim(valid, stream, writer)
