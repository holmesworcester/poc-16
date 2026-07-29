"""Pure short-lived bearer grants shared by daemon and serverless gates."""
import base64
import hashlib
import hmac
import json
import time


def now_ms():
    return int(time.time() * 1000)


def make_token(
        secret, member, workspace, verb="sync", *,
        issued_at=None, ttl_ms=60_000):
    """Mint one authenticated grant without importing a node or transport."""
    issued_at = now_ms() if issued_at is None else issued_at
    payload = json.dumps({
        "exp": issued_at + ttl_ms,
        "m": member,
        "v": verb,
        "ws": workspace,
    }, sort_keys=True)
    mac = hmac.new(
        secret, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload.encode()).decode() + "." + mac


def check_token(
        secret, authorization, workspace, verb="sync", *, trusted_now=None):
    """Return the authenticated member id, or fail closed with ``None``."""
    trusted_now = now_ms() if trusted_now is None else trusted_now
    try:
        scheme, presented = authorization.split(" ", 1)
        body, mac = presented.split(".", 1)
        payload = base64.urlsafe_b64decode(body)
        expected = hmac.new(
            secret, payload, hashlib.sha256).hexdigest()
        if scheme != "Bearer" or not hmac.compare_digest(expected, mac):
            return None
        grant = json.loads(payload)
        return grant["m"] if grant["ws"] == workspace \
            and grant["v"] == verb \
            and grant["exp"] > trusted_now else None
    except Exception:
        return None
