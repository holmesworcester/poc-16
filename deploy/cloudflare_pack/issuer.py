"""Exact short-lived R2 object requests behind the shared grant gate."""
import time

from core.pack_access import ObjectOpen, PackOpen, ScopedRequest, pack_key
from core.shape import valid_fid
from deploy.cloudflare_sigv4 import R2SigV4

from .contract import R2PackTarget, ticket_query, ticket_secret


def _system_now_ms():
    return time.time_ns() // 1_000_000


def _signed_get(target, signer, key, headers, trusted_now):
    expires_at_ms = trusted_now + target.ttl_seconds * 1000
    signed = signer.sign(
        "GET",
        target.bucket,
        key,
        headers,
        target.ttl_seconds,
        not_after_ms=expires_at_ms,
    )
    return ScopedRequest(
        signed.method,
        signed.url,
        signed.headers,
        signed.expires_at_ms,
    )


class R2PackIssuer:
    """Issue exact R2 object and pack requests after shared-gate auth."""

    def __init__(
            self, target, access_key_id, secret_access_key, put_ticket_secret,
            *, clock=_system_now_ms):
        if not isinstance(target, R2PackTarget):
            raise TypeError("R2 pack target")
        if not callable(clock):
            raise ValueError("R2 pack signing clock")
        self.target = target
        self._ticket_secret = ticket_secret(put_ticket_secret)
        self._sigv4 = R2SigV4(
            target.endpoint,
            access_key_id,
            secret_access_key,
            clock=clock,
        )

    def open_object(self, member, opened, trusted_now):
        if not valid_fid(member) or not isinstance(opened, ObjectOpen) \
                or type(trusted_now) is not int or trusted_now < 0:
            raise ValueError("R2 object request")
        return _signed_get(
            self.target,
            self._sigv4,
            self.target.physical_object_key(opened.oid),
            {},
            trusted_now,
        )

    def open_pack(self, member, opened, trusted_now):
        if not valid_fid(member) or not isinstance(opened, PackOpen) \
                or type(trusted_now) is not int or trusted_now < 0:
            raise ValueError("R2 pack request")
        if opened.method == "GET":
            headers = {}
            if opened.offset is not None:
                headers["range"] = (
                    f"bytes={opened.offset}-"
                    f"{opened.offset + opened.length - 1}"
                )
            return _signed_get(
                self.target,
                self._sigv4,
                self.target.physical_key(opened.oid),
                headers,
                trusted_now,
            )
        expires_at_ms = trusted_now + self.target.ttl_seconds * 1000
        url = f"{self.target.put_endpoint}/{pack_key(opened.oid)}?" + (
            ticket_query(
                self._ticket_secret,
                opened.oid,
                opened.pack_bytes,
                expires_at_ms,
            )
        )
        return ScopedRequest(
            "PUT",
            url,
            (
                ("content-length", str(opened.pack_bytes)),
                ("if-none-match", "*"),
            ),
            expires_at_ms,
        )
