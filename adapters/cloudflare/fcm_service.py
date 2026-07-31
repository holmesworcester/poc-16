"""Awaited FCM provider over a private Cloudflare service binding.

Firebase Admin is not a viable Pyodide dependency.  The consumer therefore
holds a narrow binding to a separately operated Firebase bridge; Cloudflare's
binding capability authenticates the call.  The bridge alone owns Firebase
credentials and must use the current ``fid`` targeting field.
"""
import base64

from notifications.delivery import (
    PushAccepted,
    PushInvalidEndpoint,
    PushRequest,
    PushRetryable,
    PushUnregistered,
)


FORMAT = "poc16-fcm-service-v1"


class FcmServiceBinding:
    """Translate one typed push request into the private bridge contract."""

    __slots__ = ("service",)

    def __init__(self, service):
        if not callable(getattr(service, "send", None)):
            raise TypeError("FCM service binding")
        self.service = service

    async def send(self, request):
        if not isinstance(request, PushRequest):
            raise TypeError("FCM request")
        document = {
            "application": request.application,
            "delivery_id": request.delivery_id,
            "environment": request.environment,
            "expires_at_ms": request.expires_at_ms,
            # Deliberately not named token: Firebase's current installation
            # targeting API is FID.
            "fid": request.target,
            "format": FORMAT,
            "kind": request.kind,
            "payload": base64.b64encode(request.payload).decode("ascii"),
            "platform": request.platform,
            "ttl_seconds": request.ttl_seconds,
        }
        try:
            response = await self.service.send(document)
        except Exception as error:
            raise PushRetryable("FCM service unavailable") from error
        if not isinstance(response, dict) \
                or not isinstance(response.get("status"), str):
            raise PushRetryable("invalid FCM service response")
        status = response["status"]
        if status == "accepted":
            try:
                return PushAccepted(response.get("message_id"))
            except (TypeError, ValueError) as error:
                raise PushRetryable("invalid FCM acceptance") from error
        if status == "unregistered":
            raise PushUnregistered("FCM installation is unregistered")
        if status == "invalid-endpoint":
            raise PushInvalidEndpoint("FCM installation was rejected")
        # Configuration, credentials, quotas, timeouts, unknown statuses and
        # malformed provider failures are all retryable.  Only the two exact
        # endpoint statuses above may terminate carrier work.
        raise PushRetryable("FCM service requested retry")


__all__ = ("FORMAT", "FcmServiceBinding")
