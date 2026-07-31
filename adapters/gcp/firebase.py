"""Lazy Firebase Admin SDK adapter for Apple and Android FCM targets."""
import base64
from datetime import timedelta
import importlib

from notifications.provider import (
    FcmAccepted,
    FcmPermanent,
    FcmRequest,
    FcmRetryable,
    FcmUnregistered,
)


_RETRYABLE = frozenset({
    "AbortedError",
    "DeadlineExceededError",
    "InternalError",
    "QuotaExceededError",
    "ResourceExhaustedError",
    "ServiceUnavailableError",
    "UnavailableError",
    "UnknownError",
})
_PERMANENT = frozenset({
    "FailedPreconditionError",
    "InvalidArgumentError",
    "NotFoundError",
    "PermissionDeniedError",
    "SenderIdMismatchError",
    "ThirdPartyAuthError",
    "UnauthenticatedError",
})


class FirebaseAdminFcm:
    """Select one configured Firebase app by application/environment."""

    def __init__(self, apps, *, messaging_module=None):
        if not isinstance(apps, dict) or not apps \
                or not all(
                    isinstance(key, tuple) and len(key) == 2
                    and all(isinstance(part, str) and part for part in key)
                    for key in apps):
            raise ValueError("Firebase app mapping")
        self.apps = dict(apps)
        self._messaging = messaging_module

    def _module(self):
        if self._messaging is None:
            try:
                self._messaging = importlib.import_module(
                    "firebase_admin.messaging")
            except ImportError as error:
                raise RuntimeError(
                    "firebase-admin is required for FCM delivery") from error
        return self._messaging

    @staticmethod
    def _titles(kind):
        return (
            ("You were mentioned", "Open the app to view the message")
            if kind == "mention"
            else ("New message", "Open the app to view it")
        )

    def send(self, request):
        if not isinstance(request, FcmRequest):
            raise TypeError("FCM request")
        app = self.apps.get((request.application, request.environment))
        if app is None:
            raise FcmPermanent("unconfigured Firebase application")
        messaging = self._module()
        title, body = self._titles(request.kind)
        message = messaging.Message(
            data={
                "delivery_id": request.delivery_id,
                "poc16": base64.b64encode(request.payload).decode("ascii"),
            },
            notification=messaging.Notification(title=title, body=body),
            android=messaging.AndroidConfig(
                ttl=timedelta(seconds=request.ttl_seconds),
                priority="normal",
            ),
            apns=messaging.APNSConfig(headers={
                "apns-collapse-id": request.delivery_id,
                "apns-expiration": str(request.expires_at_ms // 1000),
            }),
            fid=request.target,
        )
        try:
            message_id = messaging.send(message, app=app)
        except Exception as error:
            name = type(error).__name__
            if name == "UnregisteredError":
                raise FcmUnregistered("FCM target is unregistered") from error
            if name in _RETRYABLE or isinstance(
                    error, (OSError, TimeoutError)):
                raise FcmRetryable(f"FCM send failed: {name}") from error
            if name in _PERMANENT or isinstance(error, ValueError):
                raise FcmPermanent(f"FCM send failed: {name}") from error
            raise FcmRetryable(f"FCM send failed: {name}") from error
        try:
            return FcmAccepted(message_id)
        except (TypeError, ValueError) as error:
            raise FcmRetryable(
                "FCM send returned no valid message id") from error


__all__ = ("FirebaseAdminFcm",)
