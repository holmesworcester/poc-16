"""Optional FullPeer scheduling around the shared notification engine.

The repository is the authority and the notification cursor is operational
state. This composition never consults SQLite, observes repository commits,
or implements notification selection. It periodically runs the exact shared
writer-head discovery and worker used by hosted deployments.
"""
import asyncio
from dataclasses import dataclass
import os
import threading
import time

from adapters.gcp.firebase import FirebaseAdminFcm
from core.crypto import h, load_sk
from core.fact import canon
from core.shape import valid_fid
from core.store import FsStore
from notifications.carrier import (
    ACK,
    CarrierAccepted,
    CarrierDelivery,
    CarrierError,
    delivery_disposition,
)
from notifications.discovery import (
    REBOOTSTRAP_CURRENT,
    NotificationDiscovery,
    NotificationState,
)
from notifications.delivery import delivery_domain_id
from notifications.forest import current_repository
from notifications.worker import NotificationWorker, handle_carrier_delivery


MIN_CADENCE_SECONDS = .01
MAX_CADENCE_SECONDS = 24 * 60 * 60
DEFAULT_CADENCE_SECONDS = 30.0


def _secret(value):
    if isinstance(value, str):
        try:
            value = load_sk(value)
        except Exception as error:
            raise ValueError("notification push-node secret") from error
    try:
        public = value.verify_key.encode().hex()
    except Exception as error:
        raise TypeError("notification push-node secret") from error
    if not valid_fid(public):
        raise ValueError("notification push-node secret")
    return value, public


def firebase_from_default_credentials(application, environment):
    """Build one Firebase provider through Application Default Credentials.

    Credentials stay in Firebase's process-local credential chain; neither the
    configuration strings nor this adapter put them in facts or status.
    """
    if not isinstance(application, str) or not application \
            or not isinstance(environment, str) or not environment:
        raise ValueError("notification Firebase application")
    try:
        import firebase_admin
    except ImportError as error:
        raise RuntimeError(
            "firebase-admin is required for FullPeer notifications") from error
    try:
        app = firebase_admin.get_app()
    except ValueError:
        app = firebase_admin.initialize_app()
    return FirebaseAdminFcm({(application, environment): app})


class DirectCarrier:
    """Complete local work before reporting carrier acceptance.

    A managed carrier durably owns accepted work for later retry.  FullPeer's
    cursor is already durable locally, so the smaller equivalent is to leave
    it behind until the shared handler completes.  There is no local queue.
    """

    def __init__(self, handler):
        if not callable(handler):
            raise TypeError("notification delivery handler")
        self.handler = handler

    async def publish(self, body):
        message_id = h(body)
        delivery = CarrierDelivery(body, message_id, 1)
        result = await delivery_disposition(delivery, self.handler)
        if result is not ACK:
            raise CarrierError("notification delivery requires retry")
        return CarrierAccepted(message_id)


@dataclass(frozen=True, slots=True)
class NotificationTurn:
    workspace: str
    status: str

    def __post_init__(self):
        if not valid_fid(self.workspace) or not isinstance(self.status, str):
            raise ValueError("notification turn")


class FullPeerNotifications:
    """Daemon-owned cadence and wake source for local notification work."""

    def __init__(
            self, node, directory, push_node_secret, provider, *,
            cadence=DEFAULT_CADENCE_SECONDS):
        try:
            directory = os.fspath(directory)
        except TypeError as error:
            raise ValueError(
                "FullPeer notification configuration") from error
        if not callable(getattr(node, "workspaces", None)) \
                or not callable(getattr(node, "store", None)) \
                or not callable(getattr(node, "now_ms", None)) \
                or not callable(getattr(provider, "send", None)) \
                or not isinstance(directory, str) \
                or type(cadence) not in {int, float} \
                or not MIN_CADENCE_SECONDS <= cadence <= MAX_CADENCE_SECONDS:
            raise ValueError("FullPeer notification configuration")
        self.node = node
        self.directory = directory
        self.secret, self.push_node = _secret(push_node_secret)
        routes = getattr(provider, "delivery_routes", None)
        self.delivery_domain = delivery_domain_id(self.push_node, routes)
        self.owner = h(canon([
            "full-peer-notification-owner-v2",
            node.pk,
            self.delivery_domain,
        ]))
        self.provider = provider
        self.cadence = float(cadence)
        self._stores = {}
        self._stores_lock = threading.Lock()
        self._status = {}
        self._service_error = ""
        self._status_lock = threading.Lock()
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread = None

    def state_store(self, workspace):
        """Return this workspace's physically separate operational store."""
        if not valid_fid(workspace):
            raise ValueError("notification workspace")
        with self._stores_lock:
            if workspace not in self._stores:
                self._stores[workspace] = FsStore(
                    os.path.join(
                        self.directory, "notification-state", workspace))
            return self._stores[workspace]

    def _worker(self, workspace, repository):
        async def current(selected):
            if selected != workspace:
                raise ValueError("notification workspace mismatch")
            return await current_repository(repository, workspace)

        return NotificationWorker(
            current,
            self.secret,
            self.provider,
            self.node.now_ms,
        )

    def _discovery(self, workspace):
        repository = self.node.store(workspace)
        state = self.state_store(workspace)
        progress = NotificationState(state, workspace, self.owner)
        worker = self._worker(workspace, repository)

        async def handle(delivery):
            return await handle_carrier_delivery(
                delivery, workspace, progress, worker, wake=self.kick)

        return NotificationDiscovery(
            repository, state, workspace, DirectCarrier(handle),
            owner=self.owner)

    async def _bootstrap(self, workspace, mode):
        discovery = self._discovery(workspace)
        if mode == "current":
            cursor = await discovery.bootstrap_current()
        elif mode == "backfill":
            cursor = await discovery.bootstrap_backfill()
        elif mode == REBOOTSTRAP_CURRENT:
            cursor = await discovery.rebootstrap_current()
        else:
            raise ValueError("notification bootstrap mode")
        return {
            "heads": cursor.heads["root"],
            "mode": cursor.bootstrap,
            "workspace": workspace,
        }

    def bootstrap(self, workspace, mode):
        """Explicitly initialize one workspace before scheduled scanning."""
        if not valid_fid(workspace):
            raise ValueError("notification workspace")
        return asyncio.run(self._bootstrap(workspace, mode))

    async def _run_once(self):
        out = []
        for workspace in sorted(self.node.workspaces()):
            try:
                result = await self._discovery(workspace).run_once()
            except Exception as error:
                turn = NotificationTurn(workspace, "retry")
                detail = type(error).__name__
            else:
                turn = NotificationTurn(workspace, result.status)
                detail = ""
            with self._status_lock:
                self._status[workspace] = {
                    "error": detail,
                    "status": turn.status,
                    "ts": int(time.time() * 1000),
                }
            out.append(turn)
        return tuple(out)

    def run_once(self):
        """Run one bounded discovery page for every configured workspace."""
        return asyncio.run(self._run_once())

    def kick(self):
        self._wake.set()

    def _run(self):
        while not self._stopping.is_set():
            self._wake.wait(self.cadence)
            self._wake.clear()
            if self._stopping.is_set():
                return
            try:
                self.run_once()
            except Exception as error:
                # Notification availability is never peer availability.
                # Retain a non-secret type for status and retry on cadence.
                with self._status_lock:
                    self._service_error = type(error).__name__
            else:
                with self._status_lock:
                    self._service_error = ""

    def start(self):
        if self._thread is not None:
            raise RuntimeError("notification service already started")
        self._thread = threading.Thread(
            target=self._run,
            name="full-peer-notifications",
            daemon=True,
        )
        self._thread.start()
        self.kick()
        return self

    def stop(self):
        self._stopping.set()
        self._wake.set()

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout)

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def status(self):
        with self._status_lock:
            workspaces = {
                workspace: dict(value)
                for workspace, value in sorted(self._status.items())
            }
            service_error = self._service_error
        return {
            "cadence_seconds": self.cadence,
            "enabled": True,
            "error": service_error,
            "push_node": self.push_node,
            "running": self.is_alive(),
            "workspaces": workspaces,
        }


__all__ = (
    "DEFAULT_CADENCE_SECONDS",
    "DirectCarrier",
    "FullPeerNotifications",
    "NotificationTurn",
    "firebase_from_default_credentials",
)
