"""Bounded daemon ownership of outbound Iroh forwarder children."""
import threading
import time
from dataclasses import dataclass

from .iroh_process import IrohProcess


@dataclass
class _Forwarder:
    peer: dict
    process: IrohProcess | None = None
    url: str | None = None
    generation: int = 0
    failures: int = 0
    last_error: str | None = None
    retry_at: float = 0.0


class IrohForwarders:
    """Map durable reachability to disposable private HTTP loopback seams."""

    def __init__(self, binary, *, loopback=False):
        self.binary, self.loopback = binary, loopback
        self._lock = threading.RLock()
        self._configured = set()
        self._slots = {}
        self._closed = False

    def _record_failure(self, slot, error):
        slot.failures += 1
        slot.last_error = f"{type(error).__name__}: {error}"
        slot.retry_at = time.monotonic() + min(
            5.0, .1 * (2 ** min(slot.failures - 1, 8)))
        slot.url = None

    def _stop(self, slot):
        process, slot.process, slot.url = slot.process, None, None
        if process is not None:
            process.stop()

    def _slot(self, workspace, peer):
        key = workspace, peer["endpoint"]
        slot = self._slots.setdefault(key, _Forwarder(dict(peer)))
        if slot.peer != peer:
            self._stop(slot)
            slot.peer, slot.retry_at = dict(peer), 0.0
        return slot

    def _start(self, slot):
        if self._closed:
            raise RuntimeError("Iroh forwarders are closed")
        process = None
        try:
            process = IrohProcess.forward(
                self.binary, slot.peer["ticket"], loopback=self.loopback)
            if process.ready.peer_endpoint_id != slot.peer["endpoint"]:
                raise ValueError("Iroh ticket endpoint mismatch")
            # Rust binds this exact command to 127.0.0.1:0.
            slot.url = "http://" + process.ready.listen
            slot.process = process
            slot.generation += 1
            slot.retry_at = 0.0
        except BaseException as error:
            if process is not None:
                process.stop()
            self._record_failure(slot, error)
            raise

    def _dead(self, slot):
        if slot.process is None:
            return
        code = slot.process.process.poll()
        if code is None:
            return
        self._stop(slot)
        self._record_failure(
            slot, RuntimeError(f"Iroh forwarder exited unexpectedly ({code})"))

    def _start_one_due(self):
        now = time.monotonic()
        for key in sorted(self._configured):
            slot = self._slots.get(key)
            if slot is None or slot.process is not None \
                    or now < slot.retry_at:
                continue
            try:
                self._start(slot)
            except Exception:
                pass
            return

    def resolve(self, workspace, peer):
        """Return only a private HTTP URL, starting its forwarder if needed."""
        with self._lock:
            slot = self._slot(workspace, peer)
            self._dead(slot)
            if slot.process is None:
                if time.monotonic() < slot.retry_at:
                    raise ConnectionError(
                        slot.last_error or "Iroh forwarder unavailable")
                self._start(slot)
            return slot.url

    def release(self, workspace, peer):
        """Reap a temporary invite connection unless configuration retained it."""
        with self._lock:
            key = workspace, peer["endpoint"]
            if key in self._configured:
                return False
            slot = self._slots.pop(key, None)
            if slot is not None:
                self._stop(slot)
            return True

    def refresh(self, configured):
        """Apply one complete durable configuration and reap removed peers."""
        configured = {
            (workspace, peer["endpoint"]): dict(peer)
            for workspace, peer in configured
        }
        with self._lock:
            for key in self._configured - set(configured):
                slot = self._slots.pop(key, None)
                if slot is not None:
                    self._stop(slot)
            self._configured = set(configured)
            for key, peer in configured.items():
                slot = self._slot(key[0], peer)
                self._dead(slot)
            self._start_one_due()

    def maintain(self):
        """Observe child death and retry configured reachability with backoff."""
        with self._lock:
            for slot in (
                    self._slots[key] for key in self._configured
                    if key in self._slots):
                self._dead(slot)
            self._start_one_due()

    def status(self, workspace):
        with self._lock:
            rows = []
            for (candidate, endpoint), slot in sorted(self._slots.items()):
                if (candidate, endpoint) not in self._configured \
                        or candidate != workspace:
                    continue
                self._dead(slot)
                process = slot.process
                rows.append({
                    "endpoint": endpoint,
                    "state": "ready" if process is not None else "retry",
                    "loopback_url": slot.url,
                    "pid": None if process is None else process.process.pid,
                    "generation": slot.generation,
                    "failures": slot.failures,
                    "last_error": slot.last_error,
                })
            return rows

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for slot in self._slots.values():
                self._stop(slot)
            self._slots.clear()
            self._configured.clear()
