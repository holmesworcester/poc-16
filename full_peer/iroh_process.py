"""Lifecycle for the connection-only Rust Iroh byte-wrapper process."""
import os
import queue
import subprocess
import threading
from dataclasses import dataclass


READY_BYTES = 16 * 1024
READY_SECONDS = 30
STOP_SECONDS = 10
FORWARD_READY_SECONDS = 2
FORWARD_STOP_SECONDS = 2


@dataclass(frozen=True)
class IrohReady:
    """Connection information reported by the byte-wrapper child."""

    endpoint_id: str
    peer: str


@dataclass(frozen=True)
class ForwardReady:
    """Private loopback address reported by one outbound child."""

    endpoint_id: str
    peer_endpoint_id: str
    listen: str


def _readline(stream, timeout):
    """Read one bounded child line without letting startup block forever."""
    result = queue.Queue(maxsize=1)

    def read():
        try:
            result.put((stream.readline(READY_BYTES + 1), None))
        except BaseException as error:
            result.put(("", error))

    threading.Thread(target=read, daemon=True).start()
    try:
        line, error = result.get(timeout=timeout)
    except queue.Empty as error:
        raise TimeoutError("Iroh child did not report readiness") from error
    if error is not None:
        raise RuntimeError("read Iroh child readiness") from error
    if not line or len(line.encode()) > READY_BYTES:
        raise ValueError("invalid Iroh child readiness")
    return line.rstrip("\r\n")


def _fields(line, expected):
    fields = {}
    words = line.split()
    if words[:1] != ["READY"]:
        raise ValueError("invalid Iroh child readiness")
    for word in words[1:]:
        name, separator, value = word.partition("=")
        if not separator or not name or not value or name in fields:
            raise ValueError("invalid Iroh child readiness")
        fields[name] = value
    if set(fields) != set(expected):
        raise ValueError("invalid Iroh child readiness")
    return fields


class IrohProcess:
    """Own exactly one byte-wrapper child and no repository authority."""

    def __init__(self, process, ready, stop_timeout=STOP_SECONDS):
        self.process, self.ready = process, ready
        self.stop_timeout = stop_timeout

    @classmethod
    def _start(
            cls, command, ready_type, expected, ready_timeout, stop_timeout):
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            if process.stdout is None:
                raise RuntimeError("Iroh child has no readiness pipe")
            fields = _fields(
                _readline(process.stdout, ready_timeout), expected)
            ready = ready_type(*(fields[name] for name in expected))
            if process.poll() is not None:
                raise RuntimeError(
                    f"Iroh child exited during startup ({process.returncode})")
            return cls(process, ready, stop_timeout)
        except BaseException:
            cls(
                process,
                ready_type(*("" for _ in expected)),
                stop_timeout,
            ).stop()
            raise

    @classmethod
    def start(
            cls, binary, upstream, key_file, *, loopback=False,
            ready_timeout=READY_SECONDS):
        command = [
            os.fspath(binary),
            "serve",
            "--upstream", upstream,
            "--secret-key-file", os.fspath(key_file),
        ]
        if loopback:
            command.append("--loopback")
        return cls._start(
            command,
            IrohReady,
            ("endpoint_id", "peer"),
            ready_timeout,
            STOP_SECONDS,
        )

    @classmethod
    def forward(
            cls, binary, peer, *, loopback=False,
            ready_timeout=FORWARD_READY_SECONDS):
        command = [
            os.fspath(binary),
            "forward",
            f"--peer={peer}",
            "--listen", "127.0.0.1:0",
        ]
        if loopback:
            command.append("--loopback")
        return cls._start(
            command,
            ForwardReady,
            ("endpoint_id", "peer_endpoint_id", "listen"),
            ready_timeout,
            FORWARD_STOP_SECONDS,
        )

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(self.stop_timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(self.stop_timeout)
        if self.process.stdout is not None:
            self.process.stdout.close()
