"""Lifecycle for the connection-only Rust Iroh byte-wrapper process."""
import os
import queue
import subprocess
import threading
from dataclasses import dataclass


READY_BYTES = 16 * 1024
READY_SECONDS = 30
STOP_SECONDS = 10


@dataclass(frozen=True)
class IrohReady:
    """Connection information reported by the byte-wrapper child."""

    endpoint_id: str
    peer: str


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


def _parse_ready(line):
    fields = {}
    words = line.split()
    if words[:1] != ["READY"]:
        raise ValueError("invalid Iroh child readiness")
    for word in words[1:]:
        name, separator, value = word.partition("=")
        if not separator or not name or not value or name in fields:
            raise ValueError("invalid Iroh child readiness")
        fields[name] = value
    if set(fields) != {"endpoint_id", "peer"}:
        raise ValueError("invalid Iroh child readiness")
    return IrohReady(fields["endpoint_id"], fields["peer"])


class IrohProcess:
    """Own exactly one byte-wrapper child and no repository authority."""

    def __init__(self, process, ready):
        self.process, self.ready = process, ready

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
            ready = _parse_ready(
                _readline(process.stdout, ready_timeout))
            if process.poll() is not None:
                raise RuntimeError(
                    f"Iroh child exited during startup ({process.returncode})")
            return cls(process, ready)
        except BaseException:
            cls(process, IrohReady("", "")).stop()
            raise

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(STOP_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(STOP_SECONDS)
        if self.process.stdout is not None:
            self.process.stdout.close()
