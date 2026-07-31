"""Standard-library HTTP server/byte adapter for :class:`core.http.HttpGate`.

This host-only adapter contains no route decisions.  It normalizes ordinary
HTTP request bytes, selects one workspace, and delegates every authorization
and repository operation to the database-free gate.
"""
import asyncio
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
import time
from urllib.parse import parse_qs, urlparse

from . import peer_capability
from .http import AsyncFromSyncReader, HttpGate, Response
from .limits import (
    MAX_MINT_FETCHES,
    MAX_MINT_FETCH_BYTES,
    MAX_MINT_REQUEST_BYTES,
    PayloadTooLarge,
)


@dataclass(frozen=True)
class HttpGateOptions:
    """Validated host knobs passed unchanged into every request gate."""

    grant_ttl_ms: int = 60_000
    max_mint_fetches: int = MAX_MINT_FETCHES
    max_mint_fetch_bytes: int = MAX_MINT_FETCH_BYTES

    def __post_init__(self):
        if type(self.grant_ttl_ms) is not int or self.grant_ttl_ms < 1:
            raise ValueError("grant TTL")
        for label, value, ceiling in (
                ("mint fetch count", self.max_mint_fetches, MAX_MINT_FETCHES),
                (
                    "mint fetch bytes",
                    self.max_mint_fetch_bytes,
                    MAX_MINT_FETCH_BYTES,
                )):
            if type(value) is not int or not 0 <= value <= ceiling:
                raise ValueError(label)


def now_ms():
    return int(time.time() * 1000)


class _SyncReceiver:
    def __init__(self, peer, workspace):
        self.peer = peer
        self.workspace = workspace

    async def admit_object(self, oid, raw):
        return self.peer.receive_object(self.workspace, oid, raw)

    async def receive_pile(self, member, raw):
        return self.peer.receive_pile(self.workspace, member, raw)

    async def turn(self):
        return self.peer.turn(self.workspace)


class StdlibPeerHandler(BaseHTTPRequestHandler):
    """Translate ordinary HTTP bytes; ``HttpGate`` still owns the routes."""

    peer = secret = None
    sync_profile = peer_capability.FULL
    gate_options = HttpGateOptions()
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _request(self):
        parsed = urlparse(self.path)
        query = {
            key: values[0]
            for key, values in parse_qs(parsed.query).items()
            if len(values) == 1
        }
        return parsed.path, query

    def _body(self, method, path):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("unsupported transfer encoding")
        claimed = self.headers.get("Content-Length")
        try:
            length = 0 if claimed is None else int(claimed)
        except (TypeError, ValueError) as error:
            raise ValueError("content length") from error
        if length < 0:
            raise ValueError("content length")
        limit = HttpGate.request_limit(method, path)
        if not limit and method in {"POST", "PUT"}:
            limit = MAX_MINT_REQUEST_BYTES
        if length > limit:
            raise PayloadTooLarge("request body too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("short request body")
        return body

    def _send(self, response):
        self.send_response(response.status)
        headers = dict(response.headers)
        headers.setdefault("Content-Type", "application/json")
        headers["Content-Length"] = str(len(response.body))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(response.body)

    def _dispatch(self, method):
        path, query = self._request()
        try:
            body = self._body(method, path)
        except PayloadTooLarge:
            return self._send(Response(413))
        except ValueError:
            return self._send(Response(400))
        workspace = query.get("ws", "")
        public = HttpGate.public_response(method, path)
        if public is not None:
            return self._send(public)
        if not self.peer.has_workspace(workspace):
            return self._send(Response(404))
        gate = HttpGate(
            AsyncFromSyncReader(self.peer.store(workspace)),
            workspace,
            self.secret,
            now_ms,
            _SyncReceiver(self.peer, workspace),
            sync_profile=self.sync_profile,
            grant_ttl_ms=self.gate_options.grant_ttl_ms,
            max_mint_fetches=self.gate_options.max_mint_fetches,
            max_mint_fetch_bytes=self.gate_options.max_mint_fetch_bytes,
        )
        try:
            response = asyncio.run(gate.handle(
                method, path, query, dict(self.headers), body))
        except Exception:
            response = Response(503)
        return self._send(response)

    def do_GET(self):
        return self._dispatch("GET")

    def do_POST(self):
        return self._dispatch("POST")

    def do_PUT(self):
        return self._dispatch("PUT")


def handler_for(
        peer, secret, sync_profile=peer_capability.FULL, *,
        gate_options=None):
    """Bind one ordinary HTTP server without mutable global authority."""
    gate_options = HttpGateOptions() \
        if gate_options is None else gate_options
    if not isinstance(gate_options, HttpGateOptions):
        raise TypeError("HTTP gate options")
    return type(
        "BoundPeerHandler",
        (StdlibPeerHandler,),
        {
            "peer": peer,
            "secret": secret,
            "sync_profile": sync_profile,
            "gate_options": gate_options,
        },
    )


__all__ = ("HttpGateOptions", "StdlibPeerHandler", "handler_for")
