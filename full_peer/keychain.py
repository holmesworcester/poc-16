"""Full-peer-local plural signing identities, above and outside workspaces.

The keychain is deliberately not a fact family and never enters sync. Keys are
equal peers in a flat device set; a workspace binding selects which local key
authors that workspace's facts.
"""
import json
import os
import re
import tempfile

from core.crypto import keypair, load_sk

MAX_PEERS_PER_WORKSPACE = 64
MAX_IROH_PEERS = 128
MAX_HTTP_URL_CHARS = 4096
# Rust accepts at most a 4 KiB decoded EndpointAddr.
MAX_IROH_TICKET_CHARS = ((4096 + 2) // 3) * 4


def iroh_endpoint(endpoint):
    if not isinstance(endpoint, str) \
            or not re.fullmatch(r"[0-9a-f]{64}", endpoint):
        raise ValueError("invalid Iroh endpoint id")
    return endpoint


def iroh_peer(endpoint, ticket):
    """Return one bounded reachability record with no authority meaning."""
    endpoint = iroh_endpoint(endpoint)
    if not isinstance(ticket, str) or len(ticket) > MAX_IROH_TICKET_CHARS \
            or not re.fullmatch(r"[A-Za-z0-9_-]+", ticket):
        raise ValueError("invalid Iroh ticket")
    return {"kind": "iroh", "endpoint": endpoint, "ticket": ticket}


def normalize_peer(peer):
    """Validate one persisted peer address without resolving or trusting it."""
    if isinstance(peer, str):
        if not peer or len(peer) > MAX_HTTP_URL_CHARS:
            raise ValueError("invalid HTTP peer URL")
        return peer
    if not isinstance(peer, dict) \
            or set(peer) != {"kind", "endpoint", "ticket"} \
            or peer.get("kind") != "iroh":
        raise ValueError("invalid peer locator")
    return iroh_peer(peer["endpoint"], peer["ticket"])


def normalize_peers(peers):
    if not isinstance(peers, list) or len(peers) > MAX_PEERS_PER_WORKSPACE:
        raise ValueError("invalid workspace peers")
    normalized, identities = [], set()
    for peer in peers:
        peer = normalize_peer(peer)
        identity = ("http", peer) if isinstance(peer, str) \
            else ("iroh", peer["endpoint"])
        if identity in identities:
            raise ValueError("duplicate workspace peer")
        identities.add(identity)
        normalized.append(peer)
    return normalized


def is_iroh_peer(peer):
    return isinstance(peer, dict) and peer.get("kind") == "iroh"


class Keychain:
    def __init__(self, path, initial_secret=None):
        self.path = path
        existing = os.path.exists(path)
        if existing:
            with open(path) as source:
                raw = json.load(source)
        else:
            raw = {}
        self.data = None
        self.commit(self._normalize(
            raw, initial_secret, initialize=not existing))

    @staticmethod
    def _public_key(seed_hex):
        return load_sk(seed_hex).verify_key.encode().hex()

    def _normalize(self, raw, initial_secret=None, *, initialize=False):
        if not isinstance(raw, dict):
            raise ValueError("keyring must be a JSON object")
        if initialize:
            if raw:
                raise ValueError("new keyring must start empty")
            raw = {"keys": {}, "workspaces": {}}
        elif set(raw) != {"keys", "workspaces"}:
            raise ValueError("keyring schema")
        workspaces = raw["workspaces"]
        if not isinstance(workspaces, dict):
            raise ValueError("keyring workspaces must be an object")
        keys = raw["keys"]
        if not isinstance(keys, dict):
            raise ValueError("keyring keys must be an object")
        keys = dict(keys)

        if not keys:
            if not initialize:
                raise ValueError("keyring needs an identity")
            secret = initial_secret
            if isinstance(secret, str):
                secret = load_sk(secret)
            if secret is None:
                secret, public = keypair()
            else:
                public = secret.verify_key.encode().hex()
            keys[public] = secret.encode().hex()
        for key_id, seed_hex in keys.items():
            if self._public_key(seed_hex) != key_id:
                raise ValueError(f"keyring identity {key_id!r} has the wrong seed")

        default_id = next(iter(keys))
        normalized_workspaces = {}
        iroh_count = 0
        for workspace, entry in workspaces.items():
            if not isinstance(entry, dict) or set(entry) != {
                    "identity", "name", "peers"}:
                raise ValueError(f"workspace {workspace!r} metadata must be an object")
            normalized = dict(entry)
            if normalized["identity"] not in keys:
                raise ValueError(
                    f"workspace {workspace!r} names an unknown identity")
            normalized["peers"] = normalize_peers(
                normalized["peers"])
            iroh_count += sum(map(is_iroh_peer, normalized["peers"]))
            normalized_workspaces[workspace] = normalized
        if iroh_count > MAX_IROH_PEERS:
            raise ValueError("too many Iroh peers")
        return {"keys": keys, "workspaces": normalized_workspaces}

    def commit(self, proposed):
        """Atomically replace the complete durable value, then publish it live."""
        proposed = self._normalize(proposed)
        directory = os.path.dirname(self.path) or "."
        raw = json.dumps(
            proposed, separators=(",", ":")).encode()
        descriptor, temporary = tempfile.mkstemp(
            dir=directory, prefix=".keyring.", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(raw)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, self.path)
            temporary = None
            # Once replace succeeds, readers of the path see proposed. Publish
            # the same value in memory before the directory durability barrier;
            # even an fsync error must not split disk and live configuration.
            self.data = proposed
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(directory, flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def save(self):
        """Persist intentional in-memory batching as one complete value."""
        self.commit(self.data)

    def add_identity(self, secret=None, *, persist=True):
        """Add an equal signing identity and return its public-key id."""
        signing_key = secret or keypair()[0]
        if isinstance(signing_key, str):
            signing_key = load_sk(signing_key)
        key_id = signing_key.verify_key.encode().hex()
        seed_hex = signing_key.encode().hex()
        existing = self.data["keys"].get(key_id)
        if existing is not None and existing != seed_hex:
            raise ValueError(f"identity collision for {key_id}")
        proposed = {
            **self.data,
            "keys": {**self.data["keys"], key_id: seed_hex},
        }
        if persist:
            self.commit(proposed)
        else:
            self.data = self._normalize(proposed)
        return key_id

    def identity(self, key_id):
        seed_hex = self.data["keys"].get(key_id)
        if seed_hex is None:
            raise KeyError(f"unknown identity {key_id!r}")
        return load_sk(seed_hex), key_id

    def default_id(self):
        return next(iter(self.data["keys"]))

    def default(self):
        return self.identity(self.default_id())

    def bind(self, workspace, key_id):
        if key_id not in self.data["keys"]:
            raise KeyError(f"unknown identity {key_id!r}")
        if workspace not in self.data["workspaces"]:
            raise KeyError(f"unknown workspace {workspace!r}")
        workspaces = dict(self.data["workspaces"])
        workspaces[workspace] = {
            **workspaces[workspace],
            "identity": key_id,
        }
        self.commit({**self.data, "workspaces": workspaces})

    def for_workspace(self, workspace):
        entry = self.data["workspaces"].get(workspace)
        return self.default() if entry is None \
            else self.identity(entry["identity"])
