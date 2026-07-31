"""Full-peer-local plural signing identities, above and outside workspaces.

The keychain is deliberately not a fact family and never enters sync. Keys are
equal peers in a flat device set; a workspace binding selects which local key
authors that workspace's facts.
"""
import json
import os

from core.crypto import keypair, load_sk


class Keychain:
    def __init__(self, path, initial_secret=None):
        self.path = path
        if os.path.exists(path):
            with open(path) as source:
                raw = json.load(source)
        else:
            raw = {}
        self.data = self._normalize(raw, initial_secret)
        self.save()

    @staticmethod
    def _public_key(seed_hex):
        return load_sk(seed_hex).verify_key.encode().hex()

    def _normalize(self, raw, initial_secret=None):
        if not isinstance(raw, dict):
            raise ValueError("keyring must be a JSON object")
        workspaces = raw.get("workspaces", {})
        if not isinstance(workspaces, dict):
            raise ValueError("keyring workspaces must be an object")
        keys = raw.get("keys", {})
        if not isinstance(keys, dict):
            raise ValueError("keyring keys must be an object")
        keys = dict(keys)

        legacy_seed = raw.get("sk")
        if legacy_seed is not None:
            keys.setdefault(self._public_key(legacy_seed), legacy_seed)
        if not keys:
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
        for workspace, entry in workspaces.items():
            if not isinstance(entry, dict):
                raise ValueError(f"workspace {workspace!r} metadata must be an object")
            normalized = dict(entry)
            normalized.setdefault("identity", default_id)
            if normalized["identity"] not in keys:
                raise ValueError(
                    f"workspace {workspace!r} names an unknown identity")
            normalized_workspaces[workspace] = normalized
        return {"keys": keys, "workspaces": normalized_workspaces}

    def save(self):
        with open(self.path, "w") as destination:
            json.dump(self.data, destination)

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
        self.data["keys"][key_id] = seed_hex
        if persist:
            self.save()
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
        self.data["workspaces"][workspace]["identity"] = key_id
        self.save()

    def for_workspace(self, workspace):
        entry = self.data["workspaces"].get(workspace)
        return self.default() if entry is None \
            else self.identity(entry["identity"])
