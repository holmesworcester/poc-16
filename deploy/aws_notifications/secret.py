"""Decode one pinned notification secret without provider side effects."""
import json

from core.crypto import load_sk

from .config import MAX_FIREBASE_APPS, MAX_SECRET_BYTES


def decode_secret(value):
    """Return the push key and validated Firebase rows from bounded JSON."""
    if not isinstance(value, str):
        raise RuntimeError("notification secret has no SecretString")
    raw = value.encode("utf-8")
    if not 0 < len(raw) <= MAX_SECRET_BYTES:
        raise RuntimeError("notification secret size")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise RuntimeError("notification secret JSON") from None
    if not isinstance(document, dict) or set(document) != {
            "firebase_apps", "push_node_seed"}:
        raise RuntimeError("notification secret shape")
    rows = document["firebase_apps"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FIREBASE_APPS:
        raise RuntimeError("notification Firebase applications")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "application", "credential", "environment"} \
                or not all(isinstance(row[name], str) and row[name]
                           for name in ("application", "environment")) \
                or not isinstance(row["credential"], dict):
            raise RuntimeError("notification Firebase application")
        key = row["application"], row["environment"]
        if key in seen:
            raise RuntimeError("duplicate notification Firebase application")
        seen.add(key)
    try:
        secret = load_sk(document["push_node_seed"])
    except (TypeError, ValueError):
        raise RuntimeError("notification push-node seed") from None
    return secret, tuple(rows)


def push_node_id(secret):
    """Return the stable public identity selected by endpoint facts."""
    try:
        return secret.verify_key.encode().hex()
    except Exception as error:
        raise TypeError("notification push-node secret") from error


__all__ = ("decode_secret", "push_node_id")
