"""Disposable local suppression projection.

Authenticated suppression authority lives in ``SuppTree``.  The disposable
client projection stores its current action bindings as typed rows in the one
combined ``fact_index``; it never settles an action or decides whether
repository state may advance.
"""

from .fact_index import ACTION_INDEX


def active(db, sid):
    return db.execute(
        "SELECT 1 FROM fact_index WHERE kind=? AND k0=? LIMIT 1",
        (ACTION_INDEX, sid),
    ).fetchone() is not None


def suppresses(db, fact):
    import facts

    return any(active(db, sid) for sid in facts.current_scopes(fact))


__all__ = ("active", "suppresses")
