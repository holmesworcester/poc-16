"""Disposable SQLite projection rebuilt from one authenticated repository.

This is a client presentation accelerator, not a receiving or publication
engine.  Deleting or poisoning this database cannot change repository state;
``refresh`` replaces it solely from a pinned root and root-reachable objects.
"""

from . import catalog
from .crypto import h
from .fact import encode
from .repository_snapshot import action_bindings


def refresh(db, reader, *, workspace=None):
    """Replace all derived client rows from one pinned authenticated root."""
    if reader is None:
        if workspace is None:
            raise ValueError("empty projection workspace")
        validated, root_bytes = None, None
    else:
        workspace = reader.workspace
        validated = reader.all_facts()
        root_bytes = reader.root_bytes
    db.execute("BEGIN")
    try:
        for table in ("fact_index", "facts"):
            db.execute(f"DELETE FROM {table}")
        if validated is not None:
            for fid in sorted(validated.facts):
                fact = validated.facts[fid]
                db.execute(
                    "INSERT INTO facts VALUES(?,?)",
                    (fid, encode(fact)),
                )
                db.executemany(
                    "INSERT INTO fact_index VALUES(?,?,?,?)",
                    catalog.index_rows(fact),
                )
            db.executemany(
                "INSERT INTO fact_index VALUES(?,?,?,?)",
                (
                    (catalog.ACTION_INDEX, sid, "", fid)
                    for sid, fid in sorted(
                        action_bindings(validated.facts).items())
                ),
            )
        db.execute(
            "DELETE FROM meta "
            "WHERE k IN ('root','root-bytes','publish-base','tree-rebuild')")
        db.execute(
            "INSERT OR REPLACE INTO meta VALUES('root',?)",
            (h(root_bytes) if root_bytes is not None else None,),
        )
        db.execute(
            "INSERT OR REPLACE INTO meta VALUES('root-bytes',?)",
            (root_bytes,),
        )
        db.execute(
            "INSERT OR REPLACE INTO meta VALUES('index-version',?)",
            (catalog.INDEX_VERSION,),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
