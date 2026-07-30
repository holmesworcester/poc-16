"""Disposable SQLite projection rebuilt from one authenticated repository.

This is a client presentation accelerator, not a receiving or publication
engine.  Deleting or poisoning this database cannot change repository state;
``refresh`` replaces it solely from a pinned root and root-reachable objects.
"""

from . import catalog, settlement
from .crypto import h
from .fact import encode


def refresh(db, reader, *, workspace=None):
    """Replace all derived client rows from one pinned authenticated root."""
    if reader is None:
        if workspace is None:
            raise ValueError("empty projection workspace")
        archive, root_bytes = None, None
    else:
        workspace = reader.workspace
        archive = reader.archive()
        root_bytes = reader.root_bytes
    projected = settlement.project(
        workspace, archive.facts) if archive is not None else \
        settlement.Projection({}, {})
    db.execute("BEGIN")
    try:
        for table in ("fact_index", "facts"):
            db.execute(f"DELETE FROM {table}")
        if archive is not None:
            for fid in sorted(archive.facts):
                fact = archive.facts[fid]
                db.execute(
                    "INSERT INTO facts VALUES(?,?)",
                    (fid, encode(fact)),
                )
                db.executemany(
                    "INSERT INTO fact_index VALUES(?,?,?,?)",
                    catalog.index_rows(fact),
                )
            for fid, (rank, edges) in sorted(projected.standing.items()):
                db.execute(
                    "INSERT INTO fact_index VALUES(?,?,?,?)",
                    (catalog.STATE_INDEX, "eligible", str(rank), fid),
                )
                db.executemany(
                    "INSERT INTO fact_index VALUES(?,?,?,?)",
                    (
                        (
                            catalog.EDGE_INDEX,
                            f"{edge.kind}:{edge.role}",
                            edge.fid,
                            fid,
                        )
                        for edge in edges
                    ),
                )
            db.executemany(
                "INSERT INTO fact_index VALUES(?,?,?,?)",
                (
                    (catalog.ACTION_INDEX, sid, "", fid)
                    for sid, fid in sorted(projected.actions.items())
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
