#!/usr/bin/env python3
"""Measure disposable SQL warm, one-head, and deleted-file replay."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import tempfile
from time import perf_counter

import facts

from full_peer.node import FullPeer
from full_peer.sql_store import APP_VERSION, SqlStore
from core.writer_repository import FactConsumer, RepositoryMirror


TABLES = ("facts", "fact_index", "projected_heads")


def _snapshot(database):
    return {
        table: tuple(sorted(database.execute(f"SELECT * FROM {table}")))
        for table in TABLES
    }


def _restore(node, workspace, snapshot):
    database = node.idx(workspace)
    database.execute("BEGIN IMMEDIATE")
    try:
        for table in reversed(TABLES):
            database.execute(f"DELETE FROM {table}")
        for table in TABLES:
            rows = snapshot[table]
            if rows:
                markers = ",".join("?" for _ in rows[0])
                database.executemany(
                    f"INSERT INTO {table} VALUES({markers})", rows)
        database.commit()
    except Exception:
        database.rollback()
        raise


def _timed_replay(mirror):
    started = perf_counter()
    result = asyncio.run(mirror.replay_local())
    return result, perf_counter() - started


def _mirror(node, workspace, projection):
    return RepositoryMirror(
        workspace,
        node.store(workspace),
        node.writer_binding,
        FactConsumer(workspace, projection),
    )


def measure(directory, history_messages=1_000):
    """Return measured work while asserting identical reconstructed rows."""
    if type(history_messages) is not int or history_messages < 1:
        raise ValueError("SQL replay history")
    directory = Path(directory)
    node = FullPeer(str(directory))
    workspace = facts.auth.workspace.create(node, "replay", ts=1)
    for ordinal in range(history_messages):
        facts.content.message.post(
            node,
            workspace,
            "general",
            f"history-{ordinal}",
            ts=ordinal + 2,
        )

    before_delta = _snapshot(node.idx(workspace))
    facts.content.message.post(
        node,
        workspace,
        "general",
        "one-head-delta",
        ts=history_messages + 2,
    )
    expected = _snapshot(node.idx(workspace))

    # Model a crash after the accepted slot changed but before its disposable
    # SQL transaction: restore the exact prior projection, not protocol state.
    _restore(node, workspace, before_delta)
    delta, delta_seconds = _timed_replay(node.mirror(workspace))
    assert delta.errors == ()
    assert (delta.listed, delta.changed, delta.piles, delta.facts) \
        == (1, 1, 1, 2)
    assert _snapshot(node.idx(workspace)) == expected
    node.idx(workspace).close()

    # Reopening a current projection still lists the bounded slot page, but
    # its per-writer head checkpoint prevents any pile or fact replay.
    database = directory / "ws" / f"{workspace}.idx.db"
    warm_projection = SqlStore.open(str(database), workspace)
    warm, warm_seconds = _timed_replay(
        _mirror(node, workspace, warm_projection))
    assert warm.errors == ()
    assert (warm.listed, warm.changed, warm.piles, warm.facts) == (1, 0, 0, 0)
    assert _snapshot(warm_projection.db) == expected
    warm_projection.db.close()

    # Literal deletion is the worst case and must reproduce all three tables
    # under the one current application version from accepted writer bytes.
    for exact in (database, Path(str(database) + "-wal"),
                  Path(str(database) + "-shm")):
        try:
            os.unlink(exact)
        except FileNotFoundError:
            pass
    cold_projection = SqlStore.open(str(database), workspace)
    cold, cold_seconds = _timed_replay(
        _mirror(node, workspace, cold_projection))
    assert cold.errors == ()
    assert cold.listed == 1
    assert cold.piles == history_messages + 2
    assert _snapshot(cold_projection.db) == expected
    assert cold_projection.db.execute(
        "PRAGMA user_version").fetchone()[0] == APP_VERSION

    return {
        "app_version": APP_VERSION,
        "cold": {
            "facts": cold.facts,
            "piles": cold.piles,
            "seconds": cold_seconds,
        },
        "history_messages": history_messages,
        "projected_fact_rows": len(expected["facts"]),
        "one_head": {
            "facts": delta.facts,
            "piles": delta.piles,
            "seconds": delta_seconds,
        },
        "warm_restart": {
            "facts": warm.facts,
            "piles": warm.piles,
            "seconds": warm_seconds,
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages", type=int, default=1_000)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="poc16-sql-replay-") as directory:
        print(json.dumps(measure(directory, options.messages), sort_keys=True))


if __name__ == "__main__":
    main()
