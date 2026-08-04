"""Reusable ObjectStore conformance schedules.

This is test support, not provider evidence by itself.  Ordinary CI runs the
same schedules against local stores and provider fakes.  Opt-in tests invoke
them through the real direct S3 and R2 APIs.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
import asyncio
import os
import random
import threading

from core.crypto import h
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    RetryableStoreError,
    STALE,
    Versioned,
)


DEFAULT_SEED = 0xC0F016


def configured_seed():
    raw = os.environ.get("POC16_CONFORMANCE_SEED")
    return DEFAULT_SEED if raw is None else int(raw, 0)


@dataclass
class ConformanceRun:
    """Seeded values and a compact operation history for failure replay."""

    provider: str
    seed: int = field(default_factory=configured_seed)
    history: list[str] = field(default_factory=list)
    token_values: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self):
        self.random = random.Random(self.seed)

    def value(self, label):
        return (
            f"{label}:{self.random.getrandbits(128):032x}"
        ).encode("ascii")

    def record(self, operation, result):
        self.history.append(f"{operation} -> {result}")

    def observe(self, token, value):
        """Ratchet the one law provider comparison capabilities must obey."""
        incumbent = self.token_values.setdefault(token.value, value)
        assert incumbent == value, self.diagnostic()

    def diagnostic(self):
        history = "\n".join(
            f"  {index + 1}. {event}"
            for index, event in enumerate(self.history)
        ) or "  <empty>"
        return (
            f"provider conformance failure\n"
            f"provider={self.provider}\nseed={self.seed:#x}\n"
            f"history:\n{history}"
        )

    @contextmanager
    def capture(self):
        try:
            yield self
        except BaseException as error:
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note(self.diagnostic())
            raise


def _applied(result):
    return isinstance(result, Applied)


def exercise_sync_store(make_store, run, *, pace=lambda: None, list_count=7):
    """Exercise the shared synchronous ObjectStore contract.

    ``make_store`` must return independent handles over one empty isolated
    namespace.  The schedule is deliberately small enough for live buckets.
    """
    with run.capture():
        first, second = make_store(), make_store()
        assert first.read_versioned("authority") is ABSENT, run.diagnostic()
        run.record("read authority", "absent")

        authority_a = run.value("authority-a")
        created = first.cas("authority", ABSENT, authority_a)
        assert _applied(created), run.diagnostic()
        run.observe(created.token, authority_a)
        run.record("create authority", created)
        pair = second.read_versioned("authority")
        assert pair == Versioned(authority_a, created.token), run.diagnostic()
        run.observe(pair.token, pair.value)
        run.record("paired read", pair)

        ordinary = run.value("ordinary-put")
        assert first.put("probe/put", ordinary) is None
        assert second.get("probe/put") == ordinary
        run.record("ordinary put/read", "visible")

        raw = run.value("immutable")
        oid = h(raw)
        assert first.put_if_absent("obj/" + oid, raw) is CREATED
        assert second.get("obj/" + oid) == raw
        assert second.put_if_absent("obj/" + oid, raw) is EXISTS
        assert second.get("obj/" + oid) == raw
        run.record("immutable create/collision", oid)

        pace()
        authority_b = run.value("authority-b")
        authority_c = run.value("authority-c")
        start = threading.Barrier(2)

        def replace(store, value):
            start.wait(timeout=10)
            try:
                return store.cas("authority", pair.token, value)
            except RetryableStoreError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [
                future.result(timeout=30)
                for future in (
                    pool.submit(replace, first, authority_b),
                    pool.submit(replace, second, authority_c),
                )
            ]
        winners = [result for result in results if _applied(result)]
        assert len(winners) == 1, run.diagnostic()
        assert all(
            result is STALE or _applied(result)
            or isinstance(result, RetryableStoreError)
            for result in results
        ), run.diagnostic()
        winner = first.read_versioned("authority")
        assert winner.value in {authority_b, authority_c}, run.diagnostic()
        assert winner.token == winners[0].token, run.diagnostic()
        run.observe(winner.token, winner.value)
        run.record("concurrent replace", results)

        listed = []
        for ordinal in range(list_count):
            key = f"probe/list/{ordinal:04d}"
            value = run.value(f"list-{ordinal}")
            assert first.put_if_absent(key, value) is CREATED
            listed.append(key)
        assert second.list("probe/list/") == listed, run.diagnostic()
        run.record("paginated list", len(listed))

        # Value ABA is allowed.  A provider may reuse A's token only when the
        # bytes are A again; global generation uniqueness is not required.
        pace()
        aba_a = run.value("aba-a")
        to_a = first.cas("authority", winner.token, aba_a)
        assert _applied(to_a), run.diagnostic()
        run.observe(to_a.token, aba_a)
        pace()
        aba_b = run.value("aba-b")
        to_b = second.cas("authority", to_a.token, aba_b)
        assert _applied(to_b), run.diagnostic()
        run.observe(to_b.token, aba_b)
        pace()
        back_to_a = first.cas("authority", to_b.token, aba_a)
        assert _applied(back_to_a), run.diagnostic()
        run.observe(back_to_a.token, aba_a)
        final = second.read_versioned("authority")
        assert final == Versioned(aba_a, back_to_a.token), run.diagnostic()
        run.observe(final.token, final.value)
        if back_to_a.token == to_a.token:
            assert final.value == aba_a, run.diagnostic()
        run.record("A->B->A", (to_a.token, to_b.token, back_to_a.token))

        return {
            "authority": final,
            "objects": ("obj/" + oid,),
            "listed": tuple(listed),
        }


async def exercise_async_store(
        make_store, run, *, pace=None, list_count=7):
    """Awaited equivalent used by the native Cloudflare R2 binding."""
    if pace is None:
        async def pace():
            return None

    with run.capture():
        first, second = make_store(), make_store()
        assert await first.read_versioned(
            "authority") is ABSENT, run.diagnostic()
        run.record("read authority", "absent")

        authority_a = run.value("authority-a")
        created = await first.cas("authority", ABSENT, authority_a)
        assert _applied(created), run.diagnostic()
        run.observe(created.token, authority_a)
        pair = await second.read_versioned("authority")
        assert pair == Versioned(
            authority_a, created.token), run.diagnostic()
        run.observe(pair.token, pair.value)
        run.record("create/read authority", pair)

        ordinary = run.value("ordinary-put")
        assert await first.put("probe/put", ordinary) is None
        assert await second.get("probe/put") == ordinary
        run.record("ordinary put/read", "visible")

        raw = run.value("immutable")
        oid = h(raw)
        assert await first.put_if_absent("obj/" + oid, raw) is CREATED
        assert await second.get("obj/" + oid) == raw
        assert await second.put_if_absent("obj/" + oid, raw) is EXISTS
        run.record("immutable create/collision", oid)

        await pace()
        authority_b = run.value("authority-b")
        authority_c = run.value("authority-c")

        async def replace(store, value):
            try:
                return await store.cas("authority", pair.token, value)
            except RetryableStoreError as error:
                return error

        results = await asyncio.gather(
            replace(first, authority_b), replace(second, authority_c))
        winners = [result for result in results if _applied(result)]
        assert len(winners) == 1, run.diagnostic()
        assert all(
            result is STALE or _applied(result)
            or isinstance(result, RetryableStoreError)
            for result in results
        ), run.diagnostic()
        winner = await first.read_versioned("authority")
        assert winner.value in {authority_b, authority_c}, run.diagnostic()
        assert winner.token == winners[0].token, run.diagnostic()
        run.observe(winner.token, winner.value)
        run.record("concurrent replace", results)

        listed = []
        for ordinal in range(list_count):
            key = f"probe/list/{ordinal:04d}"
            assert await first.put_if_absent(
                key, run.value(f"list-{ordinal}")) is CREATED
            listed.append(key)
        assert await second.list("probe/list/") == listed, run.diagnostic()
        run.record("paginated list", len(listed))

        await pace()
        aba_a = run.value("aba-a")
        to_a = await first.cas("authority", winner.token, aba_a)
        assert _applied(to_a), run.diagnostic()
        run.observe(to_a.token, aba_a)
        await pace()
        aba_b = run.value("aba-b")
        to_b = await second.cas("authority", to_a.token, aba_b)
        assert _applied(to_b), run.diagnostic()
        run.observe(to_b.token, aba_b)
        await pace()
        back_to_a = await first.cas("authority", to_b.token, aba_a)
        assert _applied(back_to_a), run.diagnostic()
        run.observe(back_to_a.token, aba_a)
        final = await second.read_versioned("authority")
        assert final == Versioned(aba_a, back_to_a.token), run.diagnostic()
        run.observe(final.token, final.value)
        run.record("A->B->A", (to_a.token, to_b.token, back_to_a.token))

        return {
            "authority": final,
            "objects": ("obj/" + oid,),
            "listed": tuple(listed),
        }
