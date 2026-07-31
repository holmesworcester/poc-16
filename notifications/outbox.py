"""Durable notification effect established before ingress retirement."""
from dataclasses import dataclass
import time

from core.crypto import h
from core.fact import canon
from core.limits import MAX_OBJECT_BYTES, MAX_REPOSITORY_OBJECT_BYTES, decode_json
from core.object_store import CREATED, EXISTS, OutcomeUnknown
from core.shape import FACT_TS_MAX, valid_fid
from .job import (
    MAX_PUSH_JOB_BYTES,
    decode as decode_job,
    encode as encode_job,
    make_job,
)
from .matcher import match_notifications
from .queue_evidence import (
    MAX_QUEUE_EVIDENCE_BYTES,
    decode_queue_acceptance,
    pile_address,
    queue_acceptance_matches,
)


RESULT_SCHEMA = "poc16-notification-outbox-result-v2"
MAX_RESULT_BYTES = 1024 * 1024
DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000


class _ObjectMiss(BaseException):
    def __init__(self, oid):
        super().__init__(oid)
        self.oid = oid


@dataclass(frozen=True, slots=True)
class OutboxDelivery:
    pile: str
    delivery_id: str


@dataclass(frozen=True, slots=True)
class OutboxResult:
    workspace: str
    generation: str
    root: str
    triggers: tuple[str, ...]
    deliveries: tuple[OutboxDelivery, ...]

    @property
    def piles(self):
        return tuple(delivery.pile for delivery in self.deliveries)


def _result_bytes(result):
    if not isinstance(result, OutboxResult) \
            or not valid_fid(result.workspace) \
            or not valid_fid(result.generation) \
            or not valid_fid(result.root) \
            or tuple(sorted(set(result.triggers))) != result.triggers \
            or not all(valid_fid(fid) for fid in result.triggers) \
            or not isinstance(result.deliveries, tuple) \
            or not all(isinstance(value, OutboxDelivery)
                       for value in result.deliveries) \
            or tuple(sorted(
                set(result.deliveries),
                key=lambda value: (value.pile, value.delivery_id),
            )) != result.deliveries \
            or len({value.delivery_id for value in result.deliveries}) \
            != len(result.deliveries) \
            or not all(valid_fid(value.delivery_id)
                       for value in result.deliveries):
        raise ValueError("notification outbox result")
    try:
        addresses = tuple(
            pile_address(value.pile) for value in result.deliveries)
    except ValueError as error:
        raise ValueError("notification outbox result") from error
    if any(generation != result.generation
           for _push_node, generation, _digest in addresses):
        raise ValueError("notification outbox result")
    raw = canon({
        "deliveries": [
            {
                "delivery_id": value.delivery_id,
                "pile": value.pile,
            }
            for value in result.deliveries
        ],
        "generation": result.generation,
        "root": result.root,
        "schema": RESULT_SCHEMA,
        "triggers": list(result.triggers),
        "workspace": result.workspace,
    })
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError("notification outbox result size")
    return raw


def _decode_result(raw):
    value = decode_json(raw, MAX_RESULT_BYTES, "notification outbox result")
    if not isinstance(value, dict) or set(value) != {
            "deliveries", "generation", "root", "schema", "triggers",
            "workspace"} or value.get("schema") != RESULT_SCHEMA:
        raise ValueError("notification outbox result")
    try:
        deliveries = tuple(
            OutboxDelivery(item["pile"], item["delivery_id"])
            for item in value["deliveries"]
            if isinstance(item, dict) and set(item) == {
                "delivery_id", "pile"}
        )
        if len(deliveries) != len(value["deliveries"]):
            raise ValueError("notification outbox result")
        result = OutboxResult(
            value["workspace"],
            value["generation"],
            value["root"],
            tuple(value["triggers"]),
            deliveries,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("notification outbox result") from error
    if _result_bytes(result) != raw:
        raise ValueError("notification outbox result")
    return result


class NotificationOutbox:
    """RepositoryApplier effect using only its awaited object-store trait."""

    def __init__(self, *, ttl_ms=DEFAULT_TTL_MS, now_ms=None):
        if type(ttl_ms) is not int or not 0 < ttl_ms <= DEFAULT_TTL_MS:
            raise ValueError("notification TTL")
        self.ttl_ms = ttl_ms
        self.now_ms = (
            (lambda: int(time.time() * 1000))
            if now_ms is None else now_ms
        )
        if not callable(self.now_ms):
            raise TypeError("notification clock")

    @staticmethod
    async def _get(store, key, maximum):
        raw = await store.get_bounded(key, maximum)
        if raw is not None and (
                not isinstance(raw, bytes) or len(raw) > maximum):
            raise ValueError("notification outbox read")
        return raw

    async def _put_exact(self, store, key, raw):
        if not isinstance(raw, bytes) or not raw \
                or len(raw) > MAX_OBJECT_BYTES:
            raise ValueError("notification outbox object")
        unknown = None
        for _ in range(2):
            try:
                outcome = await store.put_if_absent(key, raw)
            except OutcomeUnknown as error:
                unknown = error
            else:
                if outcome not in {CREATED, EXISTS}:
                    raise TypeError("notification outbox create result")
            incumbent = await self._get(store, key, len(raw))
            if incumbent == raw:
                return
            if incumbent is not None:
                raise ValueError("notification outbox conflict")
        raise unknown or OSError("notification outbox was not preserved")

    async def _plan(self, store, root_bytes, trigger_fids):
        objects = {}

        def fetch(oid):
            if oid not in objects:
                raise _ObjectMiss(oid)
            return objects[oid]

        while True:
            try:
                return match_notifications(root_bytes, fetch, trigger_fids)
            except _ObjectMiss as miss:
                objects[miss.oid] = await self._get(
                    store,
                    "obj/" + miss.oid,
                    MAX_REPOSITORY_OBJECT_BYTES,
                )

    async def _existing(self, store, workspace, generation):
        key = "push/result/" + generation
        raw = await self._get(store, key, MAX_RESULT_BYTES)
        if raw is None:
            return None
        result = _decode_result(raw)
        if result.workspace != workspace or result.generation != generation:
            raise ValueError("notification outbox result binding")
        deliveries = set()
        for delivery in result.deliveries:
            pile = delivery.pile
            push_node, pile_generation, digest = pile_address(pile)
            if pile_generation != generation:
                raise ValueError("notification outbox pile")
            raw = await self._get(store, pile, MAX_PUSH_JOB_BYTES)
            if raw is None:
                queued = await self._get(
                    store,
                    "push/queued/" + delivery.delivery_id,
                    MAX_QUEUE_EVIDENCE_BYTES,
                )
                if queued is None:
                    raise ValueError("notification outbox handoff")
                value = decode_queue_acceptance(queued)
                if not queue_acceptance_matches(
                        value,
                        delivery_id=delivery.delivery_id,
                        job_digest=digest,
                        push_node=push_node):
                    raise ValueError("notification outbox handoff")
                continue
            if digest != h(raw):
                raise ValueError("notification outbox pile")
            job = decode_job(raw)
            if job.workspace != workspace or job.push_node != push_node \
                    or job.delivery_id != delivery.delivery_id \
                    or job.delivery_id in deliveries:
                raise ValueError("notification outbox pile binding")
            deliveries.add(job.delivery_id)
        return result

    async def establish(
            self, *, workspace, root_bytes, trigger_fids, generation,
            store):
        """Establish all jobs, then the typed completion result, exactly."""
        if not valid_fid(workspace) or not valid_fid(generation) \
                or not isinstance(root_bytes, bytes):
            raise ValueError("notification publication effect")
        existing = await self._existing(store, workspace, generation)
        if existing is not None:
            return existing
        plan = await self._plan(store, root_bytes, trigger_fids)
        if not plan.triggers:
            return None

        deliveries = []
        by_delivery = {}
        now = self.now_ms()
        if type(now) is not int or not 0 <= now <= FACT_TS_MAX:
            raise ValueError("notification clock")
        expiry = min(FACT_TS_MAX, max(1, now + self.ttl_ms))
        for intent in plan.intents:
            job = make_job(
                workspace=intent.workspace,
                event=intent.event,
                endpoint=intent.endpoint,
                push_node=intent.push_node,
                platform=intent.platform,
                application=intent.application,
                environment=intent.environment,
                sealed_target=intent.sealed_target,
                payload=intent.payload,
                payload_version=1,
                expires_at_ms=expiry,
            )
            raw = encode_job(job)
            incumbent = by_delivery.setdefault(job.delivery_id, raw)
            if incumbent != raw:
                raise ValueError("notification delivery conflict")
            key = (
                f"push/pile/{job.push_node}/{generation}/{h(raw)}")
            await self._put_exact(store, key, raw)
            deliveries.append(OutboxDelivery(key, job.delivery_id))

        result = OutboxResult(
            workspace,
            generation,
            h(root_bytes),
            plan.triggers,
            tuple(sorted(
                set(deliveries),
                key=lambda value: (value.pile, value.delivery_id),
            )),
        )
        await self._put_exact(
            store, "push/result/" + generation, _result_bytes(result))
        return result


__all__ = (
    "DEFAULT_TTL_MS",
    "MAX_RESULT_BYTES",
    "NotificationOutbox",
    "OutboxDelivery",
    "OutboxResult",
    "RESULT_SCHEMA",
)
