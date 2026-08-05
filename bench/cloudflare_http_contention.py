"""Disposable live contention proof for the Cloudflare owner gateway.

The fixture uses the production signed-head, access, object-store, deployment,
and HTTP paths.  Live mutation is deliberately opt-in and every object lives
below one random, cleanup-fenced prefix.
"""
import argparse
import asyncio
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from adapters.r2.s3 import R2S3Config, R2S3Store
from core.access import AccessGate
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.http import (
    encode_head_commit_request,
    encode_head_permit_request,
)
from core.object_store import (
    ABSENT,
    CREATED,
    EXISTS,
    Applied,
    OutcomeUnknown,
    Versioned,
    mutable_key,
)
from core.store import FsStore
from core.suppression import scoped_id, suppression_slot
from core.writer_head import (
    WriterBinding,
    decode_slot_at,
    head_slot_key,
    writer_store_binding,
)
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    OwnerPublisher,
    RepositoryMirror,
    WriterLog,
)
from deploy.cloudflare_worker import manage
from facts._policy import OWNER
from facts.auth.admin import admin
from facts.auth.device import device as device_fact
from facts.auth.device_invite import device_invite
from facts.auth.device_removal import device_removal
from facts.auth.head_request import head_request
from facts.auth.request import request as access_request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace as workspace_fact
from facts.content.message import message


LIVE_PREFIX_RE = re.compile(
    r"^poc16-http-contention/run-[0-9a-f]{32}$")
LIVE_CLEANUP_MAX_KEYS = 512
DEFAULT_RACERS = 16
DEFAULT_INDEPENDENT_WRITERS = 7
HTTP_TIMEOUT_SECONDS = 45
HTTP_MAX_ATTEMPTS = 8
HTTP_RETRY_STATUSES = frozenset({0, 404, 409, 500, 502, 503})
WRONG_WORKSPACE_MAX_ATTEMPTS = 8
ACTIVATION_TIMEOUT_SECONDS = 120
ACTIVATION_POLL_SECONDS = 0.5
PROOF_LIFETIME_MS = 15 * 60 * 1000
PROJECTED_MAX_R2_OPERATIONS = 1_000
PROJECTED_MAX_COST_USD = 0.01
SEED_WORKERS = 8


@dataclass(frozen=True)
class Candidate:
    device: str
    head: str
    proof: bytes
    closure: tuple = ()
    fact_id: str | None = None


@dataclass(frozen=True)
class WriterActor:
    secret: bytes
    device: str
    authority: tuple
    writer: WriterLog


@dataclass(frozen=True)
class Fixture:
    workspace: str
    founder: str
    root: object
    basis: str
    raced_secret: bytes
    raced_writer: WriterLog
    actors: tuple
    store: FsStore
    initial_heads: tuple
    raced: tuple
    independent: tuple


def _run(awaitable):
    return asyncio.run(awaitable)


def _signed(secret, device, root, facts):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, device, facts))


def _access_proof(secret, device, owner, root, authority, now):
    item = access_request(
        root.fid, device, owner, "sync", now + PROOF_LIFETIME_MS, "", now)
    item_signature = signature(secret, device, item, now)
    return _signed(
        secret, device, root, (*authority, item_signature, item))


def _head_proof(
        secret, device, owner, root, basis, base, proposed, now):
    item = head_request(
        root.fid,
        device,
        owner,
        base,
        proposed,
        now + PROOF_LIFETIME_MS,
        basis,
        now,
    )
    return _signed(secret, device, root, (item,))


async def _build_fixture(directory, racers, independent_writers, now):
    if not 2 <= racers <= 64:
        raise ValueError("racers must be between 2 and 64")
    if not 1 <= independent_writers <= 31:
        raise ValueError("independent writers must be between 1 and 31")
    store = FsStore(str(directory))
    founder_secret, founder = keypair()
    root = workspace_fact(
        founder_secret, founder, "live HTTP contention", now - 1000)
    primary = device_fact(
        root.fid, founder, "primary", now - 999)
    primary_signature = signature(
        founder_secret, founder, primary, primary.ts)
    primary_authority = (root, primary_signature, primary)
    identities = [(founder_secret, founder, primary_authority)]
    for ordinal in range(independent_writers):
        device_secret, device = keypair()
        invited = device_invite(
            root.fid,
            founder,
            device,
            f"independent-{ordinal:02d}",
            now - 998 + ordinal,
        )
        invited_signature = signature(
            founder_secret, founder, invited, invited.ts)
        identities.append((
            device_secret,
            device,
            (*primary_authority, invited_signature, invited),
        ))

    access = AccessGate(root.fid, store)
    for device_secret, device, authority in identities:
        admitted = await access.authorize_access(_access_proof(
            device_secret,
            device,
            founder,
            root,
            authority,
            now,
        ), now)
        if admitted is None:
            raise RuntimeError("fixture access admission failed")
    basis = (await access.state.pin()).root_oid
    heads = OpaqueHeadGate(store, access.authorize_head)

    writers = []
    initial_heads = []
    for ordinal, (device_secret, device, authority) in enumerate(identities):
        writer = WriterLog(
            root.fid,
            device,
            founder,
            writer_store_binding(root.fid, device),
            device_secret,
            store,
        )
        initial_item = message(
            root.fid,
            device,
            "general",
            f"initial-{ordinal:02d}",
            now - 500 + ordinal,
            owner=founder,
        )
        initial_signature = signature(
            device_secret, device, initial_item, initial_item.ts)
        initial = await writer.prepare((
            (*authority, initial_signature, initial_item),
        ))
        await writer.establish(initial)
        proof = _head_proof(
            device_secret,
            device,
            founder,
            root,
            basis,
            None,
            initial.head_oid,
            now,
        )
        outcome = await heads.advance(proof, initial.head_oid, now)
        if outcome.status != "applied":
            raise RuntimeError("fixture initial head failed")
        writers.append((device_secret, device, authority, writer, initial))
        initial_heads.append((device, initial.head_oid))

    raced = []
    device_secret, device, authority, writer, initial = writers[0]
    for ordinal in range(racers):
        item = message(
            root.fid,
            device,
            "general",
            f"raced-{ordinal:02d}",
            now + 100 + ordinal,
            owner=founder,
        )
        item_signature = signature(device_secret, device, item, item.ts)
        update = await writer.prepare((
            (*authority, item_signature, item),
        ))
        if update.base_head != initial.head_oid:
            raise RuntimeError("raced candidates do not share one base")
        await writer.establish(update)
        closure = (*authority, item_signature, item)
        raced.append(Candidate(
            device,
            update.head_oid,
            _head_proof(
                device_secret,
                device,
                founder,
                root,
                basis,
                initial.head_oid,
                update.head_oid,
                now,
            ),
            closure,
            item.fid,
        ))

    independent = []
    for ordinal, (
            device_secret, device, authority, writer, initial,
    ) in enumerate(writers[1:]):
        item = message(
            root.fid,
            device,
            "general",
            f"independent-advance-{ordinal:02d}",
            now + 500 + ordinal,
            owner=founder,
        )
        item_signature = signature(device_secret, device, item, item.ts)
        update = await writer.prepare((
            (*authority, item_signature, item),
        ))
        if update.base_head != initial.head_oid:
            raise RuntimeError("independent candidate base")
        await writer.establish(update)
        closure = (*authority, item_signature, item)
        independent.append(Candidate(
            device,
            update.head_oid,
            _head_proof(
                device_secret,
                device,
                founder,
                root,
                basis,
                initial.head_oid,
                update.head_oid,
                now,
            ),
            closure,
            item.fid,
        ))
    return Fixture(
        root.fid,
        founder,
        root,
        basis,
        writers[0][0],
        writers[0][3],
        tuple(WriterActor(*values[:4]) for values in writers),
        store,
        tuple(initial_heads),
        tuple(raced),
        tuple(independent),
    )


def build_fixture(directory, racers, independent_writers, now=None):
    now = time.time_ns() // 1_000_000 if now is None else now
    return _run(_build_fixture(
        Path(directory), racers, independent_writers, now))


def _r2_store(prefix, environment=os.environ):
    return R2S3Store(
        R2S3Config(
            account_id=environment["POC16_R2_ACCOUNT_ID"],
            bucket=environment["POC16_R2_BUCKET"],
            prefix=prefix,
            max_pool_connections=64,
        ),
        access_key_id=environment["POC16_R2_ACCESS_KEY_ID"],
        secret_access_key=environment["POC16_R2_SECRET_ACCESS_KEY"],
    )


def seed(store, fixture):
    keys = fixture.store.list("")
    immutables = [key for key in keys if not mutable_key(key)]
    registers = [key for key in keys if mutable_key(key)]

    def create(key):
        value = fixture.store.get(key)
        for attempt in range(3):
            try:
                result = store.put_if_absent(key, value)
            except OutcomeUnknown:
                incumbent = store.get_bounded(key, max(1, len(value)))
                if incumbent == value:
                    return
                if incumbent is not None:
                    raise RuntimeError("generated R2 prefix collided")
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
            if result is CREATED:
                return
            if result is EXISTS \
                    and store.get_bounded(key, max(1, len(value))) == value:
                return
            raise RuntimeError("generated R2 prefix was not empty")

    def initialize(key):
        value = fixture.store.get(key)
        for attempt in range(3):
            try:
                result = store.cas(key, ABSENT, value)
            except OutcomeUnknown:
                opened = store.read_versioned(key)
                if isinstance(opened, Versioned) and opened.value == value:
                    return
                if opened is not ABSENT:
                    raise RuntimeError("generated R2 prefix collided")
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
            if isinstance(result, Applied):
                return
            opened = store.read_versioned(key)
            if isinstance(opened, Versioned) and opened.value == value:
                return
            raise RuntimeError("generated R2 prefix was not empty")

    # Preserve the publication invariant even in a disposable namespace:
    # every referenced immutable exists before a mutable root or head slot.
    with ThreadPoolExecutor(max_workers=SEED_WORKERS) as pool:
        tuple(pool.map(create, immutables))
        tuple(pool.map(initialize, registers))
    return len(keys)


def cleanup(store, prefix):
    """Delete only one exact generated namespace and verify its absence."""
    if not LIVE_PREFIX_RE.fullmatch(prefix):
        raise ValueError("refusing cleanup outside HTTP contention prefix")
    keys = store.list("")
    if len(keys) > LIVE_CLEANUP_MAX_KEYS:
        raise RuntimeError("refusing unbounded HTTP contention cleanup")
    objects = []
    for key in keys:
        request = store._read_args(key)
        if not request["Key"].startswith(prefix + "/"):
            raise ValueError("refusing out-of-prefix HTTP cleanup")
        objects.append({"Key": request["Key"]})
    if objects:
        store._mutation_client.delete_objects(
            Bucket=store.config.bucket,
            Delete={"Objects": objects, "Quiet": True},
        )
    remaining = store.list("")
    if remaining:
        raise RuntimeError("live HTTP contention cleanup incomplete")
    return {"deleted": len(keys), "remaining": 0}


def _percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(
        fraction * len(ordered)) - 1)]


def contend(url, workspace, candidates, opener=urlopen):
    candidates = tuple(candidates)
    barrier = threading.Barrier(len(candidates))

    def send(candidate):
        request = Request(
            f"{url}/head/{candidate.head}?ws={workspace}",
            data=candidate.proof,
            method="POST",
            headers={
                "Content-Type": "application/octet-stream",
                "User-Agent": "poc-16-live-http-contention/1",
            },
        )
        barrier.wait()
        started = time.perf_counter()
        attempts = []
        for attempt in range(HTTP_MAX_ATTEMPTS):
            try:
                with opener(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                    response.read()
                    status = response.status
            except HTTPError as error:
                status = error.code
                error.close()
            except (URLError, OSError):
                status = 0
            attempts.append(status)
            if status not in HTTP_RETRY_STATUSES:
                break
            if attempt + 1 < HTTP_MAX_ATTEMPTS:
                time.sleep(min(2.0, 0.25 * (2 ** attempt)))
        return candidate, status, (
            time.perf_counter() - started) * 1000, tuple(attempts)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        outcomes = tuple(pool.map(send, candidates))
    elapsed = time.perf_counter() - started
    latencies = [
        latency for _candidate, _status, latency, _attempts in outcomes]
    attempt_statuses = [
        status
        for _candidate, _status, _latency, attempts in outcomes
        for status in attempts
    ]
    return outcomes, {
        "logical_requests": len(outcomes),
        "http_attempts": len(attempt_statuses),
        "attempt_status_counts": dict(sorted(Counter(
            attempt_statuses).items())),
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(len(outcomes) / elapsed, 2),
        "latency_ms_p50": round(_percentile(latencies, 0.50), 2),
        "latency_ms_p95": round(_percentile(latencies, 0.95), 2),
        "latency_ms_max": round(max(latencies), 2),
    }


def verify_slots(store, fixture, outcomes):
    statuses = [
        (candidate, status)
        for candidate, status, _latency, _attempts in outcomes
    ]
    raced_statuses = [
        status for candidate, status in statuses
        if candidate.device == fixture.raced[0].device
    ]
    initial_by_device = dict(fixture.initial_heads)
    candidate_by_device = {
        candidate.device: {candidate.head}
        for candidate in fixture.independent
    }
    candidate_by_device[fixture.raced[0].device] = {
        candidate.head for candidate in fixture.raced
    }
    observed = {}
    classifications = {}
    invalid = {}
    for device, initial in initial_by_device.items():
        key = head_slot_key(fixture.workspace, device)
        opened = store.read_versioned(key)
        if opened is ABSENT or not isinstance(opened, Versioned):
            invalid[device] = "absent"
            continue
        slot = decode_slot_at(key, opened.value)
        observed[device] = slot.head
        if slot.head == initial:
            classifications[device] = "initial"
        elif slot.head in candidate_by_device[device]:
            classifications[device] = "candidate"
        else:
            classifications[device] = "invalid"
            invalid[device] = slot.head

    raced_device = fixture.raced[0].device
    evidence = {
        "raced_writer": raced_device,
        "same_writer_candidates": len(fixture.raced),
        "same_writer_applied": raced_statuses.count(201),
        "same_writer_acknowledged": sum(
            status in {201, 204} for status in raced_statuses),
        "same_writer_conflicts": raced_statuses.count(412),
        "same_writer_retryable": raced_statuses.count(409),
        "independent_applied": sum(
            statuses.count((candidate, 201))
            for candidate in fixture.independent),
        "final_slots_verified": len(observed),
        "final_initial": sum(
            value == "initial" for value in classifications.values()),
        "final_candidate": sum(
            value == "candidate" for value in classifications.values()),
        "invalid_or_torn_slots": len(invalid),
        "status_counts": dict(sorted(Counter(
            status for _candidate, status in statuses).items())),
        "raced_status_counts": dict(sorted(Counter(
            raced_statuses).items())),
        "independent_status_counts": dict(sorted(Counter(
            status for candidate, status in statuses
            if candidate.device != raced_device).items())),
        "no_clobber": not invalid
            and len(observed) == len(initial_by_device),
    }
    if invalid:
        raise RuntimeError(
            "HTTP contention produced an invalid slot: "
            + json.dumps(evidence, sort_keys=True))
    if evidence["same_writer_acknowledged"] != 1 \
            or raced_statuses.count(412) != len(fixture.raced) - 1:
        raise RuntimeError(
            "same-writer HTTP contention result: "
            + json.dumps(evidence, sort_keys=True))
    independent_acknowledged = sum(
        status in {201, 204}
        for candidate, status in statuses
        if candidate.device != raced_device)
    evidence["independent_acknowledged"] = independent_acknowledged
    if independent_acknowledged != len(fixture.independent):
        raise RuntimeError(
            "independent HTTP head result: "
            + json.dumps(evidence, sort_keys=True))
    if evidence["final_candidate"] != len(initial_by_device) \
            or evidence["final_initial"]:
        raise RuntimeError(
            "HTTP acknowledgement did not match final slots: "
            + json.dumps(evidence, sort_keys=True))
    return evidence


def recover_same_writer(
        store, fixture, outcomes, url, receiver_directory,
        *, advance_head=None):
    """Rebase every losing closure, publish it, then cold-sync all facts.

    The forced race models multiple processes sharing one writer identity.
    Recovery deliberately uses the production ``OwnerPublisher`` and
    ``RepositoryMirror`` components; only the application policy that chooses
    to retain and rebase the losing closures lives in this harness.
    """
    raced_outcomes = tuple(
        (candidate, status)
        for candidate, status, _latency, _attempts in outcomes
        if candidate.device == fixture.raced[0].device
    )
    winners = tuple(
        candidate for candidate, status in raced_outcomes
        if status in {201, 204}
    )
    if len(winners) != 1:
        raise RuntimeError("same-writer recovery needs exactly one winner")
    winner = winners[0]
    losers = tuple(
        candidate for candidate in fixture.raced
        if candidate.head != winner.head
    )
    if len(losers) != len(fixture.raced) - 1:
        raise RuntimeError("same-writer recovery candidate accounting")

    key = head_slot_key(fixture.workspace, winner.device)
    remote_opened = store.read_versioned(key)
    if not isinstance(remote_opened, Versioned) \
            or decode_slot_at(key, remote_opened.value).head != winner.head:
        raise RuntimeError("same-writer winner is not durable")
    local_opened = fixture.store.read_versioned(key)
    if not isinstance(local_opened, Versioned):
        raise RuntimeError("same-writer local slot absent")
    imported = fixture.store.cas(
        key, local_opened.token, remote_opened.value)
    if not isinstance(imported, Applied):
        raise RuntimeError("same-writer winner import conflicted")

    rebased = _run(fixture.raced_writer.prepare(
        tuple(candidate.closure for candidate in losers)))
    if rebased.base_head != winner.head \
            or len(rebased.piles) != len(losers):
        raise RuntimeError("same-writer closures were not rebased")
    _run(fixture.raced_writer.establish(rebased))

    trusted_now = time.time_ns() // 1_000_000
    local_access = AccessGate(fixture.workspace, fixture.store)
    local_heads = OpaqueHeadGate(
        fixture.store, local_access.authorize_head)
    local_proof = _head_proof(
        fixture.raced_secret,
        winner.device,
        fixture.founder,
        fixture.root,
        fixture.basis,
        winner.head,
        rebased.head_oid,
        trusted_now,
    )
    local_advance = _run(local_heads.advance(
        local_proof, rebased.head_oid, trusted_now))
    if local_advance.status != "applied":
        raise RuntimeError("same-writer local rebase advance failed")

    http_evidence = {}

    async def make_proof(base, proposed):
        return _head_proof(
            fixture.raced_secret,
            winner.device,
            fixture.founder,
            fixture.root,
            fixture.basis,
            base,
            proposed,
            time.time_ns() // 1_000_000,
        )

    async def reject_control(*_args):
        raise RuntimeError("message-only recovery unexpectedly needs permit")

    async def advance(proof, proposed):
        if advance_head is not None:
            result = advance_head(proof, proposed)
            if hasattr(result, "__await__"):
                result = await result
            return result
        candidate = Candidate(winner.device, proposed, proof)
        posted, performance = await asyncio.to_thread(
            contend, url, fixture.workspace, (candidate,))
        _candidate, status, _latency, attempts = posted[0]
        http_evidence.update({
            "terminal_status": status,
            "attempt_statuses": list(attempts),
            "performance": performance,
        })
        return {
            201: "applied",
            204: "noop",
            409: "retryable",
            412: "conflict",
        }.get(status, "retryable")

    binding = WriterBinding(
        fixture.workspace,
        winner.device,
        fixture.founder,
        writer_store_binding(fixture.workspace, winner.device),
    )
    publisher = OwnerPublisher(
        fixture.workspace,
        winner.device,
        binding,
        fixture.store,
        store,
        make_proof,
        reject_control,
        reject_control,
        advance,
    )
    published = _run(publisher.publish())
    if published.status not in {"applied", "noop"}:
        raise RuntimeError(
            f"same-writer rebased publication {published.status}")

    consumer = FactConsumer(fixture.workspace)
    known_devices = {device for device, _head in fixture.initial_heads}

    def binding_for(workspace, device, _removal_root, _head):
        if workspace != fixture.workspace or device not in known_devices:
            return None
        return WriterBinding(
            workspace,
            device,
            fixture.founder,
            writer_store_binding(workspace, device),
        )

    mirror = RepositoryMirror(
        fixture.workspace,
        FsStore(str(receiver_directory)),
        binding_for,
        consumer,
    )
    cold = _run(mirror.sync_from(store))
    if cold.errors:
        raise RuntimeError(
            "same-writer cold sync failed: " + repr(cold.errors))
    expected = {candidate.fact_id for candidate in fixture.raced}
    present = expected.intersection(consumer.fact_ids())
    if None in expected or present != expected:
        raise RuntimeError("same-writer recovery lost message facts")

    final_opened = store.read_versioned(key)
    if not isinstance(final_opened, Versioned) \
            or decode_slot_at(key, final_opened.value).head \
            != rebased.head_oid:
        raise RuntimeError("same-writer rebased head is not durable")
    return {
        "winner_head": winner.head,
        "losing_closures_rebased": len(losers),
        "rebased_head": rebased.head_oid,
        "rebased_sequence": rebased.head.sequence,
        "publisher_status": published.status,
        "published_piles": published.piles,
        "cold_listed": cold.listed,
        "cold_changed": cold.changed,
        "cold_piles": cold.piles,
        "cold_facts": cold.facts,
        "raced_message_facts_expected": len(expected),
        "raced_message_facts_present": len(present),
        "all_raced_writes_reachable": present == expected,
        "http": http_evidence,
    }


def _post_control(
        url, workspace, proposed, phase, body, *, retry_conflict=False,
        opener=urlopen):
    if phase not in {"permit", "commit"}:
        raise ValueError("control HTTP phase")
    request = Request(
        f"{url}/head/{proposed}/{phase}?ws={workspace}",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "User-Agent": "poc-16-live-cross-device-control/1",
        },
    )
    attempts = []
    started = time.perf_counter()
    response_body = b""
    retryable = set(HTTP_RETRY_STATUSES) - {409}
    if retry_conflict:
        retryable.add(409)
    for attempt in range(HTTP_MAX_ATTEMPTS):
        try:
            with opener(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                response_body = response.read()
                status = response.status
        except HTTPError as error:
            status = error.code
            response_body = error.read()
            error.close()
        except (URLError, OSError):
            status, response_body = 0, b""
        attempts.append(status)
        if status not in retryable:
            break
        if attempt + 1 < HTTP_MAX_ATTEMPTS:
            time.sleep(min(2.0, 0.25 * (2 ** attempt)))
    return status, response_body, {
        "attempt_statuses": attempts,
        "latency_ms": round(
            (time.perf_counter() - started) * 1000, 2),
    }


def _merged_closure(*closures):
    found = set()
    merged = []
    for closure in closures:
        for fact in closure:
            if fact.fid not in found:
                found.add(fact.fid)
                merged.append(fact)
    return tuple(merged)


def cross_device_controls(store, fixture, url, opener=urlopen):
    """Force simultaneous and delayed control commits from distinct devices."""
    if len(fixture.actors) < 5:
        raise ValueError("cross-device control proof needs five writers")
    actors = fixture.actors[:5]
    slot_before = {}
    for actor in actors:
        key = head_slot_key(fixture.workspace, actor.device)
        remote = store.read_versioned(key)
        local = fixture.store.read_versioned(key)
        if not isinstance(remote, Versioned) \
                or not isinstance(local, Versioned):
            raise RuntimeError("cross-device control slot missing")
        slot_before[actor.device] = decode_slot_at(key, remote.value).head
        if decode_slot_at(key, local.value).head != slot_before[actor.device]:
            imported = fixture.store.cas(key, local.token, remote.value)
            if not isinstance(imported, Applied):
                raise RuntimeError("cross-device control import conflicted")

    access = AccessGate(fixture.workspace, store)
    pin = _run(access.state.pin())
    if pin is None:
        raise RuntimeError("cross-device control removal root absent")
    basis = pin.root_oid
    now = time.time_ns() // 1_000_000
    pairs = ((0, 1), (1, 0), (2, 3), (3, 2))
    prepared = []
    actions = []
    for ordinal, (writer_index, target_index) in enumerate(pairs):
        actor = actors[writer_index]
        target = actors[target_index]
        action = device_removal(
            fixture.workspace,
            actor.device,
            target.device,
            fixture.founder,
            OWNER,
            now + ordinal,
            fixture.founder,
        )
        action_signature = signature(
            actor.secret, actor.device, action, action.ts)
        closure = _merged_closure(
            actor.authority,
            target.authority,
            (action_signature, action),
        )
        update = _run(actor.writer.prepare((closure,)))
        if update.base_head != slot_before[actor.device]:
            raise RuntimeError("cross-device control base")
        _run(actor.writer.establish(update))
        _run(actor.writer.establish(update, store))
        proof = _head_proof(
            actor.secret,
            actor.device,
            fixture.founder,
            fixture.root,
            basis,
            update.base_head,
            update.head_oid,
            now,
        )
        prepared.append((actor, update, proof, (encode_signed_pile(
            make_signed_pile(
                actor.secret,
                fixture.workspace,
                actor.device,
                closure,
            )),)))
        actions.append((target.device, action.fid))

    clear_actor = actors[4]
    invite_secret, invite_public = keypair()
    invited_member = user_invite(
        fixture.workspace,
        fixture.founder,
        invite_public,
        now + 10,
    )
    invited_member_signature = signature(
        fixture.raced_secret,
        fixture.founder,
        invited_member,
        invited_member.ts,
    )
    _member_secret, new_member = keypair()
    joined_member = user(
        invited_member,
        invite_secret,
        new_member,
        "stale-clear-must-not-land",
        now + 11,
    )
    joined_member_signature = signature(
        _member_secret,
        new_member,
        joined_member,
        joined_member.ts,
    )
    granted_admin = admin(
        fixture.workspace,
        clear_actor.device,
        new_member,
        now + 12,
        fixture.founder,
    )
    granted_admin_signature = signature(
        clear_actor.secret,
        clear_actor.device,
        granted_admin,
        granted_admin.ts,
    )
    clear_closure = _merged_closure(
        clear_actor.authority,
        (
            invited_member_signature,
            invited_member,
            joined_member_signature,
            joined_member,
            granted_admin_signature,
            granted_admin,
        ),
    )
    clear_update = _run(clear_actor.writer.prepare((clear_closure,)))
    if clear_update.base_head != slot_before[clear_actor.device]:
        raise RuntimeError("cross-device clear base")
    _run(clear_actor.writer.establish(clear_update))
    _run(clear_actor.writer.establish(clear_update, store))
    clear_proof = _head_proof(
        clear_actor.secret,
        clear_actor.device,
        fixture.founder,
        fixture.root,
        basis,
        clear_update.base_head,
        clear_update.head_oid,
        now,
    )
    clear_control = encode_signed_pile(make_signed_pile(
        clear_actor.secret,
        fixture.workspace,
        clear_actor.device,
        clear_closure,
    ))

    permits = []
    issue_evidence = []
    for actor, update, proof, controls in prepared:
        status, permit, evidence = _post_control(
            url,
            fixture.workspace,
            update.head_oid,
            "permit",
            encode_head_permit_request(proof, controls),
            opener=opener,
        )
        if status != 200 or not permit:
            raise RuntimeError(f"cross-device permit issuance {status}")
        permits.append((actor, update, permit))
        issue_evidence.append(evidence)
    clear_status, clear_permit, clear_issue_evidence = _post_control(
        url,
        fixture.workspace,
        clear_update.head_oid,
        "permit",
        encode_head_permit_request(clear_proof, (clear_control,)),
        opener=opener,
    )
    if clear_status != 200 or not clear_permit:
        raise RuntimeError(f"cross-device clear permit {clear_status}")

    barrier = threading.Barrier(2)

    def commit(item):
        _actor, update, permit = item
        barrier.wait()
        return _post_control(
            url,
            fixture.workspace,
            update.head_oid,
            "commit",
            encode_head_commit_request(permit),
            retry_conflict=True,
            opener=opener,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        simultaneous = tuple(pool.map(commit, permits[:2]))
    delayed = []
    for _actor, update, permit in permits[2:]:
        delayed.append(_post_control(
            url,
            fixture.workspace,
            update.head_oid,
            "commit",
            encode_head_commit_request(permit),
            retry_conflict=True,
            opener=opener,
        ))
    if any(status not in {201, 204}
           for status, _body, _evidence in (*simultaneous, *delayed)):
        raise RuntimeError("cross-device removal commit failed")

    stale_clear_status, _body, stale_clear_evidence = _post_control(
        url,
        fixture.workspace,
        clear_update.head_oid,
        "commit",
        encode_head_commit_request(clear_permit),
        opener=opener,
    )
    if stale_clear_status != 409:
        raise RuntimeError("stale CLEAR permit crossed removal root")

    replay = []
    for _actor, update, permit in permits:
        replay.append(_post_control(
            url,
            fixture.workspace,
            update.head_oid,
            "commit",
            encode_head_commit_request(permit),
            opener=opener,
        )[0])
    if replay != [204] * len(permits):
        raise RuntimeError("cross-device removal replay was not exact noop")

    final_pin = _run(AccessGate(
        fixture.workspace, store).state.pin())
    if final_pin is None:
        raise RuntimeError("cross-device final removal root absent")
    active = {}
    for target, action_fid in actions:
        sid = scoped_id("device", target)
        proof = _run(final_pin.proof(sid))
        value = None if proof is None else final_pin.verify(sid, proof)
        expected = suppression_slot(action_fid)
        if value != expected:
            raise RuntimeError("cross-device removal did not converge")
        active[target] = value["action"]
    new_sid = scoped_id("member", new_member)
    new_proof = _run(final_pin.proof(new_sid))
    if new_proof is not None:
        raise RuntimeError("stale CLEAR permit introduced device authority")

    for actor, update, _permit in permits:
        key = head_slot_key(fixture.workspace, actor.device)
        opened = store.read_versioned(key)
        if not isinstance(opened, Versioned) \
                or decode_slot_at(key, opened.value).head \
                != update.head_oid:
            raise RuntimeError("cross-device control head missing")
    clear_key = head_slot_key(fixture.workspace, clear_actor.device)
    clear_opened = store.read_versioned(clear_key)
    if not isinstance(clear_opened, Versioned) \
            or decode_slot_at(clear_key, clear_opened.value).head \
            != slot_before[clear_actor.device]:
        raise RuntimeError("stale CLEAR head became visible")

    commit_evidence = [
        evidence for _status, _body, evidence
        in (*simultaneous, *delayed)
    ]
    return {
        "issue_statuses": [200] * (len(permits) + 1),
        "issue_attempt_statuses": [
            item["attempt_statuses"]
            for item in (*issue_evidence, clear_issue_evidence)
        ],
        "simultaneous_terminal_statuses": [
            status for status, _body, _evidence in simultaneous],
        "delayed_terminal_statuses": [
            status for status, _body, _evidence in delayed],
        "commit_attempt_statuses": [
            item["attempt_statuses"] for item in commit_evidence],
        "commit_latency_ms": [item["latency_ms"]
                              for item in commit_evidence],
        "active_removals_expected": len(actions),
        "active_removals_present": len(active),
        "mutual_removals_land": len(active) == len(actions),
        "exact_replay_statuses": replay,
        "stale_clear_terminal_status": stale_clear_status,
        "stale_clear_attempt_statuses": stale_clear_evidence[
            "attempt_statuses"],
        "stale_clear_absent": new_proof is None,
        "final_removal_root": final_pin.root_oid,
    }


def _health(url, opener):
    try:
        with opener(Request(
                url + "/healthz",
                headers={
                    "User-Agent": "poc-16-live-http-contention/1",
                },
        ), timeout=10) as response:
            if response.status != 200:
                response.read()
                return response.status
            try:
                return 200 if json.loads(
                    response.read()).get("ok") is True else -1
            except (AttributeError, TypeError, ValueError):
                return -1
    except HTTPError as error:
        status = error.code
        error.close()
        return status
    except (URLError, OSError):
        return 0


def _activate(url, probes, opener=urlopen):
    if not 1 <= probes <= 64:
        raise ValueError("activation probes")
    deadline = time.monotonic() + ACTIVATION_TIMEOUT_SECONDS
    rounds = 0
    statuses = Counter()
    while True:
        rounds += 1
        with ThreadPoolExecutor(max_workers=probes) as pool:
            ready = tuple(pool.map(
                lambda _ordinal: _health(url, opener), range(probes)))
        statuses.update(ready)
        if all(status == 200 for status in ready):
            return {
                "rounds": rounds,
                "requests": rounds * probes,
                "status_counts": dict(sorted(statuses.items())),
            }
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "live Worker did not activate concurrently: "
                + json.dumps({
                    "rounds": rounds,
                    "requests": rounds * probes,
                    "status_counts": dict(sorted(statuses.items())),
                }, sort_keys=True))
        time.sleep(ACTIVATION_POLL_SECONDS)


def _wrong_workspace(url, fixture, opener=urlopen):
    wrong = "0" * 64
    if wrong == fixture.workspace:
        wrong = "f" * 64
    candidate = fixture.raced[0]
    request = Request(
        f"{url}/head/{candidate.head}?ws={wrong}",
        data=candidate.proof,
        method="POST",
        headers={"User-Agent": "poc-16-live-http-contention/1"},
    )
    for attempt in range(WRONG_WORKSPACE_MAX_ATTEMPTS):
        headers = {}
        try:
            with opener(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                response.read()
                status = response.status
                headers = response.headers
        except HTTPError as error:
            status = error.code
            headers = error.headers or {}
            error.close()
        except (URLError, OSError):
            status = 0
        # A workers.dev rollout 404 is not proof that HttpGate rejected the
        # workspace. Require the security headers added by the running Worker.
        if status == 404 \
                and headers.get("X-Content-Type-Options") == "nosniff" \
                and headers.get("Cache-Control") == "no-store":
            return status
        if status not in HTTP_RETRY_STATUSES:
            raise RuntimeError("wrong-workspace request reached wrong handler")
        if attempt + 1 < WRONG_WORKSPACE_MAX_ATTEMPTS:
            time.sleep(min(2.0, 0.25 * (2 ** attempt)))
    raise RuntimeError("wrong-workspace denial was not Worker-authenticated")


def _deployment_environment(fixture, prefix, run_id, environment):
    account = environment["POC16_R2_ACCOUNT_ID"]
    bucket = environment["POC16_R2_BUCKET"]
    return {
        **environment,
        "CLOUDFLARE_ACCOUNT_ID": account,
        "CF_WORKSPACE": fixture.workspace,
        "CF_R2_BUCKET": bucket,
        "CF_R2_ENDPOINT": (
            f"https://{account}.r2.cloudflarestorage.com"),
        "CF_PACK_PUT_ENDPOINT": "https://poc16.invalid",
        "CF_STORE_PREFIX": prefix,
        "CF_DEPLOYMENT_OWNER": f"poc16-http-{run_id}",
        "GRANT_SECRET": base64.b64encode(
            secrets.token_bytes(manage.EDGE_SECRET_BYTES)).decode(),
        "PERMIT_SECRET": base64.b64encode(
            secrets.token_bytes(manage.PERMIT_SECRET_BYTES)).decode(),
        "PACK_TICKET_SECRET": base64.b64encode(
            secrets.token_bytes(manage.PACK_TICKET_SECRET_BYTES)).decode(),
        "R2_ACCESS_KEY_ID": environment["POC16_R2_ACCESS_KEY_ID"],
        "R2_SECRET_ACCESS_KEY": environment[
            "POC16_R2_SECRET_ACCESS_KEY"],
    }


def live_run(
        racers=DEFAULT_RACERS,
        independent_writers=DEFAULT_INDEPENDENT_WRITERS,
        environment=os.environ):
    if environment.get("POC16_LIVE_CF_HTTP") != "1":
        raise ValueError(
            "set POC16_LIVE_CF_HTTP=1 to authorize live Worker/R2 changes")
    run_id = secrets.token_hex(16)
    prefix = "poc16-http-contention/run-" + run_id
    if not LIVE_PREFIX_RE.fullmatch(prefix):
        raise AssertionError("generated live prefix")
    with tempfile.TemporaryDirectory(
            prefix="poc16-http-contention-") as directory:
        fixture = build_fixture(
            directory, racers, independent_writers)
        store = _r2_store(prefix, environment)
        deployed_environment = _deployment_environment(
            fixture, prefix, run_id, dict(environment))
        secrets_value = manage._secrets(deployed_environment)
        config = manage.generated_config(
            deployed_environment, smoke=True)
        previous = os.environ.copy()
        os.environ.clear()
        os.environ.update(deployed_environment)
        attempted = False
        primary = cleanup_error = None
        report = None
        try:
            if manage._worker_settings(config) is not manage._ABSENT:
                raise RuntimeError(
                    "generated contention Worker name already exists")
            seeded = seed(store, fixture)
            attempted = True
            deployed = manage._deploy(config, secrets_value, capture=True)
            manage._require_owned(config)
            match = manage.WORKERS_URL.search(
                deployed.stdout + deployed.stderr)
            if match is None:
                raise RuntimeError(
                    "Wrangler did not report a workers.dev URL")
            url = match.group(0)
            all_candidates = (*fixture.raced, *fixture.independent)
            activation = _activate(url, len(all_candidates))
            outcomes, performance = contend(
                url, fixture.workspace, all_candidates)
            correctness = verify_slots(store, fixture, outcomes)
            recovery = recover_same_writer(
                store,
                fixture,
                outcomes,
                url,
                Path(directory) / "cold-receiver",
            )
            cross_device = cross_device_controls(
                store, fixture, url)
            wrong_status = _wrong_workspace(url, fixture)
            if wrong_status != 404:
                raise RuntimeError("wrong workspace was not denied")
            report = {
                "target": "cloudflare-worker-r2",
                "workspace": fixture.workspace,
                "prefix": prefix,
                "projected": {
                    "maximum_r2_operations": PROJECTED_MAX_R2_OPERATIONS,
                    "maximum_cost_usd": PROJECTED_MAX_COST_USD,
                },
                "seeded_objects": seeded,
                "activation": activation,
                "http": performance,
                "correctness": correctness,
                "same_writer_recovery": recovery,
                "cross_device_controls": cross_device,
                "wrong_workspace_status": wrong_status,
            }
        except Exception as error:  # noqa: BLE001 - preserve cleanup evidence
            primary = error
        finally:
            errors = []
            if attempted:
                try:
                    manage._delete(config, force=True, timeout=60)
                except Exception as error:  # noqa: BLE001
                    errors.append(error)
            try:
                cleanup_result = cleanup(store, prefix)
                if report is not None:
                    report["cleanup"] = cleanup_result
            except Exception as error:  # noqa: BLE001
                errors.append(error)
            os.environ.clear()
            os.environ.update(previous)
            if errors:
                cleanup_error = ExceptionGroup(
                    "Cloudflare HTTP contention cleanup failed", errors)
        if primary is not None and cleanup_error is not None:
            raise ExceptionGroup(
                "Cloudflare HTTP contention and cleanup both failed",
                [primary, cleanup_error],
            )
        if primary is not None:
            raise primary
        if cleanup_error is not None:
            raise cleanup_error
        return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--racers", type=int, default=DEFAULT_RACERS)
    parser.add_argument(
        "--independent-writers",
        type=int,
        default=DEFAULT_INDEPENDENT_WRITERS,
    )
    args = parser.parse_args(argv)
    if not args.live:
        raise SystemExit("pass --live for the opt-in Cloudflare run")
    report = live_run(args.racers, args.independent_writers)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
