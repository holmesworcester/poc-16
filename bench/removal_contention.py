"""Reusable removal-concurrency scenarios for the shared lookup gate.

The deterministic suite supplies filesystem stores.  The opt-in R2 suite
supplies separate direct-provider instances for each named namespace.  The
same scenario code therefore measures the running gate rather than a parallel
model.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import perf_counter

from core.access import AccessGate, ControlHeadRetry, LookupActive, LookupRefresh
from core.close import decode_signed_pile, encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.limits import MAX_HEAD_REMOVAL_UPDATES
from core.removal_path import decode as decode_removal_path
from core.suppression import scoped_id, suppression_slot
from core.writer_head import writer_store_binding
from core.writer_repository import OpaqueHeadGate, WriterLog
from facts.auth.admin import admin
from facts.auth.head_request import head_request
from facts.auth.removal import removal
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace


PERMIT_SECRET = b"live removal contention permit" * 2


def _run(awaitable):
    return asyncio.run(awaitable)


class CountingStore:
    """Count provider-class operations while preserving one store namespace."""

    def __init__(self, store):
        self.store = store
        self.operations = {
            "cas": 0,
            "get": 0,
            "list": 0,
            "put_if_absent": 0,
        }

    def __getattr__(self, name):
        return getattr(self.store, name)

    def namespace_id(self):
        return self.store.namespace_id()

    def get_bounded(self, key, maximum):
        self.operations["get"] += 1
        return self.store.get_bounded(key, maximum)

    def copy_pile_object(self, oid, maximum, write):
        self.operations["get"] += 1
        return self.store.copy_pile_object(oid, maximum, write)

    def has(self, key):
        self.operations["get"] += 1
        return self.store.has(key)

    def read_versioned(self, key):
        self.operations["get"] += 1
        return self.store.read_versioned(key)

    def put_if_absent(self, key, value):
        self.operations["put_if_absent"] += 1
        return self.store.put_if_absent(key, value)

    def cas(self, key, token, value):
        self.operations["cas"] += 1
        return self.store.cas(key, token, value)

    def list_page(self, prefix, cursor=None, limit=256):
        self.operations["list"] += 1
        return self.store.list_page(prefix, cursor, limit)


@dataclass(frozen=True)
class World:
    founder_secret: object
    founder: str
    root: object
    second_secret: object
    second: str
    second_closure: tuple
    second_admin_closure: tuple


def _signed(secret, writer, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, writer, closure))


def _world():
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, "removal contention", 1)
    invite_secret, invite_public = keypair()
    invite = user_invite(root.fid, founder, invite_public, 2)
    invite_sig = signature(founder_secret, founder, invite, 2)
    second_secret, second = keypair()
    joined = user(invite, invite_secret, second, "second admin", 3)
    joined_sig = signature(second_secret, second, joined, 3)
    closure = (root, invite_sig, invite, joined_sig, joined)
    elevated = admin(root.fid, founder, second, 4)
    elevated_sig = signature(founder_secret, founder, elevated, 4)
    return World(
        founder_secret,
        founder,
        root,
        second_secret,
        second,
        closure,
        (*closure, elevated_sig, elevated),
    )


def _mutual_controls(value):
    first = removal(
        value.root.fid, value.founder, value.second, 10)
    first_sig = signature(
        value.founder_secret, value.founder, first, 10)
    second = removal(
        value.root.fid, value.second, value.founder, 11)
    second_sig = signature(
        value.second_secret, value.second, second, 11)
    return (
        (
            value.founder,
            _signed(
                value.founder_secret,
                value.founder,
                value.root,
                (*value.second_closure, first_sig, first),
            ),
        ),
        (
            value.second,
            _signed(
                value.second_secret,
                value.second,
                value.root,
                (*value.second_admin_closure, second_sig, second),
            ),
        ),
    )


def _access_proof(secret, device, root, basis=""):
    item = request(
        root.fid, device, device, "sync", 10_000, basis, 20)
    return _signed(secret, device, root, (item,))


def _head_proof(secret, device, root, basis, proposed):
    item = head_request(
        root.fid, device, device, None, proposed, 10_000, basis, 21)
    return _signed(secret, device, root, (item,))


def _retry_control(state, raw, writer, pace):
    for attempt in range(8):
        result = _run(state.apply_control(raw, writer))
        if result.status != "retryable":
            return result
        pace()
    raise AssertionError("removal control did not converge after fair retry")


def _cost(operations):
    """Upper-bound R2 request cost using the bead's published unit prices."""
    class_a = operations["cas"] + operations["put_if_absent"]
    class_b = operations["get"] + operations["list"]
    return round(class_a * 4.50 / 1_000_000
                 + class_b * 0.36 / 1_000_000, 8)


def _report(label, stores, started, **values):
    operations = {name: 0 for name in (
        "cas", "get", "list", "put_if_absent")}
    for store in stores:
        for name, count in store.operations.items():
            operations[name] += count
    return {
        "scenario": label,
        "seconds": round(perf_counter() - started, 3),
        "operations": operations,
        "projected_r2_usd": _cost(operations),
        **values,
    }


def scenario_8_and_10_convergent_removers(store_factory, pace=lambda: None):
    """Two admin logs mutually remove; three recipients permute arrival."""
    value = _world()
    controls = _mutual_controls(value)
    stores, tips, judgments = [], [], []
    started = perf_counter()
    for recipient, order in enumerate(((0, 1), (1, 0), (0, 1))):
        # Reopening the same named namespace supplies distinct provider
        # instances while retaining the recipient's one private tree.
        name = f"scenario-8-10/{recipient}"
        instances = [CountingStore(store_factory(name))]
        if recipient == 0:
            instances.append(CountingStore(store_factory(name)))
        stores.extend(instances)
        store = instances[0]
        gate = AccessGate(value.root.fid, store)
        assert _run(gate.state.bootstrap(_signed(
            value.founder_secret,
            value.founder,
            value.root,
            (value.root,),
        ))).status in {"applied", "noop"}
        pace()
        if recipient == 0:
            states = tuple(
                AccessGate(value.root.fid, instance).state
                for instance in instances)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = tuple(
                    pool.submit(
                        _run,
                        states[index].apply_control(
                            controls[selected][1], controls[selected][0]),
                    )
                    for index, selected in enumerate(order)
                )
                results = tuple(future.result() for future in futures)
            for index, (selected, result) in enumerate(zip(order, results)):
                if result.status == "retryable":
                    writer, raw = controls[selected]
                    result = _retry_control(states[index], raw, writer, pace)
                assert result.status in {"applied", "noop"}
        else:
            for at, selected in enumerate(order):
                writer, raw = controls[selected]
                assert _retry_control(
                    gate.state, raw, writer, pace).status in {
                        "applied", "noop"}
                if at + 1 < len(order):
                    pace()
        tip = _run(gate.state.pin()).root_oid
        tips.append(tip)
        active = []
        for secret, subject in (
                (value.founder_secret, value.founder),
                (value.second_secret, value.second)):
            try:
                _run(gate.authorize_access(
                    _access_proof(secret, subject, value.root, tip), 100))
            except LookupActive as error:
                path = decode_removal_path(error.path)
                active.append((error.tip, tuple(
                    sid for sid, _proof in path.proofs)))
        judgments.append(tuple(active))
    assert len(set(tips)) == 1
    assert len(set(judgments)) == 1
    assert len(judgments[0]) == 2
    return _report(
        "8+10-concurrent-permuted-mutual-removal",
        stores,
        started,
        recipients=3,
        provider_instances=len(stores),
        identical_tip=tips[0],
        active_subjects=2,
    )


def scenario_9_removal_publish_race(store_factory, pace=lambda: None):
    """A stale issued permit cannot cross a live removal-root advance."""
    value = _world()
    store = CountingStore(store_factory("scenario-9"))
    started = perf_counter()

    async def scenario():
        gate = AccessGate(value.root.fid, store)
        assert (await gate.state.bootstrap(_signed(
            value.founder_secret,
            value.founder,
            value.root,
            (value.root,),
        ))).status in {"applied", "noop"}
        basis = (await gate.state.pin()).root_oid
        pace()
        action = removal(
            value.root.fid, value.founder, value.founder, 30)
        action_sig = signature(
            value.founder_secret, value.founder, action, 30)
        control = _signed(
            value.founder_secret,
            value.founder,
            value.root,
            (value.root, action_sig, action),
        )
        closure = decode_signed_pile(control).facts
        log = WriterLog(
            value.root.fid,
            value.founder,
            value.founder,
            writer_store_binding(value.root.fid, value.founder),
            value.founder_secret,
            store,
        )
        update = await log.prepare((closure,))
        await log.establish(update)
        proof = _head_proof(
            value.founder_secret, value.founder,
            value.root, basis, update.head_oid)
        permit = await gate.issue_head_permit(
            proof, update.head_oid, (control,), 100, PERMIT_SECRET)

        # Move the live root after issue. The old CLEAR request refreshes and
        # the old permit must not apply across that root.
        assert (await gate.state.tree.apply(((
            scoped_id("member", h(b"unrelated live overlap")),
            suppression_slot(),
        ),))).status == "applied"
        try:
            await gate.authorize_access(_access_proof(
                value.founder_secret, value.founder,
                value.root, basis), 100)
        except LookupRefresh:
            refreshed = True
        else:
            refreshed = False
        head_gate = OpaqueHeadGate(store, gate.authorize_head)
        try:
            await gate.commit_head_permit(
                head_gate, permit, update.head_oid, PERMIT_SECRET)
        except ControlHeadRetry:
            stale_rejected = True
        else:
            stale_rejected = False
        assert refreshed and stale_rejected

        pace()
        live = (await gate.state.pin()).root_oid
        rebound = _head_proof(
            value.founder_secret, value.founder,
            value.root, live, update.head_oid)
        permit = await gate.issue_head_permit(
            rebound, update.head_oid, (control,), 100, PERMIT_SECRET)
        committed = await gate.commit_head_permit(
            head_gate, permit, update.head_oid, PERMIT_SECRET)
        assert committed.status == "applied"
        try:
            await gate.authorize_access(_access_proof(
                value.founder_secret, value.founder,
                value.root, live), 100)
        except LookupActive:
            active = True
        else:
            active = False
        assert active
        return committed.status

    status = _run(scenario())
    return _report(
        "9-removal-vs-publish-live-pin",
        (store,),
        started,
        stale_permit_rejected=True,
        rebound_commit=status,
    )


def scenario_11_mass_purge(
        store_factory, pace=lambda: None, members=100):
    """Apply 100 signed removals in <=6-row paced transitions."""
    if type(members) is not int or members < 1:
        raise ValueError("mass purge member count")
    value = _world()
    store = CountingStore(store_factory("scenario-11"))
    state = AccessGate(value.root.fid, store).state
    started = perf_counter()
    assert _run(state.bootstrap(_signed(
        value.founder_secret,
        value.founder,
        value.root,
        (value.root,),
    ))).status in {"applied", "noop"}
    pace()
    controls = []
    subjects = []
    for index in range(members):
        invite_secret, invite_public = keypair()
        invite = user_invite(
            value.root.fid, value.founder, invite_public, 1000 + 4 * index)
        invite_sig = signature(
            value.founder_secret, value.founder, invite, invite.ts)
        member_secret, member = keypair()
        joined = user(
            invite, invite_secret, member, f"purge {index}", invite.ts + 1)
        joined_sig = signature(
            member_secret, member, joined, joined.ts)
        action = removal(
            value.root.fid, value.founder, member, invite.ts + 2)
        action_sig = signature(
            value.founder_secret, value.founder, action, action.ts)
        controls.append(_signed(
            value.founder_secret,
            value.founder,
            value.root,
            (value.root, invite_sig, invite, joined_sig, joined,
             action_sig, action),
        ))
        subjects.append((member_secret, member))

    transitions = 0
    for start in range(0, len(controls), MAX_HEAD_REMOVAL_UPDATES):
        batch = tuple(controls[start:start + MAX_HEAD_REMOVAL_UPDATES])
        plan = state.plan_control(batch, value.founder)
        assert len(plan.updates) <= MAX_HEAD_REMOVAL_UPDATES
        result = _run(state.apply_plan(plan))
        while result.status == "retryable":
            pace()
            result = _run(state.apply_plan(plan))
        assert result.status in {"applied", "noop"}
        transitions += 1
        if start + len(batch) < len(controls):
            pace()

    gate = AccessGate(value.root.fid, store)
    for secret, member in (subjects[0], subjects[-1]):
        try:
            _run(gate.authorize_access(
                _access_proof(secret, member, value.root), 100))
        except LookupActive:
            pass
        else:
            raise AssertionError("purged subject did not reject ACTIVE")
    expected = (members + MAX_HEAD_REMOVAL_UPDATES - 1) \
        // MAX_HEAD_REMOVAL_UPDATES
    assert transitions == expected
    return _report(
        "11-mass-purge-paced",
        (store,),
        started,
        members=members,
        transitions=transitions,
        rows_per_transition=MAX_HEAD_REMOVAL_UPDATES,
        offline_over_bound="blocked:poc-16-6j4.26",
    )


def run_removal_scenarios(store_factory, pace=lambda: None, members=100):
    """Run live-ready scenarios 8-11 and return operation/cost reports."""
    return (
        scenario_8_and_10_convergent_removers(store_factory, pace),
        scenario_9_removal_publish_race(store_factory, pace),
        scenario_11_mass_purge(store_factory, pace, members),
    )


__all__ = (
    "run_removal_scenarios",
    "scenario_8_and_10_convergent_removers",
    "scenario_9_removal_publish_race",
    "scenario_11_mass_purge",
)
