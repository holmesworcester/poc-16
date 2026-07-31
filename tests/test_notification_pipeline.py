"""Authenticated matching and publication-to-outbox transition tests."""
import asyncio

import facts
import pytest
from core.crypto import h, keypair
from core.fact import canon
from core.repository_applier import RepositoryApplier
from core.store import FsStore
from facts import _policy
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.auth.signature import signature
from facts.content import delete as deletion
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.dispatcher import dispatch_one
from notifications.job import decode as decode_job
from notifications.matcher import match_notifications
from notifications.outbox import NotificationOutbox

from .queue_fakes import MemoryQueueService
from .util import all_fids, closed_subset


def run(awaitable):
    return asyncio.run(awaitable)


def _world(tmp_path, name="node"):
    node = FullPeer(
        str(tmp_path / name),
        publication_effect_factory=lambda _workspace, _store: (
            NotificationOutbox()),
    )
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    _, push_node = keypair()
    endpoint = push_endpoint.register(
        node,
        workspace,
        h(b"installation-1"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        push_endpoint.encode_sealed_target(b"x" * 49),
        ts=2,
    )
    return node, workspace, push_node, endpoint


def _match(node, workspace, event):
    reader = node.reader(workspace)
    return match_notifications(
        reader.root_bytes,
        lambda oid: node.store(workspace).get("obj/" + oid),
        (event,),
    )


def _jobs(node, workspace):
    return tuple(
        decode_job(node.store(workspace).get(key))
        for key in node.store(workspace).list("push/pile/")
    )


def _author_pair(node, workspace, setting, event, extra=()):
    secret, public = node.identity(workspace)
    setting_signature = signature(
        secret, public, setting, setting.ts)
    event_signature = signature(secret, public, event, event.ts)
    member = node.sql(workspace).resolve_offer(
        "member", public, node.pk)
    device = node.sql(workspace).resolve_offer(
        "device_key", public, node.pk)
    news = [setting_signature, setting, event_signature, event, *extra]
    deps = {
        setting_signature.fid: (),
        setting.fid: (
            setting_signature.fid, member, device,
            *preference.superseded_fids(setting),
        ),
        event_signature.fid: (),
        event.fid: (event_signature.fid, member),
    }
    return news, deps


def test_global_all_expands_one_user_to_every_live_endpoint(tmp_path):
    node, workspace, push_node, first = _world(tmp_path)
    second = push_endpoint.register(
        node,
        workspace,
        h(b"installation-2"),
        push_node,
        "apple",
        "poc16.mobile",
        "production",
        push_endpoint.encode_sealed_target(b"y" * 49),
        ts=3,
    )
    preference.set_global(node, workspace, preference.ALL, ts=4)
    event = message.post(
        node, workspace, "general", "hello", ts=5)

    plan = _match(node, workspace, event)

    assert [intent.endpoint for intent in plan.intents] \
        == sorted((first, second))
    assert {intent.user for intent in plan.intents} == {node.pk}
    assert {job.endpoint for job in _jobs(node, workspace)} \
        == {first, second}


def test_mentions_are_canonical_principal_metadata_not_text_parsing(
        tmp_path):
    node, workspace, _push_node, endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.MENTIONS, ts=3)
    text_only = message.post(
        node,
        workspace,
        "general",
        "@alice is display text only",
        ts=4,
    )
    explicit = message.post(
        node,
        workspace,
        "general",
        "canonical mention",
        ts=5,
        mentions=(node.pk,),
    )

    assert _match(node, workspace, text_only).intents == ()
    intent, = _match(node, workspace, explicit).intents
    assert intent.endpoint == endpoint
    assert b'"kind":"mention"' in intent.payload
    assert [job.event for job in _jobs(node, workspace)] == [explicit]


def test_channel_mute_overrides_global_and_inherit_restores_it(tmp_path):
    node, workspace, _push_node, endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    preference.set_channel(
        node, workspace, "general", preference.NONE, ts=4)
    muted = message.post(
        node, workspace, "general", "muted", ts=5)
    muted_plan = _match(node, workspace, muted)
    other = message.post(
        node, workspace, "random", "allowed", ts=6)
    other_plan = _match(node, workspace, other)
    preference.set_channel(
        node, workspace, "general", preference.INHERIT, ts=7)
    restored = message.post(
        node, workspace, "general", "restored", ts=8)

    assert muted_plan.intents == ()
    assert [intent.endpoint for intent in other_plan.intents] == [endpoint]
    assert [intent.endpoint for intent in _match(
        node, workspace, restored).intents] == [endpoint]
    assert {job.event for job in _jobs(node, workspace)} \
        == {other, restored}


def test_preference_and_event_in_same_pile_match_against_proposed_root(
        tmp_path):
    node, workspace, _push_node, endpoint = _world(tmp_path)
    secret, public = node.identity(workspace)
    setting = preference.notification_preference(
        workspace,
        public,
        node.pk,
        preference.GLOBAL,
        "",
        preference.ALL,
        0,
        (),
        10,
    )
    event = message.message(
        workspace, public, "general", "same pile", 11, node.pk)
    news, deps = _author_pair(node, workspace, setting, event)

    node.ingest_new(workspace, news, deps)

    job, = _jobs(node, workspace)
    assert (job.event, job.endpoint) == (event.fid, endpoint)


def test_same_pile_channel_mute_filters_global_route(tmp_path):
    node, workspace, _push_node, _endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    secret, public = node.identity(workspace)
    mute = preference.notification_preference(
        workspace,
        public,
        node.pk,
        preference.CHANNEL,
        "general",
        preference.NONE,
        0,
        (),
        10,
    )
    event = message.message(
        workspace, public, "general", "same-pile mute", 11, node.pk)
    news, deps = _author_pair(node, workspace, mute, event)

    node.ingest_new(workspace, news, deps)

    assert _jobs(node, workspace) == ()
    assert node.store(workspace).list("push/result/")


def test_same_pile_deletion_filters_the_trigger(tmp_path):
    node, workspace, _push_node, _endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    secret, public = node.identity(workspace)
    event = message.message(
        workspace, public, "general", "deleted", 10, node.pk)
    event_signature = signature(secret, public, event, 10)
    removal = deletion.delete(
        workspace,
        public,
        event.key,
        _policy.OWNER,
        11,
        node.pk,
    )
    removal_signature = signature(secret, public, removal, 11)
    member = node.sql(workspace).resolve_offer(
        "member", public, node.pk)

    node.ingest_new(
        workspace,
        [event_signature, event, removal_signature, removal],
        {
            event_signature.fid: (),
            event.fid: (event_signature.fid, member),
            removal_signature.fid: (),
            removal.fid: (
                removal_signature.fid, event.fid, member),
        },
    )

    assert _jobs(node, workspace) == ()
    assert node.reader(workspace).worker().fact_active(event.fid) is False


def test_later_preference_does_not_backfill_an_old_event(tmp_path):
    node, workspace, _push_node, _endpoint = _world(tmp_path)
    event = message.post(
        node, workspace, "general", "before opt-in", ts=4)

    preference.set_global(node, workspace, preference.ALL, ts=5)

    assert _jobs(node, workspace) == ()
    assert _match(node, workspace, event).intents


def test_matcher_uses_only_exact_notification_posting_joins(
        tmp_path, monkeypatch):
    node, workspace, _push_node, _endpoint = _world(tmp_path)
    preference.set_global(node, workspace, preference.ALL, ts=3)
    event = message.post(
        node, workspace, "general", "indexed", ts=4)
    from core.worker import WorkerView

    calls = []
    original = WorkerView.postings

    def recording(self, kind, k0=None, k1=None, **options):
        calls.append((kind, k0, k1))
        return original(self, kind, k0, k1, **options)

    monkeypatch.setattr(WorkerView, "postings", recording)

    assert _match(node, workspace, event).intents
    assert calls
    assert {kind for kind, _k0, _k1 in calls} <= {
        "notification.route.type",
        "notification.route.channel",
        "notification.preference",
        "notification.endpoint",
    }
    assert all(kind != "fact.type" for kind, _k0, _k1 in calls)


def _hosted_before_message(tmp_path):
    source, workspace, _push_node, endpoint = _world(tmp_path, "source")
    preference.set_global(source, workspace, preference.ALL, ts=3)
    baseline = closed_subset(
        source, workspace, all_fids(source, workspace))
    store = FsStore(str(tmp_path / "hosted"))
    bootstrap = RepositoryApplier(workspace, store)
    key = run(bootstrap.stage("bootstrap-member", baseline))
    assert run(bootstrap.apply(key)).status == "applied"
    event = message.post(
        source, workspace, "general", "hosted", ts=4)
    raw = closed_subset(source, workspace, (event,))
    return source, workspace, endpoint, event, raw, store


def test_only_cas_winner_runs_the_publication_effect(tmp_path):
    _source, workspace, _endpoint, _event, raw, store = \
        _hosted_before_message(tmp_path)

    class Spy:
        def __init__(self):
            self.calls = []

        async def establish(self, **values):
            self.calls.append(values)

    first_spy, second_spy = Spy(), Spy()
    first = RepositoryApplier(
        workspace, store, publication_effect=first_spy)
    second = RepositoryApplier(
        workspace, store, publication_effect=second_spy)
    source = run(first.stage("same-member", raw))
    first_proposal = run(first.propose(raw))
    second_proposal = run(second.propose(raw))

    won = run(first.commit(source, raw, first_proposal))
    lost = run(second.commit(source, raw, second_proposal))

    assert won.status == "applied"
    assert lost.status == "stale"
    assert len(first_spy.calls) == 1
    assert second_spy.calls == []


def test_crash_after_root_cas_replays_exact_source_into_outbox(tmp_path):
    _source, workspace, endpoint, event, raw, store = \
        _hosted_before_message(tmp_path)

    class CrashBeforeOutbox:
        async def establish(self, **_values):
            raise OSError("injected outbox outage")

    failing = RepositoryApplier(
        workspace, store, publication_effect=CrashBeforeOutbox())
    source = run(failing.stage("retained-member", raw))
    proposal = run(failing.propose(raw))

    try:
        run(failing.commit(source, raw, proposal))
    except OSError as error:
        assert str(error) == "injected outbox outage"
    else:
        raise AssertionError("outbox crash was not injected")

    assert store.get(source) == raw
    assert store.list("push/pile/") == []
    restarted = RepositoryApplier(
        workspace, store, publication_effect=NotificationOutbox())
    result = run(restarted.apply(source))

    assert result.status == "noop"
    assert result.retired is True
    key, = store.list("push/pile/")
    job = decode_job(store.get(key))
    assert (job.event, job.endpoint) == (event, endpoint)


def test_outbox_completion_is_idempotent_across_post_handoff_crash(
        tmp_path):
    _source, workspace, endpoint, event, raw, store = \
        _hosted_before_message(tmp_path)

    class CrashAfterOutbox:
        def __init__(self):
            self.inner = NotificationOutbox()

        async def establish(self, **values):
            await self.inner.establish(**values)
            raise OSError("lost completion response")

    failing = RepositoryApplier(
        workspace, store, publication_effect=CrashAfterOutbox())
    source = run(failing.stage("retained-member", raw))
    try:
        run(failing.apply(source))
    except OSError as error:
        assert str(error) == "lost completion response"
    else:
        raise AssertionError("post-handoff crash was not injected")
    before = tuple(store.list("push/pile/"))

    result = run(RepositoryApplier(
        workspace,
        store,
        publication_effect=NotificationOutbox(),
    ).apply(source))

    assert result.status == "noop"
    assert result.retired is True
    assert tuple(store.list("push/pile/")) == before
    key, = before
    job = decode_job(store.get(key))
    assert (job.event, job.endpoint) == (event, endpoint)
    result_raw, = (
        store.get(key)
        for key in store.list("push/result/"))
    assert b'"schema":"poc16-notification-outbox-result-v2"' \
        in result_raw


def test_outbox_recovery_accepts_durable_queue_handoff_after_pile_delete(
        tmp_path):
    _source, workspace, _endpoint, _event, raw, store = \
        _hosted_before_message(tmp_path)

    class CrashAfterOutbox:
        def __init__(self):
            self.inner = NotificationOutbox()

        async def establish(self, **values):
            await self.inner.establish(**values)
            raise OSError("lost completion response")

    failing = RepositoryApplier(
        workspace, store, publication_effect=CrashAfterOutbox())
    source = run(failing.stage("retained-member", raw))
    with pytest.raises(OSError, match="lost completion response"):
        run(failing.apply(source))
    pile, = store.list("push/pile/")
    job = decode_job(store.get(pile))
    service = MemoryQueueService()

    dispatched = dispatch_one(
        store, service.handle(), pile, push_node=job.push_node)

    assert dispatched.status == "published"
    assert store.get(pile) is None
    result = run(RepositoryApplier(
        workspace,
        store,
        publication_effect=NotificationOutbox(),
    ).apply(source))
    assert result.status == "noop"
    assert result.retired is True
    assert len(service.records) == 1
