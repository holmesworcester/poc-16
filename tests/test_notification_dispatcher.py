"""Durable push-pile to managed-queue handoff behavior."""
import facts

from core.crypto import h, keypair
from core.delivery_queue import PublishOutcomeUnknown
from core.store import FsStore
from facts.auth import push_endpoint
from facts.auth.device import bind
from facts.content import message
from facts.content import notification_preference as preference
from full_peer.node import FullPeer
from notifications.dispatcher import dispatch_one, dispatch_page
from notifications.job import decode as decode_job
from notifications.outbox import NotificationOutbox
from .queue_fakes import MemoryQueueService


def _pending(tmp_path):
    node = FullPeer(
        str(tmp_path / "node"),
        publication_effect_factory=lambda _workspace, _store: (
            NotificationOutbox()),
    )
    workspace = facts.auth.workspace.create(node, "alice", ts=1)
    bind(node, workspace, "phone")
    _, push_node = keypair()
    endpoint = push_endpoint.register(
        node,
        workspace,
        h(b"installation"),
        push_node,
        "android",
        "poc16.mobile",
        "production",
        push_endpoint.encode_sealed_target(b"x" * 49),
        ts=2,
    )
    preference.set_global(node, workspace, preference.ALL, ts=3)
    event = message.post(
        node, workspace, "general", "queued", ts=4)
    key, = node.store(workspace).list("push/pile/")
    return node, workspace, push_node, endpoint, event, key


def test_dispatcher_records_acceptance_before_retiring_pile(tmp_path):
    node, workspace, push_node, endpoint, event, key = _pending(tmp_path)
    service = MemoryQueueService()

    result = dispatch_one(
        node.store(workspace), service.handle(), key, push_node=push_node)

    assert result.status == "published"
    assert node.store(workspace).get(key) is None
    acceptance = node.store(workspace).get(
        "push/queued/" + result.delivery_id)
    assert acceptance is not None
    delivery, = service.handle().pull(lease_seconds=10)
    job = decode_job(delivery.body)
    assert (job.event, job.endpoint) == (event, endpoint)


def test_existing_acceptance_retires_replayed_pile_without_republish(
        tmp_path):
    node, workspace, push_node, _endpoint, _event, key = _pending(tmp_path)
    store = node.store(workspace)
    raw = store.get(key)
    service = MemoryQueueService()
    first = dispatch_one(store, service.handle(), key, push_node=push_node)
    store.put_if_absent(key, raw)

    second = dispatch_one(store, service.handle(), key, push_node=push_node)

    assert first.delivery_id == second.delivery_id
    assert second.status == "already-published"
    assert len(service.records) == 1
    assert store.get(key) is None


def test_ambiguous_publish_leaves_pile_for_at_least_once_retry(tmp_path):
    node, workspace, push_node, _endpoint, _event, key = _pending(tmp_path)
    service = MemoryQueueService()

    class Ambiguous:
        def publish(self, body):
            service.handle().publish(body)
            raise PublishOutcomeUnknown("lost response")

    result = dispatch_page(
        node.store(workspace), Ambiguous(), push_node)

    assert result.items[0].status == "retry"
    assert node.store(workspace).get(key) is not None
    assert len(service.records) == 1

    recovered = dispatch_page(
        node.store(workspace), service.handle(), push_node)
    assert recovered.items[0].status == "published"
    assert node.store(workspace).get(key) is None
    assert len(service.records) == 2
    assert service.records[0].body == service.records[1].body


def test_invalid_hash_bound_job_moves_to_typed_failure(tmp_path):
    store = FsStore(str(tmp_path / "store"))
    _, push_node = keypair()
    generation = h(b"generation")
    raw = b"not a canonical job"
    key = f"push/pile/{push_node}/{generation}/{h(raw)}"
    store.put_if_absent(key, raw)

    result = dispatch_one(
        store, MemoryQueueService().handle(), key, push_node=push_node)

    assert result.status == "failed"
    assert result.error == "invalid-job"
    assert store.get(key) is None
    failure, = store.list("push/failed/")
    assert b'"classification":"invalid-job"' in store.get(failure)


def test_page_isolates_retryable_job_and_dispatches_its_sibling(tmp_path):
    node, workspace, push_node, _endpoint, _event, first_key = \
        _pending(tmp_path)
    store = node.store(workspace)
    first_raw = store.get(first_key)
    first_job = decode_job(first_raw)
    # A second exact pile can have a distinct generation while preserving the
    # deterministic endpoint delivery id.
    second_key = (
        f"push/pile/{push_node}/{h(b'second-generation')}/{h(first_raw)}")
    store.put_if_absent(second_key, first_raw)

    class FailFirst:
        def __init__(self):
            self.calls = 0
            self.queue = MemoryQueueService().handle()

        def publish(self, body):
            self.calls += 1
            if self.calls == 1:
                raise OSError("temporary queue outage")
            return self.queue.publish(body)

    queue = FailFirst()
    page = dispatch_page(store, queue, push_node)

    assert [item.status for item in page.items] == ["retry", "published"]
    retained = next(item.pile for item in page.items
                    if item.status == "retry")
    retired = next(item.pile for item in page.items
                   if item.status == "published")
    assert store.get(retained) is not None
    assert store.get(retired) is None
    assert store.get("push/queued/" + first_job.delivery_id) is not None
