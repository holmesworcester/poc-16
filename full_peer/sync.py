"""Two-way FullPeer reconciliation through the shared writer-forest core."""
import asyncio
import random

import facts

from core.crypto import h
from core.limits import MAX_CONTROL_PILE_BYTES
from core.object_store import Versioned
from core.store import RemoteStore
from core.writer_head import (
    MAX_WRITER_HEAD_BYTES,
    WriterBinding,
    decode_head,
    decode_slot_at,
    head_slot_key,
    require_bound_head,
    writer_store_binding,
)
from core.writer_repository import (
    OwnerPublisher,
    RepositoryMirror,
    open_accepted_pile,
)
from facts.auth._proof import historical_owner

from .walk import Peer


# FullPeer owns scheduling policy; provider-neutral core only retains the exact
# permit/body and invokes the injected pause. Cancellation aborts that turn.
CONTROL_HEAD_RETRY_BASE_MS = 10
CONTROL_HEAD_RETRY_MAX_MS = 1_000


def _run(awaitable):
    return asyncio.run(awaitable)


async def _control_head_retry_pause(attempt):
    """Apply bounded exponential full jitter in the active sender turn."""
    ceiling = min(
        CONTROL_HEAD_RETRY_MAX_MS,
        CONTROL_HEAD_RETRY_BASE_MS * (1 << min(attempt, 16)),
    )
    await asyncio.sleep(random.random() * ceiling / 1_000)


def _local_publication_binding(node, workspace):
    """Select live authorship or one exact accepted self-removal terminal.

    Local SQL is authoritative for continued authorship.  Its only absence
    exception is the current signed final head whose last accepted pile
    activates this same device's removal cell.  Reconstructing that binding
    from durable bytes lets a restarted sender deliver the terminal transition
    without retaining ambient post-removal authority.
    """
    with node.lock:
        binding = node.local_writer_binding(workspace)
        if binding is not None:
            return binding

        _secret, device = node.identity(workspace)
        store = node.store(workspace)
        key = head_slot_key(workspace, device)
        opened = store.read_versioned(key)
        if not isinstance(opened, Versioned):
            return None
        slot = decode_slot_at(key, opened.value)
        raw_head = store.get_bounded(
            "obj/" + slot.head, MAX_WRITER_HEAD_BYTES)
        if raw_head is None or h(raw_head) != slot.head:
            raise ValueError("local publication head integrity")
        head = decode_head(raw_head)
        binding = WriterBinding(
            workspace,
            device,
            historical_owner(node, workspace, device),
            writer_store_binding(workspace, device),
        )
        require_bound_head(head, binding)
        if head.sequence < 1:
            return None
        terminal = _run(open_accepted_pile(
            store,
            workspace,
            device,
            head.sequence,
            max_bytes=MAX_CONTROL_PILE_BYTES,
        ))
        try:
            plan = node.access_gate(workspace).state.plan_control(
                (terminal,), device)
        except ValueError:
            return None
        expected = facts.principal_sid("device", device)
        return binding if plan.active_sids == (expected,) else None


def sync(node, workspace, url):
    """Pull, then reverse-mirror every locally accepted writer over HTTP.

    Pull consumption happens before the reverse pass, so a peer may relay a
    remote writer only after its own :class:`FactConsumer` accepted the
    original signed head/tree/piles.  The receiver repeats that same mirror
    validation at ``PUT /mirror``; HTTP carries objects and grants no fact
    authority of its own.
    """
    peer = Peer(node, workspace, url)
    remote = RemoteStore(peer)

    pulled = _run(node.mirror(workspace).sync_from(remote))
    if pulled.errors:
        raise ValueError(
            "unresolved remote writer difference") from ValueError(
                pulled.errors[0][1])

    pushed_count = 0
    if peer.accepts_push:
        outbound = RepositoryMirror(
            workspace,
            remote,
            node.writer_binding,
            None,
        )
        pushed = _run(outbound.sync_from(node.store(workspace)))
        if pushed.errors:
            raise ValueError(
                "unresolved local writer difference") from ValueError(
                    pushed.errors[0][1])
        pushed_count = pushed.piles
    elif peer.accepts_owner_publish:
        binding = _local_publication_binding(node, workspace)
        if binding is None:
            raise ValueError(
                "local writer has no current or terminal publication binding")
        device = binding.device

        async def make_proof(base, proposed):
            def build():
                path = peer.removal_path()
                return node.head_proof(
                    workspace,
                    binding.owner,
                    base,
                    proposed,
                    removal_path=path,
                )

            return await asyncio.to_thread(build)

        publisher = OwnerPublisher(
            workspace,
            device,
            binding,
            node.store(workspace),
            remote,
            make_proof,
            peer.issue_head_permit,
            peer.commit_head_permit,
            peer.advance_head,
            retry_pause=_control_head_retry_pause,
        )
        published = _run(publisher.publish())
        if published.status == "conflict":
            raise ValueError("owner-head publication requires rebase")
        if published.status == "retryable":
            raise ValueError("concurrent owner-head publication")
        pushed_count = published.piles

    node._ensure_projection(workspace)
    return int(bool(pulled.changed)), pushed_count


__all__ = ["sync"]
