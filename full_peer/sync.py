"""Two-way FullPeer reconciliation through the shared writer-forest core."""
import asyncio
import random

from core.store import RemoteStore
from core.writer_repository import OwnerPublisher, RepositoryMirror

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
        binding = node.local_writer_binding(workspace)
        if binding is None:
            raise ValueError("local writer has no current authority binding")
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
