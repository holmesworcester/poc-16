"""Two-way FullPeer reconciliation through the shared writer-forest core."""
import asyncio

from core.store import RemoteStore
from core.writer_repository import OwnerPublisher, RepositoryMirror

from .walk import Peer


def _run(awaitable):
    return asyncio.run(awaitable)


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
            return await asyncio.to_thread(
                node.head_proof,
                workspace,
                binding.owner,
                base,
                proposed,
            )

        publisher = OwnerPublisher(
            workspace,
            device,
            binding,
            node.store(workspace),
            remote,
            make_proof,
            peer.advance_head,
        )
        published = _run(publisher.publish())
        if published.status == "retryable":
            raise ValueError("concurrent owner-head publication")
        pushed_count = published.piles

    node._ensure_projection(workspace)
    return int(bool(pulled.changed)), pushed_count


__all__ = ["sync"]
