"""PLAN SKELETON (poc-16-808.2/.3, stages S1–S2) — the thin initiator.

walk.walk's hand-rolled fence compare becomes tree.diff with pull/push
emitters; Peer (HTTP + grants) stays as-is and store.RemoteStore adapts it to
the engine's fetch callback. The responder still runs zero sync logic.

    sync = tree.diff(my root, their root)
        their-side-only keys -> pull the leaf pile VERBATIM into MY ingress
                                (the WAL; my next turn folds it)
        my-side-only keys    -> close per range, PUT into THEIR ingress
                                (push = a fold executed by someone else)

jbg.2's GET-only pruned walk over R2 is this same function with a
range-reading fetch driver and no push emitter.
"""


def sync(node, ws, url):
    """One dial converges both sides; returns (pulled, pushed). Carries ONE
    kernel.Scratchpad across consecutive differing ranges (S2 — closes the
    catchup re-verify tax). Replaces walk.walk."""
    raise NotImplementedError("poc-16-808.2")


def pull(node, ws, oid, raw):
    """A differing range's leaf pile, verbatim, into my own ingress."""
    raise NotImplementedError("poc-16-808.2")


def push(node, ws, peer, fids):
    """Close one range's push set and PUT it — the mirror of the pull
    (walk._push today, unchanged in spirit)."""
    raise NotImplementedError("poc-16-808.2")
