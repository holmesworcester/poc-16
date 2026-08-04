"""Peer session scheduling and small-mesh convergence."""
import itertools
import threading
import time

from .endpoint import PeerEndpoint
from .walk import sync


class SessionCoordinator:
    """Collapse overlapping opposite dials while preserving solo initiation."""

    def __init__(self, collision_window=0.02):
        self.collision_window = collision_window
        self._condition = threading.Condition()
        self._sessions = {}

    def dial(self, initiator, responder):
        if not isinstance(initiator, PeerEndpoint) \
                or not isinstance(responder, PeerEndpoint) \
                or initiator is responder:
            raise ValueError("peer dial")
        pair = tuple(sorted((initiator.endpoint_id, responder.endpoint_id)))
        me = initiator.endpoint_id
        with self._condition:
            entry = self._sessions.get(pair)
            if entry is None:
                entry = {
                    "offers": {me: (initiator, responder)},
                    "deadline": time.monotonic() + self.collision_window,
                    "runner": None,
                    "done": False,
                    "result": None,
                    "error": None,
                    "remaining": 1,
                }
                self._sessions[pair] = entry
                while len(entry["offers"]) == 1 and not entry["done"]:
                    remaining = entry["deadline"] - time.monotonic()
                    if remaining <= 0:
                        entry["runner"] = me
                        break
                    self._condition.wait(remaining)
            elif not entry["done"] and entry["runner"] is None:
                entry["offers"][me] = (initiator, responder)
                entry["remaining"] = len(entry["offers"])
                entry["runner"] = min(entry["offers"])
                self._condition.notify_all()
            else:
                # The prior turn is already sealed; this is a later dial.
                while not entry["done"]:
                    self._condition.wait()
                return self.dial(initiator, responder)
            runner = entry["runner"]
            if runner is None:
                runner = min(entry["offers"])
                entry["runner"] = runner
            selected = entry["offers"].get(runner)

        if me == runner:
            try:
                result = sync(*selected)
                error = None
            except Exception as caught:  # deliver the same failure to both dials
                result, error = None, caught
            with self._condition:
                entry["result"], entry["error"], entry["done"] = result, error, True
                self._condition.notify_all()
        else:
            with self._condition:
                while not entry["done"]:
                    self._condition.wait()

        with self._condition:
            result, error = entry["result"], entry["error"]
            entry["remaining"] -= 1
            if entry["remaining"] == 0:
                self._sessions.pop(pair, None)
        if error is not None:
            raise error
        return {**result, "driver": runner, "collapsed": len(entry["offers"]) > 1}


def mesh_sync(peers):
    """One deterministic pair sweep; three peers converge within one sweep."""
    peers = tuple(peers)
    if len(peers) < 2 or any(not isinstance(peer, PeerEndpoint) for peer in peers):
        raise ValueError("peer mesh")
    reports = []
    for left, right in itertools.combinations(peers, 2):
        reports.append(sync(left, right))
    return tuple(reports)
