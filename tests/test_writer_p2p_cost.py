from bench.writer_p2p_cost import measure_two_party_sync


class _Sql:
    def __init__(self, node):
        self.node = node

    def fact_ids(self):
        self.node.events.append(f"{self.node.name}:facts")
        return set(self.node.facts)


class _Node:
    def __init__(self, name, facts, events):
        self.name = name
        self.facts = set(facts)
        self.events = events

    def sql(self, workspace):
        assert workspace == "workspace"
        return _Sql(self)


def test_two_party_sync_timer_excludes_snapshots_and_result_counting():
    events = []
    local = _Node("local", {"shared", "local"}, events)
    remote = _Node("remote", {"shared", "remote"}, events)
    clock_values = iter((10.0, 12.5))

    def clock():
        events.append("clock")
        return next(clock_values)

    def sync_turn(node, workspace, url):
        events.append("sync")
        assert (node, workspace, url) == (
            local, "workspace", "http://remote")
        local.facts.add("remote")
        remote.facts.add("local")
        return 1, 1

    result = measure_two_party_sync(
        local,
        remote,
        "workspace",
        "http://remote",
        sync_turn=sync_turn,
        clock=clock,
    )

    assert events == [
        "local:facts",
        "remote:facts",
        "clock",
        "sync",
        "clock",
        "local:facts",
        "remote:facts",
    ]
    assert result.local_facts == result.remote_facts == 1
    assert result.facts == 2
    assert result.elapsed_seconds == 2.5
    assert result.facts_per_second == 0.8
    assert (result.pulled_changed, result.pushed_piles) == (1, 1)
