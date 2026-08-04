from bench.writer_p2p_cost import measure_two_party_sync


class _Node:
    def __init__(self, name, facts, events):
        self.name = name
        self.facts = set(facts)
        self.events = events

    def snapshot(self, workspace):
        assert workspace == "workspace"
        self.events.append(f"{self.name}:snapshot")
        return set(self.facts), len(self.facts)


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
        snapshot=lambda node, workspace: node.snapshot(workspace),
    )

    assert events == [
        "local:snapshot",
        "remote:snapshot",
        "clock",
        "sync",
        "clock",
        "local:snapshot",
        "remote:snapshot",
    ]
    assert result.local_facts == result.remote_facts == 1
    assert result.facts == 2
    assert result.pulled_piles == result.pushed_piles == 1
    assert result.elapsed_seconds == 2.5
    assert result.facts_per_second == 0.8
    assert result.pull_changed == 1
