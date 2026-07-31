"""Replayable differential histories for the pure repository compiler."""

from dataclasses import dataclass, replace
import random

import facts
from facts import _policy

from core import indexes, merkle_map, snapshot
from core.crypto import h, load_sk
from core.kernel import drain
from core.repository_snapshot import (
    compile_snapshot,
    extend_snapshot,
    logical_rows,
)


FIXED_SEEDS = (0xF30001, 0xF30002, 0xF30007, 0xF3000D)


@dataclass(frozen=True, slots=True)
class CompilerCorpus:
    workspace: str
    anchor: object
    facts: dict
    groups: dict
    landmarks: dict


@dataclass(frozen=True, slots=True)
class Step:
    name: str
    fids: tuple


@dataclass(frozen=True, slots=True)
class Plan:
    seed: int
    steps: tuple

    def diagnostic(self, prefix):
        replay = "\n".join(
            f"  {ordinal + 1}. {step.name}: "
            f"{','.join(fid[:8] for fid in step.fids) or '<empty>'}"
            for ordinal, step in enumerate(prefix)
        )
        return (
            f"F3 compiler replay seed={self.seed:#x}\n"
            f"first failing prefix:\n{replay or '  <empty>'}"
        )


@dataclass(frozen=True, slots=True)
class Run:
    root: bytes
    roots: dict
    suppression: dict
    residents: frozenset


def build_corpus():
    """Build one kernel-validated family corpus without host or SQL state."""
    secret = load_sk(h(b"poc16-f3-compiler-founder"))
    public = secret.verify_key.encode().hex()
    anchor = facts.auth.workspace.workspace(
        secret, public, "compiler-fuzzer", 1)
    workspace = anchor.fid
    ordered, groups = [anchor], {}

    def signed(name, fact):
        signature = facts.auth.signature.signature(
            secret, public, fact, fact.ts)
        ordered.extend((signature, fact))
        groups[name] = (signature.fid, fact.fid)
        return fact

    targets = {
        name: signed(
            name,
            facts.content.message.message(
                workspace, public, "f3", name, timestamp, public),
        )
        for name, timestamp in (
            ("target-first", 10),
            ("target-later", 11),
            ("target-batch", 12),
            ("target-competing", 13),
        )
    }
    for ordinal in range(10):
        name = f"filler-{ordinal:02d}"
        signed(
            name,
            facts.content.message.message(
                workspace, public, "f3", name, 20 + ordinal, public),
        )
    file_root = h(b"poc16-f3-file-root")
    descriptor = signed(
        "multi-scope-file",
        facts.content.file.file(
            workspace, public, "f3", "multi-scope.bin",
            1, file_root, 1, 40, public),
    )
    chunk = signed(
        "multi-scope-chunk",
        facts.content.chunk.chunk(
            workspace, public, "f3", file_root, 0, 1,
            h(b"poc16-f3-chunk-object"), 41, descriptor.fid, public),
    )
    assert len(facts.fact_scopes(chunk)) == 2

    actions = {}
    for name, target, mode, timestamp in (
            ("action-after-target", "target-first", _policy.OWNER, 100),
            ("action-before-target", "target-later", _policy.ADMIN, 101),
            ("action-batch", "target-batch", _policy.OWNER, 102),
            ("competing-late", "target-competing", _policy.OWNER, 180),
            ("competing-early", "target-competing", _policy.ADMIN, 170)):
        actions[name] = signed(
            name,
            facts.content.delete.delete(
                workspace, public, targets[target].key,
                mode, timestamp, public),
        )
    removals = {
        name: signed(
            name,
            facts.auth.removal.removal(
                workspace, public, public, timestamp),
        )
        for name, timestamp in (
            ("removal-late", 210),
            ("removal-early", 200),
        )
    }
    judgment = drain(ordered, workspace)
    assert judgment.ok and len(judgment.valids) == len(ordered)
    validated = {valid.fact.fid: valid.fact for valid in judgment.valids}
    assert set(validated) == {fact.fid for fact in ordered}

    def only_scope(fact):
        scopes = facts.fact_scopes(fact)
        assert len(scopes) == 1
        return next(iter(scopes))

    return CompilerCorpus(
        workspace,
        anchor,
        validated,
        groups,
        {
            "target_first_sid": only_scope(targets["target-first"]),
            "target_later_sid": only_scope(targets["target-later"]),
            "competing_sid": only_scope(targets["target-competing"]),
            "action_after": actions["action-after-target"].fid,
            "action_before": actions["action-before-target"].fid,
            "competing_late": actions["competing-late"].fid,
            "competing_early": actions["competing-early"].fid,
            "member_sid": facts.principal_sid("member", public),
            "removal_late": removals["removal-late"].fid,
            "removal_early": removals["removal-early"].fid,
        },
    )


def build_plan(corpus, seed):
    """Generate one bounded stateful history; the seed fully identifies it."""
    if type(seed) is not int:
        raise ValueError("F3 seed")
    group = corpus.groups
    target_first = group["target-first"]
    steps = [
        Step("single-target-before-action", (target_first[-1],)),
        Step("single-target-evidence", (target_first[0],)),
        Step("action-after-target", group["action-after-target"]),
        Step("action-before-target", group["action-before-target"]),
        Step("target-after-action", group["target-later"]),
        Step(
            "target-action-batch",
            group["target-batch"] + group["action-batch"],
        ),
        Step("multi-scope-file", group["multi-scope-file"]),
        Step("multi-scope-chunk", group["multi-scope-chunk"]),
        Step("competing-target", group["target-competing"]),
        Step("competing-action-late", group["competing-late"]),
        Step("competing-action-earlier", group["competing-early"]),
        Step("removal-late", group["removal-late"]),
        Step(
            "duplicate-existing",
            (target_first[-1], group["action-after-target"][-1]),
        ),
        Step("empty-noop", ()),
        Step("removal-earlier", group["removal-early"]),
    ]

    rng = random.Random(seed)
    remaining = [group[f"filler-{ordinal:02d}"] for ordinal in range(10)]
    rng.shuffle(remaining)
    seen = [fid for step in steps for fid in step.fids]
    batch = 0
    while remaining:
        width = rng.randint(1, min(3, len(remaining)))
        selected, remaining = remaining[:width], remaining[width:]
        fids = tuple(fid for pair in selected for fid in pair)
        if rng.randrange(2):
            fids += (rng.choice(seen),)
        steps.append(Step(f"seeded-batch-{batch}", fids))
        seen.extend(fids)
        if rng.randrange(3) == 0:
            duplicate = tuple(rng.sample(seen, rng.randint(1, 3)))
            steps.append(Step(f"seeded-duplicate-{batch}", duplicate))
        batch += 1
    return Plan(seed, tuple(steps))


def _retain(objects, outbox):
    for oid, raw in outbox:
        assert h(raw) == oid
        incumbent = objects.setdefault(oid, raw)
        assert incumbent == raw


def _root_rows(root, objects):
    decoded = snapshot.decode_root(root)
    rows = {}
    for name, descriptor in decoded.maps.items():
        if not descriptor["root"]:
            rows[name] = {}
            continue
        reader = merkle_map.Reader(
            descriptor["root"],
            decoded.layout_seed,
            objects.get,
            expected_count=descriptor["count"],
            expected_depth=descriptor["depth"],
        )
        rows[name] = dict(reader.items())
    return decoded, rows


def run_plan(corpus, plan, incremental=extend_snapshot):
    """Compare full and path-copy compilation after every state transition."""
    resident = {corpus.workspace: corpus.anchor}
    current = compile_snapshot(corpus.workspace, resident)
    objects, roots, suppression, prefix = {}, {}, {}, []
    _retain(objects, current.outbox)

    for step in plan.steps:
        prefix.append(step)
        incoming = {fid: corpus.facts[fid] for fid in step.fids}
        previous_root = current.root
        try:
            candidate = incremental(
                corpus.workspace, current.root, incoming, objects.get)
            expected_facts = {**resident, **incoming}
            full = compile_snapshot(corpus.workspace, expected_facts)
            expected_rows, expected_oids = logical_rows(
                corpus.workspace, expected_facts)
            assert candidate.root == full.root
            assert snapshot.decode_root(candidate.root).maps \
                == snapshot.decode_root(full.root).maps
            assert candidate.fact_oids == {
                fid: expected_oids[fid] for fid in incoming}

            full_outbox = dict(full.outbox)
            assert len(full_outbox) == len(full.outbox)
            candidate_outbox = dict(candidate.outbox)
            assert len(candidate_outbox) == len(candidate.outbox)
            # Incremental publication may establish unreachable intermediate
            # path roots. They are harmless immutable garbage; only the final
            # root must match the history-independent full compiler.
            assert all(h(raw) == oid
                       for oid, raw in candidate_outbox.items())
            _retain(objects, candidate.outbox)
            assert all(
                objects.get(oid) == raw for oid, raw in full.outbox)

            decoded, actual_rows = _root_rows(candidate.root, objects)
            assert set(decoded.maps) == set(snapshot.MAP_NAMES)
            assert actual_rows == expected_rows
            for sid, slot in actual_rows[indexes.SUPP].items():
                if slot["state"] == "active":
                    action = expected_facts[slot["action"]]
                    assert sid in facts.action_sids(action)
                    assert actual_rows[indexes.FACT].get(
                        indexes.fact_key(action.fid)
                    ) == expected_oids[action.fid]
            assert not any(
                key.startswith("action:")
                for key in actual_rows[indexes.FACT]
            )

            if not set(incoming) - set(resident):
                assert candidate.root == previous_root
                assert candidate.outbox == ()
            resident, current = expected_facts, candidate
            roots[step.name] = candidate.root
            suppression[step.name] = dict(expected_rows[indexes.SUPP])
        except Exception as error:
            add_note = getattr(error, "add_note", None)
            if callable(add_note):
                add_note(plan.diagnostic(prefix))
            raise

    return Run(
        current.root,
        roots,
        suppression,
        frozenset(resident),
    )


def shrink_plan(plan, fails):
    """Greedily remove steps and batch members to a one-minimal replay."""
    current = plan
    while True:
        for ordinal in range(len(current.steps)):
            candidate = replace(
                current,
                steps=current.steps[:ordinal] + current.steps[ordinal + 1:],
            )
            if fails(candidate):
                current = candidate
                break
        else:
            for ordinal, step in enumerate(current.steps):
                for at in range(len(step.fids)):
                    fids = step.fids[:at] + step.fids[at + 1:]
                    candidate = replace(
                        current,
                        steps=current.steps[:ordinal]
                        + (replace(step, fids=fids),)
                        + current.steps[ordinal + 1:],
                    )
                    if fails(candidate):
                        current = candidate
                        break
                else:
                    continue
                break
            else:
                return current
