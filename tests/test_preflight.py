from pathlib import Path
from types import SimpleNamespace

from tools import preflight


EXPECTED_CHECKS = (
    ("Python syntax", (
        "python3", "-m", "compileall", "-q",
        "core", "full_peer", "facts", "infrastructure", "notifications",
        "adapters", "deploy", "bench", "tests", "tools",
    )),
    ("Repository authority layout", (
        "python3", "-m", "pytest", "-q", "tests/test_repository_layout.py",
    )),
    ("Worktree whitespace", ("git", "diff", "--check")),
    ("Staged whitespace", ("git", "diff", "--cached", "--check")),
    ("No unstaged beads export", (
        "git", "diff", "--quiet", "--", ".beads/issues.jsonl",
    )),
    ("No staged beads export", (
        "git", "diff", "--cached", "--quiet", "--", ".beads/issues.jsonl",
    )),
    ("Bead schema", ("bd", "lint")),
    ("Bead dependency graph", ("bd", "dep", "cycles")),
    ("Full Python suite", ("python3", "-m", "pytest", "-q")),
)


def test_preflight_manifest_is_python_and_matches_the_documented_gate():
    assert preflight.CHECKS == EXPECTED_CHECKS
    assert not {"go", "gofmt", "golangci-lint", "nix"} & {
        command[0] for _, command in preflight.CHECKS}
    commands = tuple(" ".join(command) for _, command in preflight.CHECKS)
    forbidden = ("go.sum", "default.nix", "cmd/bd/version.go")
    assert not any(token in command for command in commands
                   for token in forbidden)

    for document in ("README.md", "AGENTS.md"):
        text = (Path(preflight.__file__).parents[1] / document).read_text()
        assert "python3 tools/preflight.py" in text


def test_preflight_stops_before_later_gates_after_a_failure(monkeypatch):
    calls = []

    def fake_run(command, *, check):
        calls.append(command)
        return SimpleNamespace(returncode=7 if len(calls) == 2 else 0)

    monkeypatch.setattr(preflight.subprocess, "run", fake_run)
    assert preflight.run(EXPECTED_CHECKS[:3]) == 7
    assert calls == [
        EXPECTED_CHECKS[0][1],
        EXPECTED_CHECKS[1][1],
    ]
