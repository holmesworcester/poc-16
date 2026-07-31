#!/usr/bin/env python3
"""Run POC-16's repository gates without beads' Go-specific defaults."""
from __future__ import annotations

import shlex
import subprocess
import sys


CHECKS = (
    ("Python syntax", (
        "python3", "-m", "compileall", "-q",
        "core", "full_peer", "facts", "adapters", "deploy", "bench", "tests",
        "tools",
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


def run(checks=CHECKS):
    """Run checks in order and stop at the first failure."""
    for number, (name, command) in enumerate(checks, 1):
        print(f"[{number}/{len(checks)}] {name}: {shlex.join(command)}",
              flush=True)
        try:
            result = subprocess.run(command, check=False)
        except OSError as error:
            print(f"{name} could not start: {error}", file=sys.stderr)
            return 1
        if result.returncode:
            print(f"{name} failed with exit {result.returncode}",
                  file=sys.stderr)
            return result.returncode
    print(f"All {len(checks)} preflight checks passed.")
    return 0


def main(argv):
    if argv == ["--list"]:
        for name, command in CHECKS:
            print(f"{name}: {shlex.join(command)}")
        return 0
    if argv:
        print("usage: python3 tools/preflight.py [--list]", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
