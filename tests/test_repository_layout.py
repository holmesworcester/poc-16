"""Small structural ratchets; runtime claims belong in behavioral tests."""
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {"AGENTS.md", "DESIGN.md", "README.md"}


def tracked(*patterns):
    result = subprocess.run(
        ["git", "ls-files", *patterns],
        cwd=ROOT, check=True, capture_output=True, text=True)
    out = set()
    for line in result.stdout.splitlines():
        path = Path(line)
        if line.strip() and not path.parts[0].startswith(".") \
                and (ROOT / path).exists():
            out.add(path)
    return out


def test_only_three_markdown_authorities_remain():
    assert tracked("*.md", "**/*.md") == {
        Path(name) for name in ROOT_DOCS}
    assert not (ROOT / "docs").exists()


def test_root_document_links_resolve_locally():
    link = re.compile(r"\[[^]]+]\(([^)]+)\)")
    for name in ROOT_DOCS:
        source = ROOT / name
        for target in link.findall(source.read_text()):
            if "://" in target or target.startswith("#"):
                continue
            path = target.split("#", 1)[0]
            assert (source.parent / path).exists(), (
                f"{name} links missing {target}")


def test_sources_do_not_point_at_retired_doc_ledgers():
    retired = re.compile(
        r"docs/|TODO\.md|REMOVALS\.md|SIMPLIFY\.md|CUTOVER\.md|"
        r"KEY_HIERARCHY_ADR|PUNCTURABLE_ENCRYPTION_SOURCE")
    offenders = []
    for path in tracked("*.py", "**/*.py", "*.md"):
        if path == Path("tests/test_repository_layout.py"):
            continue
        text = (ROOT / path).read_text()
        if retired.search(text):
            offenders.append(str(path))
    assert offenders == []


def test_deleted_dual_paths_do_not_return():
    assert not (ROOT / "core" / "removals.py").exists()
    assert not (ROOT / "tests" / "test_removals.py").exists()
    assert not (ROOT / "tests" / "test_key_hierarchy_adr.py").exists()
    assert not (
        ROOT / "tests" / "test_puncturable_encryption_source.py").exists()
    for path in (
            "facts/auth/legacy_genesis.py",
            "facts/auth/legacy_invite.py",
            "facts/auth/legacy_join.py",
            "facts/auth/legacy_signature.py",
            "facts/content/legacy_file.py",
            "tests/test_auth_upgrade.py"):
        assert not (ROOT / path).exists()
