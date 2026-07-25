"""Repository boundaries are executable, not naming conventions."""
import ast
import json
import re
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ROOT_DOCS = {"AGENTS.md", "DESIGN.md", "README.md"}
LINK = re.compile(r"\[[^]]*]\(([^)]+)\)")
OLD_REFERENCE = re.compile(
    r"(?<!docs/)(?:SIMPLIFY|DELETION_CLOSURE|MODEL|WORKSPACES|"
    r"MULTILEVEL_PILE|CHAINED_AUTH_PLAN|IMPLEMENTATION|TREAP_PROTOTYPE)\.md"
    r"|tinyp2p(?:/|\.)"
    r"|(?<![A-Za-z0-9_./-])(?:tree|layout|hoist|shape|sync|walk|kernel|node|"
    r"mint|pump|fact|store|close|cmds|cli|daemon|keychain|suppression|treap)"
    r"\.py"
)


def test_only_entrypoint_docs_live_at_root():
    assert {path.name for path in ROOT.glob("*.md")} == ROOT_DOCS
    assert not (ROOT / "tinyp2p").exists()
    assert (ROOT / "core" / "__init__.py").is_file()
    assert (ROOT / "facts" / "__init__.py").is_file()


def test_python_imports_do_not_restore_the_old_namespace():
    for directory in ("core", "facts", "tests", "bench"):
        for path in (ROOT / directory).rglob("*.py"):
            tree = ast.parse(path.read_text())
            package_depth = len(path.relative_to(ROOT).parts) - 1
            assert all(
                node.level <= package_depth
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            ), path
            names = [
                node.module for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            ] + [
                alias.name for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names
            ]
            assert not any(
                name == "tinyp2p" or name.startswith("tinyp2p.")
                for name in names if name
            ), path


def test_local_document_links_resolve():
    documents = list(ROOT.glob("*.md")) + list((ROOT / "docs").glob("*.md"))
    for document in documents:
        for target in LINK.findall(document.read_text()):
            path = urllib.parse.unquote(target.split("#", 1)[0])
            if path and "://" not in path and not path.startswith("mailto:"):
                assert (document.parent / path).exists(), (document, target)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def test_exported_beads_use_current_paths():
    for line in (ROOT / ".beads" / "issues.jsonl").read_text().splitlines():
        issue = json.loads(line)
        if issue["id"] == "poc-16-niz":  # the migration specification
            continue
        text = "\n".join(strings(issue))
        assert not OLD_REFERENCE.search(text), issue["id"]
