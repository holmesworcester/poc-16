"""Small structural ratchets; runtime claims belong in behavioral tests."""
import ast
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


def test_suppression_state_uses_the_explicit_module_name():
    assert (ROOT / "core" / "suppression_state.py").is_file()
    assert (ROOT / "tests" / "test_suppression_state.py").is_file()
    assert not (ROOT / "core" / "actions.py").exists()
    assert not (ROOT / "tests" / "test_actions.py").exists()


def test_durable_fact_admission_has_one_kernel_mediated_entrance():
    """Raw facts may be loaded only into the named in-memory scratch type."""
    node_tree = ast.parse((ROOT / "core" / "node.py").read_text())
    node = next(
        item for item in node_tree.body
        if isinstance(item, ast.ClassDef) and item.name == "Node")
    methods = {
        item.name: item
        for item in node.body if isinstance(item, ast.FunctionDef)
    }
    assert "merge" not in methods
    assert "admit" in methods
    calls = [
        call
        for call in ast.walk(methods["admit"])
        if isinstance(call, ast.Call)
    ]
    assert any(
        isinstance(call.func, ast.Name) and call.func.id == "drain"
        for call in calls)
    assert sum(
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "_admit_valid"
        for call in calls) == 1

    private_calls = []
    for path in tracked(
            "core/*.py", "facts/**/*.py", "adapters/**/*.py",
            "deploy/**/*.py", "bench/*.py"):
        tree = ast.parse((ROOT / path).read_text())

        class Calls(ast.NodeVisitor):
            def __init__(self):
                self.functions = []

            def visit_ClassDef(self, item):
                self.functions.append(item.name)
                self.generic_visit(item)
                self.functions.pop()

            def visit_FunctionDef(self, item):
                self.functions.append(item.name)
                self.generic_visit(item)
                self.functions.pop()

            def visit_Call(self, item):
                if isinstance(item.func, ast.Attribute) \
                        and item.func.attr == "_admit_valid":
                    private_calls.append(
                        (str(path), tuple(self.functions)))
                self.generic_visit(item)

        Calls().visit(tree)
    assert private_calls == [("core/node.py", ("Node", "admit"))]

    catalog_source = (ROOT / "core" / "catalog.py").read_text()
    assert "class ScratchCatalog" in catalog_source
    assert "def stage(" not in catalog_source
