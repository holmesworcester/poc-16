"""Source and routing contract for the POC-16 fact-family boundary."""
import ast
import pathlib

import facts

from core import fact as core_fact
from core.fact import Fact
from core.kernel import MemoryContext

ROOT = pathlib.Path(__file__).resolve().parent.parent
FACTS = ROOT / "facts"
SECTIONS = ["# SHAPE", "# NEEDS", "# VALIDATE", "# MODE",
            "# COMMANDS", "# QUERIES"]


def family_files():
    return sorted(path for path in FACTS.rglob("*.py")
                  if path.name != "__init__.py" and not path.name.startswith("_"))


def test_every_family_has_the_new_contract_in_order():
    """Shape, judgment, command, and query authority are visibly ordered."""
    paths = family_files()
    assert paths
    for path in paths:
        source = path.read_text()
        relative = path.relative_to(FACTS).with_suffix("")
        assert source.startswith(f'"""facts/{relative.as_posix()}.py — '), path
        positions = [source.find(section) for section in SECTIONS]
        assert min(positions) >= 0 and positions == sorted(positions), path

        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body
                     if isinstance(node, ast.FunctionDef)}
        for name, arity in {"needs": 1, "validate": 2}.items():
            assert name in functions, (path, name)
            assert len(functions[name].args.args) == arity, (path, name)

        assignments = {target.id: node.value
                       for node in tree.body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
        assert isinstance(assignments.get("TAG"), ast.Constant), path
        assert isinstance(assignments.get("DURABLE"), ast.Constant), path
        assert isinstance(assignments["DURABLE"].value, bool), path
        assert "TABLES" not in assignments, path
        assert "materialize" not in functions, path
        assert "received" not in functions, path

        validation_names = {node.id for node in ast.walk(functions["validate"])
                            if isinstance(node, ast.Name)}
        assert "globals_" not in validation_names, path
        for handler in (
                node for node in ast.walk(functions["validate"])
                if isinstance(node, ast.ExceptHandler)):
            caught = {
                node.id for node in ast.walk(handler.type)
                if isinstance(node, ast.Name)
            } if handler.type is not None else {"BaseException"}
            assert caught.isdisjoint({"Exception", "BaseException"}), path
        for returned in (node for node in ast.walk(functions["validate"])
                         if isinstance(node, ast.Return)):
            assert not isinstance(returned.value, (ast.Tuple, ast.Dict, ast.Set)), path


def test_family_modules_do_not_own_persistence_tables():
    """Families assemble queries; storage shape stays family-neutral."""
    for path in family_files():
        tree = ast.parse(path.read_text())
        assignments = {
            target.id
            for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name)
        }
        functions = {
            node.name for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }
        assert "TABLES" not in assignments, path
        assert {"materialize", "received", "clear"}.isdisjoint(functions), path


def test_router_covers_each_family_once():
    paths = family_files()
    assert len(facts.MODULES) == len(paths) == len(facts.FAMILIES)
    assert set(facts.FAMILIES) == {module.TAG for module in facts.MODULES}
    assert all(
        facts.family_for(module.TAG) is module
        and module.POLICY is not None
        for module in facts.MODULES
    )
    assert all(
        command.__module__ == module.__name__
        for module in facts.MODULES
        for command in getattr(module, "CLI", {}).values()
    )


def test_every_family_validator_is_total_for_a_malformed_body():
    workspace = "0" * 64
    for module in facts.MODULES:
        malformed = Fact(
            module.TAG,
            1,
            [],
            {},
            None if getattr(module, "GENESIS", False) else workspace,
        )
        anchor = malformed.fid \
            if getattr(module, "GENESIS", False) else workspace
        assert module.validate(malformed, MemoryContext(anchor)) is False


def test_core_fact_module_has_no_family_authors():
    """The canonical value cannot silently grow auth/content policy again."""
    retired = {"workspace", "signature", "user_invite", "user", "sig_for", "msg",
               "file_fact", "evict", "req"}
    assert retired.isdisjoint(vars(core_fact))


def test_core_judge_and_engine_do_not_name_family_policy():
    for name in (
            "fact.py", "fact_index.py", "indexes.py", "kernel.py",
            "repository_applier.py", "repository_reader.py",
            "repository_snapshot.py", "snapshot.py", "validated_set.py",
            "worker.py"):
        source = (ROOT / "core" / name).read_text()
        for vocabulary in (
                '"admin"', '"device_key"', '"member"', '"removed"',
                '"request"'):
            assert vocabulary not in source, (name, vocabulary)


def test_cli_and_daemon_have_no_application_command_inventory():
    for name in ("cli.py", "daemon.py"):
        source = (ROOT / "full_peer" / name).read_text()
        assert all(path not in source for path in facts.COMMANDS), name


def test_only_ephemeral_families_have_worker_grants():
    grants = [
        module for module in facts.MODULES if hasattr(module, "authorize")
    ]
    assert grants
    assert all(module.DURABLE is False for module in grants)
    assert all(module.authorize.__code__.co_argcount == 4 for module in grants)
