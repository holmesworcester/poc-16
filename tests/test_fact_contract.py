"""Source and routing contract for the POC-16 fact-family boundary."""
import ast
import pathlib
import sqlite3

import facts

from core import fact as core_fact

ROOT = pathlib.Path(__file__).resolve().parent.parent
FACTS = ROOT / "facts"
SECTIONS = ["# SHAPE", "# NEEDS", "# VALIDATE", "# MODE",
            "# MATERIALIZE", "# COMMANDS", "# QUERIES"]


def family_files():
    return sorted(path for path in FACTS.rglob("*.py")
                  if path.name != "__init__.py" and not path.name.startswith("_"))


def test_every_family_has_the_new_contract_in_order():
    """Validation, mode effects, and projection are visibly separate seams."""
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
        for name, arity in {"needs": 1, "validate": 2, "global_rows": 1,
                            "blob_refs": 1, "materialize": 3}.items():
            assert name in functions, (path, name)
            assert len(functions[name].args.args) == arity, (path, name)

        assignments = {target.id: node.value
                       for node in tree.body if isinstance(node, ast.Assign)
                       for target in node.targets if isinstance(target, ast.Name)}
        assert isinstance(assignments.get("TAG"), ast.Constant), path
        assert isinstance(assignments.get("DURABLE"), ast.Constant), path
        assert isinstance(assignments["DURABLE"].value, bool), path
        assert isinstance(assignments.get("TABLES"), ast.Tuple), path
        assert all(isinstance(item, ast.Constant)
                   and isinstance(item.value, str)
                   for item in assignments["TABLES"].elts), path

        validation_names = {node.id for node in ast.walk(functions["validate"])
                            if isinstance(node, ast.Name)}
        assert "globals_" not in validation_names, path
        for returned in (node for node in ast.walk(functions["validate"])
                         if isinstance(node, ast.Return)):
            assert not isinstance(returned.value, (ast.Tuple, ast.Dict, ast.Set)), path


def test_projector_tables_are_source_keyed_and_handlers_are_insert_only():
    db = sqlite3.connect(":memory:")
    db.executescript(facts.APP_SCHEMA)
    tables = {"projected"} | {
        table for module in facts.MODULES for table in module.TABLES
    }
    for table in tables:
        columns = {
            name: primary
            for _, name, _, _, _, primary in db.execute(
                f"PRAGMA table_info({table})")
        }
        assert columns.get("src", 0) > 0, table

    for path in family_files():
        tree = ast.parse(path.read_text())
        materialize = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "materialize")
        sql = " ".join(
            node.value.upper() for node in ast.walk(materialize)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str))
        assert "UPDATE " not in sql and "DELETE " not in sql, path


def test_router_covers_each_family_once():
    paths = family_files()
    assert len(facts.MODULES) == len(paths) == len(facts.ROUTES)
    assert set(facts.ROUTES) == {module.TAG for module in facts.MODULES}
    assert all(facts.handler_for(module.TAG) is module for module in facts.MODULES)


def test_core_fact_module_has_no_family_authors():
    """The canonical value cannot silently grow auth/content policy again."""
    retired = {"workspace", "signature", "user_invite", "user", "sig_for", "msg",
               "file_fact", "evict", "req"}
    assert retired.isdisjoint(vars(core_fact))


def test_core_judge_and_engine_do_not_name_family_policy():
    for name in ("fact.py", "kernel.py", "node.py", "manifest.py"):
        source = (ROOT / "core" / name).read_text()
        assert '"removal"' not in source, name
        assert '"workspace"' not in source, name
        assert '"member"' not in source, name


def test_only_ephemeral_families_have_evaluate_hooks():
    evaluators = [module for module in facts.MODULES if hasattr(module, "evaluate")]
    assert evaluators
    assert all(module.DURABLE is False for module in evaluators)
    assert all(module.evaluate.__code__.co_argcount == 3
               for module in evaluators)
