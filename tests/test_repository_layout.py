"""Structural authority ratchets complement the behavioral role tests."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {"AGENTS.md", "DESIGN.md", "README.md"}
SOURCE_ROOTS = ("core", "facts", "adapters", "deploy")
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".wrangler",
    "build",
    "generated",
    "node_modules",
}


def source_paths():
    """Discover the working filesystem, including untracked production code."""
    paths = []
    for root_name in SOURCE_ROOTS:
        for path in (ROOT / root_name).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if EXCLUDED_PARTS.intersection(relative.parts) \
                    or path.name.startswith("test_") \
                    or "tests" in relative.parts:
                continue
            paths.append(relative)
    return tuple(sorted(paths))


def parsed(path):
    return ast.parse((ROOT / path).read_text(), filename=str(path))


def class_definitions(name):
    return [
        path
        for path in source_paths()
        for item in ast.walk(parsed(path))
        if isinstance(item, ast.ClassDef) and item.name == name
    ]


def calls_named(name):
    return [
        (path, call)
        for path in source_paths()
        for call in ast.walk(parsed(path))
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == name
    ]


def test_only_three_markdown_authorities_remain():
    found = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*.md")
        if not any(
            part.startswith(".") or part in EXCLUDED_PARTS
            for part in path.relative_to(ROOT).parts)
    }
    assert found == ROOT_DOCS
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


def test_retired_authority_implementations_cannot_return():
    for relative in (
            "core/admission.py",
            "core/cmds.py",
            "core/legacy_v7.py",
            "core/mint.py",
            "core/publication.py",
            "core/runtime.py",
            "core/removals.py",
            "deploy/cloudflare_upload/worker/publisher_stub.py"):
        assert not (ROOT / relative).exists()
    for name in (
            "AdmissionMembrane",
            "Publisher",
            "WorkspaceRuntime"):
        assert class_definitions(name) == []
    assert class_definitions("PileSender") == [Path("core/pile_sender.py")]
    assert class_definitions("RepositoryApplier") == [
        Path("core/repository_applier.py")]
    assert class_definitions("RepositoryReader") == [
        Path("core/repository_reader.py")]


def test_core_dispatches_through_facts_without_importing_family_modules():
    """Core may call the checked router, but family modules stay authoritative."""
    offenders = []
    for path in source_paths():
        if path.parts[0] != "core":
            continue
        for item in ast.walk(parsed(path)):
            if isinstance(item, ast.ImportFrom):
                names = (item.module or "",)
            elif isinstance(item, ast.Import):
                names = tuple(alias.name for alias in item.names)
            else:
                continue
            for name in names:
                if name == "facts.auth" or name.startswith("facts.auth.") \
                        or name == "facts.content" \
                        or name.startswith("facts.content."):
                    offenders.append((path.as_posix(), name))
    assert offenders == []


def test_one_semantic_root_cas_and_one_root_compiler():
    semantic = []
    for path, call in calls_named("cas"):
        if call.args and isinstance(call.args[0], ast.Constant) \
                and call.args[0].value == "root":
            semantic.append(path)
    assert semantic == [Path("core/repository_applier.py")]

    encode_root = []
    for path in source_paths():
        if path == Path("core/snapshot.py"):
            continue
        for call in ast.walk(parsed(path)):
            if isinstance(call, ast.Call) \
                    and isinstance(call.func, ast.Attribute) \
                    and call.func.attr == "encode_root":
                encode_root.append(path)
    assert encode_root == [Path("core/repository_snapshot.py")]


def test_applier_owns_object_establishment_generations_and_retirement():
    for function, expected in (
            ("ensure_object_async", {"core/repository_applier.py"}),
            ("pile_source", {"core/repository_applier.py"}),
            ("retire_exact_async", {"core/repository_applier.py"})):
        callers = {
            path.as_posix()
            for path in source_paths()
            if path != Path("core/object_store.py")
            and path != Path("core/ingress.py")
            for call in ast.walk(parsed(path))
            if isinstance(call, ast.Call)
            and (
                isinstance(call.func, ast.Name)
                and call.func.id == function
                or isinstance(call.func, ast.Attribute)
                and call.func.attr == function)
        }
        assert callers == expected


def test_pile_sender_is_the_only_production_encoder():
    callers = set()
    for path in source_paths():
        if path == Path("core/close.py"):
            continue
        for call in ast.walk(parsed(path)):
            if isinstance(call, ast.Call) and (
                    isinstance(call.func, ast.Name)
                    and call.func.id == "encode_pile"
                    or isinstance(call.func, ast.Attribute)
                    and call.func.attr == "encode_pile"):
                callers.add(path.as_posix())
    # decode_pile owns canonical-wire validation, so no receiver re-encodes.
    assert callers == {"core/pile_sender.py"}


def test_ordinary_pile_surfaces_have_no_embedded_object_channel():
    """Detached object ingress cannot grow back as optional pile plumbing."""
    surfaces = (
        (Path("core/close.py"), None, "encode_pile"),
        (Path("core/close.py"), None, "decode_pile"),
        (Path("core/pile_sender.py"), "PileSender", "pack"),
        (Path("core/pile_sender.py"), "PileSender", "pile"),
        (Path("core/pile_sender.py"), "PileSender", "send"),
        (Path("core/node.py"), "Node", "ingest_new"),
        (Path("facts/_commands.py"), None, "publish"),
        (Path("core/repository_applier.py"), "RepositoryApplier", "propose"),
    )
    for path, owner, name in surfaces:
        tree = parsed(path)
        scope = tree.body
        if owner is not None:
            scope = next(
                item.body for item in tree.body
                if isinstance(item, ast.ClassDef) and item.name == owner)
        definition = next(
            item for item in scope
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name)
        parameters = {
            argument.arg
            for argument in (
                *definition.args.posonlyargs,
                *definition.args.args,
                *definition.args.kwonlyargs,
            )
        }
        assert "blobs" not in parameters, (path, owner, name)


def test_pile_sender_owns_outbound_peer_delivery():
    for method in ("put_obj", "put_pile"):
        assert {
            path.as_posix()
            for path, _ in calls_named(method)
        } == {"core/pile_sender.py"}


def test_reader_is_side_effect_free_and_owns_subordinate_view_construction():
    reader = parsed(Path("core/repository_reader.py"))
    forbidden = {
        "apply",
        "cas",
        "delete",
        "drain",
        "list",
        "list_page",
        "put",
        "put_if_absent",
        "stage",
        "turn",
    }
    assert not [
        call.func.attr
        for call in ast.walk(reader)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in forbidden
    ]

    bypasses = []
    for path in source_paths():
        if path in {
                Path("core/repository_reader.py"),
                Path("core/candidate_archive.py")}:
            continue
        for call in ast.walk(parsed(path)):
            if not isinstance(call, ast.Call):
                continue
            direct_candidate = (
                isinstance(call.func, ast.Name)
                and call.func.id == "CandidateView")
            direct_worker = (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "WorkerView"
                and call.func.attr == "from_root")
            if direct_candidate or direct_worker:
                bypasses.append(path.as_posix())
    assert bypasses == []


def test_untrusted_read_boundaries_have_no_whole_get_fallback():
    boundaries = (
        (Path("deploy/gateway.py"), "AsyncFromSyncReader", "get_bounded"),
        (Path("deploy/gateway.py"), "Gateway", "_get"),
        (Path("deploy/upload_broker.py"), "UploadBroker", "_get"),
        (
            Path("core/repository_applier.py"),
            "RepositoryApplier",
            "_get_bounded",
        ),
    )
    for path, class_name, method_name in boundaries:
        owner = next(
            item for item in parsed(path).body
            if isinstance(item, ast.ClassDef) and item.name == class_name)
        method = next(
            item for item in owner.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == method_name)
        attributes = {
            call.func.attr
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
        }
        assert "get_bounded" in attributes
        assert "get" not in attributes

    for path, class_name in (
            (Path("deploy/gateway.py"), "AsyncFromSyncReader"),
            (Path("deploy/cloudflare_worker/runtime.py"), "ReadOnlyStore"),
            (
                Path("deploy/cloudflare_upload/reader.py"),
                "R2CanonicalReader",
            )):
        owner = next(
            item for item in parsed(path).body
            if isinstance(item, ast.ClassDef) and item.name == class_name)
        assert not [
            item for item in owner.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == "get"
        ]


def test_sync_file_and_status_boundaries_keep_explicit_io_budgets():
    remote_store = next(
        item for item in parsed(Path("core/store.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "RemoteStore")
    remote_bounded = next(
        item for item in remote_store.body
        if isinstance(item, ast.FunctionDef)
        and item.name == "get_bounded")
    assert {
        call.func.attr
        for call in ast.walk(remote_bounded)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
    } >= {"obj", "root"}

    sync_tree = parsed(Path("core/sync.py"))
    remote_fetch = next(
        item for item in ast.walk(sync_tree)
        if isinstance(item, ast.FunctionDef)
        and item.name == "fetch_remote")
    file_tree = parsed(Path("facts/content/file.py"))
    file_reads = [
        item for item in file_tree.body
        if isinstance(item, ast.FunctionDef)
        and item.name in {"_state", "_payloads"}
    ]
    node = next(
        item for item in parsed(Path("core/node.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "Node")
    failures = next(
        item for item in node.body
        if isinstance(item, ast.FunctionDef)
        and item.name == "ingress_failures")

    for method in (remote_fetch, *file_reads):
        attributes = {
            call.func.attr
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
        }
        assert "get_bounded" in attributes
        assert "get" not in attributes
    failure_attributes = {
        call.func.attr
        for call in ast.walk(failures)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
    }
    assert "list_page" in failure_attributes
    assert "list" not in failure_attributes


def test_http_and_worker_boundaries_never_whole_materialize_bodies():
    functions = (
        (Path("facts/auth/user.py"), "accept", "read_bounded", "read"),
        (Path("core/cli.py"), "ctl", "read_bounded", "read"),
        (Path("core/cli.py"), "main", "read_bounded", "read"),
        (
            Path("deploy/cloudflare_worker/runtime.py"),
            "_bounded_body",
            "getReader",
            "bytes",
        ),
        (
            Path("deploy/cloudflare_upload/worker/runtime.py"),
            "_bounded_body",
            "getReader",
            "bytes",
        ),
        (
            Path("deploy/cloudflare_upload/reader.py"),
            "_bounded_response",
            "getReader",
            "arrayBuffer",
        ),
    )
    for path, name, required, forbidden in functions:
        function = next(
            item for item in parsed(path).body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name)
        attributes = {
            call.func.attr
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
        }
        names = {
            call.func.id
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
        }
        assert required in attributes | names
        assert forbidden not in attributes


def test_provider_list_adapters_validate_native_page_shape_before_use():
    s3 = (ROOT / "adapters/s3/store.py").read_text()
    r2 = (ROOT / "adapters/r2/worker.py").read_text()

    assert 'len(contents) > args["MaxKeys"]' in s3
    assert "_page_objects(page.objects, limit)" in r2
    assert "for _ in range(limit + 1)" in r2
    assert "validate_key(logical)" in r2
    assert "not isinstance(key, str)" in r2


def test_repository_apply_and_mutations_require_exact_stored_source():
    owner = next(
        item for item in parsed(Path("core/repository_applier.py")).body
        if isinstance(item, ast.ClassDef)
        and item.name == "RepositoryApplier")
    methods = {
        item.name: item
        for item in owner.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name in {"apply", "commit", "reject"}
    }
    apply = methods["apply"]
    assert [arg.arg for arg in apply.args.args] == ["self", "source"]
    assert apply.args.vararg is None
    assert apply.args.kwarg is None
    assert [arg.arg for arg in apply.args.kwonlyargs] == ["retire"]

    for name, mutations in (
            ("commit", {"_establish_outbox", "cas"}),
            ("reject", {"_put_evidence", "retire_exact_async"})):
        method = methods[name]
        exact_reads = [
            call for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "_get_bounded"
            and len(call.args) == 3
            and isinstance(call.args[1], ast.Name)
            and call.args[1].id == "source"
            and isinstance(call.args[2], ast.Name)
            and call.args[2].id == "MAX_PILE_BYTES"
        ]
        guards = [
            compare for compare in ast.walk(method)
            if isinstance(compare, ast.Compare)
            and isinstance(compare.left, ast.Name)
            and compare.left.id == "incumbent"
            and len(compare.ops) == 1
            and isinstance(compare.ops[0], ast.NotEq)
            and len(compare.comparators) == 1
            and isinstance(compare.comparators[0], ast.Name)
            and compare.comparators[0].id == "raw"
        ]
        mutation_calls = [
            call for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in mutations
                or isinstance(call.func, ast.Name)
                and call.func.id in mutations
            )
        ]
        assert len(exact_reads) == len(guards) == 1
        assert mutation_calls
        assert exact_reads[0].lineno < guards[0].lineno \
            < min(call.lineno for call in mutation_calls)


def test_protocol_front_doors_route_semantic_reads_through_one_reader():
    boundaries = (
        (Path("core/daemon.py"), "Handler", "mint", {"reader", "mint"}),
        (Path("deploy/gateway.py"), "Gateway", "_mint", {"mint_awaited"}),
        (
            Path("deploy/upload_broker.py"),
            "UploadBroker",
            "_authorize",
            {"mint_awaited"},
        ),
    )
    forbidden_effects = {
        "apply",
        "cas",
        "delete",
        "drain",
        "list",
        "list_page",
        "put",
        "put_if_absent",
        "stage",
        "turn",
    }
    bypasses = []
    for path, class_name, method_name, required in boundaries:
        tree = parsed(path)
        owner = next(
            item for item in tree.body
            if isinstance(item, ast.ClassDef) and item.name == class_name)
        method = next(
            item for item in owner.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == method_name)
        attributes = {
            call.func.attr
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
        }
        assert required <= attributes
        assert attributes.isdisjoint(forbidden_effects)
        if path == Path("core/daemon.py"):
            assert "worker" not in attributes
            assert any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "mint"
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "reader"
                for call in ast.walk(method)
            )
        else:
            assert any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "mint_awaited"
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "RepositoryReader"
                for call in ast.walk(method)
            )

        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            direct_root_decode = (
                isinstance(call.func, ast.Name)
                and call.func.id == "decode_root"
                or isinstance(call.func, ast.Attribute)
                and call.func.attr == "decode_root")
            compatibility_mint = (
                isinstance(call.func, ast.Name)
                and call.func.id in {"stateless", "async_stateless"}
                or isinstance(call.func, ast.Attribute)
                and call.func.attr in {"stateless", "async_stateless"})
            if direct_root_decode or compatibility_mint:
                bypasses.append(path.as_posix())
    assert bypasses == []


def test_deployed_reader_core_allowlists_equal_their_import_closures():
    from deploy.python_role_modules import (
        REPOSITORY_READER_CORE_MODULES,
        UPLOAD_BROKER_CORE_MODULES,
    )

    script = """
import importlib
import json
import sys
for module in sys.argv[1:]:
    importlib.import_module(module)
print(json.dumps(sorted(
    name for name in sys.modules
    if name == "core"
    or name.startswith("core.") and name.count(".") == 1
)))
"""

    def expected(modules):
        return sorted(
            "core" if name == "__init__.py" else "core." + name[:-3]
            for name in modules
        )

    for imports, modules in (
            (
                ("deploy.gateway",),
                REPOSITORY_READER_CORE_MODULES,
            ),
            (
                ("deploy.upload_broker", "deploy.upload_broker_http"),
                UPLOAD_BROKER_CORE_MODULES,
            )):
        result = subprocess.run(
            [sys.executable, "-c", script, *imports],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        assert json.loads(result.stdout) == expected(modules)


def test_applier_and_reader_import_closures_are_database_and_role_clean():
    script = """
import json
import sys
target = sys.argv[1]
__import__(target)
print(json.dumps(sorted(sys.modules)))
"""
    banned = {
        "core.admission",
        "core.catalog",
        "core.client_projection",
        "core.legacy_v7",
        "core.node",
        "core.pile_sender",
        "core.publication",
        "core.runtime",
        "sqlite3",
    }
    closures = {}
    for module in ("core.repository_applier", "core.repository_reader"):
        result = subprocess.run(
            [sys.executable, "-c", script, module],
            cwd=ROOT, check=True, capture_output=True, text=True)
        loaded = set(json.loads(result.stdout))
        assert loaded.isdisjoint(banned)
        closures[module] = loaded
    assert "core.repository_reader" not in closures[
        "core.repository_applier"]
    assert "core.repository_applier" not in closures[
        "core.repository_reader"]


def test_full_node_composes_roles_without_a_second_receiving_loop():
    node_tree = parsed(Path("core/node.py"))
    node = next(
        item for item in node_tree.body
        if isinstance(item, ast.ClassDef) and item.name == "Node")
    turn = next(
        item for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name == "turn")
    attributes = [
        call.func.attr
        for call in ast.walk(turn)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
    ]
    assert attributes.count("turn") == 1
    assert "list" not in attributes
    assert "list_page" not in attributes


def test_production_vocabulary_has_no_retired_positive_roles():
    offenders = []
    retired = re.compile(
        r"\b(?:AdmissionMembrane|WorkspaceRuntime|Publisher)\b|"
        r"\bpublisher(?:_stub| principal| role| package)?\b",
        re.IGNORECASE,
    )
    for path in source_paths():
        if retired.search((ROOT / path).read_text()):
            offenders.append(path.as_posix())
    assert offenders == []


def test_suppression_state_uses_the_explicit_module_name():
    assert (ROOT / "core" / "suppression_state.py").is_file()
    assert not (ROOT / "core" / "actions.py").exists()
