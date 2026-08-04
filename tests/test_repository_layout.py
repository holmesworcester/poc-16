"""Small structural ratchets for the running peer architecture.

Behavior belongs in black-box tests.  These assertions protect boundaries
that are easy to violate accidentally while still producing correct-looking
unit results: one core protocol, private removal state, and no resurrection of
the retired aggregate repository.
"""

import ast
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {"AGENTS.md", "DESIGN.md", "README.md"}
SOURCE_ROOTS = (
    "core", "full_peer", "facts", "notifications", "adapters", "deploy")
EXCLUDED_PARTS = {
    "__pycache__", ".pytest_cache", ".wrangler", "build", "generated",
    "node_modules", "python_modules",
}


def source_paths():
    """Include untracked production Python while excluding build artifacts."""
    found = []
    for root_name in SOURCE_ROOTS:
        for path in (ROOT / root_name).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if EXCLUDED_PARTS.intersection(relative.parts) \
                    or any(part.startswith(".") for part in relative.parts) \
                    or path.name.startswith("test_") \
                    or "tests" in relative.parts:
                continue
            found.append(relative)
    return tuple(sorted(found))


def parsed(path):
    return ast.parse((ROOT / path).read_text(), filename=str(path))


def definitions(name, kind=ast.ClassDef):
    return [
        path
        for path in source_paths()
        for item in ast.walk(parsed(path))
        if isinstance(item, kind) and item.name == name
    ]


def owner(path, name):
    return next(
        item for item in parsed(path).body
        if isinstance(item, ast.ClassDef) and item.name == name)


def method(path, class_name, name):
    return next(
        item for item in owner(path, class_name).body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == name)


def imports(path):
    names = []
    for item in ast.walk(parsed(path)):
        if isinstance(item, ast.Import):
            names.extend(alias.name for alias in item.names)
        elif isinstance(item, ast.ImportFrom):
            names.append(item.module or "")
    return tuple(names)


def production_text():
    return "\n".join((ROOT / path).read_text() for path in source_paths())


def flat(path):
    return re.sub(r"\s+", " ", (ROOT / path).read_text())


def test_only_three_root_documents_exist_and_links_resolve():
    found = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*.md")
        if not any(
            part.startswith(".") or part in EXCLUDED_PARTS
            for part in path.relative_to(ROOT).parts)
    }
    assert found == ROOT_DOCS
    assert not (ROOT / "docs").exists()

    link = re.compile(r"\[[^]]+]\(([^)]+)\)")
    for name in ROOT_DOCS:
        source = ROOT / name
        for target in link.findall(source.read_text()):
            if "://" in target or target.startswith("#"):
                continue
            assert (source.parent / target.split("#", 1)[0]).exists(), (
                f"{name} links missing {target}")


def test_documents_describe_the_running_writer_forest_and_access_gate():
    design = flat(ROOT / "DESIGN.md")
    readme = flat(ROOT / "README.md")
    guide = flat(ROOT / "AGENTS.md")
    joined = " ".join((design, readme, guide))

    assert "defines the running architecture" in design
    assert "There is no workspace-global mutable content root" in readme
    assert "POC-16 has no backwards-compatibility surface" in guide
    assert "AccessGate" in design and "AccessGate" in guide
    assert "ClosedPileEvaluator" in design
    assert "Pull is replication. Push is not." in design
    assert "Every logical writer-tree leaf is independently closed" in design
    assert "no range or page boundary splits a pile" in design
    assert "Historical membership reveals only the caller's path" in design
    assert "Every pile is signed directly by its publishing device" in design
    assert "range-based set reconciliation (RBSR)" in design
    assert "not one sync session per pile" in design
    assert "Hosted and local turns are isomorphic" in design

    stale_claims = (
        "accepted target architecture",
        "Current `main` still implements the predecessor",
        "One-way cutover from the current global root",
        "After cutover, no workspace-global mutable content root remains",
    )
    assert all(claim not in joined for claim in stale_claims)


def test_retired_aggregate_repository_cannot_return():
    retired = {
        "core/admission.py",
        "core/admission_proof.py",
        "core/authority.py",
        "core/candidate_archive.py",
        "core/catalog.py",
        "core/client_projection.py",
        "core/ingress.py",
        "core/node.py",
        "core/pile_sender.py",
        "core/publication.py",
        "core/repository_applier.py",
        "core/repository_reader.py",
        "core/repository_snapshot.py",
        "core/runtime.py",
        "core/settlement.py",
        "core/snapshot.py",
        "core/sync.py",
        "core/validated_set.py",
        "core/worker.py",
        "deploy/gateway.py",
        "deploy/upload_broker.py",
        "deploy/upload_client.py",
        "deploy/upload_journal.py",
        "full_peer/upload_client.py",
        "full_peer/upload_journal.py",
    }
    assert not [relative for relative in retired if (ROOT / relative).exists()]

    for name in (
            "AdmissionMembrane", "AuthorityRepository", "Candidate",
            "FactRecord", "Node", "Publisher", "RepositoryApplier",
            "RepositoryReader", "Settlement", "ValidatedSet", "WorkerView",
            "WorkspaceRuntime"):
        assert definitions(name) == []

    text = production_text()
    for retired_name in (
            "AuthorityRepository.publish", "AUTHORITY_ROOT_KEY",
            "_publish_authority", "advance_leaf"):
        assert retired_name not in text


def test_core_is_the_database_free_engine_and_families_own_semantics():
    offenders = []
    for path in source_paths():
        names = imports(path)
        if path.parts[0] == "core":
            offenders.extend(
                (path, name) for name in names
                if name == "sqlite3" or name == "full_peer"
                or name.startswith("full_peer.")
                or name == "notifications"
                or name.startswith("notifications."))
            offenders.extend(
                (path, name) for name in names
                if name == "facts.auth" or name.startswith("facts.auth.")
                or name == "facts.content"
                or name.startswith("facts.content."))
        elif path.parts[0] == "facts":
            offenders.extend(
                (path, name) for name in names
                if name.split(".", 1)[0] in {
                    "adapters", "deploy", "full_peer"})
    assert offenders == []

    assert definitions("FactContext") == [Path("facts/_policy.py")]
    assert definitions("FullPeer") == [Path("full_peer/node.py")]
    assert definitions("HttpGate") == [Path("core/http.py")]
    assert definitions("AccessGate") == [Path("core/access.py")]


def test_core_writer_engine_has_one_authority_flow():
    expected = Path("core/writer_repository.py")
    for name in (
            "FactConsumer", "OpaqueHeadGate", "OwnerPublisher",
            "RepositoryMirror", "WriterLog"):
        assert definitions(name) == [expected]

    node = (ROOT / "full_peer/node.py").read_text()
    sync = (ROOT / "full_peer/sync.py").read_text()
    assert "RepositoryMirror(" in node
    assert "OwnerPublisher(" in sync
    assert "RepositoryMirror(" in sync
    assert "RepositoryApplier" not in node + sync
    assert "authority_root" not in node + sync
    assert "authority_recover" not in node + sync

    node_methods = {
        item.name for item in owner(Path("full_peer/node.py"), "FullPeer").body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"mirror", "publish_closed"} <= node_methods
    assert {"turn", "receive_pile", "applier"}.isdisjoint(node_methods)


def test_http_has_one_route_table_and_only_private_removal_control():
    handle = method(Path("core/http.py"), "HttpGate", "handle")
    routes = {
        item.value for item in ast.walk(handle)
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.startswith("/")
    }
    assert {
        "/ctl", "/head/", "/heads", "/invite/", "/layout/", "/mint",
        "/mirror/", "/obj", "/obj/", "/obj/open", "/pack/open",
        "/readyz", "/removal/apply", "/removal/bootstrap",
        "/removal/path",
    } <= routes
    assert {
        "/authority", "/page", "/page/", "/pile/", "/removal/advance",
        "/root",
    }.isdisjoint(routes)

    # Adapters compose HttpGate; they do not grow a second peer route table.
    assert not {
        item.value
        for item in ast.walk(parsed(Path("core/http_stdlib.py")))
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.startswith("/")
    }
    daemon = parsed(Path("full_peer/daemon.py"))
    assert not [
        item for item in ast.walk(daemon)
        if isinstance(item, ast.FunctionDef)
        and item.name in {"do_GET", "do_PUT"}
    ]

    source = (ROOT / "core/http.py").read_text()
    assert source.index('path == "/removal/apply"') \
        < source.index("require_object_put=True")
    assert "removal_apply(body, writer=writer)" in source
    assert "POST /authority" not in production_text()


def test_removal_roots_and_nodes_are_not_generic_objects_or_grants():
    tree = (ROOT / "core/suppression_tree.py").read_text()
    keys = (ROOT / "core/object_store.py").read_text()
    assert 'REMOVAL_ROOT_KEY = "removal"' in keys
    assert 'REMOVAL_NODE_PREFIX = "removal-node/"' in keys
    assert "private_node_key" in tree

    exposed = "\n".join(
        (ROOT / path).read_text()
        for path in (
            Path("core/grants.py"),
            Path("core/pack_access.py"),
            Path("core/writer_layout.py"),
        ))
    assert "REMOVAL_ROOT_KEY" not in exposed
    assert "REMOVAL_NODE_PREFIX" not in exposed
    assert "removal-node/" not in exposed

    http = (ROOT / "core/http.py").read_text()
    assert '"obj/" + oid' in http
    assert '"removal-node/"' not in http
    assert '"removal"' not in ast.get_docstring(parsed(Path("core/http.py")))


def test_closed_signed_piles_are_the_only_semantic_transfer_unit():
    close = parsed(Path("core/close.py"))
    functions = {
        item.name for item in close.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"decode_signed_pile", "encode_signed_pile"} <= functions
    assert {"decode_pile", "encode_pile"}.isdisjoint(functions)
    assert definitions("ClosedPileEvaluator") == [Path("core/close.py")]

    text = production_text()
    assert "put_pile" not in text
    assert "decode_pile" not in text
    assert "encode_pile" not in text

    for path, class_name, name in (
            (Path("full_peer/pile_sender.py"), "PileSender", "pack"),
            (Path("full_peer/pile_sender.py"), "PileSender", "send"),
            (Path("full_peer/node.py"), "FullPeer", "publish_closed")):
        parameters = {
            argument.arg
            for argument in (
                *method(path, class_name, name).args.posonlyargs,
                *method(path, class_name, name).args.args,
                *method(path, class_name, name).args.kwonlyargs,
            )
        }
        assert "blobs" not in parameters


def test_canonical_object_creation_has_no_detached_write_door():
    assert not [
        (path, call.lineno)
        for path in source_paths()
        for call in ast.walk(parsed(path))
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "admit_object"
    ]
    assert definitions("UploadClient") == []
    assert definitions("UploadSource") == []
    assert definitions("UploadSourceBuilder") == []
    assert not (ROOT / "core/ingress.py").exists()

    remote = owner(Path("core/store.py"), "RemoteStore")
    methods = {
        item.name for item in remote.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"copy_pile_object", "get_bounded", "put_if_absent"} <= methods


def test_untrusted_boundaries_stay_bounded_and_stream_large_piles():
    async_reader = method(
        Path("core/http.py"), "AsyncFromSyncReader", "get_bounded")
    calls = [
        item for item in ast.walk(async_reader)
        if isinstance(item, ast.Call)
    ]
    assert any(
        isinstance(call.func, ast.Name) and call.func.id == "_to_thread"
        and any(
            isinstance(node, ast.Attribute) and node.attr == "get_bounded"
            for node in ast.walk(call))
        for call in calls)
    assert not any(
        isinstance(call.func, ast.Attribute) and call.func.attr == "get"
        for call in calls)

    remote = owner(Path("core/store.py"), "RemoteStore")
    bounded = next(
        item for item in remote.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "get_bounded")
    copied = next(
        item for item in remote.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "copy_pile_object")
    assert "copy_obj" not in ast.unparse(bounded)
    assert "copy_obj" in ast.unparse(copied)

    for path, class_name in (
            (Path("core/store.py"), "FsStore"),
            (Path("core/store.py"), "RemoteStore"),
            (Path("adapters/s3/store.py"), "S3Store"),
            (Path("adapters/r2/worker.py"), "R2BindingStore")):
        assert "copy_pile_object" in {
            item.name for item in owner(path, class_name).body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }


def test_provider_lists_validate_native_pages_before_consuming_them():
    s3 = (ROOT / "adapters/s3/store.py").read_text()
    r2 = (ROOT / "adapters/r2/listing.py").read_text()
    assert 'len(contents) > args["MaxKeys"]' in s3
    assert "_page_objects(page.objects, limit)" in r2
    assert "for _ in range(limit + 1)" in r2
    assert "validate_key(logical)" in r2
    assert "not isinstance(key, str)" in r2


def test_notification_delivery_is_outside_repository_publication():
    assert not [
        (path, name)
        for path in source_paths() if path.parts[0] == "core"
        for name in imports(path)
        if name == "notifications" or name.startswith("notifications.")
    ]
    assert not (ROOT / "core/delivery_queue.py").exists()
    discovery = (ROOT / "notifications/discovery.py").read_text()
    assert "OPERATIONAL_CURSOR_KEY" in discovery
    for retired in (
            "RepositoryApplier", "RepositoryReader", "repository_snapshot"):
        assert retired not in discovery

    full_peer = (ROOT / "full_peer/notifications.py").read_text()
    assert full_peer.count("NotificationDiscovery(") == 1
    assert full_peer.count("handle_carrier_delivery(") == 1
    assert "notification" not in (ROOT / "full_peer/node.py").read_text()


def test_deployed_core_allowlist_is_exact_and_contains_no_retired_role():
    from deploy.python_role_modules import HOSTED_GATE_CORE_MODULES

    assert set(HOSTED_GATE_CORE_MODULES) <= {
        path.name for path in (ROOT / "core").glob("*.py")
    }
    assert {
        "access.py", "http.py", "removal_state.py",
        "suppression_tree.py", "writer_repository.py",
    } <= set(HOSTED_GATE_CORE_MODULES)
    assert {
        "authority.py", "repository_applier.py", "repository_reader.py",
        "repository_snapshot.py", "snapshot.py", "validated_set.py",
        "worker.py",
    }.isdisjoint(HOSTED_GATE_CORE_MODULES)


def test_a_writer_protocol_suite_uses_real_access_authorization():
    """Mechanical CAS helpers cannot be the only head-advance coverage."""
    path = Path("tests/test_full_peer_writer_http_contract.py")
    tree = parsed(path)
    test = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef)
        and item.name == "test_hosted_mode_pulls_all_writers_but_publishes_only_the_dialer")
    source = ast.unparse(test)
    assert "AccessGate(workspace, cloud)" in source
    assert "mechanical_head_authorizer" not in source
    assert ".state.bootstrap(" in source
    assert "sync_module.sync(" in source


def test_iroh_only_wraps_full_peer_connections():
    crate = ROOT / "full_peer/iroh"
    assert {
        path.relative_to(crate).as_posix()
        for path in crate.rglob("*") if path.is_file()
    } == {"Cargo.lock", "Cargo.toml", "src/lib.rs", "src/main.rs"}

    manifest = (crate / "Cargo.toml").read_text()
    for dependency in (
            "axum", "aws-sdk-s3", "http", "hyper", "object_store",
            "reqwest", "serde_json"):
        assert not re.search(rf"(?m)^{re.escape(dependency)}\s*=", manifest)
    rust = "\n".join(
        (crate / relative).read_text()
        for relative in ("src/lib.rs", "src/main.rs"))
    for protocol in (
            '"/mint"', '"/page', '"/pile', '"/root"',
            '"Authorization"', '"Bearer "'):
        assert protocol not in rust
    assert not any(path.suffix == ".rs" for path in (ROOT / "core").rglob("*"))
    assert all(
        "endpoint_id" not in (ROOT / path).read_text()
        for path in source_paths() if path.parts[0] == "core")


def test_sql_projection_and_bao_native_io_are_full_peer_only():
    sqlite_importers = [
        path for path in source_paths()
        if "sqlite3" in imports(path)
    ]
    assert sqlite_importers == [Path("full_peer/sql_store.py")]
    sql = (ROOT / "full_peer/sql_store.py").read_text()
    assert sql.count("CREATE TABLE IF NOT EXISTS") == 3
    assert "APP_VERSION = facts.APP_VERSION" in sql
    assert "PRAGMA user_version={APP_VERSION}" in sql

    assert (ROOT / "facts/_bao.py").is_file()
    assert (ROOT / "full_peer/bao_native.py").is_file()
    assert not (ROOT / "core/bao.py").exists()


def test_full_peer_projection_has_no_durable_repository_authority():
    source = (ROOT / "full_peer/sql_store.py").read_text()
    for retired in (
            "admission_receipts", "has_facts", "index-version", "proofs",
            "publish-base", "root-bytes"):
        assert retired not in source
    projection = owner(Path("full_peer/sql_store.py"), "SqlStore")
    methods = {
        item.name for item in projection.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "fact_of" in methods
    assert "fact" not in methods


def test_deployment_commands_do_not_name_deleted_test_files():
    named = re.compile(r"[\"'](tests/test_[a-z0-9_]+\.py)[\"']")
    missing = []
    for path in source_paths():
        if path.parts[0] != "deploy":
            continue
        for relative in named.findall((ROOT / path).read_text()):
            if not (ROOT / relative).is_file():
                missing.append((path.as_posix(), relative))
    assert missing == []
