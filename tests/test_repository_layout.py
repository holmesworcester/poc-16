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
    "core", "full_peer", "facts", "infrastructure", "notifications",
    "adapters", "deploy")
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


def semantic_store_mutations():
    """Name every protocol-layer external create/CAS completion call."""
    found = set()
    roots = {"core", "full_peer", "notifications", "peerlog"}
    peerlog_paths = tuple(
        path.relative_to(ROOT)
        for path in (ROOT / "peerlog").rglob("*.py")
        if not EXCLUDED_PARTS.intersection(path.relative_to(ROOT).parts)
        and not path.name.startswith("test_")
    )
    for path in (*source_paths(), *peerlog_paths):
        if path.parts[0] not in roots:
            continue
        tree = parsed(path)
        parents = {}
        for item in ast.walk(tree):
            for child in ast.iter_child_nodes(item):
                parents[child] = item
        for item in ast.walk(tree):
            if not isinstance(item, ast.Call) \
                    or not isinstance(item.func, ast.Attribute) \
                    or item.func.attr not in {
                        "cas", "complete_multipart", "create",
                        "put_if_absent",
                    }:
                continue
            function = class_name = None
            current = item
            while current in parents:
                current = parents[current]
                if function is None and isinstance(
                        current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    function = current.name
                elif class_name is None and isinstance(current, ast.ClassDef):
                    class_name = current.name
            found.add((
                path.as_posix(), class_name, function, item.func.attr))
    return found


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
    assert "Admission creates the exact subject row once" in design
    assert "there is no `POST /removal/path` route" in design
    assert "Every pile is signed directly by its publishing device" in design
    assert "range-based set reconciliation (RBSR)" in design
    assert "not one sync session per pile" in design
    assert "Hosted and local turns are isomorphic" in design
    assert "MAX_SEMANTIC_PILE_BYTES" in design
    assert "MAX_DIRECT_OBJECT_BYTES" in design

    stale_claims = (
        "accepted target architecture",
        "Current `main` still implements the predecessor",
        "One-way cutover from the current global root",
        "After cutover, no workspace-global mutable content root remains",
    )
    assert all(claim not in joined for claim in stale_claims)


def test_every_protocol_store_mutation_has_a_concurrency_owner():
    """Adding a durable write door requires classifying its shared target.

    Provider adapters are mechanics below this inventory. Fact-family
    ``delete`` commands mutate the local authored log rather than an external
    key. These are all protocol-layer calls that can create/replace provider
    state, partitioned by the identity class allowed to race them.
    """
    multi_device_or_relay = {
        ("core/object_store.py", None, "ensure_object_async",
         "put_if_absent"),
        ("core/removal_tree.py", "RemovalTree", "apply_at", "cas"),
        ("core/removal_tree.py", None, "_ensure_node",
         "put_if_absent"),
        ("core/writer_layout.py", None, "publish_placements", "cas"),
        ("core/writer_repository.py", None, "ensure_pile_async",
         "put_if_absent"),
        ("core/writer_repository.py", "RepositoryMirror", "_sync_slot",
         "cas"),
        ("peerlog/cloud.py", "CloudQueue", "repair_directory", "cas"),
    }
    per_writer_identity = {
        ("core/writer_repository.py", "OpaqueHeadGate", "_advance_slot",
         "cas"),
        ("peerlog/cloud.py", "CloudQueue", "publish", "create"),
        ("peerlog/cloud.py", "CloudQueue", "publish", "cas"),
        ("peerlog/cloud.py", "CloudQueue", "readmit_orphan", "cas"),
        ("peerlog/cloud.py", "CloudQueue", "_write_segment", "create"),
        ("peerlog/cloud.py", "CloudQueue", "_append_mono",
         "complete_multipart"),
        ("peerlog/cloud.py", "CloudQueue", "fold_idle", "cas"),
    }
    isolated_service_state = {
        ("notifications/discovery.py", "NotificationState", "complete",
         "cas"),
        ("notifications/discovery.py", "NotificationDiscovery",
         "_cas_exact", "cas"),
    }
    mechanical_passthrough = {
        ("core/object_store.py", "SyncStoreAdapter", "put_if_absent",
         "put_if_absent"),
        ("core/object_store.py", "SyncStoreAdapter", "cas", "cas"),
        ("core/writer_repository.py", "CandidateSource", "put_if_absent",
         "put_if_absent"),
        ("core/writer_repository.py", "CandidateSource", "cas", "cas"),
    }
    classes = (
        multi_device_or_relay,
        per_writer_identity,
        isolated_service_state,
        mechanical_passthrough,
    )
    assert not any(left & right for index, left in enumerate(classes)
                   for right in classes[index + 1:])
    assert semantic_store_mutations() == set().union(*classes)

    # Every low-level mutable namespace is accounted for above: removal is
    # multi-device, cursor is isolated service state, heads split by owner vs
    # validated relay route, and layouts are multi-relay hints.
    from core.object_store import SINGLETON_CAS_KEYS, mutable_key

    assert SINGLETON_CAS_KEYS == frozenset({"removal", "cursor"})
    assert mutable_key("heads/" + "0" * 64 + "/" + "1" * 64)
    assert mutable_key(
        "layouts/" + "0" * 64 + "/" + "1" * 64
        + "/0000000000000001")


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


def test_semantic_and_physical_byte_limits_cannot_collapse_again():
    text = production_text()
    assert "MAX_PILE_BYTES" not in text
    for path in (
            "core/store.py",
            "full_peer/walk.py",
            "adapters/s3/store.py",
            "adapters/r2/worker.py"):
        assert "MAX_DIRECT_OBJECT_BYTES" in (ROOT / path).read_text()
    for path in (
            "core/close.py",
            "core/writer_fetch.py",
            "core/writer_layout.py",
            "core/writer_packer.py",
            "core/writer_repository.py"):
        assert "MAX_SEMANTIC_PILE_BYTES" in (ROOT / path).read_text()


def test_http_has_one_route_table_and_only_private_removal_control():
    handle = method(Path("core/http.py"), "HttpGate", "handle")
    routes = {
        item.value for item in ast.walk(handle)
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.startswith("/")
    }
    assert {
        "/ctl", "/head/", "/heads", "/layout/", "/mint",
        "/mirror/", "/obj", "/obj/", "/obj/open", "/pack/open",
        "/readyz", "/removal/bootstrap",
    } <= routes
    assert {
        "/authority", "/invite/", "/page", "/page/", "/pile/",
        "/removal/advance", "/removal/apply", "/root",
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
    assert 'parts[2] == "permit"' in source
    assert 'parts[2] == "commit"' in source
    assert "self.head_permit_issue(" in source
    assert "self.head_permit_commit(" in source
    assert "HttpGate.requires_access_callbacks(method, path)" in (
        ROOT / "core/http_stdlib.py").read_text()
    assert "HttpGate.requires_mirror_callback(method, path)" in (
        ROOT / "core/http_stdlib.py").read_text()
    production = production_text()
    assert "/removal/apply" not in production
    assert "POST /authority" not in production


def test_removal_roots_and_nodes_are_not_generic_objects_or_grants():
    tree = (ROOT / "core/removal_tree.py").read_text()
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


def test_cloud_owner_mutators_cannot_redefine_commit_with_directory_repair():
    queue = owner(Path("peerlog/cloud.py"), "CloudQueue")
    mutators = {
        item.name: item for item in queue.body
        if isinstance(item, ast.FunctionDef)
        and item.name in {"publish", "readmit_orphan", "fold_idle"}
    }
    assert set(mutators) == {"publish", "readmit_orphan", "fold_idle"}
    for mutation in mutators.values():
        parameters = {
            argument.arg for argument in (
                *mutation.args.posonlyargs, *mutation.args.args,
                *mutation.args.kwonlyargs)
        }
        assert "announce" not in parameters
        assert not any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "repair_directory"
            for call in ast.walk(mutation))


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
        "removal_tree.py", "writer_repository.py",
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
