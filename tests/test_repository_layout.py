"""Structural authority ratchets complement the behavioral role tests."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {"AGENTS.md", "DESIGN.md", "README.md"}
SOURCE_ROOTS = (
    "core", "full_peer", "facts", "notifications", "adapters", "deploy")
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".wrangler",
    "build",
    "generated",
    "node_modules",
    "python_modules",
}


def source_paths():
    """Discover the working filesystem, including untracked production code."""
    paths = []
    for root_name in SOURCE_ROOTS:
        for path in (ROOT / root_name).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if EXCLUDED_PARTS.intersection(relative.parts) \
                    or any(part.startswith(".") for part in relative.parts) \
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


def annotated_fields(path, class_name):
    owner = next(
        item for item in parsed(path).body
        if isinstance(item, ast.ClassDef) and item.name == class_name)
    return tuple(
        item.target.id
        for item in owner.body
        if isinstance(item, ast.AnnAssign)
        and isinstance(item.target, ast.Name)
    )


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


def test_deployment_test_commands_name_existing_test_files():
    """A deleted protocol suite cannot leave a green-looking test command."""
    named = re.compile(r"[\"'](tests/test_[a-z0-9_]+\.py)[\"']")
    missing = []
    for path in source_paths():
        if path.parts[0] != "deploy":
            continue
        for relative in named.findall((ROOT / path).read_text()):
            if not (ROOT / relative).is_file():
                missing.append((path.as_posix(), relative))
    assert missing == []


def test_writer_forest_is_the_only_running_content_protocol():
    documents = {
        name: re.sub(r"\s+", " ", (ROOT / name).read_text().replace(">", ""))
        for name in ROOT_DOCS
    }
    assert "defines the running architecture" in documents["DESIGN.md"]
    assert "no predecessor-format content root or ingress path is accepted" \
        in documents["DESIGN.md"]
    assert "There is no workspace-global mutable content root" \
        in documents["README.md"]
    assert "POC-16 has no backwards-compatibility surface" \
        in documents["AGENTS.md"]
    stale = (
        "Current `main` still implements the predecessor",
        "accepted target architecture",
        "One-way cutover from the current global root",
        "After cutover, no workspace-global mutable content root remains",
    )
    assert all(
        phrase not in " ".join(documents.values()) for phrase in stale)


def test_target_has_one_closed_pile_evaluation_boundary():
    design = (ROOT / "DESIGN.md").read_text()
    guide = (ROOT / "AGENTS.md").read_text()
    flat_design = re.sub(r"\s+", " ", design)

    assert "CloudGate" not in design + guide
    assert "ClosedPileEvaluator" in design
    assert "AuthorityGate" in design and "AuthorityGate" in guide
    assert "Pull is replication. Push is not." in design
    assert "A pushed pile never enters" in design + guide
    assert "Hosted and local turns are isomorphic" in design
    assert "Every logical writer-tree leaf is independently closed" \
        in flat_design
    assert "no range or page boundary splits a pile" in flat_design


def test_authority_bootstrap_is_only_self_confined_removal_path():
    documents = {
        name: (ROOT / name).read_text()
        for name in ("DESIGN.md", "README.md", "AGENTS.md")
    }
    flat = {
        name: re.sub(r"\s+", " ", text)
        for name, text in documents.items()
    }

    assert "Historical membership reveals only the caller's path" \
        in documents["DESIGN.md"]
    assert "Every request is one bounded canonical closed pile signed by " \
        "the requesting member device" in flat["DESIGN.md"]
    assert "a device-ownership or device-join fact signed by that same " \
        "member" in flat["DESIGN.md"]
    assert "proof_refresh_required" in documents["DESIGN.md"]
    assert "Removal-root and page bytes live under a private removal " \
        "namespace" in flat["DESIGN.md"]
    assert "non-disclosing sibling commitments" in flat["DESIGN.md"]
    assert "Neither turn installs authority facts" in flat["AGENTS.md"]
    assert "neither synchronizes or mutates recipient authority state" \
        in flat["README.md"]

    rejected = (
        "AuthorityRepository / AuthorityGate",
        "Authority publication is ordinary closed-pile admission",
        "Peer bootstrap is a sequence of independently closed authority piles",
        "The full peer projects and recloses one family-declared authority subset",
        "publish authority facts",
        "same authority repository, pile codec",
    )
    joined = "\n".join(documents.values())
    assert all(phrase not in joined for phrase in rejected)


def test_target_uses_signed_piles_and_per_device_rbsr():
    design = (ROOT / "DESIGN.md").read_text()
    guide = (ROOT / "AGENTS.md").read_text()
    flat_design = re.sub(r"\s+", " ", design)
    flat_guide = re.sub(r"\s+", " ", guide)

    assert "Every pile is signed directly by its publishing device" in design
    assert "pile signature and tree authentication have different jobs" \
        in flat_design
    assert "Cloud mutation is origin-confined" in design
    assert "may not upload a relayed pile into that cloud writer log" \
        in flat_design
    assert "range-based set reconciliation (RBSR)" in design
    assert "not one sync session per pile" in flat_design
    assert "not a second combined content log" in flat_design
    assert "per-device RBSR forest is the initial" in flat_design
    assert "Full-peer replication is validate-first peer sync" in flat_guide
    assert "Do not add a combined P2P content log" in flat_guide
    assert "previous immutable head oid" not in design
    assert "does not link a permanent chain of historical heads" \
        in flat_design


def test_retired_authority_implementations_cannot_return():
    for relative in (
            "core/admission.py",
            "core/admission_proof.py",
            "core/candidate_archive.py",
            "core/cmds.py",
            "core/legacy_v7.py",
            "core/mint.py",
            "core/publication.py",
            "core/settlement.py",
            "core/runtime.py",
            "core/removals.py",
            "core/bao.py",
            "core/catalog.py",
            "core/cli.py",
            "core/client_projection.py",
            "core/daemon.py",
            "core/keychain.py",
            "core/node.py",
            "core/pile_sender.py",
            "core/status.py",
            "core/suppression_state.py",
            "core/sync.py",
            "core/walk.py",
            "deploy/upload_client.py",
            "deploy/upload_client_http.py",
            "deploy/upload_journal.py",
            "full_peer/upload_client.py",
            "full_peer/upload_client_http.py",
            "full_peer/upload_journal.py",
            "core/ingress.py",
            "deploy/upload_broker.py",
            "deploy/upload_broker_http.py",
            "deploy/upload_session.py",
            "deploy/upload_wire.py",
            "deploy/gateway.py",
            "deploy/cloudflare_upload/worker/publisher_stub.py"):
        assert not (ROOT / relative).exists()
    for name in (
            "AdmissionMembrane",
            "Publisher",
            "WorkspaceRuntime"):
        assert class_definitions(name) == []
    assert class_definitions("PileSender") == [
        Path("full_peer/pile_sender.py")]
    assert class_definitions("FullPeer") == [Path("full_peer/node.py")]
    assert class_definitions("UploadClient") == []
    assert class_definitions("UploadSource") == []
    assert class_definitions("UploadSourceBuilder") == []
    assert class_definitions("Node") == []
    assert class_definitions("RepositoryApplier") == [
        Path("core/repository_applier.py")]
    assert class_definitions("RepositoryReader") == [
        Path("core/repository_reader.py")]


def test_validated_residence_has_no_persisted_admission_judgment():
    """A closed pile is the certificate; repository residence stores no path."""
    for name in (
            "AdmissionProof",
            "Candidate",
            "CandidateView",
            "FactRecord",
            "Settlement",
    ):
        assert class_definitions(name) == []

    assert annotated_fields(Path("core/fact.py"), "Need") == (
        "role", "name", "a0", "a1")
    assert annotated_fields(Path("core/kernel.py"), "ResolvedEdge") == (
        "role", "fid")
    assert annotated_fields(Path("core/kernel.py"), "Valid") == (
        "fact", "edges")
    assert annotated_fields(
        Path("core/validated_set.py"), "ValidatedSet") == (
            "workspace", "root", "facts")


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


def test_repository_core_cannot_own_notification_delivery():
    """Push is a replayable consequence of a root, never a commit effect."""
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
            offenders.extend(
                (path.as_posix(), name)
                for name in names
                if name == "notifications" or name.startswith("notifications."))
    assert offenders == []
    assert not (ROOT / "core/delivery_queue.py").exists()
    applier = (ROOT / "core/repository_applier.py").read_text()
    assert "publication_effect" not in applier
    assert "notification" not in applier


def test_facts_depend_on_host_capabilities_not_full_peer_or_deploy():
    """Family policy/commands name behavior, never one host implementation."""
    offenders = []
    for path in source_paths():
        if path.parts[0] != "facts":
            continue
        for item in ast.walk(parsed(path)):
            if isinstance(item, ast.ImportFrom):
                names = (item.module or "",)
            elif isinstance(item, ast.Import):
                names = tuple(alias.name for alias in item.names)
            else:
                continue
            offenders.extend(
                (path.as_posix(), name)
                for name in names
                if name.split(".", 1)[0] in {
                    "adapters", "deploy", "full_peer"}
            )
    assert offenders == []

    node = next(
        item for item in parsed(Path("full_peer/node.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "FullPeer")
    methods = {
        item.name for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"attachment_io", "now_ms"} <= methods
    assert not methods & {
        "abandon_upload", "collect_upload", "create_upload",
        "load_upload", "run_upload", "upload_status",
    }


def test_full_peer_has_no_second_provider_upload_protocol():
    """Writer sync is the only outbound publication algorithm."""
    offenders = []
    for path in source_paths():
        if path.parts[0] != "full_peer":
            continue
        for item in ast.walk(parsed(path)):
            if isinstance(item, ast.ImportFrom):
                names = (item.module or "",)
            elif isinstance(item, ast.Import):
                names = tuple(alias.name for alias in item.names)
            else:
                continue
            offenders.extend(
                (path.as_posix(), name)
                for name in names
                if name == "deploy" or name.startswith("deploy.")
            )
    assert offenders == []
    for name in (
            "FinalizedUpload",
            "OpenedUpload",
            "UploadCapability"):
        assert class_definitions(name) == []


def test_one_explicit_fact_context_serves_core_and_full_peer_authoring():
    assert class_definitions("FactContext") == [Path("facts/_policy.py")]
    for path, owner in (
            (Path("core/kernel.py"), "MemoryContext"),
            (Path("full_peer/sql_store.py"), "SqlStore")):
        definition = next(
            item for item in parsed(path).body
            if isinstance(item, ast.ClassDef) and item.name == owner)
        members = {
            item.name for item in definition.body
            if isinstance(item, ast.FunctionDef)
        } | {
            target.id
            for item in definition.body if isinstance(item, ast.Assign)
            for target in item.targets if isinstance(target, ast.Name)
        }
        assert {"fact_of", "offers_from", "resolve_offer"} <= members

    for path in (Path("core/kernel.py"), Path("facts/_policy.py")):
        assert not [
            call for call in ast.walk(parsed(path))
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "hasattr"
        ]


def test_no_workspace_root_key_and_one_snapshot_compiler():
    predecessor = []
    for path, call in calls_named("cas"):
        if call.args and isinstance(call.args[0], ast.Constant) \
                and call.args[0].value == "root":
            predecessor.append((path, call))
    assert predecessor == []
    notification = (
        ROOT / "notifications" / "discovery.py").read_text()
    assert notification.count("OPERATIONAL_CURSOR_KEY") >= 5

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

    applier = (ROOT / "core" / "repository_applier.py").read_text()
    assert "extend_snapshot" in applier
    assert "compile_snapshot" not in applier
    assert "reconstruct" not in applier


def test_provider_authentication_has_no_materialized_winner_tree():
    from core import indexes, snapshot
    from core.worker import WorkerView

    assert snapshot.MAP_NAMES == ("fact_order", "fact", "supp")
    assert indexes.TREE_NAMES == ("fact", "supp")
    assert not hasattr(indexes, "AUTHORITY")
    assert not hasattr(indexes, "action_key")
    assert not hasattr(WorkerView, "authority_provider")
    assert not hasattr(WorkerView, "authority_known")
    assert hasattr(WorkerView, "fact_known")


def test_applier_owns_object_establishment_and_exact_source_identity():
    object_store_functions = {
        item.name for item in parsed(Path("core/object_store.py")).body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "ensure_object" not in object_store_functions

    for function, expected in (
            ("ensure_object_async", {
                "core/repository_applier.py",
                "core/writer_repository.py",
                "notifications/discovery.py",
            }),):
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

    assert not {
        path.as_posix()
        for path in source_paths()
        if path != Path("core/object_store.py")
        for call in ast.walk(parsed(path))
        if isinstance(call, ast.Call)
        and (
            isinstance(call.func, ast.Name)
            and call.func.id == "retire_exact_async"
            or isinstance(call.func, ast.Attribute)
            and call.func.attr == "retire_exact_async")
    }


def test_canonical_objects_have_no_detached_write_door():
    callers = {
        path.as_posix()
        for path in source_paths()
        for call in ast.walk(parsed(path))
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "admit_object"
    }
    assert callers == set()

    # Provider adapters expose mutation mechanics and deployment code may
    # conditionally create isolated ingress. Neither is another canonical
    # obj/* writer. Track simple local aliases as well as inline key building
    # so the ratchet does not ban legitimate non-canonical creates.
    offenders = []
    for path in source_paths():
        if path.parts[0] not in {"full_peer", "adapters", "deploy"}:
            continue
        for function in (
                item for item in ast.walk(parsed(path))
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))):
            names = set()

            def canonical(expression):
                return any(
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and (node.value == "obj" or node.value.startswith("obj/"))
                    or isinstance(node, ast.Name) and node.id in names
                    for node in ast.walk(expression)
                )

            for assignment in (
                    item for item in ast.walk(function)
                    if isinstance(item, (ast.Assign, ast.AnnAssign))):
                value = assignment.value
                if value is None or not canonical(value):
                    continue
                targets = assignment.targets \
                    if isinstance(assignment, ast.Assign) \
                    else (assignment.target,)
                names.update(
                    node.id
                    for target in targets
                    for node in ast.walk(target)
                    if isinstance(node, ast.Name)
                )
            offenders.extend(
                (path, call.lineno)
                for call in ast.walk(function)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in {"put", "put_if_absent", "_replace"}
                and call.args
                and canonical(call.args[0])
            )
    assert not offenders


def test_exact_applier_has_no_overwriteable_operational_hints():
    applier = next(
        item for item in parsed(Path("core/repository_applier.py")).body
        if isinstance(item, ast.ClassDef)
        and item.name == "RepositoryApplier")
    callers = {
        method.name
        for method in applier.body
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "_put_hint"
            for call in ast.walk(method)
        )
    }
    assert callers == set()


def test_unsigned_predecessor_pile_codec_is_absent():
    close = parsed(Path("core/close.py"))
    definitions = {
        item.name for item in close.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"encode_pile", "decode_pile"}.isdisjoint(definitions)
    assert not [
        path for path in source_paths()
        if "encode_pile" in (ROOT / path).read_text()
        or "decode_pile" in (ROOT / path).read_text()
    ]


def test_ordinary_pile_surfaces_have_no_embedded_object_channel():
    """Detached object ingress cannot grow back as optional pile plumbing."""
    surfaces = (
        (Path("core/close.py"), None, "encode_signed_pile"),
        (Path("core/close.py"), None, "decode_signed_pile"),
        (Path("full_peer/pile_sender.py"), "PileSender", "pack"),
        (Path("full_peer/pile_sender.py"), "PileSender", "pile"),
        (Path("full_peer/pile_sender.py"), "PileSender", "send"),
        (Path("full_peer/node.py"), "FullPeer", "ingest_new"),
        (Path("facts/_commands.py"), None, "publish"),
        (Path("core/repository_applier.py"), "RepositoryApplier",
         "apply_pile"),
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


def test_writer_sync_uses_immutable_objects_not_a_pile_delivery_alias():
    assert calls_named("put_pile") == []
    remote = parsed(Path("core/store.py"))
    owner = next(
        item for item in remote.body
        if isinstance(item, ast.ClassDef) and item.name == "RemoteStore")
    assert any(
        isinstance(item, ast.AsyncFunctionDef)
        and item.name == "put_if_absent"
        for item in owner.body)
    assert not [
        path for path in source_paths()
        if "put_pile" in (ROOT / path).read_text()
    ]


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
                Path("core/validated_set.py"),
                Path("core/worker.py")}:
            continue
        for call in ast.walk(parsed(path)):
            if not isinstance(call, ast.Call):
                continue
            direct_validated = (
                isinstance(call.func, ast.Name)
                and call.func.id == "ValidatedView")
            direct_worker = (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "WorkerView"
                and call.func.attr == "from_root")
            if direct_validated or direct_worker:
                bypasses.append(path.as_posix())
    assert bypasses == []


def test_worker_delegates_integrity_loading_without_gaining_view_authority():
    worker = parsed(Path("core/worker.py"))
    imports = {
        alias.name
        for item in worker.body
        if isinstance(item, ast.ImportFrom)
        for alias in item.names
    }
    assert "ValidatedView" in imports
    forbidden = {"decode_root", "Reader", "verified_object", "decode"}
    assert not [
        call.func.attr if isinstance(call.func, ast.Attribute)
        else call.func.id
        for call in ast.walk(worker)
        if isinstance(call, ast.Call)
        and (
            isinstance(call.func, ast.Name) and call.func.id in forbidden
            or isinstance(call.func, ast.Attribute)
            and call.func.attr in forbidden
        )
    ]

    owner = next(
        item for item in worker.body
        if isinstance(item, ast.ClassDef) and item.name == "WorkerView")
    methods = {
        item.name for item in owner.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not methods & {"closure", "providers", "fact_ids"}


def test_untrusted_read_boundaries_have_no_whole_get_fallback():
    boundaries = (
        (Path("core/http.py"), "AsyncFromSyncReader", "get_bounded"),
        (Path("core/http.py"), "HttpGate", "_get"),
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
        calls = [
            call for call in ast.walk(method)
            if isinstance(call, ast.Call)
        ]
        if class_name == "AsyncFromSyncReader":
            assert any(
                isinstance(call.func, ast.Name)
                and call.func.id == "_to_thread"
                and call.args
                and isinstance(call.args[0], ast.Attribute)
                and isinstance(call.args[0].value, ast.Attribute)
                and isinstance(call.args[0].value.value, ast.Name)
                and call.args[0].value.value.id == "self"
                and call.args[0].value.attr == "reader"
                and call.args[0].attr == "get_bounded"
                for call in calls)
        else:
            assert any(
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "get_bounded"
                for call in calls)
        assert not any(
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "get"
            for call in calls)

    stdlib = parsed(Path("core/http_stdlib.py"))
    assert not any(
        isinstance(item, ast.ClassDef) and item.name == "_SyncStore"
        for item in stdlib.body
    )
    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id == "AsyncFromSyncReader"
        for call in ast.walk(stdlib)
        if isinstance(call, ast.Call)
    )


def test_writer_sync_keeps_buffered_and_streamed_object_reads_distinct():
    remote_store = next(
        item for item in parsed(Path("core/store.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "RemoteStore")
    remote_bounded = next(
        item for item in remote_store.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "get_bounded")
    bounded_attributes = {
        item.attr for item in ast.walk(remote_bounded)
        if isinstance(item, ast.Attribute)
    }
    assert "obj" in bounded_attributes
    assert "copy_obj" not in bounded_attributes

    remote_copy = next(
        item for item in remote_store.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "copy_pile_object")
    copy_attributes = {
        item.attr for item in ast.walk(remote_copy)
        if isinstance(item, ast.Attribute)
    }
    assert "copy_obj" in copy_attributes

    sync_source = (ROOT / "full_peer" / "sync.py").read_text()
    assert sync_source.count("RepositoryMirror(") == 1
    assert "fetch_remote" not in sync_source
    assert "RepositoryApplier" not in sync_source

    file_tree = parsed(Path("facts/content/file.py"))
    file_methods = [
        item for item in file_tree.body
        if isinstance(item, ast.FunctionDef)
        and item.name in {"_state", "_payloads"}
    ]
    for method in file_methods:
        attributes = {
            call.func.attr
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
        }
        assert {"get", "get_bounded"}.isdisjoint(attributes)


def test_large_pile_copy_is_a_required_store_operation_without_fallback():
    writer = parsed(Path("core/writer_repository.py"))
    copy = next(
        item for item in writer.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "_copy_pile_object")
    names = {
        item.id for item in ast.walk(copy) if isinstance(item, ast.Name)
    }
    attributes = {
        item.attr for item in ast.walk(copy)
        if isinstance(item, ast.Attribute)
    }
    assert "NotImplemented" not in names
    assert "getattr" not in names
    assert "get_bounded" not in attributes
    assert "copy_pile_object" in attributes

    for path, owner_name in (
            (Path("core/store.py"), "FsStore"),
            (Path("core/store.py"), "RemoteStore"),
            (Path("adapters/s3/store.py"), "S3Store"),
            (Path("adapters/r2/worker.py"), "R2BindingStore"),
    ):
        owner = next(
            item for item in parsed(path).body
            if isinstance(item, ast.ClassDef) and item.name == owner_name)
        assert any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == "copy_pile_object"
            for item in owner.body)


def test_writer_binding_resolver_has_one_current_signature():
    writer = parsed(Path("core/writer_repository.py"))
    owner = next(
        item for item in writer.body
        if isinstance(item, ast.ClassDef)
        and item.name == "RepositoryMirror")
    binding = next(
        item for item in owner.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "_binding")
    source = ast.unparse(binding)
    assert "inspect.signature" not in source
    assert "candidate=head" not in source
    calls = [
        item for item in ast.walk(binding)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == "resolver"
    ]
    assert len(calls) == 1
    assert len(calls[0].args) == 4
    assert calls[0].keywords == []


def test_status_exposes_writer_state_without_predecessor_cleanup_code():
    status = (ROOT / "full_peer" / "status.py").read_text()
    node = (ROOT / "full_peer" / "node.py").read_text()
    assert "forest_fingerprint" in status
    for retired in (
            '"root"', "_sync_sql", "ingress_failures",
            "ingress_attempt_failures"):
        assert retired not in status
    assert "app.db" not in node


def test_http_and_worker_boundaries_never_whole_materialize_bodies():
    functions = (
        (Path("facts/auth/user.py"), "accept", "read_bounded", "read"),
        (Path("full_peer/cli.py"), "ctl", "read_bounded", "read"),
        (Path("full_peer/cli.py"), "main", "read_bounded", "read"),
        (
            Path("deploy/cloudflare_worker/runtime.py"),
            "_bounded_body",
            "getReader",
            "bytes",
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
    r2 = (ROOT / "adapters/r2/listing.py").read_text()

    assert 'len(contents) > args["MaxKeys"]' in s3
    assert "_page_objects(page.objects, limit)" in r2
    assert "for _ in range(limit + 1)" in r2
    assert "validate_key(logical)" in r2
    assert "not isinstance(key, str)" in r2


def test_authority_applier_accepts_only_one_in_hand_closed_pile():
    owner = next(
        item for item in parsed(Path("core/repository_applier.py")).body
        if isinstance(item, ast.ClassDef)
        and item.name == "RepositoryApplier")
    methods = {
        item.name: item
        for item in owner.body
        if isinstance(item, ast.AsyncFunctionDef)
    }
    public = {
        name for name in methods
        if not name.startswith("_")
    }
    assert public == {"apply_pile"}
    assert [arg.arg for arg in methods["apply_pile"].args.args] == [
        "self", "raw"]
    assert {"apply", "propose", "commit", "stage"}.isdisjoint(methods)

    calls = [
        call.func.attr
        for call in ast.walk(owner)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
    ]
    assert calls.count("cas") == 1
    assert {"list", "list_page", "delete", "retire_exact_async"} \
        .isdisjoint(calls)


def test_authority_applier_has_no_ingress_or_work_discovery_path():
    source = (ROOT / "core" / "repository_applier.py").read_text()
    assert "secrets." not in source
    assert "staged/claim/" not in source
    assert "_staged_claim_key" not in source
    assert "_claimed_staged_source" not in source
    assert "applier/generation/" not in source
    assert "applier/spent/" not in source
    assert "failed/" not in source

    owner = next(
        item for item in parsed(Path("core/repository_applier.py")).body
        if isinstance(item, ast.ClassDef)
        and item.name == "RepositoryApplier")
    methods = {
        item.name: item
        for item in owner.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert {"_stage", "apply_exact", "receive_pile"}.isdisjoint(methods)
    called = {
        call.func.attr
        for method in methods.values()
        for call in ast.walk(method)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
    }
    assert called.isdisjoint(
        {"delete", "list", "list_page", "retire_exact_async"})


def test_exact_sources_need_no_shared_rejection_schema():
    definitions = {
        name: [
            path for path in source_paths()
            for item in ast.walk(parsed(path))
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name
        ]
        for name in (
            "decode_rejection_record",
            "encode_rejection_record",
            "validate_create",
        )
    }
    assert definitions == {
        "decode_rejection_record": [],
        "encode_rejection_record": [],
        "validate_create": [Path("core/object_store.py")],
    }

    def importers(name):
        return {
            path
            for path in source_paths()
            for item in parsed(path).body
            if isinstance(item, ast.ImportFrom)
            and any(alias.name == name for alias in item.names)
        }

    assert importers("decode_rejection_record") == set()
    assert importers("encode_rejection_record") == set()
    assert importers("validate_create") == {
        Path("adapters/r2/worker.py"),
        Path("adapters/s3/store.py"),
        Path("core/store.py"),
    }

    assert not (ROOT / "core" / "ingress.py").exists()


def test_protocol_front_doors_route_semantic_reads_through_one_reader():
    boundaries = (
        (Path("core/http.py"), "HttpGate", "_mint", {"mint_authorize"}),
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
        HOSTED_GATE_CORE_MODULES,
        REPOSITORY_READER_CORE_MODULES,
    )

    script = """
import importlib
import json
import sys
for module in sys.argv[1:]:
    importlib.import_module(module)
from core.close import ClosedPileEvaluator, encode_signed_pile, make_signed_pile
from core.crypto import keypair
from facts.auth.workspace import workspace
secret, public = keypair()
anchor = workspace(secret, public, "import closure", 1)
raw = encode_signed_pile(make_signed_pile(
    secret, anchor.fid, public, (anchor,)))
ClosedPileEvaluator(anchor.fid).evaluate(raw)
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
                    ("deploy.aws_lambda.app",),
                    HOSTED_GATE_CORE_MODULES,
                ),
                (
                    ("core.http", "core.repository_reader"),
                    REPOSITORY_READER_CORE_MODULES,
                ),
                ):
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
        "core.legacy_v7",
        "core.publication",
        "core.runtime",
        "full_peer",
        "full_peer.node",
        "full_peer.pile_sender",
        "full_peer.sql_store",
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


def test_notification_engine_has_no_applier_or_aggregate_root_reader():
    script = """
import json
import sys
import notifications.discovery
print(json.dumps(sorted(sys.modules)))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT, check=True, capture_output=True, text=True)
    loaded = set(json.loads(result.stdout))
    assert loaded.isdisjoint({
        "core.repository_applier",
        "core.repository_reader",
        "core.repository_snapshot",
    })


def test_full_peer_notifications_only_compose_the_shared_engine():
    source = (ROOT / "full_peer" / "notifications.py").read_text()
    assert source.count("NotificationDiscovery(") == 1
    assert source.count("handle_carrier_delivery(") == 1
    for duplicate_authority in (
            "RepositoryApplier", "FactOrder", ".sql(", ".idx(",
            ".list(", ".list_page(", ".cas("):
        assert duplicate_authority not in source
    node = (ROOT / "full_peer" / "node.py").read_text()
    assert "notification" not in node


def test_full_node_has_no_predecessor_receiving_loop():
    node_tree = parsed(Path("full_peer/node.py"))
    node = next(
        item for item in node_tree.body
        if isinstance(item, ast.ClassDef) and item.name == "FullPeer")
    methods = {
        item.name for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"turn", "receive_pile", "applier"}.isdisjoint(methods)
    assert {"mirror", "publish_closed"} <= methods


def test_stdlib_http_composes_only_writer_mirror_and_authority_gate():
    adapter = parsed(Path("core/http_stdlib.py"))
    assert class_definitions("_SyncReceiver") == []

    dispatch = next(
        item for item in ast.walk(adapter)
        if isinstance(item, ast.FunctionDef) and item.name == "_dispatch")
    gates = [
        call for call in ast.walk(dispatch)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "HttpGate"
    ]
    assert len(gates) == 1
    keywords = {keyword.arg for keyword in gates[0].keywords}
    assert {"mirror", "mint_authorize", "sync_profile"} <= keywords
    assert "receiver" not in keywords
    source = (ROOT / "core" / "http_stdlib.py").read_text()
    assert "RepositoryApplier" not in source


def test_core_is_the_complete_database_free_repository_engine():
    """Hosted correctness stops at core; full_peer is only a composition."""
    assert class_definitions("RepositoryApplier") == [
        Path("core/repository_applier.py")]
    assert class_definitions("RepositoryReader") == [
        Path("core/repository_reader.py")]
    assert class_definitions("HttpGate") == [Path("core/http.py")]
    assert class_definitions("StdlibPeerHandler") == [
        Path("core/http_stdlib.py")]

    offenders = []
    for path in source_paths():
        if path.parts[0] != "core":
            continue
        for item in ast.walk(parsed(path)):
            names = ()
            if isinstance(item, ast.Import):
                names = tuple(alias.name for alias in item.names)
            elif isinstance(item, ast.ImportFrom):
                names = (item.module or "",)
            for name in names:
                if name == "sqlite3" or name == "full_peer" \
                        or name.startswith("full_peer."):
                    offenders.append((path.as_posix(), name))
    assert offenders == []


def test_one_core_http_gate_owns_peer_routes_and_control_is_separate():
    gate = next(
        item for item in parsed(Path("core/http.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "HttpGate")
    handle = next(
        item for item in gate.body
        if isinstance(item, ast.AsyncFunctionDef) and item.name == "handle")
    route_literals = {
        value.value
        for value in ast.walk(handle)
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value.startswith("/")
    }
    assert {
        "/ctl",
        "/authority",
        "/head/",
        "/heads",
        "/invite/",
        "/layout/",
        "/mint",
        "/mirror/",
        "/obj",
        "/obj/",
        "/obj/open",
        "/pack/open",
        "/readyz",
    } <= route_literals
    assert {"/page", "/page/", "/pile/", "/root"}.isdisjoint(
        route_literals)
    assert "_put_object" not in {
        item.name for item in gate.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    # Object creation has one metadata OPEN plus direct streaming data plane;
    # no small-body PUT fallback may reappear in the buffered core gate.
    request_limit = next(
        item for item in gate.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == "request_limit")
    assert "MAX_OBJECT_BYTES" not in {
        node.id for node in ast.walk(request_limit)
        if isinstance(node, ast.Name)
    }

    adapter_literals = {
        value.value
        for value in ast.walk(parsed(Path("core/http_stdlib.py")))
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value.startswith("/")
    }
    assert adapter_literals == set()

    daemon = parsed(Path("full_peer/daemon.py"))
    peer_methods = [
        item.name
        for item in ast.walk(daemon)
        if isinstance(item, ast.FunctionDef)
        and item.name in {"do_GET", "do_PUT"}
    ]
    assert peer_methods == []
    assert "/ctl/command" in {
        value.value
        for value in ast.walk(daemon)
        if isinstance(value, ast.Constant)
    }


def test_local_control_is_unconditionally_loopback_and_not_peer_data():
    source = (ROOT / "full_peer" / "daemon.py").read_text()
    assert "ipaddress.ip_address(host).is_loopback" in source
    assert '"127.0.0.1", control_port' in source

    serve = next(
        item for item in parsed(Path("full_peer/daemon.py")).body
        if isinstance(item, ast.FunctionDef) and item.name == "serve")
    parameters = {
        argument.arg
        for argument in (
            *serve.args.posonlyargs,
            *serve.args.args,
            *serve.args.kwonlyargs,
        )
    }
    assert "control_host" not in parameters


def test_iroh_is_a_full_peer_owned_connection_wrapper_only():
    crate = ROOT / "full_peer" / "iroh"
    assert {
        path.relative_to(crate).as_posix()
        for path in crate.rglob("*")
        if path.is_file()
    } == {
        "Cargo.lock",
        "Cargo.toml",
        "src/lib.rs",
        "src/main.rs",
    }

    manifest = (crate / "Cargo.toml").read_text()
    for authority_or_protocol_dependency in (
            "axum",
            "aws-sdk-s3",
            "http",
            "hyper",
            "object_store",
            "reqwest",
            "serde_json"):
        assert not re.search(
            rf"(?m)^{re.escape(authority_or_protocol_dependency)}\s*=",
            manifest,
        )
    rust = "\n".join(
        (crate / relative).read_text()
        for relative in ("src/lib.rs", "src/main.rs")
    )
    for duplicate_route_or_credential in (
            '"/mint"',
            '"/page',
            '"/pile',
            '"/root"',
            '"Authorization"',
            '"Bearer "'):
        assert duplicate_route_or_credential not in rust

    daemon = (ROOT / "full_peer" / "daemon.py").read_text()
    process = (ROOT / "full_peer" / "iroh_process.py").read_text()
    forwarders = (ROOT / "full_peer" / "iroh_forwarders.py").read_text()
    node = (ROOT / "full_peer" / "node.py").read_text()
    assert "class IrohProcess" in process
    assert '"serve"' in process
    assert '"forward"' in process
    assert '"--upstream"' in process
    assert "class IrohForwarders" in forwarders
    assert "IrohProcess.forward(" in forwarders
    assert "urllib" not in forwarders
    assert "peer_handler_for(" in daemon
    assert "gate_options=gate_options" in daemon
    assert "self.node.peer_address = None if iroh_binary is not None" in daemon
    assert "self.node.use_iroh(" in daemon
    assert "url = self.node.resolve_peer(workspace, peer)" in daemon
    assert "sync(self.node, workspace, url)" in daemon
    assert "def set_iroh_peer(" in node
    assert "def remove_iroh_peer(" in node
    assert "_control_server(" in daemon
    assert not any(
        path.suffix == ".rs"
        for path in (ROOT / "core").rglob("*")
    )
    assert all(
        "endpoint_id" not in (ROOT / path).read_text()
        for path in source_paths()
        if path.parts[0] == "core"
    )
    assert all(
        "iroh" not in (ROOT / path).read_text().lower()
        for path in (
            Path("facts/auth/user.py"),
            Path("facts/auth/user_invite.py"),
        )
    )


def test_full_peer_projection_has_no_repository_authority_residue():
    source = (ROOT / "full_peer" / "sql_store.py").read_text()
    for retired in (
            "index-version",
            "publish-base",
            "root-bytes",
            "has_facts",
            "by_type",
            "admission_receipts",
            "proofs"):
        assert retired not in source
    assert source.count("CREATE TABLE IF NOT EXISTS") == 3
    assert "APP_VERSION = facts.APP_VERSION" in source
    assert "PRAGMA user_version={APP_VERSION}" in source
    projection = next(
        item for item in parsed(Path("full_peer/sql_store.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "SqlStore")
    methods = {
        item.name for item in projection.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "fact_of" in methods
    assert "fact" not in methods
    worker = next(
        item for item in parsed(Path("core/worker.py")).body
        if isinstance(item, ast.ClassDef) and item.name == "WorkerView")
    worker_methods = {
        item.name for item in worker.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "fact_of" in worker_methods
    assert "fact" not in worker_methods


def test_bao_native_io_is_full_peer_only():
    assert (ROOT / "facts" / "_bao.py").is_file()
    assert (ROOT / "full_peer" / "bao_native.py").is_file()
    assert not (ROOT / "core" / "bao.py").exists()


def test_production_vocabulary_has_no_retired_positive_roles():
    for name in ("AdmissionMembrane", "Publisher", "WorkspaceRuntime"):
        assert class_definitions(name) == []
    assert not [
        path for path in source_paths()
        if "publisher_stub" in (ROOT / path).read_text()
    ]


def test_sql_projection_has_one_explicit_full_peer_boundary():
    sqlite_importers = []
    for path in source_paths():
        for item in ast.walk(parsed(path)):
            names = ()
            if isinstance(item, ast.Import):
                names = tuple(alias.name for alias in item.names)
            elif isinstance(item, ast.ImportFrom):
                names = (item.module or "",)
            if any(name == "sqlite3" for name in names):
                sqlite_importers.append(path)
    assert sqlite_importers == [Path("full_peer/sql_store.py")]
    assert not (ROOT / "core" / "catalog.py").exists()
    assert not (ROOT / "core" / "client_projection.py").exists()
