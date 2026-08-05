"""Host-only S3/R2 selection and daemon composition."""
from pathlib import Path
import json
import subprocess
import sys

import pytest

from adapters import host
import facts

from core.crypto import keypair
from core.object_store import (
    MAX_LOGICAL_KEY_BYTES,
    MAX_PROVIDER_KEY_BYTES,
    MAX_STORE_PREFIX_BYTES,
)
from full_peer import cli, daemon
from full_peer.node import FullPeer
from core.store import FsStore
from tests.provider_fakes import FakeS3Bucket
from tests.util import writer_slots


ROOT = Path(__file__).resolve().parents[1]
S3 = {
    "schema": host.SCHEMA,
    "backend": "s3",
    "bucket": "poc16-test-bucket",
    "base_prefix": "tenant/integration",
    "region_name": "us-west-2",
    "list_page_size": 2,
}
R2 = {
    "schema": host.SCHEMA,
    "backend": "r2",
    "account_id": "a" * 32,
    "bucket": "poc16-test-bucket",
    "base_prefix": "tenant/integration",
    "list_page_size": 2,
}


def _injected_factory(document, bucket=None):
    bucket = bucket or FakeS3Bucket(page_size=2)
    clients = []

    def client(backend, workspace):
        actor = f"{backend}:{workspace}:{len(clients)}"
        value = bucket.client(actor)
        clients.append(value)
        return value

    return host.factory_from_mapping(
        document, client_factory=client), bucket, clients


def test_default_node_store_is_the_same_local_filesystem_layout(tmp_path):
    workspace = "a" * 64
    node = FullPeer(str(tmp_path))
    store = node.store(workspace)

    assert isinstance(store, FsStore)
    assert Path(store.root) == tmp_path / "ws" / workspace


def test_two_independent_nodes_share_one_injected_provider_store(tmp_path):
    factory, bucket, clients = _injected_factory(S3)
    secret, _ = keypair()
    first = FullPeer(
        str(tmp_path / "first"), initial_secret=secret,
        store_factory=factory)
    workspace = facts.auth.workspace.create(first, "shared", ts=1)
    fid = facts.content.message.post(
        first, workspace, "general", "provider-backed", ts=2)

    second = FullPeer(
        str(tmp_path / "second"), initial_secret=secret,
        store_factory=factory)
    second.add_workspace(workspace, "shared", peers=[])
    second.rebuild(workspace)

    assert second.fact_of(workspace, fid).body["text"] == "provider-backed"
    assert facts.content.message.messages(second, workspace) == facts.content.message.messages(first, workspace)
    assert len(clients) >= 2
    physical = f"tenant/integration/workspace/{workspace}/"
    assert f"{physical}root" not in bucket.data
    assert any(
        key.startswith(f"{physical}heads/{workspace}/")
        for key in bucket.data)


def test_full_workspace_ids_create_disjoint_bucket_namespaces(tmp_path):
    factory, bucket, _ = _injected_factory(S3)
    node = FullPeer(str(tmp_path), store_factory=factory)
    first = facts.auth.workspace.create(node, "first", ts=1)
    second = facts.auth.workspace.create(node, "second", ts=2)
    assert first != second

    prefixes = {
        workspace:
            f"tenant/integration/workspace/{workspace}/"
        for workspace in (first, second)
    }
    keys_by_workspace = {}
    for workspace, prefix in prefixes.items():
        assert f"{prefix}root" not in bucket.data
        assert any(
            key.startswith(f"{prefix}heads/{workspace}/")
            for key in bucket.data)
        keys_by_workspace[workspace] = {
            key for key in bucket.data if key.startswith(prefix)}
        assert keys_by_workspace[workspace]
    assert keys_by_workspace[first].isdisjoint(keys_by_workspace[second])

    with pytest.raises(ValueError, match="64 lowercase hex"):
        factory(first[:-1])
    with pytest.raises(ValueError, match="64 lowercase hex"):
        factory("A" * 64)


@pytest.mark.parametrize(
    "document",
    [
        {},
        {**S3, "schema": "future"},
        {**S3, "backend": "filesystem"},
        {**S3, "base_prefix": ""},
        {**S3, "bucket": "not_a_bucket"},
        {**S3, "endpoint_url": "http://127.0.0.1:9000"},
        {**S3, "secret_access_key": "must-not-be-here"},
        {**S3, "connect_timeout": float("nan")},
        {**R2, "account_id": "cached.example"},
        {**R2, "region_name": "auto"},
        {**R2, "read_timeout": float("inf")},
    ],
)
def test_strict_config_rejects_malformed_or_credential_fields_before_clients(
        document):
    clients = []
    with pytest.raises(ValueError):
        host.factory_from_mapping(
            document,
            client_factory=lambda *args: clients.append(args))
    assert clients == []


def test_every_logical_namespace_fits_before_provider_client_creation():
    fixed = len("/workspace/") + 64
    maximum_base = "x" * (MAX_STORE_PREFIX_BYTES - fixed)
    clients = []

    factory = host.factory_from_mapping(
        {**S3, "base_prefix": maximum_base},
        client_factory=lambda *args: clients.append(args) or object())
    store = factory("0" * 64)
    layout = "layouts/" + "0" * 64 + "/" + "1" * 64 \
        + "/0000000000000001"
    assert MAX_LOGICAL_KEY_BYTES == len(layout)
    assert len(store._physical(layout).encode("ascii")) \
        == MAX_PROVIDER_KEY_BYTES
    for key in (
            "removal",
            "cursor",
            "obj/" + "0" * 64,
            layout):
        assert len(store._physical(key).encode("ascii")) \
            <= MAX_PROVIDER_KEY_BYTES
    assert len(clients) == 1

    with pytest.raises(ValueError, match="exceeds 1024"):
        host.factory_from_mapping(
            {**S3, "base_prefix": maximum_base + "x"},
            client_factory=lambda *args: clients.append(args))

    assert len(clients) == 1


def test_loader_rejects_duplicates_oversize_and_never_echoes_secret(
        tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema":"poc16-host-store-v1","backend":"s3",'
        '"backend":"r2","bucket":"poc16-test-bucket",'
        '"base_prefix":"tenant"}')
    with pytest.raises(ValueError, match="duplicate"):
        host.load_store_factory(
            duplicate, client_factory=lambda *args: object())

    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b" " * (host.MAX_CONFIG_BYTES + 1))
    with pytest.raises(ValueError, match="byte limit"):
        host.load_store_factory(
            oversize, client_factory=lambda *args: object())

    secret = "do-not-print-this-credential"
    forbidden = tmp_path / "forbidden.json"
    forbidden.write_text(json.dumps({
        **S3, "secret_access_key": secret}))
    with pytest.raises(ValueError) as caught:
        host.load_store_factory(
            forbidden, client_factory=lambda *args: object())
    assert secret not in str(caught.value)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_loader_rejects_nonstandard_json_numbers_before_clients(
        tmp_path, constant):
    config_path = tmp_path / "store.json"
    config_path.write_text(
        json.dumps(S3).replace(
            '"list_page_size": 2',
            f'"connect_timeout": {constant}'))
    clients = []

    with pytest.raises(ValueError, match="invalid JSON constant"):
        host.load_store_factory(
            config_path,
            client_factory=lambda *args: clients.append(args))

    assert clients == []


@pytest.mark.parametrize("document", [S3, R2])
def test_only_selected_cloud_backend_requires_the_optional_sdk(
        document, monkeypatch):
    real_import = host.importlib.import_module
    attempted = []

    def unavailable(name):
        attempted.append(name)
        if name in {"boto3", "botocore.config"}:
            raise ImportError(name)
        return real_import(name)

    monkeypatch.setattr(host.importlib, "import_module", unavailable)
    with pytest.raises(RuntimeError, match="requires boto3 and botocore"):
        host.factory_from_mapping(document)
    assert attempted == ["boto3"]

    factory, _, _ = _injected_factory(document)
    assert factory("0" * 64) is not None


def test_real_cli_daemon_path_passes_only_the_generic_factory(
        tmp_path, monkeypatch):
    factory, _, _ = _injected_factory(S3)
    secret, _ = keypair()
    state = tmp_path / "state"
    bootstrap = FullPeer(
        str(state), initial_secret=secret, store_factory=factory)
    workspace = facts.auth.workspace.create(bootstrap, "daemon", ts=1)
    config_path = tmp_path / "store.json"
    config_path.write_text(json.dumps(S3))
    seen = {}

    monkeypatch.setattr(host, "load_store_factory", lambda path: factory)

    def serve(
            directory, port, host_name, cadence, url, *,
            control_port, store_factory, gate_options,
            iroh_binary, iroh_key_file,
            iroh_loopback, notification_enabled,
            notification_cadence, notification_provider):
        seen["arguments"] = (
            directory, port, host_name, cadence, url, control_port,
            gate_options, iroh_binary, iroh_key_file, iroh_loopback,
            notification_enabled, notification_cadence,
            notification_provider)
        seen["peer"] = FullPeer(
            directory, initial_secret=secret,
            store_factory=store_factory)

    monkeypatch.setattr(daemon, "serve", serve)
    assert cli.main([
        "daemon", str(state), "--port", "0",
        "--store-config", str(config_path),
    ]) is None

    selected = seen["peer"]
    assert writer_slots(selected, workspace) \
        == writer_slots(bootstrap, workspace)
    assert writer_slots(selected, workspace)
    assert seen["arguments"][1:3] == (0, "127.0.0.1")
    assert seen["arguments"][6].grant_ttl_ms == 60_000
    assert seen["arguments"][7:] == (
        None, None, False, False, 30.0, None)


def test_daemon_help_documents_reproducible_s3_r2_config(capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["daemon", "--help"])
    assert stopped.value.code == 0
    output = capsys.readouterr().out
    assert "--store-config PATH" in output
    assert '"backend":"s3"' in output
    assert '"backend":"r2"' in output
    assert "Credentials are not allowed" in output


def test_filesystem_daemon_path_imports_no_cloud_adapter_or_sdk():
    script = r"""
import builtins
import tempfile
import threading

real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split(".", 1)[0] in {"boto3", "botocore"} \
            or name.startswith(("adapters.host", "adapters.s3", "adapters.r2")):
        raise AssertionError("cloud dependency imported: " + name)
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded

from full_peer import cli, daemon

class Server:
    made = []

    def __init__(self, address, handler):
        self.server_address = (address[0], 19000 + len(self.made))
        self.handler = handler
        self.daemon_threads = False
        self.stopped = threading.Event()
        self.closed = False
        self.made.append(self)

    def serve_forever(self):
        if self is self.made[0]:
            self.stopped.wait(5)

    def shutdown(self):
        self.stopped.set()

    def server_close(self):
        self.closed = True

daemon.ThreadingHTTPServer = Server
try:
    cli.main([
        "daemon", tempfile.mkdtemp(), "--port", "0", "--control-port", "0",
    ])
except RuntimeError as error:
    assert "control listener stopped unexpectedly" in str(error)
else:
    raise AssertionError("fake control lifecycle did not stop daemon")

assert len(Server.made) == 2
assert all(server.stopped.is_set() and server.closed for server in Server.made)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT,
        capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
