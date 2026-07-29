"""Provider-free checks for the optional host SDK capability smoke."""
from types import SimpleNamespace

import pytest

from adapters.s3.sdk_smoke import require_s3_capabilities


class Config:
    calls = []

    def __init__(self, **options):
        self.calls.append(options)


class Session:
    def __init__(self, fields):
        self.fields = fields
        self.calls = []

    def get_service_model(self, name):
        self.calls.append(("get_service_model", name))
        operation = SimpleNamespace(
            input_shape=SimpleNamespace(
                members={field: object() for field in self.fields}))
        return SimpleNamespace(
            operation_model=lambda operation_name: (
                self.calls.append(("operation_model", operation_name))
                or operation))


def test_sdk_capability_smoke_is_no_io_and_checks_exact_surfaces():
    Config.calls.clear()
    session = Session({"IfMatch", "IfNoneMatch", "ChecksumSHA256", "Body"})

    assert require_s3_capabilities(Config, session) == (
        "ChecksumSHA256", "IfMatch", "IfNoneMatch")
    assert Config.calls == [{"ignore_configured_endpoint_urls": True}]
    assert session.calls == [
        ("get_service_model", "s3"),
        ("operation_model", "PutObject"),
    ]


def test_sdk_capability_smoke_names_missing_model_and_config_support():
    with pytest.raises(RuntimeError, match="lacks IfMatch"):
        require_s3_capabilities(
            Config, Session({"IfNoneMatch", "ChecksumSHA256"}))

    class OldConfig:
        def __init__(self, **_options):
            raise TypeError("unknown option")

    with pytest.raises(RuntimeError, match="endpoint-isolation"):
        require_s3_capabilities(
            OldConfig,
            Session({"IfMatch", "IfNoneMatch", "ChecksumSHA256"}))
