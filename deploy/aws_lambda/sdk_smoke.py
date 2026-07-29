"""Fail unless the packaged SDK/crypto versions support the running adapter."""
from pathlib import Path
import os
import platform
import sys
import tempfile
from unittest.mock import patch


def _endpoint_isolation(boto3, Config):
    """Prove ambient endpoint configuration cannot redirect AWS clients."""
    with tempfile.NamedTemporaryFile("w", prefix="poc16-aws-config-") as file:
        file.write(
            "[default]\nservices = hostile\n"
            "[services hostile]\ns3 =\n"
            "  endpoint_url = https://shared-profile.invalid\n")
        file.flush()
        hostile = {
            "AWS_CONFIG_FILE": file.name,
            "AWS_ENDPOINT_URL": "https://global-environment.invalid",
            "AWS_ENDPOINT_URL_S3": "https://s3-environment.invalid",
        }
        with patch.dict(os.environ, hostile):
            session = boto3.Session(
                aws_access_key_id="smoke",
                aws_secret_access_key="smoke",
                region_name="us-west-2")
            config = Config(ignore_configured_endpoint_urls=True)
            default = session.client("s3", config=config)
            explicit = session.client(
                "s3", config=config,
                endpoint_url="https://explicit.r2.invalid")
        if "invalid" in default.meta.endpoint_url:
            raise RuntimeError("ambient endpoint URL reached the S3 client")
        if explicit.meta.endpoint_url != "https://explicit.r2.invalid":
            raise RuntimeError("explicit provider endpoint was not preserved")


def main():
    import boto3
    import botocore
    from botocore.config import Config
    import nacl
    from botocore.session import get_session
    from nacl.public import PrivateKey, SealedBox

    if sys.version_info[:2] != (3, 13) \
            or sys.platform != "linux" \
            or platform.machine() not in {"x86_64", "AMD64"}:
        raise RuntimeError("SDK smoke is not running in Lambda Python 3.13 x86")
    expected = {
        "boto3": (boto3.__version__, "1.43.51"),
        "botocore": (botocore.__version__, "1.43.51"),
        "PyNaCl": (nacl.__version__, "1.6.2"),
    }
    wrong = {
        name: actual
        for name, (actual, wanted) in expected.items()
        if actual != wanted
    }
    if wrong:
        raise RuntimeError(f"unexpected packaged versions: {wrong}")
    artifact = Path(__file__).resolve().parents[2]
    for name, module in (
            ("boto3", boto3), ("botocore", botocore), ("PyNaCl", nacl)):
        module_path = Path(module.__file__).resolve()
        if not module_path.is_relative_to(artifact):
            raise RuntimeError(f"{name} was not imported from the artifact")
    _endpoint_isolation(boto3, Config)

    operation = get_session().get_service_model(
        "s3").operation_model("PutObject")
    fields = operation.input_shape.members
    required = {"IfMatch", "IfNoneMatch", "ChecksumSHA256"}
    missing = required - set(fields)
    if missing:
        raise RuntimeError(
            f"botocore PutObject model lacks {sorted(missing)}")
    secret = PrivateKey.generate()
    message = b"lambda-package-smoke"
    sealed = SealedBox(secret.public_key).encrypt(message)
    if SealedBox(secret).decrypt(sealed) != message:
        raise RuntimeError("PyNaCl sealed-box smoke failed")
    print(
        f"boto3={boto3.__version__} "
        f"botocore={botocore.__version__} "
        f"python={platform.python_version()} sdk-smoke=ok")


if __name__ == "__main__":
    main()
