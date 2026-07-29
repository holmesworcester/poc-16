"""No-I/O capability check for the optional host S3 provider SDK."""

REQUIRED_PUT_OBJECT_FIELDS = frozenset({
    "ChecksumSHA256",
    "IfMatch",
    "IfNoneMatch",
})


def require_s3_capabilities(config_type, session):
    """Fail before provider I/O when the installed SDK lacks required APIs."""
    try:
        config_type(ignore_configured_endpoint_urls=True)
    except Exception as error:
        raise RuntimeError(
            "botocore Config lacks endpoint-isolation support") from error
    try:
        operation = session.get_service_model(
            "s3").operation_model("PutObject")
        members = operation.input_shape.members
    except Exception as error:
        raise RuntimeError(
            "botocore has no usable S3 PutObject model") from error
    missing = REQUIRED_PUT_OBJECT_FIELDS - set(members)
    if missing:
        raise RuntimeError(
            "botocore S3 PutObject model lacks "
            + ", ".join(sorted(missing)))
    return tuple(sorted(REQUIRED_PUT_OBJECT_FIELDS))


def installed_capabilities():
    """Inspect the installed boto3/botocore pair without creating a client."""
    try:
        import boto3
        import botocore
        from botocore.config import Config
        from botocore.session import get_session
    except ImportError as error:
        raise RuntimeError(
            "host cloud stores require boto3 and botocore") from error
    require_s3_capabilities(Config, get_session())
    return boto3.__version__, botocore.__version__


def main():
    boto3_version, botocore_version = installed_capabilities()
    print(
        f"boto3={boto3_version} botocore={botocore_version} "
        "s3-sdk-smoke=ok")


if __name__ == "__main__":
    main()
