"""Fail unless the packaged SDK/crypto versions support the running adapter."""


def main():
    import boto3
    import botocore
    from botocore.session import get_session
    from nacl.public import PrivateKey, SealedBox

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
        f"botocore={botocore.__version__} sdk-smoke=ok")


if __name__ == "__main__":
    main()
