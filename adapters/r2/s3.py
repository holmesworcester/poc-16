"""Cloudflare R2 S3-compatible ObjectStore for Python hosts."""
import base64
from dataclasses import dataclass
import hashlib
import re

from adapters.s3 import S3Config, S3Store

ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")


@dataclass(frozen=True)
class R2S3Config:
    """Direct R2 account endpoint and one bucket/prefix namespace."""

    account_id: str
    bucket: str
    prefix: str = ""
    connect_timeout: float = 5.0
    read_timeout: float = 30.0
    max_pool_connections: int = 10
    read_total_max_attempts: int = 3
    list_page_size: int = 1000
    max_list_pages: int = 10_000

    def __post_init__(self):
        if not isinstance(self.account_id, str) \
                or not ACCOUNT_ID_RE.fullmatch(self.account_id):
            raise ValueError("R2 account id")
        # Reuse S3Config's remaining validation at configuration time.
        self.as_s3()

    @property
    def endpoint_url(self):
        return (
            f"https://{self.account_id}.r2.cloudflarestorage.com")

    def as_s3(self):
        return S3Config(
            bucket=self.bucket,
            prefix=self.prefix,
            region_name="auto",
            endpoint_url=self.endpoint_url,
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            max_pool_connections=self.max_pool_connections,
            read_total_max_attempts=self.read_total_max_attempts,
            addressing_style="path",
            list_page_size=self.list_page_size,
            max_list_pages=self.max_list_pages,
        )


class R2S3Store(S3Store):
    """S3-compatible R2 path with R2-supported request headers only.

    R2 supports PutObject conditionals and Content-MD5, but not AWS's flexible
    ``x-amz-checksum-algorithm`` request header. The conditional algorithm and
    error vocabulary remain the tested S3Store implementation; only client
    construction and put integrity headers differ.
    """

    def __init__(
            self, config: R2S3Config, *,
            access_key_id=None, secret_access_key=None,
            client=None, read_client=None, mutation_client=None):
        if not isinstance(config, R2S3Config):
            raise TypeError("R2S3Config required")
        if (access_key_id is None) != (secret_access_key is None):
            raise ValueError("both R2 access credentials are required")
        if access_key_id is not None and (
                client is not None or read_client is not None
                or mutation_client is not None):
            raise ValueError("credentials cannot accompany injected clients")
        s3_config = config.as_s3()
        if access_key_id is not None:
            if not isinstance(access_key_id, str) or not access_key_id \
                    or not isinstance(secret_access_key, str) \
                    or not secret_access_key:
                raise ValueError("R2 access credentials")
            read_client, mutation_client = self._sdk_clients(
                s3_config,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
            )
        super().__init__(
            s3_config, client=client, read_client=read_client,
            mutation_client=mutation_client)
        self.r2_config = config

    def _put_args(self, key, value):
        args = super()._put_args(key, value)
        args.pop("ChecksumAlgorithm", None)
        args.pop("ChecksumSHA256", None)
        args["ContentMD5"] = base64.b64encode(
            hashlib.md5(value, usedforsecurity=False).digest()).decode("ascii")
        return args
