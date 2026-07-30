"""Generate the Cloudflare authority boundary for staged R2 uploads.

This module describes provider resources; it does not pretend that a Wrangler
binding is read-only.  The broker receives no native R2 binding.  Its
canonical reads use a separately provisioned Object Read-only S3 credential,
and its only write-capable parent credential is scoped to the distinct ingress
bucket.  The publisher alone receives native bindings to both buckets.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlsplit

from core.staged_intent import staging_prefix


ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
BUCKET = re.compile(
    r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
HEX_ID = re.compile(r"^[0-9a-f]{32}$")
OWNER = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
WORKER = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
WORKSPACE = re.compile(r"^[0-9a-f]{64}$")
JURISDICTIONS = frozenset({"default", "eu", "fedramp"})

READ_GROUP = "Workers R2 Storage Bucket Item Read"
WRITE_GROUP = "Workers R2 Storage Bucket Item Write"
OWNER_BINDING = "POC16_DEPLOYMENT_OWNER"
ROLE_BINDING = "POC16_DEPLOYMENT_ROLE"

BROKER_SECRET_NAMES = (
    "CANONICAL_READ_ACCESS_KEY_ID",
    "CANONICAL_READ_SECRET_ACCESS_KEY",
    "INGRESS_PARENT_ACCESS_KEY_ID",
    "INGRESS_PARENT_SECRET_ACCESS_KEY",
    "UPLOAD_SESSION_KEYRING",
)

COMPATIBILITY_DATE = "2026-07-29"
DEFAULT_PRESIGN_TTL_SECONDS = 15 * 60
DEFAULT_STAGE_RETENTION_SECONDS = 7 * 24 * 60 * 60
UPLOAD_PROTOCOL = "isolated-ingress-v1"
UPLOAD_ORDER = "objects-first-pile-last"


def _safe_prefix(value, label):
    if not isinstance(value, str):
        raise ValueError(label)
    value = value.strip("/")
    parts = value.split("/")
    if not value or len(value.encode()) > 768 \
            or any(not part or part in {".", ".."} for part in parts):
        raise ValueError(label)
    if any(not re.fullmatch(r"[A-Za-z0-9:._-]+", part) for part in parts):
        raise ValueError(label)
    return value


@dataclass(frozen=True)
class Deployment:
    account_id: str
    workspace: str
    canonical_bucket: str
    ingress_bucket: str
    owner: str
    broker_name: str
    publisher_name: str
    read_permission_group_id: str
    write_permission_group_id: str
    jurisdiction: str = "default"
    canonical_bucket_profile: str = "dedicated-workspace"
    canonical_prefix: str | None = None
    ingress_prefix: str | None = None
    presign_ttl_seconds: int = DEFAULT_PRESIGN_TTL_SECONDS
    stage_retention_seconds: int = DEFAULT_STAGE_RETENTION_SECONDS

    def __post_init__(self):
        fields = (
            (ACCOUNT, self.account_id, "account id"),
            (WORKSPACE, self.workspace, "workspace"),
            (BUCKET, self.canonical_bucket, "canonical bucket"),
            (BUCKET, self.ingress_bucket, "ingress bucket"),
            (OWNER, self.owner, "deployment owner"),
            (WORKER, self.broker_name, "broker Worker name"),
            (WORKER, self.publisher_name, "publisher Worker name"),
            (HEX_ID, self.read_permission_group_id, "read permission id"),
            (HEX_ID, self.write_permission_group_id, "write permission id"),
        )
        for pattern, value, label in fields:
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise ValueError(label)
        if self.canonical_bucket == self.ingress_bucket:
            raise ValueError("canonical and ingress buckets must differ")
        if self.broker_name == self.publisher_name:
            raise ValueError("broker and publisher Worker names must differ")
        if self.jurisdiction not in JURISDICTIONS:
            raise ValueError("R2 jurisdiction")
        if self.canonical_bucket_profile != "dedicated-workspace":
            raise ValueError(
                "canonical bucket must use the dedicated-workspace profile")
        canonical = _safe_prefix(
            self.canonical_prefix
            or f"workspaces/{self.workspace}",
            "canonical prefix",
        )
        ingress = _safe_prefix(
            self.ingress_prefix
            or f"ingress/v1/workspaces/{self.workspace}",
            "ingress prefix",
        )
        expected_ingress = f"ingress/v1/workspaces/{self.workspace}"
        if ingress != expected_ingress:
            raise ValueError(
                "ingress prefix must use the selected logical protocol")
        object.__setattr__(self, "canonical_prefix", canonical)
        object.__setattr__(self, "ingress_prefix", ingress)
        if not isinstance(self.presign_ttl_seconds, int) \
                or isinstance(self.presign_ttl_seconds, bool) \
                or not 1 <= self.presign_ttl_seconds <= 60 * 60:
            raise ValueError("presigned PUT TTL")
        if not isinstance(self.stage_retention_seconds, int) \
                or isinstance(self.stage_retention_seconds, bool) \
                or not 24 * 60 * 60 <= self.stage_retention_seconds \
                <= 30 * 24 * 60 * 60:
            raise ValueError("stage retention")
        if self.stage_retention_seconds <= self.presign_ttl_seconds:
            raise ValueError("stage retention must exceed presigned PUT TTL")

    @property
    def endpoint(self):
        jurisdiction = (
            "" if self.jurisdiction == "default"
            else f".{self.jurisdiction}"
        )
        return (
            f"https://{self.account_id}{jurisdiction}."
            "r2.cloudflarestorage.com"
        )

    @classmethod
    def from_environment(cls, environment):
        workspace = environment.get("CF_UPLOAD_WORKSPACE", "")
        return cls(
            account_id=environment.get("CLOUDFLARE_ACCOUNT_ID", ""),
            workspace=workspace,
            canonical_bucket=environment.get(
                "CF_UPLOAD_CANONICAL_BUCKET", ""),
            ingress_bucket=environment.get("CF_UPLOAD_INGRESS_BUCKET", ""),
            owner=environment.get("CF_UPLOAD_DEPLOYMENT_OWNER", ""),
            broker_name=environment.get(
                "CF_UPLOAD_BROKER_NAME", "poc16-upload-broker"),
            publisher_name=environment.get(
                "CF_UPLOAD_PUBLISHER_NAME", "poc16-upload-publisher"),
            read_permission_group_id=environment.get(
                "CF_R2_BUCKET_ITEM_READ_PERMISSION_ID", ""),
            write_permission_group_id=environment.get(
                "CF_R2_BUCKET_ITEM_WRITE_PERMISSION_ID", ""),
            jurisdiction=environment.get(
                "CF_R2_JURISDICTION", "default"),
            canonical_bucket_profile=environment.get(
                "CF_UPLOAD_CANONICAL_BUCKET_PROFILE", ""),
            canonical_prefix=environment.get(
                "CF_UPLOAD_CANONICAL_PREFIX",
                f"workspaces/{workspace}"),
            ingress_prefix=environment.get(
                "CF_UPLOAD_INGRESS_PREFIX",
                f"ingress/v1/workspaces/{workspace}"),
            presign_ttl_seconds=_integer(
                environment.get(
                    "CF_UPLOAD_PRESIGN_TTL_SECONDS",
                    DEFAULT_PRESIGN_TTL_SECONDS),
                "presigned PUT TTL",
            ),
            stage_retention_seconds=_integer(
                environment.get(
                    "CF_UPLOAD_STAGE_RETENTION_SECONDS",
                    DEFAULT_STAGE_RETENTION_SECONDS),
                "stage retention",
            ),
        )


def _integer(value, label):
    if isinstance(value, bool):
        raise ValueError(label)
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(label) from error


def bucket_resource(deployment, bucket):
    if bucket not in {
            deployment.canonical_bucket, deployment.ingress_bucket}:
        raise ValueError("bucket is outside this deployment")
    return (
        "com.cloudflare.edge.r2.bucket."
        f"{deployment.account_id}_{deployment.jurisdiction}_{bucket}"
    )


def _access_policy(deployment, *, name, bucket, group_id, group_name):
    return {
        "name": f"{deployment.owner}:{name}",
        "policies": [{
            "effect": "allow",
            "resources": {
                bucket_resource(deployment, bucket): "*",
            },
            "permission_groups": [{
                "id": group_id,
                "name": group_name,
            }],
        }],
    }


def access_policies(deployment):
    """Return the two R2 S3-token policies the broker needs.

    Cloudflare's bucket-item write permission is intentionally represented as
    broad within ingress.  Isolation comes from the resource naming the
    ingress bucket and never the canonical bucket.
    """
    return {
        "broker_canonical_reader": _access_policy(
            deployment,
            name="broker-canonical-read",
            bucket=deployment.canonical_bucket,
            group_id=deployment.read_permission_group_id,
            group_name=READ_GROUP,
        ),
        "broker_ingress_parent": _access_policy(
            deployment,
            name="broker-ingress-parent",
            bucket=deployment.ingress_bucket,
            group_id=deployment.write_permission_group_id,
            group_name=WRITE_GROUP,
        ),
    }


def _policy_digest(policy):
    raw = json.dumps(
        policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _worker_base(deployment, *, role, name, main):
    return {
        "$schema": "node_modules/wrangler/config-schema.json",
        "name": name,
        "main": main,
        "base_dir": "worker",
        "compatibility_date": COMPATIBILITY_DATE,
        "compatibility_flags": ["python_workers"],
        "workers_dev": False,
        "preview_urls": False,
        "routes": [],
        "vars": {
            "WORKSPACE": deployment.workspace,
            "CANONICAL_BUCKET_PROFILE":
                deployment.canonical_bucket_profile,
            "UPLOAD_PROTOCOL": UPLOAD_PROTOCOL,
            "UPLOAD_ORDER": UPLOAD_ORDER,
            OWNER_BINDING: deployment.owner,
            ROLE_BINDING: role,
        },
        "python_modules": {
            "excludes": ["**/*.pyc", "**/__pycache__"],
        },
        "observability": {
            "enabled": True,
            "head_sampling_rate": 0.01,
        },
    }


def broker_config(deployment):
    """Generate a broker with segregated credentials and no R2 binding."""
    policies = access_policies(deployment)
    config = _worker_base(
        deployment,
        role="broker",
        name=deployment.broker_name,
        main="worker/broker_stub.py",
    )
    config["r2_buckets"] = []
    config["vars"].update({
        "R2_ENDPOINT": deployment.endpoint,
        "CANONICAL_BUCKET": deployment.canonical_bucket,
        "CANONICAL_PREFIX": deployment.canonical_prefix,
        "INGRESS_BUCKET": deployment.ingress_bucket,
        "INGRESS_PREFIX": deployment.ingress_prefix,
        "PRESIGN_TTL_SECONDS": deployment.presign_ttl_seconds,
        "CANONICAL_READ_POLICY_SHA256": _policy_digest(
            policies["broker_canonical_reader"]),
        "INGRESS_PARENT_POLICY_SHA256": _policy_digest(
            policies["broker_ingress_parent"]),
    })
    config["secrets"] = {"required": list(BROKER_SECRET_NAMES)}
    return config


def publisher_config(deployment):
    """Generate the only role with native write paths to both buckets."""
    config = _worker_base(
        deployment,
        role="publisher",
        name=deployment.publisher_name,
        main="worker/publisher_stub.py",
    )
    config["vars"].update({
        "CANONICAL_PREFIX": deployment.canonical_prefix,
        "INGRESS_PREFIX": deployment.ingress_prefix,
    })
    config["r2_buckets"] = [
        {
            "binding": "INGRESS",
            "bucket_name": deployment.ingress_bucket,
            "jurisdiction": deployment.jurisdiction,
        },
        {
            "binding": "CANONICAL",
            "bucket_name": deployment.canonical_bucket,
            "jurisdiction": deployment.jurisdiction,
        },
    ]
    return config


def ingress_lifecycle(deployment):
    """Collect only loose object bytes; durable pile markers are excluded."""
    suffix = hashlib.sha256(
        f"{deployment.owner}:{deployment.ingress_prefix}".encode()
    ).hexdigest()[:16]
    return {
        "rules": [{
            "id": f"poc16-abandoned-stage-{suffix}",
            "enabled": True,
            "conditions": {
                "prefix": staging_prefix(deployment.workspace, "obj"),
            },
            "deleteObjectsTransition": {
                "condition": {
                    "type": "Age",
                    "maxAge": deployment.stage_retention_seconds,
                },
            },
        }],
    }


def generated_boundary(deployment):
    return {
        "broker": broker_config(deployment),
        "publisher": publisher_config(deployment),
        "access_policies": access_policies(deployment),
        "ingress_lifecycle": ingress_lifecycle(deployment),
        "provider_claim": {
            "kind": "isolated-ingress-presigned-put-v1",
            "live_verified": False,
            "canonical_raw_put_sha256_safe": False,
            "payload_mode": "UNSIGNED-PAYLOAD",
            "upload_protocol": UPLOAD_PROTOCOL,
            "upload_order": UPLOAD_ORDER,
            "session_nonce": "32-lowercase-hex",
            "object_key": (
                "ingress/v1/workspaces/<ws64>/objects/"
                "<nonce32>/<sha256>"
            ),
            "ready_marker_key": (
                "ingress/v1/workspaces/<ws64>/piles/"
                "<nonce32>/<member16>/<sha256>"
            ),
            "ready_marker_is_sole_durable_intent": True,
        },
    }


def endpoint_host(deployment):
    host = urlsplit(deployment.endpoint).hostname
    if host is None:
        raise ValueError("R2 endpoint")
    return host
