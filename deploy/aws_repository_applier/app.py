"""AWS binding for one caller-named exact RepositoryApplier transition.

The private Lambda invocation is the work item: one workspace, one immutable
ingress key, and its digest.  This module never accepts S3 notifications or
batches and never discovers, queues, schedules, or deletes work.
"""
import asyncio
import os

from adapters.s3 import S3Config, S3Store
from core.repository_applier import RepositoryApplier
from core.shape import valid_fid
from core.staged_intent import parse_staging_key
from deploy.repository_apply_wire import (
    decode_apply_request,
    encode_apply_result,
)


_stores = None


def _required(name):
    value = os.environ.get(name)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"missing {name}")
    return value


def _owner():
    value = _required("TINYP2P_UPLOAD_EXPECTED_BUCKET_OWNER")
    if len(value) != 12 or not value.isdigit():
        raise RuntimeError("invalid expected S3 bucket owner")
    return value


def _workspace():
    value = _required("TINYP2P_UPLOAD_WORKSPACE_ID")
    if not valid_fid(value):
        raise RuntimeError("invalid workspace")
    return value


def _repository_stores():
    """Construct separate canonical and ingress adapters once per sandbox."""
    global _stores
    if _stores is None:
        canonical_bucket = _required(
            "TINYP2P_UPLOAD_CANONICAL_BUCKET")
        ingress_bucket = _required("TINYP2P_UPLOAD_INGRESS_BUCKET")
        if canonical_bucket == ingress_bucket:
            raise RuntimeError(
                "canonical and ingress buckets must differ")
        common = {
            "region_name": _required("AWS_REGION"),
            "expected_bucket_owner": _owner(),
            "read_total_max_attempts": 1,
            "probe_access_denied_missing": False,
            # The applier has only conditional writes. A hidden existing key
            # therefore fails its create/CAS instead of being overwritten.
            "access_denied_is_absent": True,
        }
        _stores = (
            S3Store(S3Config(
                bucket=canonical_bucket,
                prefix=_required("TINYP2P_UPLOAD_CANONICAL_PREFIX"),
                **common,
            )),
            S3Store(S3Config(
                bucket=ingress_bucket,
                prefix="",
                **common,
            )),
        )
    return _stores


def _exact_request(request, workspace):
    """Validate the complete private invocation and its staged-key binding."""
    requested_workspace, key, digest = decode_apply_request(request)
    if requested_workspace != workspace:
        raise ValueError("AWS applier request binding")
    address = parse_staging_key(key)
    if address.workspace != workspace \
            or address.object_class != "pile" \
            or address.digest != digest:
        raise ValueError("AWS applier source binding")
    return key, digest


async def apply_request(
        request, *, canonical=None, ingress=None, workspace=None):
    """Apply exactly one privately named immutable ingress pile."""
    workspace = _workspace() if workspace is None else workspace
    if not valid_fid(workspace):
        raise ValueError("repository workspace")
    if canonical is None or ingress is None:
        configured_canonical, configured_ingress = _repository_stores()
        canonical = configured_canonical if canonical is None else canonical
        ingress = configured_ingress if ingress is None else ingress
    key, digest = _exact_request(request, workspace)
    return await RepositoryApplier(
        workspace, canonical,
    ).apply_exact(ingress, key, digest)


def handler(event, _context):
    """Return the same small typed result as the private Worker RPC."""
    return encode_apply_result(asyncio.run(apply_request(event)))


__all__ = ("apply_request", "handler")
