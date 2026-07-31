"""AWS scheduling adapter for the shared database-free RepositoryApplier.

S3 notifications and scheduled invocations are discovery hints only.  Every
exact marker is fetched from isolated ingress and translated by the same
``RepositoryApplier.apply_staged`` method used by filesystem and Cloudflare
compositions.  This module owns AWS configuration and event normalization;
it contains no repository policy, tree, or CAS algorithm.
"""
import asyncio
from dataclasses import dataclass
import os
from urllib.parse import unquote_plus

from adapters.s3 import S3Config, S3Store
from core.repository_applier import RepositoryApplier
from core.shape import valid_fid
from core.staged_intent import parse_staging_key, staging_prefix


_stores = None
MAX_EVENT_RECORDS = 256
_FINISHED = frozenset({
    "admitted",
    "applied",
    "confirmed",
    "noop",
    "rejected",
    "rejected-staging",
})


@dataclass(frozen=True, slots=True)
class DrainResult:
    """One invocation's internal work, staged work, and rejected hints."""

    internal: tuple
    staged: tuple
    rejected_hints: int = 0


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
        ingress_bucket = _required(
            "TINYP2P_UPLOAD_INGRESS_BUCKET")
        if canonical_bucket == ingress_bucket:
            raise RuntimeError(
                "canonical and ingress buckets must differ")
        common = {
            "region_name": _required("AWS_REGION"),
            "expected_bucket_owner": _owner(),
            "read_total_max_attempts": 1,
            "probe_access_denied_missing": True,
        }
        canonical = S3Store(S3Config(
            bucket=canonical_bucket,
            prefix=_required("TINYP2P_UPLOAD_CANONICAL_PREFIX"),
            **common,
        ))
        ingress = S3Store(S3Config(
            bucket=ingress_bucket,
            prefix="",
            **common,
        ))
        _stores = canonical, ingress
    return _stores


def _event_keys(event, workspace, ingress_bucket):
    """Extract exact same-bucket pile markers from an S3 notification."""
    if not isinstance(event, dict):
        raise ValueError("AWS applier event")
    records = event.get("Records")
    if records is None:
        return ()
    if not isinstance(records, list):
        raise ValueError("AWS applier records")
    if len(records) > MAX_EVENT_RECORDS:
        raise ValueError("AWS applier record budget")
    prefix = staging_prefix(workspace, "pile")
    keys, rejected = set(), 0
    for record in records:
        try:
            s3 = record.get("s3") if isinstance(record, dict) else None
            bucket = s3.get("bucket") if isinstance(s3, dict) else None
            item = s3.get("object") if isinstance(s3, dict) else None
            name = bucket.get("name") if isinstance(bucket, dict) else None
            encoded = item.get("key") if isinstance(item, dict) else None
            if name != ingress_bucket or not isinstance(encoded, str):
                raise ValueError("AWS applier record binding")
            key = unquote_plus(encoded)
            address = parse_staging_key(key)
            if address.workspace != workspace \
                    or address.object_class != "pile" \
                    or not key.startswith(prefix):
                raise ValueError("AWS applier marker")
            keys.add(key)
        except (TypeError, ValueError):
            rejected += 1
    return tuple(sorted(keys)), rejected


async def drain(event, *, canonical=None, ingress=None, workspace=None):
    """Run exact notified markers, or one scheduled LIST snapshot."""
    workspace = _workspace() if workspace is None else workspace
    if not valid_fid(workspace):
        raise ValueError("repository workspace")
    if canonical is None or ingress is None:
        configured_canonical, configured_ingress = _repository_stores()
        canonical = configured_canonical if canonical is None else canonical
        ingress = configured_ingress if ingress is None else ingress
    applier = RepositoryApplier(workspace, canonical)
    internal = await applier.turn()
    bucket = os.environ.get("TINYP2P_UPLOAD_INGRESS_BUCKET", "")
    notified = isinstance(event, dict) and "Records" in event
    if notified:
        keys, rejected = _event_keys(
            event, workspace, bucket)
    else:
        keys, rejected = (), 0
    if notified:
        outcomes = []
        for key in keys:
            try:
                outcomes.append((key, await applier.apply_staged(
                    ingress, key)))
            except Exception as error:
                outcomes.append((key, error))
        return DrainResult(internal, tuple(outcomes), rejected)
    return DrainResult(
        internal,
        await applier.drain_staged(ingress),
        rejected,
    )


def handler(event, _context):
    """Lambda entrypoint with a bounded, secret-free result summary."""
    result = asyncio.run(drain(event))
    outcomes = tuple(
        item.error if item.error is not None else item.result
        for item in result.internal
    ) + tuple(
        outcome for _, outcome in result.staged)
    applied = sum(
        not isinstance(outcome, Exception)
        and outcome is not None
        and (
            outcome.status in _FINISHED
            if hasattr(outcome, "status")
            else outcome.result.status in _FINISHED
        )
        for outcome in outcomes
    )
    failed = sum(
        isinstance(outcome, Exception)
        for outcome in outcomes
    ) + result.rejected_hints
    return {
        "applied": applied,
        "discovered": len(outcomes) + result.rejected_hints,
        "failed": failed,
    }


__all__ = ("drain", "handler")
