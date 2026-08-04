"""Direct S3-compatible provider adapter for :mod:`peerlog.cloud`.

Cloudflare R2 exposes the required suffix ranges, conditional PUTs, and
multipart UploadPartCopy through its S3 endpoint.  This adapter deliberately
wraps the repository's configured ``S3Store``/``R2S3Store`` so credentials,
endpoint validation, bucket-owner fencing, and physical prefixing remain in
one existing place.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from .cloud import (
    CloudMetrics,
    EPOCH_CAP,
    MULTIPART_EDGE,
    PartCopyUnavailable,
    VersionedObject,
)


MAX_CLOUD_READ = EPOCH_CAP + 2 * MULTIPART_EDGE


def _status(error):
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return None, None
    metadata = response.get("ResponseMetadata", {})
    detail = response.get("Error", {})
    return metadata.get("HTTPStatusCode"), detail.get("Code")


def _is(error, statuses, codes):
    status, code = _status(error)
    return status in statuses or code in codes


def _body(response):
    length = response.get("ContentLength")
    stream = response.get("Body")
    if type(length) is not int or length < 0 or length > MAX_CLOUD_READ \
            or stream is None:
        raise ValueError("cloud provider response")
    try:
        chunks = []
        remaining = length
        for _attempt in range(4096):
            if not remaining:
                return b"".join(chunks)
            chunk = stream.read(min(64 * 1024, remaining))
            if not isinstance(chunk, bytes) or not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raise ValueError("cloud provider response length")
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            close()


@dataclass
class _Upload:
    key: str
    provider_id: str
    parts: list


class S3Cloud:
    """Synchronous cloud queue effects over a configured S3-compatible store."""

    def __init__(self, configured_store):
        required = (
            "_read_args", "_put_args", "_read_client", "_mutation_client",
            "list", "config",
        )
        if any(not hasattr(configured_store, name) for name in required):
            raise TypeError("configured S3-compatible store required")
        self.store = configured_store
        self.metrics = CloudMetrics()
        self._metrics_lock = threading.Lock()
        self._uploads = {}

    def get(self, key, *, if_none_match=None, suffix=None):
        with self._metrics_lock:
            self.metrics.gets += 1
        request = self.store._read_args(key)
        if if_none_match is not None:
            with self._metrics_lock:
                self.metrics.conditional_gets += 1
            request["IfNoneMatch"] = if_none_match
        if suffix is not None:
            if type(suffix) is not int or suffix <= 0:
                raise ValueError("cloud suffix range")
            request["Range"] = f"bytes=-{suffix}"
        try:
            response = self.store._read_client.get_object(**request)
        except Exception as error:
            if _is(error, {304}, {"304", "NotModified"}):
                return None, if_none_match
            if _is(error, {404}, {"NoSuchKey", "NotFound"}):
                return None, None
            raise
        value = _body(response)
        token = response.get("ETag")
        if not isinstance(token, str) or not token:
            raise ValueError("cloud provider ETag")
        with self._metrics_lock:
            self.metrics.downloaded_bytes += len(value)
        return value, token

    def read_versioned(self, key):
        value, token = self.get(key)
        return VersionedObject(value, token)

    def create(self, key, value):
        self.metrics.puts += 1
        self.metrics.uploaded_bytes += len(value)
        self.metrics.object_upload_bytes += len(value)
        request = self.store._put_args(key, value)
        request["IfNoneMatch"] = "*"
        try:
            self.store._mutation_client.put_object(**request)
            return True
        except Exception as error:
            if not _is(error, {409, 412}, {
                    "ConditionalRequestConflict", "PreconditionFailed"}):
                raise
        incumbent, _token = self.get(key)
        if incumbent != value:
            raise ValueError("immutable object collision")
        return False

    def cas(self, key, token, value):
        self.metrics.cas += 1
        self.metrics.uploaded_bytes += len(value)
        self.metrics.register_upload_bytes += len(value)
        request = self.store._put_args(key, value)
        if token is None:
            request["IfNoneMatch"] = "*"
        else:
            request["IfMatch"] = token
        try:
            self.store._mutation_client.put_object(**request)
            return True
        except Exception as error:
            if _is(error, {409, 412}, {
                    "ConditionalRequestConflict", "PreconditionFailed"}):
                return False
            raise

    def list(self, prefix):
        self.metrics.lists += 1
        return tuple(self.store.list(prefix))

    def begin_multipart(self, key):
        request = self.store._read_args(key)
        self.metrics.multipart_creates += 1
        response = self.store._mutation_client.create_multipart_upload(**request)
        upload_id = response.get("UploadId")
        if not isinstance(upload_id, str) or not upload_id:
            raise ValueError("cloud multipart upload id")
        handle = object()
        self._uploads[handle] = _Upload(key, upload_id, [])
        return handle

    def _part_args(self, handle):
        upload = self._uploads.get(handle)
        if upload is None:
            raise ValueError("cloud multipart handle")
        args = self.store._read_args(upload.key)
        args.update({
            "UploadId": upload.provider_id,
            "PartNumber": len(upload.parts) + 1,
        })
        return upload, args

    def copy_part(self, handle, source_key, stop=None):
        upload, request = self._part_args(handle)
        source = self.store._read_args(source_key)
        request["CopySource"] = {
            "Bucket": source["Bucket"],
            "Key": source["Key"],
        }
        if stop is not None:
            if type(stop) is not int or stop < MULTIPART_EDGE:
                raise ValueError("cloud copied part edge")
            request["CopySourceRange"] = f"bytes=0-{stop - 1}"
        try:
            response = self.store._mutation_client.upload_part_copy(**request)
        except Exception as error:
            # A copy failure cannot expose a partial destination. The queue
            # aborts this upload and starts a bounded epoch from local tail
            # bytes, which is safe for unsupported and unreliable providers.
            raise PartCopyUnavailable("provider part copy unavailable") from error
        result = response.get("CopyPartResult", {})
        etag = result.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise PartCopyUnavailable("provider part copy response")
        upload.parts.append({"ETag": etag, "PartNumber": request["PartNumber"]})
        self.metrics.part_copies += 1
        if stop is not None:
            self.metrics.copied_bytes += stop

    def upload_part(self, handle, value):
        upload, request = self._part_args(handle)
        request["Body"] = value
        self.metrics.puts += 1
        self.metrics.uploaded_bytes += len(value)
        self.metrics.object_upload_bytes += len(value)
        response = self.store._mutation_client.upload_part(**request)
        etag = response.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise ValueError("cloud upload part response")
        upload.parts.append({"ETag": etag, "PartNumber": request["PartNumber"]})

    def complete_multipart(self, handle):
        upload = self._uploads.pop(handle, None)
        if upload is None or not upload.parts:
            raise ValueError("cloud multipart handle")
        request = self.store._read_args(upload.key)
        request.update({
            "UploadId": upload.provider_id,
            "MultipartUpload": {"Parts": upload.parts},
        })
        self.store._mutation_client.complete_multipart_upload(**request)
        self.metrics.multipart_completes += 1
        return None

    def abort_multipart(self, handle):
        upload = self._uploads.pop(handle, None)
        if upload is None:
            return
        request = self.store._read_args(upload.key)
        request["UploadId"] = upload.provider_id
        self.store._mutation_client.abort_multipart_upload(**request)


__all__ = ("S3Cloud",)
