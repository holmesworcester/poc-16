"""Direct-provider fakes for adapter wiring and deterministic fault probes."""
import asyncio
from dataclasses import dataclass
import io
import threading


class ProviderError(Exception):
    def __init__(self, status, code=None):
        super().__init__(code or str(status))
        self.response = {
            "ResponseMetadata": {"HTTPStatusCode": status},
            "Error": {"Code": code or str(status)},
        }


class AtomicBody(io.BytesIO):
    def __init__(self, value, on_read=None):
        super().__init__(value)
        self.on_read = on_read

    def read(self, *args):
        if self.on_read is not None:
            callback, self.on_read = self.on_read, None
            callback()
        return super().read(*args)


class BrokenBody:
    def __init__(self):
        self.closed = False

    @staticmethod
    def read(_amount):
        raise ConnectionError("scripted truncated response")

    def close(self):
        self.closed = True


class FakeS3Bucket:
    """Strong per-key fake with value-ABA tokens and cursor pagination."""

    def __init__(self, *, page_size=3):
        self.data = {}
        self.tokens = {}
        self.value_tokens = {}
        self.generation = 0
        self.page_size = page_size
        self.lock = threading.Lock()
        self.history = []
        self.drop_after_apply = 0
        self.deny_missing_get = False
        self.body_factory = None
        self.insert_after_page = None

    def client(self, actor):
        return FakeS3Client(self, actor)

    def _etag(self, value):
        token = self.value_tokens.get(value)
        if token is None:
            self.generation += 1
            token = f'"opaque-value-{self.generation}"'
            self.value_tokens[value] = token
        return token

    def _record(self, actor, operation, key, result):
        self.history.append((actor, operation, key, result))


class FakeS3Client:
    def __init__(self, bucket, actor):
        self.bucket, self.actor = bucket, actor

    def get_object(self, **request):
        key = request["Key"]
        with self.bucket.lock:
            if key not in self.bucket.data:
                status = 403 if self.bucket.deny_missing_get else 404
                code = "AccessDenied" if status == 403 else "NoSuchKey"
                raise ProviderError(status, code)
            value = self.bucket.data[key]
            token = self.bucket.tokens[key]
            factory = self.bucket.body_factory
            body = factory(value) if factory is not None else AtomicBody(value)
            self.bucket._record(
                self.actor, "get", key, (value, token))
            return {
                "Body": body,
                "ContentLength": len(value),
                "ETag": token,
            }

    def head_object(self, **request):
        key = request["Key"]
        with self.bucket.lock:
            if key not in self.bucket.data:
                raise ProviderError(404, "NotFound")
            return {"ETag": self.bucket.tokens[key]}

    def put_object(self, **request):
        key, value = request["Key"], bytes(request["Body"])
        with self.bucket.lock:
            if request.get("IfNoneMatch") == "*" \
                    and key in self.bucket.data:
                raise ProviderError(412, "PreconditionFailed")
            expected = request.get("IfMatch")
            if expected is not None \
                    and self.bucket.tokens.get(key) != expected:
                raise ProviderError(412, "PreconditionFailed")
            token = self.bucket._etag(value)
            self.bucket.data[key] = value
            self.bucket.tokens[key] = token
            self.bucket._record(self.actor, "put", key, token)
            if self.bucket.drop_after_apply:
                self.bucket.drop_after_apply -= 1
                raise ConnectionError("scripted response loss after apply")
            return {"ETag": token}

    def list_objects_v2(self, **request):
        prefix = request["Prefix"]
        cursor = request.get("ContinuationToken")
        limit = min(request["MaxKeys"], self.bucket.page_size)
        with self.bucket.lock:
            keys = sorted(
                key for key in self.bucket.data
                if key.startswith(prefix)
                and (cursor is None or key > cursor)
            )
            page = keys[:limit]
            truncated = len(keys) > limit
            response = {
                "Contents": [{"Key": key} for key in page],
                "IsTruncated": truncated,
            }
            if truncated:
                response["NextContinuationToken"] = page[-1]
            self.bucket._record(
                self.actor, "list", prefix, tuple(page))
            insertion = self.bucket.insert_after_page
            self.bucket.insert_after_page = None
            if insertion is not None:
                key, value = insertion
                self.bucket.data[key] = value
                self.bucket.tokens[key] = self.bucket._etag(value)
            return response

    def delete_object(self, **request):
        key = request["Key"]
        with self.bucket.lock:
            self.bucket.data.pop(key, None)
            self.bucket.tokens.pop(key, None)
            self.bucket._record(self.actor, "delete", key, None)


@dataclass
class R2Page:
    objects: list
    truncated: bool
    cursor: str | None = None


class R2Object:
    def __init__(self, key, value, etag):
        self.key, self.value, self.etag = key, value, etag
        self.size = len(value)

    async def arrayBuffer(self):
        return self.value


class OneShotAsyncBarrier:
    """Release exactly one group of awaited fake-provider operations."""

    def __init__(self, parties):
        self.parties = parties
        self.arrivals = 0
        self.released = False
        self._event = asyncio.Event()

    async def wait(self):
        if self.released:
            return
        self.arrivals += 1
        if self.arrivals == self.parties:
            self.released = True
            self._event.set()
        await self._event.wait()


class FakeR2Bucket:
    """Async binding fake with the same value-ABA token schedule."""

    def __init__(self, *, page_size=3):
        self.data = {}
        self.tokens = {}
        self.value_tokens = {}
        self.generation = 0
        self.page_size = page_size
        self.history = []
        self.conditional_barrier = None

    def _etag(self, value):
        token = self.value_tokens.get(value)
        if token is None:
            self.generation += 1
            token = f"opaque-r2-value-{self.generation}"
            self.value_tokens[value] = token
        return token

    async def get(self, key):
        self.history.append(("get", key))
        if key not in self.data:
            return None
        return R2Object(key, self.data[key], self.tokens[key])

    async def head(self, key):
        self.history.append(("head", key))
        if key not in self.data:
            return None
        return R2Object(key, b"", self.tokens[key])

    async def put(self, key, value, **options):
        self.history.append(("put", key, options))
        condition = options.get("onlyIf")
        if isinstance(condition, dict) and "etagMatches" in condition \
                and self.conditional_barrier is not None:
            await self.conditional_barrier.wait()
        if isinstance(condition, dict) \
                and condition.get("If-None-Match") == "*" \
                and key in self.data:
            return None
        if isinstance(condition, dict) and "etagMatches" in condition \
                and self.tokens.get(key) != condition["etagMatches"]:
            return None
        value = bytes(value)
        self.data[key] = value
        self.tokens[key] = self._etag(value)
        return R2Object(key, b"", self.tokens[key])

    async def list(self, prefix, limit, cursor=None):
        self.history.append(("list", prefix, limit, cursor))
        keys = sorted(key for key in self.data if key.startswith(prefix))
        start = int(cursor or 0)
        stop = min(len(keys), start + self.page_size)
        return R2Page(
            [
                R2Object(key, b"", self.tokens[key])
                for key in keys[start:stop]
            ],
            stop < len(keys),
            str(stop) if stop < len(keys) else None,
        )

    async def delete(self, key):
        self.history.append(("delete", key))
        self.data.pop(key, None)
        self.tokens.pop(key, None)


def provider_store(kind, directory, *, prefix="tenant"):
    """Build one provider-neutral store over the realistic shared fakes."""
    from adapters.r2 import R2BindingStore
    from adapters.s3 import S3Config, S3Store
    from core.store import FsStore

    if kind == "fs":
        return FsStore(str(directory))
    if kind == "s3":
        return S3Store(
            S3Config(
                "receipt-bucket",
                prefix,
                read_total_max_attempts=1,
            ),
            client=FakeS3Bucket().client("applier"),
        )
    if kind == "r2":
        return R2BindingStore(FakeR2Bucket(), prefix)
    raise ValueError("provider store kind")
