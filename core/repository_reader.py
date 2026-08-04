"""One side-effect-free view pinned to exact published repository bytes."""
from dataclasses import dataclass

from . import snapshot
from .crypto import h
from .object_store import StoreError, verified_object
from .limits import MAX_OBJECT_BYTES, PayloadTooLarge
from .validated_set import ValidatedView, reconstruct
from .worker import WorkerView


class _ObjectMiss(BaseException):
    """Escape fail-closed synchronous policy code to one awaited fetch loop."""

    __slots__ = ("oid",)

    def __init__(self, oid):
        super().__init__(oid)
        self.oid = oid


class RepositoryRootError(ValueError):
    """The exact root cannot open a Reader for the named workspace."""


@dataclass(frozen=True, slots=True)
class RepositoryReader:
    """Read authenticated state without LIST, SQL, turns, or mutations.

    Provider and daemon adapters fetch one named root register, then construct this
    object with an immutable-object callback.  Every answer from the instance
    is therefore explainable by the same pinned root even if another applier
    commits concurrently.
    """

    workspace: str
    root_bytes: bytes
    fetch: object

    def __post_init__(self):
        if not isinstance(self.root_bytes, bytes) or not callable(self.fetch):
            raise TypeError("repository reader")
        try:
            root = snapshot.decode_root(self.root_bytes)
        except (TypeError, ValueError) as error:
            raise RepositoryRootError(str(error)) from error
        if root.anchor != self.workspace:
            raise RepositoryRootError("repository reader workspace")

    @property
    def etag(self):
        return h(self.root_bytes)

    @property
    def root(self):
        return snapshot.decode_root(self.root_bytes)

    def worker(self):
        """Return the bounded authorization/query view at this exact root."""
        return WorkerView.from_root(self.root_bytes, self.fetch)

    def validated(self):
        """Return authenticated validated-fact point/range reads."""
        return ValidatedView(self.root_bytes, self.fetch)

    def all_facts(self):
        """Verify and return the complete root-reachable validated set."""
        return reconstruct(self.root_bytes, self.fetch)

    def object(self, oid):
        """Read one hash-verified immutable object through the pinned reader."""
        return verified_object(
            oid, self.fetch, max_bytes=MAX_OBJECT_BYTES)

    def mint(self, pile_bytes, trusted_now, *, purpose="sync"):
        """Run the family authorization hook against this exact root."""
        return self.worker().mint(
            pile_bytes, trusted_now, purpose=purpose)

    @classmethod
    async def answer_awaited(
            cls, workspace, root_bytes, fetch, answer, *,
            max_unique_fetches, max_fetch_bytes):
        """Run one synchronous Reader answer over bounded awaited fetches."""
        if type(max_unique_fetches) is not int or max_unique_fetches < 0:
            raise ValueError("reader unique-fetch budget")
        if type(max_fetch_bytes) is not int or max_fetch_bytes < 0:
            raise ValueError("reader byte budget")
        if not callable(fetch) or not callable(answer):
            raise TypeError("awaited reader operation")

        cache = {}
        fetched_bytes = 0

        def cached_fetch(oid):
            if oid not in cache:
                raise _ObjectMiss(oid)
            return cache[oid]

        reader = cls(workspace, root_bytes, cached_fetch)
        while True:
            try:
                return answer(reader)
            except _ObjectMiss as miss:
                oid = miss.oid

            if oid in cache or len(cache) >= max_unique_fetches:
                return None
            try:
                raw = await fetch(oid)
            except (PayloadTooLarge, StoreError):
                # Provider failure is not an authorization denial.  Let the
                # request boundary report it as unavailable; semantic misses
                # still fail closed below.
                raise
            except Exception:
                return None
            if raw is not None and not isinstance(raw, bytes):
                return None
            fetched_bytes += len(raw) if raw is not None else 0
            if fetched_bytes > max_fetch_bytes:
                return None
            cache[oid] = raw

    @classmethod
    async def mint_awaited(
            cls, workspace, root_bytes, fetch, pile_bytes, trusted_now, *,
            max_unique_fetches, max_fetch_bytes, purpose="sync"):
        """Adapt awaited object I/O without creating another read engine."""
        return await cls.answer_awaited(
            workspace,
            root_bytes,
            fetch,
            lambda reader: reader.mint(
                pile_bytes, trusted_now, purpose=purpose),
            max_unique_fetches=max_unique_fetches,
            max_fetch_bytes=max_fetch_bytes,
        )
