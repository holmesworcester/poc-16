"""A live peer exposed solely as the passive GET/PUT sync surface."""
import hashlib
import threading

from core.fact import canon
from core.limits import MAX_WRITER_PACK_BYTES, decode_json

from .coverage import Coverage
from .fact import fid
from .ingest import PeerState, ingest
from .proof import decode_run, encode_run, prove_run
from .treap import snapshot
from .walk import OBJECT_PREFIX, ROOT_KEY

LOCATOR_PREFIX = "peerlog/fact/"
RUN_PREFIX = "peerlog/run/"
LOCATOR_FORMAT = "poc16-peer-locator-v1"


def locator_bytes(writer, seq):
    return canon([LOCATOR_FORMAT, writer.hex(), seq])


def decode_locator(raw):
    value = decode_json(raw, 512, "peer fact locator")
    if not isinstance(value, list) or len(value) != 3 \
            or value[0] != LOCATOR_FORMAT or canon(value) != raw:
        raise ValueError("peer fact locator")
    try:
        writer = bytes.fromhex(value[1])
    except (TypeError, ValueError) as error:
        raise ValueError("peer fact locator") from error
    if len(writer) != 32 or type(value[2]) is not int or value[2] < 0:
        raise ValueError("peer fact locator")
    return writer, value[2]


class PeerEndpoint:
    """Stable pages plus dynamic closed-run reads and verified run PUTs."""

    def __init__(self, state=None, coverage=None, endpoint_id=None):
        self.state = state or PeerState()
        self.coverage = coverage or Coverage(())
        self.state.coverage = self.coverage
        self.endpoint_id = endpoint_id or hashlib.sha256(
            str(id(self)).encode()).digest()
        self._objects = {}
        self._lock = threading.RLock()
        self.get_calls = []
        self.put_calls = []
        self.received_bytes = 0
        self.sent_bytes = 0
        self.refresh()

    def refresh(self):
        with self._lock, self.state.lock:
            built = snapshot(self.state.treap, self.coverage)
            for oid, raw in built.objects:
                self._objects.setdefault(OBJECT_PREFIX + oid.hex(), raw)
            self._objects[ROOT_KEY] = built.root
            for writer, log in self.state.logs.items():
                for seq in log._facts:
                    fact_id = fid(log.fact(seq)).decode("ascii")
                    self._objects[LOCATOR_PREFIX + fact_id] = locator_bytes(writer, seq)

    def get(self, key, rng=None):
        with self._lock:
            self.get_calls.append(key)
            if key.startswith(RUN_PREFIX):
                writer, lo, hi = _parse_run_key(key)
                log = self.state.logs.get(writer)
                raw = None if log is None else encode_run(prove_run(log, lo, hi))
            else:
                raw = self._objects.get(key)
            if isinstance(rng, tuple) and len(rng) == 2 \
                    and rng[0] == "if-none-match":
                if raw is not None and hashlib.sha256(raw).hexdigest() == rng[1]:
                    return None
                rng = None
            if raw is not None and rng is not None:
                lo, hi = rng
                raw = raw[lo:hi]
            if raw is not None:
                self.sent_bytes += len(raw)
            return raw

    def put(self, key, val):
        if not isinstance(val, bytes):
            raise ValueError("peer PUT bytes")
        with self._lock:
            self.put_calls.append(key)
            self.received_bytes += len(val)
            if key.startswith(RUN_PREFIX):
                run = decode_run(val)
                if key != run_key(run.writer, run.lo, run.hi):
                    raise ValueError("peer run key")
                ingest(self.state, run)
                self.refresh()
                return
            if key.startswith(OBJECT_PREFIX):
                oid = key.removeprefix(OBJECT_PREFIX)
                if oid != hashlib.sha256(val).hexdigest():
                    raise ValueError("immutable object key")
                incumbent = self._objects.setdefault(key, val)
                if incumbent != val:
                    raise ValueError("immutable object collision")
                return
            if key == ROOT_KEY:
                self._objects[key] = val
                return
            raise ValueError("peer PUT key")


def run_key(writer, lo, hi):
    if not isinstance(writer, bytes) or len(writer) != 32 \
            or type(lo) is not int or type(hi) is not int or lo < 0 or hi <= lo:
        raise ValueError("peer run key")
    return f"{RUN_PREFIX}{writer.hex()}/{lo}/{hi}"


def _parse_run_key(key):
    try:
        writer_hex, lo, hi = key.removeprefix(RUN_PREFIX).split("/")
        writer = bytes.fromhex(writer_hex)
        lo, hi = int(lo), int(hi)
    except (TypeError, ValueError) as error:
        raise ValueError("peer run key") from error
    if run_key(writer, lo, hi) != key:
        raise ValueError("peer run key")
    return writer, lo, hi
