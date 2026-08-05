"""Dense own-writer streams and honest island copies for foreign writers."""
from dataclasses import dataclass
import struct

from nacl import signing
from nacl.exceptions import BadSignatureError

from core.fact import canon

from .fact import Fact, canonical, decode_slice, encode_slice, is_control
from .tree import IncrementalTree

HEAD_DOMAIN = "poc16-peer-writer-head-v1"
EMPTY_ROOT = __import__("hashlib").sha256(b"peerlog/seq/empty/v1").digest()


def valid_writer(value):
    return isinstance(value, bytes) and len(value) == 32


@dataclass(frozen=True)
class Head:
    writer: bytes
    seq: int
    root: bytes
    control_root: bytes
    sig: bytes

    def __post_init__(self):
        if not valid_writer(self.writer) or type(self.seq) is not int \
                or self.seq < -1 or self.seq >= 1 << 63 \
                or not isinstance(self.root, bytes) \
                or len(self.root) != 32 or not isinstance(self.control_root, bytes) \
                or len(self.control_root) != 32 or not isinstance(self.sig, bytes) \
                or len(self.sig) != 64:
            raise ValueError("writer head")


def _head_message(writer, seq, tree_root, control_root):
    return canon([
        HEAD_DOMAIN, writer.hex(), seq, tree_root.hex(), control_root.hex(),
    ])


def verify_head(head):
    if not isinstance(head, Head):
        return False
    try:
        signing.VerifyKey(head.writer).verify(
            _head_message(head.writer, head.seq, head.root, head.control_root),
            head.sig,
        )
        return True
    except (BadSignatureError, TypeError, ValueError):
        return False


def encode_head(head):
    if not isinstance(head, Head) or not verify_head(head):
        raise ValueError("writer head")
    return b"P16H2\x00" + head.writer + struct.pack(">q", head.seq) \
        + head.root + head.control_root + head.sig


def decode_head(raw):
    if not isinstance(raw, bytes) or len(raw) != 174 \
            or not raw.startswith(b"P16H2\x00"):
        raise ValueError("peer writer head")
    try:
        head = Head(
            raw[6:38], struct.unpack(">q", raw[38:46])[0],
            raw[46:78], raw[78:110], raw[110:174],
        )
    except (TypeError, ValueError, struct.error) as error:
        raise ValueError("peer writer head") from error
    if not verify_head(head) or encode_head(head) != raw:
        raise ValueError("peer writer head")
    return head


class WriterLog:
    def __init__(self, writer: bytes, secret=None):
        if secret is not None and not isinstance(secret, signing.SigningKey):
            raise ValueError("writer secret")
        if secret is not None and writer != bytes(secret.verify_key):
            raise ValueError("writer secret binding")
        if not valid_writer(writer):
            raise ValueError("writer")
        self.writer = writer
        self._secret = secret
        self._facts = {}
        self._paths = {}
        self._head = None
        self._tree = IncrementalTree() if secret is not None else None
        self._control_tree = IncrementalTree() if secret is not None else None
        self._next_owned_seq = 0 if secret is not None else None

    @classmethod
    def owned(cls, secret=None):
        secret = secret or signing.SigningKey.generate()
        return cls(bytes(secret.verify_key), secret)

    def append(self, fact: Fact) -> int:
        """Own-log only; returns the assigned zero-based seq."""
        if self._secret is None:
            raise ValueError("foreign writer log")
        if not isinstance(fact, Fact):
            raise ValueError("fact")
        seq = self._next_owned_seq
        if len(self._facts) != seq:
            raise ValueError("own writer log gap")
        self._facts[seq] = fact
        raw = canonical(fact)
        self._tree.append(raw)
        if is_control(fact):
            self._control_tree.append(raw)
        self._next_owned_seq += 1
        self._sign_head()
        return seq

    def slice(self, lo: int, hi: int) -> bytes:
        """Canonical bytes for seqs [lo, hi); raises on any gap."""
        if type(lo) is not int or type(hi) is not int or lo < 0 or hi <= lo:
            raise ValueError("writer slice")
        try:
            facts = tuple(self._facts[seq] for seq in range(lo, hi))
        except KeyError as error:
            raise ValueError("writer slice gap") from error
        return encode_slice(facts)

    def coverage(self) -> tuple[tuple[int, int], ...]:
        """Contiguous (lo, hi) seq intervals held locally."""
        intervals = []
        for seq in sorted(self._facts):
            if intervals and intervals[-1][1] == seq:
                intervals[-1] = (intervals[-1][0], seq + 1)
            else:
                intervals.append((seq, seq + 1))
        return tuple(intervals)

    def head(self) -> Head:
        """Latest signed head observed (own log: latest appended)."""
        if self._head is None:
            if self._secret is None:
                raise ValueError("writer head unavailable")
            self._sign_head()
        return self._head

    def fact(self, seq):
        try:
            return self._facts[seq]
        except KeyError as error:
            raise ValueError("writer sequence unavailable") from error

    def _sign_head(self):
        tree_root = self._tree.root()
        control_root = self._control_tree.root()
        seq = len(self._facts) - 1
        message = _head_message(self.writer, seq, tree_root, control_root)
        self._head = Head(
            self.writer, seq, tree_root, control_root,
            self._secret.sign(message).signature,
        )

    def _install(self, lo, facts, head):
        """Install an already verified run without exposing partial mutation."""
        if head.writer != self.writer:
            raise ValueError("writer mismatch")
        replacements = dict(self._facts)
        for offset, fact in enumerate(facts):
            seq = lo + offset
            incumbent = replacements.get(seq)
            if incumbent is not None and canonical(incumbent) != canonical(fact):
                raise ValueError("writer equivocation")
            replacements[seq] = fact
        self._facts = replacements
        if self._head is None or head.seq > self._head.seq:
            self._head = head

    def _raw(self, seq):
        return canonical(self.fact(seq))

    def __len__(self):
        return len(self._facts)
