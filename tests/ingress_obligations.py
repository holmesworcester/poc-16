"""Replayable proof obligations for destructive shared-ingress retirement.

Safety law
==========

An acknowledged shared pile ``(key, exact_bytes)`` remains an obligation
until a DELETE of that exact value cites one of two durable witnesses:

* a committed, authenticated root whose validated set contains every
  durable ``Valid`` minted for those bytes; or
* exact, read-back rejection payload and typed permanent-rejection metadata.

CAS attempts, retry counts, local catalogs, and local diagnostics are not
witnesses.  An unknown CAS result must first reconcile to a committed root.
LIST may delay an obligation, but may never erase one.
"""
import ast
from dataclasses import dataclass
from pathlib import Path

import facts

from core.validated_set import reconstruct
from core.close import decode_pile
from core.crypto import h
from core.fact import canon
from core.ingress import (
    KernelRejected,
    PermanentIngressRejection,
    check_source,
    decode_rejection_record,
)
from core.kernel import drain
from core.limits import (
    MAX_REJECTION_RECORD_BYTES,
    decode_json,
)
from core.object_store import CREATED, Applied


@dataclass(frozen=True)
class PublicationObservation:
    """Runtime classification made after validation and before retirement."""

    seq: int
    key: str
    raw: bytes
    validated_fids: frozenset[str]


@dataclass(frozen=True)
class Obligation:
    key: str
    raw: bytes
    created_seq: int


@dataclass(frozen=True)
class Discharge:
    key: str
    raw: bytes
    delete_seq: int
    witness: str
    witness_seq: int


@dataclass(frozen=True)
class ObligationReport:
    discharges: tuple[Discharge, ...]
    live: tuple[Obligation, ...]


class ObligationViolation(AssertionError):
    """The first destructive event unsupported by its preceding trace."""

    def __init__(self, event, reason, prefix, diagnostic):
        self.event = event
        self.reason = reason
        self.prefix = tuple(prefix)
        message = (
            f"event #{event.seq}: unsupported DELETE {event.key}: {reason}")
        if diagnostic:
            message += "\n" + diagnostic
        super().__init__(message)


@dataclass(frozen=True)
class CallSite:
    path: str
    function: str
    line: int
    receiver: str
    use: str


@dataclass(frozen=True)
class _Snapshot:
    seq: int
    root: bytes
    objects: tuple


def _record(raw, maximum, fields):
    value = decode_json(raw, maximum, "F10 evidence")
    if not isinstance(value, dict) or set(value) != set(fields) \
            or canon(value) != raw:
        raise ValueError("F10 evidence")
    return value


class ObligationTrace:
    """Check pile lifetimes against authenticated publication/rejection proof."""

    def __init__(self, bucket, workspace):
        self.bucket = bucket
        self.workspace = workspace
        self.observations = []
        self._snapshot_fids = {}
        self._snapshot_errors = {}

    def observe_node_retirement(self, node, workspace, key, raw):
        """Record the production runtime's post-commit classification.

        Permanent decoder/kernel rejection deliberately records no
        publication witness; that path must stand on its durable rejection
        evidence instead.
        """
        if workspace != self.workspace:
            raise AssertionError("workspace mismatch")
        try:
            stream = decode_pile(raw, workspace)
            judgment = drain(stream, workspace)
        except PermanentIngressRejection:
            return None
        if not judgment.ok:
            return None
        validated_fids = frozenset(
            receipt.fact.fid for receipt in judgment.valids
            if facts.family_for(receipt.fact.t).DURABLE)
        observation = PublicationObservation(
            len(self.bucket.history), key, raw, validated_fids)
        self.observations.append(observation)
        return observation

    def observe_publication(self, key, raw, validated_fids):
        """Add an explicit observation for small checker mutation tests."""
        observation = PublicationObservation(
            len(self.bucket.history), key, raw,
            frozenset(validated_fids))
        self.observations.append(observation)
        return observation

    def check(self):
        """Return all discharges/live obligations or fail at the first DELETE."""
        self.bucket.assert_valid_history()
        data = dict(self.bucket.initial)
        obligations = {
            key: Obligation(key, raw, 0)
            for key, raw in data.items() if key.startswith("pile/")
        }
        verified = {}
        definite_creates = {}
        ambiguous = self._ambiguous_mutations()
        discharges = []

        for event in self.bucket.history:
            if event.op == "get":
                if event.key.startswith((
                        "failed/", "applier/generation/",
                        "applier/spent/",
                )) \
                        and event.result is not None:
                    verified[event.key] = (event.seq, event.result)
            elif event.op == "put":
                self._apply_create(event, data, obligations)
            elif event.op == "put_if_absent":
                if event.result is CREATED:
                    self._apply_create(event, data, obligations)
                    if event.seq not in ambiguous:
                        definite_creates.setdefault(
                            event.key, []).append((
                                event.seq, event.value, event.actor))
            elif event.op == "cas":
                if isinstance(event.result, Applied):
                    data[event.key] = event.value
            elif event.op == "delete":
                if event.key.startswith("pile/") and event.result:
                    obligation = obligations.get(event.key)
                    if obligation is None:
                        self._fail(
                            event, "no live acknowledged pile obligation")
                    publication, publication_reason = \
                        self._publication_witness(obligation, event.seq)
                    rejection, rejection_reason = self._rejection_witness(
                        obligation, event, data, verified, definite_creates)
                    witness = publication or rejection
                    if witness is None:
                        self._fail(
                            event,
                            f"{publication_reason}; {rejection_reason}")
                    discharges.append(Discharge(
                        obligation.key, obligation.raw, event.seq,
                        witness[0], witness[1]))
                    obligations.pop(event.key)
                data.pop(event.key, None)

        return ObligationReport(
            tuple(discharges),
            tuple(sorted(
                obligations.values(),
                key=lambda item: (item.created_seq, item.key))))

    def _apply_create(self, event, data, obligations):
        previous = data.get(event.key)
        if event.key.startswith("pile/"):
            if previous is not None and previous != event.value:
                self._fail(
                    event,
                    "content-addressed pile key was destructively overwritten")
            if previous is None:
                obligations[event.key] = Obligation(
                    event.key, event.value, event.seq)
        data[event.key] = event.value

    def _publication_witness(self, obligation, delete_seq):
        candidates = [
            observation for observation in self.observations
            if observation.key == obligation.key
            and observation.raw == obligation.raw
            and obligation.created_seq <= observation.seq < delete_seq
        ]
        if not candidates:
            return None, (
                "no post-create runtime publication classification "
                "for the exact bytes")
        reasons = []
        for observation in candidates:
            current = max(
                (
                    snapshot for snapshot in self._snapshots()
                    if snapshot.seq <= observation.seq
                ),
                key=lambda snapshot: snapshot.seq,
                default=None)
            if current is None:
                continue
            try:
                validated_fids = self._validated_snapshot(current)
            except Exception as error:
                reasons.append(
                    f"current root at event #{current.seq} is not "
                    f"authenticated: {type(error).__name__}: {error}")
                continue
            if observation.validated_fids <= validated_fids:
                return ("publication", current.seq), ""
            reasons.append(
                "current committed root does not contain every "
                "kernel-valid durable fact")
        return None, reasons[-1] if reasons else (
            "current committed root does not contain every "
            "kernel-valid durable fact")

    def _rejection_witness(
            self, obligation, deletion, data, verified, definite_creates):
        delete_seq = deletion.seq
        try:
            binding = check_source(obligation.key, obligation.raw)
        except ValueError:
            return None, "rejected obligation has no exact generation binding"
        reservation_key = "applier/generation/" + binding.generation
        reservation = verified.get(reservation_key)
        if reservation is None \
                or not obligation.created_seq <= reservation[0] < delete_seq \
                or data.get(reservation_key) != reservation[1]:
            return None, "no exact durable generation reservation read-back"
        try:
            generation = _record(
                reservation[1], MAX_REJECTION_RECORD_BYTES,
                {
                    "actor", "kind", "origin", "payload", "workspace",
                })
        except ValueError:
            return None, "invalid generation reservation"
        if generation != {
                "actor": binding.member,
                "kind": "internal-generation-v1",
                "origin": generation["origin"],
                "payload": binding.payload,
                "workspace": self.workspace,
        } or not isinstance(generation["origin"], str) \
                or h(reservation[1]) != binding.generation:
            return None, "generation reservation binding mismatch"

        payload_key = "failed/pile/" + h(obligation.raw)
        payload = verified.get(payload_key)
        if payload is None or payload[0] >= delete_seq \
                or payload[0] < obligation.created_seq \
                or payload[1] != obligation.raw \
                or data.get(payload_key) != obligation.raw:
            return None, "no exact durable rejection payload read-back"

        expected_id = h(obligation.raw)
        rejection_type, classification_reason = \
            _classify_permanent_rejection(
                obligation.raw, self.workspace)
        if rejection_type is None:
            return None, classification_reason
        rejection_reason = (
            "no exact durable metadata agreeing with deterministic "
            f"{rejection_type} classification")
        for key, (verified_seq, raw) in verified.items():
            if not key.startswith("failed/meta/") \
                    or verified_seq >= delete_seq \
                    or verified_seq < obligation.created_seq \
                    or data.get(key) != raw \
                    or key != "failed/meta/" + h(raw):
                continue
            try:
                record = decode_rejection_record(
                    raw,
                    workspace=self.workspace,
                    source=obligation.key,
                    payload=expected_id,
                    generation=binding.generation,
                )
            except ValueError:
                continue
            if record["classification"] != rejection_type \
                    or record["pile"] != payload_key:
                continue
            spend_key = "applier/spent/" + binding.generation
            spend_raw = canon({
                "kind": "internal-generation-spend-v1",
                "outcome": "rejected",
                "proof": h(raw),
            })
            created = [
                seq for seq, value, actor
                in definite_creates.get(spend_key, ())
                if value == spend_raw
                and actor == deletion.actor
                and max(
                    obligation.created_seq,
                    reservation[0],
                    payload[0],
                    verified_seq,
                ) < seq < delete_seq
            ]
            if not created:
                rejection_reason = "no definite fresh rejection spend"
                continue
            spend = verified.get(spend_key)
            if spend is None \
                    or not max(created) < spend[0] < delete_seq \
                    or spend[1] != spend_raw \
                    or data.get(spend_key) != spend_raw:
                rejection_reason = (
                    "no exact durable rejection spend read-back")
                continue
            return (
                "rejection",
                max(
                    reservation[0], payload[0], verified_seq,
                    max(created), spend[0],
                ),
            ), ""
        return None, rejection_reason

    def _ambiguous_mutations(self):
        """Locate history events whose after-linearization result was not seen."""
        ambiguous = set()
        for gate in getattr(self.bucket, "_rules", ()):
            if gate.when != "after" or gate.error is None \
                    or gate.seen < gate.nth:
                continue
            matches = [
                event for event in self.bucket.history
                if (event.actor, event.op, event.key) == (
                    gate.actor, gate.op, gate.key)
            ]
            if len(matches) >= gate.nth:
                ambiguous.add(matches[gate.nth - 1].seq)
        return ambiguous

    def _snapshots(self):
        initial_root = self.bucket.initial.get("root")
        initial_objects = tuple(sorted(
            (key[4:], raw)
            for key, raw in self.bucket.initial.items()
            if key.startswith("obj/")))
        initial = () if initial_root is None else (
            _Snapshot(0, initial_root, initial_objects),)
        committed = tuple(
            _Snapshot(commit.seq, commit.root, commit.objects)
            for commit in self.bucket.commits)
        return initial + committed

    def _validated_snapshot(self, snapshot):
        cache_key = (snapshot.seq, h(snapshot.root))
        if cache_key in self._snapshot_errors:
            raise self._snapshot_errors[cache_key]
        if cache_key in self._snapshot_fids:
            return self._snapshot_fids[cache_key]
        try:
            objects = dict(snapshot.objects)
            fetch = objects.get
            validated = reconstruct(snapshot.root, fetch)
            if validated.workspace != self.workspace:
                raise ValueError("foreign workspace anchor")
            validated_fids = frozenset(validated.facts)
        except Exception as error:
            self._snapshot_errors[cache_key] = error
            raise
        self._snapshot_fids[cache_key] = validated_fids
        return validated_fids

    def _fail(self, event, reason):
        diagnostic = getattr(self.bucket, "diagnostic", None)
        rendered = diagnostic() if callable(diagnostic) else (
            f"bucket seed={self.bucket.seed:#x}; "
            f"history prefix ends at event #{event.seq}")
        raise ObligationViolation(
            event, reason, self.bucket.history[:event.seq], rendered)


def _classify_permanent_rejection(raw, workspace):
    """Re-run the immutable input door; a type-name string is not authority."""
    try:
        stream = decode_pile(raw, workspace)
    except PermanentIngressRejection as error:
        return type(error).__name__, ""
    except Exception as error:
        return None, (
            "exact bytes raise a decoder program failure, not a permanent "
            f"verdict: {type(error).__name__}: {error}")
    try:
        judgment = drain(stream, workspace)
    except PermanentIngressRejection as error:
        return type(error).__name__, ""
    except Exception as error:
        return None, (
            "exact bytes raise a kernel program failure, not a permanent "
            f"verdict: {type(error).__name__}: {error}")
    if judgment.ok:
        return None, (
            "exact bytes pass the immutable input door; rejection is forged")
    if judgment.failure is not None:
        if isinstance(judgment.failure, PermanentIngressRejection):
            return type(judgment.failure).__name__, ""
        return None, (
            "exact bytes expose a family/program failure, not a permanent "
            f"verdict: {type(judgment.failure).__name__}: "
            f"{judgment.failure}")
    return KernelRejected.__name__, ""


def production_call_sites(root, method):
    """Inventory every structured method capability in production Python.

    This is intentionally AST-based and exhaustive over ``core/**/*.py``:
    direct calls, aliases such as ``deleter = store.delete``, and dynamic
    ``getattr(store, "delete")`` references are all visible. Moving or
    renaming the one destructive capability changes the ratchet instead of
    silently evading a text grep.
    """
    root = Path(root)
    sites = []
    for path in sorted((root / "core").rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        functions = []

        class Calls(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                functions.append(node.name)
                self.generic_visit(node)
                functions.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Attribute(self, node):
                if node.attr == method:
                    parent = parents.get(node)
                    direct = isinstance(parent, ast.Call) \
                        and parent.func is node
                    sites.append(CallSite(
                        str(path.relative_to(root)),
                        functions[-1] if functions else "<module>",
                        node.lineno,
                        ast.unparse(node.value),
                        "direct" if direct else "alias"))
                self.generic_visit(node)

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name) \
                        and node.func.id == "getattr" \
                        and len(node.args) >= 2 \
                        and isinstance(node.args[1], ast.Constant) \
                        and node.args[1].value == method:
                    sites.append(CallSite(
                        str(path.relative_to(root)),
                        functions[-1] if functions else "<module>",
                        node.lineno,
                        ast.unparse(node.args[0]),
                        "getattr"))
                self.generic_visit(node)

        Calls().visit(tree)
    return tuple(sites)
