"""Stateful peer composition over the complete database-free writer core."""
import asyncio
import os
import threading
import time

import facts

from core import fact_index
from core.access import AccessGate
from core.close import encode_signed_pile
from core.crypto import kdf
from core.fact import Fact
from core.limits import MAX_CONTROL_PILE_BYTES
from core.store import FsStore
from core.writer_head import WriterBinding, writer_store_binding
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
    open_accepted_pile,
)
from facts.auth.head_request import payload as head_proof_payload
from facts.auth.removal_path_request import payload as path_proof_payload

from . import bao_native, sql_store
from .keychain import (
    MAX_IROH_PEERS,
    Keychain,
    iroh_endpoint,
    iroh_peer,
    is_iroh_peer,
    normalize_peer,
    normalize_peers,
)
from .pile_sender import PileSender


ACCESS_PROOF_TTL_MS = 120_000


def now_ms():
    return int(time.time() * 1000)


def _run_core(awaitable):
    """Run the shared async core at the blocking stateful-peer boundary."""
    return asyncio.run(awaitable)


class FullPeer:
    def __init__(self, dir, initial_secret=None, *, store_factory=None):
        self.dir = dir
        os.makedirs(dir, exist_ok=True)
        self.lock = threading.RLock()
        self._store_factory = store_factory
        self.peer_address = None  # daemon-owned URL or Iroh reachability
        self._forwarders = None
        self._kr_path = os.path.join(dir, "keyring.json")
        self.keychain = Keychain(self._kr_path, initial_secret)
        self.sk, self.pk = self.keychain.default()
        self._stores, self._sql, self._senders = {}, {}, {}
        self._consumers, self._mirrors, self._writers = {}, {}, {}
        self._access_gates = {}
        self._iroh_peer_urls = {}  # (ws, endpoint) -> disposable loopback URL
        self._sync_errors = {}
        for ws in self.workspaces():
            self._ensure_projection(ws)

    # ---- full-peer-local state -----------------------------------------------

    def save_keyring(self):
        self.keychain.save()

    @property
    def keyring(self):
        """The currently committed full-peer-local configuration value."""
        return self.keychain.data

    @property
    def member(self):
        return self.pk

    def identity(self, workspace=None):
        return self.keychain.default() if workspace is None \
            else self.keychain.for_workspace(workspace)

    def identity_id(self, workspace=None):
        return self.identity(workspace)[1]

    def member_for(self, workspace):
        return self.identity_id(workspace)

    def workspaces(self):
        return list(self.keyring["workspaces"])

    def has_workspace(self, workspace):
        return workspace in self.keyring["workspaces"]

    def sender(self, workspace):
        """Return the SQL-permitted local pile author."""
        with self.lock:
            if workspace not in self._senders:
                self._senders[workspace] = PileSender(self, workspace)
            return self._senders[workspace]

    def consumer(self, workspace):
        """Compose core pile judgment with the disposable SQL sink."""
        with self.lock:
            if workspace not in self._consumers:
                self._consumers[workspace] = FactConsumer(
                    workspace,
                    sql_store.LockedProjection(
                        self.sql(workspace), self.lock),
                )
            return self._consumers[workspace]

    def mirror(self, workspace):
        """Return the exact directory/RBSR receiver shared with cloud peers."""
        with self.lock:
            if workspace not in self._mirrors:
                access = self.access_gate(workspace)
                self._mirrors[workspace] = RepositoryMirror(
                    workspace,
                    self.store(workspace),
                    self.writer_binding,
                    self.consumer(workspace),
                    current_binding_for=self.current_writer_binding,
                    apply_control=access.state.apply_control,
                )
            return self._mirrors[workspace]

    def access_gate(self, workspace):
        """Return the database-free two-phase gate for one recipient."""
        with self.lock:
            if workspace not in self._access_gates:
                self._access_gates[workspace] = AccessGate(
                    workspace, self.store(workspace))
            return self._access_gates[workspace]

    def head_gate(self, workspace):
        """Compose exact-head CAS with the same database-free access gate."""
        return OpaqueHeadGate(
            self.store(workspace),
            self.access_gate(workspace).authorize_head,
        )

    def removal_bootstrap_pile(self, workspace):
        """Open this device's original signed control leaf without reclosure."""
        _secret, device = self.identity(workspace)
        return _run_core(open_accepted_pile(
            self.store(workspace),
            workspace,
            device,
            1,
            max_bytes=MAX_CONTROL_PILE_BYTES,
        ))

    def add_workspace(self, workspace, name, peers, identity=None):
        """Record the locally trusted anchor before its first pile is opened."""
        with self.lock:
            identity = identity or self.keychain.default_id()
            self.keychain.identity(identity)
            peers = normalize_peers(peers)
            if self._forwarders is not None and any(
                    not is_iroh_peer(peer) for peer in peers):
                raise ValueError("Iroh mode requires Iroh peer locators")
            current_iroh = sum(
                is_iroh_peer(peer)
                for candidate, entry in self.keyring["workspaces"].items()
                if candidate != workspace
                for peer in entry["peers"]
            )
            if current_iroh + sum(map(is_iroh_peer, peers)) \
                    > MAX_IROH_PEERS:
                raise ValueError("too many Iroh peers")
            entry = {
                "peers": peers, "name": name,
                "identity": identity}
            self._save_workspace(workspace, entry)
            self._forget_iroh_workspace(workspace)
            self._peers_changed()

    def use_iroh(self, advertised, forwarders):
        """Attach daemon-owned Iroh reachability; never repository authority."""
        advertised = normalize_peer(advertised)
        if not is_iroh_peer(advertised):
            raise ValueError("Iroh advertisement must be an Iroh peer")
        with self.lock:
            if any(
                    not is_iroh_peer(peer)
                    for entry in self.keyring["workspaces"].values()
                    for peer in entry["peers"]):
                raise ValueError("Iroh mode requires Iroh peer locators")
            self.peer_address = advertised
            self._forwarders = forwarders
            self._peers_changed()

    def advertised_peer(self):
        if isinstance(self.peer_address, dict):
            return dict(self.peer_address)
        if isinstance(self.peer_address, str) and self.peer_address:
            return self.peer_address
        raise ValueError("peer has no advertised address")

    # ---- fact-family command host -------------------------------------------

    def now_ms(self):
        return now_ms()

    def attachment_io(self):
        return bao_native

    def resolve_peer(self, workspace, peer):
        """Resolve local reachability; callers still use the ordinary HTTP client."""
        peer = normalize_peer(peer)
        if isinstance(peer, str):
            if self._forwarders is not None:
                raise ValueError("Iroh mode rejects plain HTTP peers")
            return peer
        if self._forwarders is None:
            raise ValueError("Iroh peer requires an Iroh-enabled full peer")
        url = self._forwarders.resolve(workspace, peer)
        key = workspace, peer["endpoint"]
        with self.lock:
            self._iroh_peer_urls[key] = url
        return url

    def release_peer(self, workspace, peer):
        peer = normalize_peer(peer)
        if is_iroh_peer(peer) and self._forwarders is not None:
            with self.lock:
                if self._forwarders.release(workspace, peer):
                    self._forget_iroh_peer(workspace, peer["endpoint"])

    def iroh_peers(self):
        return tuple(
            (workspace, dict(peer))
            for workspace, entry in self.keyring["workspaces"].items()
            for peer in entry["peers"]
            if is_iroh_peer(peer)
        )

    def set_iroh_peer(self, workspace, endpoint, ticket):
        """Durably add or refresh one reachability record by endpoint id."""
        peer = iroh_peer(endpoint, ticket)
        self._edit_iroh_peer(workspace, peer["endpoint"], peer)

    def remove_iroh_peer(self, workspace, endpoint):
        """Durably remove one reachability record and its local forwarder."""
        self._edit_iroh_peer(workspace, iroh_endpoint(endpoint), None)

    def _edit_iroh_peer(self, workspace, endpoint, replacement):
        with self.lock:
            if self._forwarders is None:
                raise ValueError("peer.iroh requires an Iroh-enabled daemon")
            entry = self.keyring["workspaces"][workspace]
            peers, found = [], False
            for peer in entry["peers"]:
                if is_iroh_peer(peer) and peer["endpoint"] == endpoint:
                    found = True
                    if replacement is not None:
                        peers.append(replacement)
                else:
                    peers.append(peer)
            if replacement is None and not found:
                raise KeyError(f"unknown Iroh peer {endpoint!r}")
            if replacement is not None and not found:
                if len(self.iroh_peers()) >= MAX_IROH_PEERS:
                    raise ValueError("too many Iroh peers")
                peers.append(replacement)
            peers = normalize_peers(peers)
            self._save_workspace(workspace, {**entry, "peers": peers})
            self._forget_iroh_peer(workspace, endpoint)
            self._peers_changed()

    def peer_connection_status(self, workspace):
        return [] if self._forwarders is None \
            else self._forwarders.status(workspace)

    def _peers_changed(self):
        if self._forwarders is not None:
            self._forwarders.refresh(self.iroh_peers())

    def _save_workspace(self, workspace, entry):
        workspaces = dict(self.keyring["workspaces"])
        workspaces[workspace] = entry
        self.keychain.commit({**self.keyring, "workspaces": workspaces})

    def bind_identity(self, workspace, identity):
        with self.lock:
            self.keychain.bind(workspace, identity)

    def _forget_iroh_peer(self, workspace, endpoint):
        with self.lock:
            self._iroh_peer_urls.pop((workspace, endpoint), None)

    def _forget_iroh_workspace(self, workspace):
        with self.lock:
            for key in [
                    key for key in self._iroh_peer_urls
                    if key[0] == workspace]:
                self._forget_iroh_peer(*key)

    def record_sync_failure(self, ws, url, error):
        with self.lock:
            self._sync_errors[(ws, url)] = {
                "error": f"{type(error).__name__}: {error}",
                "peer": url,
                "ts": now_ms(),
            }

    def record_sync_success(self, ws, url):
        with self.lock:
            self._sync_errors.pop((ws, url), None)

    def sync_failures(self, ws):
        with self.lock:
            return [
                dict(value)
                for (workspace, _), value in sorted(self._sync_errors.items())
                if workspace == ws
            ]

    def store(self, ws):
        with self.lock:
            if ws not in self._stores:
                self._stores[ws] = self._store_factory(ws) \
                    if self._store_factory is not None \
                    else FsStore(os.path.join(self.dir, "ws", ws))
            return self._stores[ws]

    def idx(self, ws):
        """Expose the raw connection only to SQL-backed authoring helpers."""
        return self.sql(ws).db

    def sql(self, ws):
        with self.lock:
            if ws not in self._sql:
                self._sql[ws] = sql_store.SqlStore.open(
                    os.path.join(self.dir, "ws", ws + ".idx.db"), ws)
            return self._sql[ws]

    def _ensure_projection(self, ws):
        """Replay accepted slots whose transactional SQL checkpoint lags."""
        result = _run_core(self.mirror(ws).replay_local())
        if result.errors:
            raise ValueError(
                f"writer projection replay failed: {result.errors[0][1]}")

    def fact_of(self, ws, fid) -> Fact:
        with self.lock:
            self._ensure_projection(ws)
            return self.sql(ws).fact_of(fid)

    def select(
            self, ws, kind, k0=None, k1=None, *,
            include_suppressed=False, **_options):
        """Select current facts through the one generic type/offer index."""
        with self.lock:
            self._ensure_projection(ws)
            projection = self.sql(ws)
            rows = projection.indexed(kind, k0, k1)
            if include_suppressed:
                return rows
            return tuple(
                fact for fact in rows
                if not projection.suppresses(fact)
            )

    def by_type(self, ws, tag, **options):
        return self.select(ws, fact_index.TYPE_INDEX, tag, **options)

    def keys(self, ws):
        """Canonical validated keys for client-only query assembly."""
        with self.lock:
            self._ensure_projection(ws)
            return [
                fact_key for (fact_key,) in self.idx(ws).execute(
                    "SELECT i.k0 FROM fact_index i "
                    "WHERE i.kind='fact.key' ORDER BY i.k0",
                )
            ]

    # ---- authoring tail: close -> signed writer leaf -> accepted slot --------

    def ingest_new(self, ws, news, deps_new, *, owner=None):
        return self.sender(ws).send(news, deps_new, owner=owner)

    def _projected_writer_binding(self, workspace, device, owner=None):
        """Read one live local authoring identity from disposable SQL."""
        projection = self.sql(workspace)
        owners = set()
        if any(
                not projection.suppresses(fact)
                and ("member", device, device) in fact.offers()
                for fact in projection.indexed(
                    "member", device, device)):
            owners.add(device)
        owners.update(
            offered_owner
            for fact in projection.indexed("device_key", device)
            if not projection.suppresses(fact)
            for name, key, offered_owner in fact.offers()
            if name == "device_key" and key == device and offered_owner
            and (owner is None or offered_owner == owner)
        )
        if owner is not None:
            owners.intersection_update((owner,))
        if len(owners) > 1:
            raise ValueError("ambiguous writer ownership")
        if not owners:
            return None
        selected = next(iter(owners))
        if not any(
                not projection.suppresses(fact)
                and ("member", selected, selected) in fact.offers()
                for fact in projection.indexed(
                    "member", selected, selected)) \
                or device != selected and not any(
                not projection.suppresses(fact)
                and ("device_key", device, selected) in fact.offers()
                for fact in projection.indexed(
                    "device_key", device, selected)):
            return None
        return WriterBinding(
            workspace,
            device,
            selected,
            writer_store_binding(workspace, device),
        )

    async def writer_binding(
            self, workspace, device, _removal_root, candidate):
        """Bind a signed-head claim; its closed piles must prove the claim."""
        if getattr(candidate, "workspace", None) != workspace \
                or getattr(candidate, "device", None) != device:
            raise ValueError("writer head claim")
        return WriterBinding(
            workspace,
            device,
            candidate.owner,
            writer_store_binding(workspace, device),
        )

    async def current_writer_binding(
            self, workspace, device, removal_root, candidate):
        """Use the same claim binding for new suffixes; core validates piles."""
        return await self.writer_binding(
            workspace, device, removal_root, candidate)

    def local_writer_binding(self, workspace):
        """Return this peer's live owner binding for one publication turn."""
        with self.lock:
            self._ensure_projection(workspace)
            _secret, device = self.identity(workspace)
            return self._projected_writer_binding(workspace, device)

    def _writer(self, workspace, owner):
        secret, device = self.identity(workspace)
        key = workspace, device, owner
        if key not in self._writers:
            binding = WriterBinding(
                workspace, device, owner,
                writer_store_binding(workspace, device))
            self._writers[key] = WriterLog(
                workspace, device, owner, binding.store,
                secret, self.store(workspace))
        return self._writers[key]

    def removal_path_proof(
            self, workspace, *, owner=None, closures=()):
        """Build the historical-member phase signed by this exact device."""
        timestamp = now_ms()
        closed = path_proof_payload(
            self,
            workspace,
            timestamp + ACCESS_PROOF_TTL_MS,
            timestamp,
            owner=owner,
            closures=closures,
        )
        return self.sender(workspace).pack(closed)

    def head_proof(
            self, workspace, owner, base_head, proposed_head, *,
            removal_path, closures=()):
        """Build one disposable proof for this device's exact head update."""
        timestamp = now_ms()
        closed = head_proof_payload(
            self,
            workspace,
            owner,
            base_head,
            proposed_head,
            timestamp + ACCESS_PROOF_TTL_MS,
            removal_path,
            timestamp,
            closures=closures,
        )
        return self.sender(workspace).pack(closed)

    def publish_closed(self, workspace, closures, *, owner=None):
        """Publish and consume one batch through the same core as a pull."""
        closures = tuple(tuple(closure) for closure in closures)
        if not closures:
            return []
        with self.lock:
            secret, device = self.identity(workspace)
            binding = self._projected_writer_binding(
                workspace, device)
            if owner is not None:
                if binding is not None and binding.owner != owner:
                    raise ValueError("publishing identity owner mismatch")
            elif binding is not None:
                owner = binding.owner
            else:
                bootstrap_owners = {
                    owner
                    for closure in closures
                    for fact in closure
                    for name, key, owner in fact.offers()
                    if name == "member" and key == device and owner == device
                }
                if bootstrap_owners != {device} \
                        or self.sql(workspace).fact_ids():
                    raise ValueError("writer has no current durable owner")
                owner = device
            before = self.sql(workspace).fact_ids()
            writer = self._writer(workspace, owner)
            update = _run_core(writer.prepare(closures))
            _run_core(writer.establish(update))
            access = self.access_gate(workspace)
            raw_piles = tuple(map(encode_signed_pile, update.piles))
            if _run_core(access.state.pin()) is None:
                for raw in raw_piles:
                    result = _run_core(access.state.bootstrap(raw))
                    if result.status in {"applied", "noop"}:
                        break
                if _run_core(access.state.pin()) is None:
                    raise ValueError(
                        "first writer update needs a clear control pile")

            classified = self.consumer(workspace).prepare_batch(
                tuple((raw, device) for raw in raw_piles),
                owner=owner,
            )
            control = set(classified.control_piles)
            control_piles = tuple(
                raw for oid, raw in zip(update.pile_oids, raw_piles)
                if oid in control)

            path_proof = self.removal_path_proof(
                workspace, owner=owner, closures=closures)
            removal_path = _run_core(access.removal_path(
                path_proof, now_ms()))
            if removal_path is None:
                raise ValueError("historical membership proof rejected")
            proof = self.head_proof(
                workspace,
                owner,
                update.base_head,
                update.head_oid,
                removal_path=removal_path,
                closures=closures,
            )
            head_gate = self.head_gate(workspace)
            if control_piles:
                permit_secret = kdf(
                    secret.encode(), "control-head-permit")
                permit = _run_core(access.issue_head_permit(
                    proof,
                    update.head_oid,
                    control_piles,
                    now_ms(),
                    permit_secret,
                ))
                if not isinstance(permit, bytes):
                    raise ValueError("control-head permit rejected")
                grant = _run_core(access.authorize_permitted_head(
                    permit, update.head_oid, control_piles, permit_secret))
                outcome = _run_core(head_gate.advance_grant(
                    grant, update.head_oid))
            else:
                outcome = _run_core(head_gate.advance(
                    proof, update.head_oid, now_ms()))
            if outcome.status not in {"applied", "noop"}:
                raise RuntimeError("writer head advance requires rebase")
            replay = _run_core(self.mirror(workspace).replay_local())
            if replay.errors:
                raise ValueError(
                    f"writer projection failed: {replay.errors[0][1]}")
            return sorted(self.sql(workspace).fact_ids() - before)

    # ---- rebuild: the store's own units through the same kernel --------------

    def rebuild(self, ws, *, republish=False):
        """Rebuild only disposable SQL from durable accepted writer slots."""
        if republish:
            raise ValueError("writer trees are never rebuilt from SQL")
        with self.lock:
            self.sql(ws).reset()
            result = _run_core(self.mirror(ws).replay_local())
            if result.errors:
                raise ValueError(
                    f"writer projection rebuild failed: {result.errors[0][1]}")

    # ---- exact suppression consult -------------------------------------------

    def suppressed(self, ws, fact):
        """The one local mask: explicit fact scopes intersect active actions."""
        with self.lock:
            self._ensure_projection(ws)
            return self.sql(ws).suppresses(fact)

    def suppression_active(self, ws, sid):
        with self.lock:
            self._ensure_projection(ws)
            return self.sql(ws).active(sid)
