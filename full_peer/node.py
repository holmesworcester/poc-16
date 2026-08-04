"""Stateful peer composition over the complete database-free writer core."""
import asyncio
from dataclasses import asdict
import os
import threading
import time

import facts

from core import fact_index
from core.close import decode_signed_pile, encode_signed_pile, make_signed_pile
from core.fact import Fact
from core.authority import AuthorityRepository, authority_resident
from core.store import FsStore
from core.writer_head import WriterBinding, writer_store_binding
from core.writer_repository import (
    FactConsumer,
    OpaqueHeadGate,
    RepositoryMirror,
    WriterLog,
)
from facts.auth.head_request import head_request
from facts.auth.signature import signature as signature_fact
from full_peer.upload_journal import UploadSource

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
        self._authorities = {}
        self.sync_cache = {}  # (ws, peer_url) -> walk state
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
                    workspace, self.sql(workspace))
            return self._consumers[workspace]

    def mirror(self, workspace):
        """Return the exact directory/RBSR receiver shared with cloud peers."""
        with self.lock:
            if workspace not in self._mirrors:
                self._mirrors[workspace] = RepositoryMirror(
                    workspace,
                    self.store(workspace),
                    self.writer_binding,
                    self.consumer(workspace),
                    current_binding_for=self.current_writer_binding,
                    authority_publish=self._consume_authority,
                )
            return self._mirrors[workspace]

    def authority(self, workspace):
        """Return the shared database-free authority repository."""
        with self.lock:
            if workspace not in self._authorities:
                self._authorities[workspace] = AuthorityRepository(
                    workspace, self.store(workspace))
            return self._authorities[workspace]

    async def _consume_authority(self, raw):
        """Join one authority-only signed pile; ignore ordinary content piles."""
        try:
            pile = decode_signed_pile(raw)
            if not pile.facts or any(
                    facts.family_for(fact.t) is None
                    or facts.family_for(fact.t).DURABLE
                    and not authority_resident(fact)
                    for fact in pile.facts):
                return None
        except Exception:
            return None
        repository = self.authority(pile.workspace)
        for _ in range(8):
            result = await repository.publish(raw)
            if result.status in {"applied", "noop"}:
                return result
            if result.status != "retryable":
                raise ValueError("authority publication rejected")
        raise RuntimeError("authority publication contention")

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
            self._evict_sync_cache(workspace)
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

    def create_upload(self, workspace, pile):
        return UploadSource.create(
            os.path.join(self.dir, "uploads"),
            workspace,
            self.member_for(workspace),
            pile,
        )

    def load_upload(self, upload_id):
        return UploadSource.load(
            os.path.join(self.dir, "uploads", upload_id))

    def upload_status(self, workspace, cursor=None):
        """Return one bounded page of local delivery state, never publication."""
        page = UploadSource.discover(
            os.path.join(self.dir, "uploads"), self.now_ms(), cursor)
        return {
            "cursor": page.cursor,
            "uploads": [
                asdict(status)
                for status in page.uploads
                if status.workspace == workspace
            ],
        }

    def abandon_upload(self, workspace, upload_id):
        source = self.load_upload(upload_id)
        if source.workspace != workspace:
            raise ValueError("upload source workspace")
        return asdict(source.abandon(self.now_ms()))

    def collect_upload(self, workspace, upload_id):
        return UploadSource.collect(
            os.path.join(self.dir, "uploads"),
            workspace, upload_id, self.now_ms())

    def run_upload(self, source, broker_url, provider_origin, proof):
        from full_peer.upload_client_http import run_http
        return run_http(source, broker_url, provider_origin, proof)

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
            previous = self._iroh_peer_urls.get(key)
            if previous is not None and previous != url:
                self._evict_sync_cache(workspace, previous)
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
            self._evict_sync_cache(workspace)

    def _evict_sync_cache(self, workspace, url=None):
        """Detach reachability state without mutating an in-flight walk."""
        with self.lock:
            for key in [
                key for key in self.sync_cache
                if key[0] == workspace
                and (url is None or key[1] == url)
            ]:
                self.sync_cache.pop(key)

    def sync_state(self, workspace, url):
        """Acquire one walk state at the same lock boundary used for eviction."""
        with self.lock:
            return self.sync_cache.setdefault((workspace, url), {})

    def _forget_iroh_peer(self, workspace, endpoint):
        with self.lock:
            previous = self._iroh_peer_urls.pop((workspace, endpoint), None)
            if previous is not None:
                self._evict_sync_cache(workspace, previous)

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

    async def writer_binding(
            self, workspace, device, authority_root, candidate):
        """Resolve one already-accepted head at its recorded authority pin."""
        owner = None if candidate is None else candidate.owner
        return await self.authority(workspace).writer_binding_at(
            authority_root, device, owner)

    async def current_writer_binding(
            self, workspace, device, _authority_root, candidate):
        """Resolve an incoming head only through current authenticated state."""
        owner = None if candidate is None else candidate.owner
        return await self.authority(workspace).writer_binding(device, owner)

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

    def _head_proof_closure(
            self, workspace, closures, request, request_signature):
        """Close a head request over only its member/device authority.

        Content closures are useful for discovering a bootstrap provider, but
        message, file, and other payload facts must never be copied into the
        discarded authority request merely because they shared a publication
        batch.
        """
        from core.kernel import drain

        body = request.body
        device, owner = body["device"], body["owner"]
        supplied = {
            fact.fid: fact
            for closure in closures
            for fact in closure
        }

        def candidates(name):
            values = {
                fact.fid: fact
                for fact in supplied.values()
                if (name, device, owner) in fact.offers()
            }
            values.update({
                fact.fid: fact
                for fact in self.sql(workspace).indexed(
                    name, device, owner)
                if not self.sql(workspace).suppresses(fact)
            })
            return tuple(sorted(
                values.values(), key=lambda fact: (fact.key, fact.fid)))

        roles = (("member", candidates("member")),)
        if device != owner:
            roles += (("device", candidates("device_key")),)
        providers = []
        for role, choices in roles:
            if not choices:
                raise ValueError(f"writer has no current {role} authority")
            providers.append(choices[0])

        def provider_closure(provider):
            for closure in closures:
                positions = [
                    index for index, fact in enumerate(closure)
                    if fact.fid == provider.fid
                ]
                if positions:
                    prefix = tuple(closure[:positions[0] + 1])
                    if drain(prefix, workspace).ok:
                        return prefix
            return self.sender(workspace).close((provider,), {})

        out, seen = [], set()
        for provider in providers:
            for fact in provider_closure(provider):
                if fact.fid not in seen:
                    seen.add(fact.fid)
                    out.append(fact)
        out.extend((request_signature, request))
        if not drain(out, workspace).ok:
            raise ValueError("head authority closure")
        return tuple(out)

    def head_proof(
            self, workspace, owner, base_head, proposed_head, *,
            closures=()):
        """Build one disposable proof for this device's exact head update."""
        secret, device = self.identity(workspace)
        timestamp = now_ms()
        request = head_request(
            workspace,
            device,
            owner,
            base_head,
            proposed_head,
            timestamp + 120_000,
            timestamp,
        )
        request_signature = signature_fact(
            secret, device, request, timestamp)
        authority = self._head_proof_closure(
            workspace,
            tuple(tuple(closure) for closure in closures),
            request,
            request_signature,
        )
        return encode_signed_pile(make_signed_pile(
            secret, workspace, device, authority))

    def authority_publication(self, workspace):
        """Reclose current durable authority for idempotent peer bootstrap.

        The authority repository stores facts, not historical validation
        paths.  A stateful peer can therefore rebuild one ordinary closed
        pile from its disposable projection whenever a peer needs bootstrap
        or retry; no upload journal or admission witness is required.
        """
        with self.lock:
            self._ensure_projection(workspace)
            pin = _run_core(self.authority(workspace).pin())
            if pin is None:
                raise ValueError("workspace has no authority root")
            projection = self.sql(workspace)
            current = tuple(sorted(
                (
                    fact
                    for fid in projection.fact_ids()
                    if (fact := projection.fact_of(fid)) is not None
                    and authority_resident(fact)
                ),
                key=lambda fact: (fact.key, fact.fid),
            ))
            if not current:
                raise ValueError("workspace has no authority facts")
            closed = self.sender(workspace).close(current, {})
            if any(not authority_resident(fact) for fact in closed):
                raise ValueError("authority closure escaped its repository")
            return pin.root_oid, self.sender(workspace).pack(closed)

    def publish_closed(self, workspace, closures, *, owner=None):
        """Publish and consume one batch through the same core as a pull."""
        closures = tuple(tuple(closure) for closure in closures)
        if not closures:
            return []
        with self.lock:
            _secret, device = self.identity(workspace)
            binding = _run_core(
                self.authority(workspace).writer_binding(device))
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

            proof = self.head_proof(
                workspace,
                owner,
                update.base_head,
                update.head_oid,
                closures=closures,
            )
            authority_repository = self.authority(workspace)
            publications = tuple(
                encode_signed_pile(pile)
                for closure, pile in zip(closures, update.piles)
                if all(
                    authority_resident(fact)
                    for fact in closure
                    if facts.family_for(fact.t).DURABLE
                )
            )

            async def publish_authority():
                for raw in publications:
                    await self._consume_authority(raw)

            async def authorize(raw, proposed):
                return await authority_repository.authorize_head(
                    raw, proposed, now_ms())

            grant = _run_core(authorize(proof, update.head_oid))
            published_first = grant is None and bool(publications)
            if published_first:
                _run_core(publish_authority())
            outcome = _run_core(OpaqueHeadGate(
                self.store(workspace), authorize).advance(
                    proof, update.head_oid))
            if outcome.status not in {"applied", "noop"}:
                raise RuntimeError("writer head advance requires rebase")
            if not published_first:
                _run_core(publish_authority())
            replay = _run_core(self.mirror(workspace).replay_local())
            if replay.errors:
                raise ValueError(
                    f"writer projection failed: {replay.errors[0][1]}")
            self._evict_sync_cache(workspace)
            return sorted(self.sql(workspace).fact_ids() - before)

    def authorize_access(self, workspace, proof_raw, purpose):
        """Run one signed access proof through the shared discarded gate."""
        with self.lock:
            return _run_core(self.authority(workspace).authorize_access(
                proof_raw,
                now_ms(),
                purpose=purpose,
            ))

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
