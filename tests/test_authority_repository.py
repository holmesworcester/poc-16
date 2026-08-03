"""The authority repository is distinct, signed, pinned, and SQL-free."""
import asyncio
import sqlite3
from dataclasses import dataclass

import pytest

from core.authority import AuthorityRepository
from core.close import encode_signed_pile, make_signed_pile
from core.crypto import h, keypair
from core.object_store import AUTHORITY_ROOT_KEY, Versioned, VersionToken
from core.repository_reader import RepositoryReader
from core.store import FsStore
from facts.auth.removal import removal
from facts.auth.request import request
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.auth.workspace import workspace
from facts.content.message import message


def run(awaitable):
    return asyncio.run(awaitable)


def signed(secret, public, root, closure):
    return encode_signed_pile(make_signed_pile(
        secret, root.fid, public, closure))


@dataclass(frozen=True)
class World:
    founder_secret: object
    founder: str
    root: object
    invite_signature: object
    invitation: object
    member_secret: object
    member: str
    member_signature: object
    joined: object

    @property
    def membership(self):
        return (
            self.root,
            self.invite_signature,
            self.invitation,
            self.member_signature,
            self.joined,
        )


def authority_world():
    founder_secret, founder = keypair()
    root = workspace(founder_secret, founder, "workspace", 1)
    invite_secret, invite_public = keypair()
    invitation = user_invite(root.fid, founder, invite_public, 2)
    invite_signature = signature(
        founder_secret, founder, invitation, 2)
    member_secret, member = keypair()
    joined = user(invitation, invite_secret, member, "member", 3)
    member_signature = signature(member_secret, member, joined, 3)
    return World(
        founder_secret,
        founder,
        root,
        invite_signature,
        invitation,
        member_secret,
        member,
        member_signature,
        joined,
    )


def access_proof(world, *, exp=1_000):
    item = request(
        world.root.fid, world.member, "sync", exp, 4)
    item_signature = signature(
        world.member_secret, world.member, item, 4)
    return signed(
        world.member_secret,
        world.member,
        world.root,
        (*world.membership, item_signature, item),
    )


def publish(repository, secret, public, root, closure):
    return run(repository.receive_pile(
        public, signed(secret, public, root, closure)))


def test_never_resident_denied_then_publication_grants_without_sql(
        tmp_path, monkeypatch):
    world = authority_world()
    store = FsStore(str(tmp_path / "repository"))
    repository = AuthorityRepository(world.root.fid, store)
    proof = access_proof(world)

    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("authority path opened SQLite"),
    )

    bootstrap = publish(
        repository,
        world.founder_secret,
        world.founder,
        world.root,
        (world.root,),
    )
    assert bootstrap.status == "applied"
    assert store.get("root") is None
    assert store.get(AUTHORITY_ROOT_KEY) == bootstrap.root

    # This closure is cryptographically valid, but its selected user provider
    # has never entered the authority FactTree.
    assert run(repository.authorize_access(proof, 10)) is None

    joined = publish(
        repository,
        world.member_secret,
        world.member,
        world.root,
        world.membership,
    )
    assert joined.status == "applied"
    assert run(repository.authorize_access(proof, 10)) == (
        world.member, "sync")
    restarted = AuthorityRepository(
        world.root.fid, FsStore(str(tmp_path / "repository")))
    assert run(restarted.authorize_access(proof, 10)) == (
        world.member, "sync")

    # Pin identity is the exact root content hash, never the provider's opaque
    # conditional-write capability.
    pin = run(repository.pin())
    assert pin.root_bytes == joined.root
    assert pin.root_oid == h(joined.root)
    assert isinstance(pin.version, VersionToken)


def test_current_removal_denies_an_old_valid_access_proof(tmp_path):
    world = authority_world()
    store = FsStore(str(tmp_path / "repository"))
    repository = AuthorityRepository(world.root.fid, store)
    publish(
        repository,
        world.member_secret,
        world.member,
        world.root,
        world.membership,
    )
    proof = access_proof(world)
    assert run(repository.authorize_access(proof, 10)) == (
        world.member, "sync")

    evicted = removal(
        world.root.fid, world.founder, world.member, 5)
    evicted_signature = signature(
        world.founder_secret, world.founder, evicted, 5)
    result = publish(
        repository,
        world.founder_secret,
        world.founder,
        world.root,
        (*world.membership, evicted_signature, evicted),
    )
    assert result.status == "applied"
    assert run(repository.authorize_access(proof, 10)) is None


def test_content_family_rejects_the_whole_authority_publication(tmp_path):
    world = authority_world()
    store = FsStore(str(tmp_path / "repository"))
    repository = AuthorityRepository(world.root.fid, store)
    accepted = publish(
        repository,
        world.member_secret,
        world.member,
        world.root,
        world.membership,
    )

    item = message(
        world.root.fid,
        world.member,
        "general",
        "content does not belong in authority",
        5,
    )
    item_signature = signature(
        world.member_secret, world.member, item, 5)
    rejected = publish(
        repository,
        world.member_secret,
        world.member,
        world.root,
        (*world.membership, item_signature, item),
    )

    assert rejected.status == "rejected"
    assert store.get(AUTHORITY_ROOT_KEY) == accepted.root
    pin = run(repository.pin())
    with pytest.raises(ValueError, match="missing validated fact"):
        pin_reader = RepositoryReader(
            world.root.fid,
            pin.root_bytes,
            lambda oid: store.get("obj/" + oid),
        )
        pin_reader.validated().fact(item.fid)


def test_authority_pin_does_not_treat_an_opaque_version_as_root_identity(
        tmp_path):
    world = authority_world()
    inner = FsStore(str(tmp_path / "repository"))
    repository = AuthorityRepository(world.root.fid, inner)
    result = publish(
        repository,
        world.founder_secret,
        world.founder,
        world.root,
        (world.root,),
    )

    class OpaqueVersionFs:
        def get_bounded(self, key, maximum):
            return inner.get_bounded(key, maximum)

        def read_versioned(self, key):
            opened = inner.read_versioned(key)
            if isinstance(opened, Versioned):
                return Versioned(opened.value, VersionToken("opaque-cas-token"))
            return opened

        def put_if_absent(self, key, value):
            return inner.put_if_absent(key, value)

        def cas(self, key, token, value):
            return inner.cas(key, token, value)

    pin = run(AuthorityRepository(
        world.root.fid, OpaqueVersionFs()).pin())
    assert pin.version == VersionToken("opaque-cas-token")
    assert pin.root_oid == h(result.root)
    assert pin.root_oid != pin.version.value
