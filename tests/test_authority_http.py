"""The public authority bootstrap door and discarded mint share one core."""
import asyncio
import base64
import json

from core.authority import AuthorityRepository
from core.http import AsyncFromSyncReader, HttpGate
from core.limits import MAX_AUTHORITY_PILE_BYTES
from core.store import FsStore
from facts.auth.signature import signature
from facts.content.message import message
from tests.test_authority_repository import (
    access_proof,
    authority_world,
    signed,
)


def run(awaitable):
    return asyncio.run(awaitable)


def test_public_authority_bootstrap_enables_mint_without_retaining_the_proof(
        tmp_path):
    world = authority_world()
    store = FsStore(str(tmp_path / "repository"))
    repository = AuthorityRepository(world.root.fid, store)

    async def authorize(pile, purpose):
        return await repository.authorize_access(
            pile, 10, purpose=purpose)

    gateway = HttpGate(
        AsyncFromSyncReader(store),
        world.root.fid,
        b"authority-http-secret" * 2,
        lambda: 10,
        authority_publish=repository.publish,
        mint_authorize=authorize,
    )
    authority = signed(
        world.member_secret,
        world.member,
        world.root,
        world.membership,
    )

    applied = run(gateway.handle(
        "POST", "/authority", {"ws": world.root.fid}, {}, authority))
    duplicate = run(gateway.handle(
        "POST", "/authority", {"ws": world.root.fid}, {}, authority))
    assert applied.status == 201
    assert duplicate.status == 204

    proof = access_proof(world)
    before = tuple(store.list("obj/"))
    response = run(gateway.handle(
        "POST",
        "/mint",
        {"ws": world.root.fid},
        {},
        json.dumps({
            "pile": base64.b64encode(proof).decode(),
            "ws": world.root.fid,
        }).encode(),
    ))
    assert response.status == 200
    assert tuple(store.list("obj/")) == before
    assert not store.list("ingress/")


def test_authority_http_rejects_content_and_bounds_before_provider_work(
        tmp_path):
    world = authority_world()
    store = FsStore(str(tmp_path / "repository"))
    repository = AuthorityRepository(world.root.fid, store)
    gateway = HttpGate(
        AsyncFromSyncReader(store),
        world.root.fid,
        b"authority-http-secret" * 2,
        lambda: 10,
        authority_publish=repository.publish,
    )

    item = message(
        world.root.fid, world.member, "general", "not authority", 5)
    item_signature = signature(
        world.member_secret, world.member, item, 5)
    content = signed(
        world.member_secret,
        world.member,
        world.root,
        (*world.membership, item_signature, item),
    )
    assert run(gateway.handle(
        "POST", "/authority", {"ws": world.root.fid}, {}, content,
    )).status == 403
    assert store.list("") == []

    rejected = run(gateway.handle(
        "POST", "/authority", {"ws": world.root.fid}, {},
        b"x" * (MAX_AUTHORITY_PILE_BYTES + 1)))
    assert rejected.status == 413
    assert store.list("") == []
