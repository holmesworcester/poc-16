"""The one provider-independent exact ingress address grammar."""
import pytest

from core.ingress import (
    IngressAddress,
    InvalidIngressAddress,
    ingress_key,
    ingress_prefix,
    parse_ingress_key,
)


WORKSPACE = "a" * 64
SESSION = "b" * 32
MEMBER = "c" * 64
DIGEST = "d" * 64


def test_exact_pile_address_round_trips_in_path_order():
    key = ingress_key(WORKSPACE, SESSION, MEMBER, DIGEST)

    assert key == (
        f"ingress/v1/workspaces/{WORKSPACE}/piles/"
        f"{SESSION}/{MEMBER}/{DIGEST}"
    )
    assert key.startswith(ingress_prefix(WORKSPACE))
    assert parse_ingress_key(key) == IngressAddress(
        WORKSPACE, SESSION, MEMBER, DIGEST)


@pytest.mark.parametrize("mutate", (
    str.upper,
    lambda key: key.replace("/v1/", "/v2/"),
    lambda key: "/" + key,
    lambda key: key + "/extra",
    lambda key: key.replace("/piles/", "/objects/"),
    lambda key: key.replace(SESSION, SESSION[:-1]),
    lambda key: key.replace(MEMBER, MEMBER.upper()),
    lambda key: key[:-1],
))
def test_parser_rejects_every_noncanonical_path(mutate):
    with pytest.raises(InvalidIngressAddress, match="ingress key"):
        parse_ingress_key(mutate(
            ingress_key(WORKSPACE, SESSION, MEMBER, DIGEST)))


@pytest.mark.parametrize("args", (
    ("A" * 64, SESSION, MEMBER, DIGEST),
    (WORKSPACE, SESSION[:-1], MEMBER, DIGEST),
    (WORKSPACE, SESSION, MEMBER[:-1], DIGEST),
    (WORKSPACE, SESSION, MEMBER, DIGEST[:-1]),
))
def test_builder_rejects_ambiguous_components(args):
    with pytest.raises(ValueError, match="ingress key component"):
        ingress_key(*args)
