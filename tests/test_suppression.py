"""Death/suppression keys are extractable from clear envelopes alone."""
import pytest

from core import cmds
from core.close import decode_pile, encode_pile
from core.fact import Fact, from_json
from facts.auth.signature import signature
from facts.content.file import file
from facts.content.message import message
from core.kernel import offer_src
from core.node import Node
from core.suppression import atom, deathkey, is_deletion, suppkeys


class EnvelopeOnly:
    def __init__(self, atoms):
        self.atoms = atoms

    @property
    def body(self):
        raise AssertionError("suppression extraction read the body")


def test_channel_targets_share_an_envelope_visible_suppkey():
    msg = message("pk", "general", "hello", 1)
    attachment = file("pk", "general", "a.txt", 3, "ab" * 32, 1, 2)

    assert suppkeys(msg) == suppkeys(attachment) == {'["chan","general"]'}
    assert deathkey(msg) is None
    assert not is_deletion(msg)
    assert msg.atoms == [atom("general")]


def test_deathkey_and_tag_are_body_free():
    target = EnvelopeOnly([atom("general")])
    deletion = EnvelopeOnly([atom("general", deletion=True)])

    assert suppkeys(target) == {deathkey(deletion)} == {'["chan","general"]'}
    assert not is_deletion(target)
    assert is_deletion(deletion)
    assert suppkeys(deletion) == frozenset()  # a death marker is no membership


def test_suppression_marker_survives_the_wire_codec():
    deletion = Fact("channel_delete", 3, [atom("general", deletion=True)], {})
    decoded, _ = decode_pile(encode_pile([deletion]))

    assert decoded == [deletion]
    assert is_deletion(decoded[0])
    assert deathkey(decoded[0]) == '["chan","general"]'


@pytest.mark.parametrize("fact", [
    Fact("msg", 1, [],
         {"pk": "pk", "chan": "general", "text": "markerless"}),
    Fact("file", 1, [],
         {"pk": "pk", "chan": "general", "name": "old.txt",
          "size": 6, "blob": "blob"}),
])
def test_post_cutover_markerless_content_is_rejected(fact, tmp_path):
    node = Node(str(tmp_path / "node"))
    workspace = cmds.create(node, "alice")
    secret, public = node.identity(workspace)
    member = offer_src(node.idx(workspace), "member", public)
    body = {**fact.body, "pk": public}
    markerless = Fact(fact.t, node.fact_of(workspace, member).ts + 1, [], body)
    proof = signature(secret, public, markerless, markerless.ts)

    with pytest.raises(ValueError, match="outside the canonical set"):
        node.ingest_new(
            workspace, [proof, markerless],
            {proof.fid: [], markerless.fid: [proof.fid, member]},
        )

    assert node.fact_of(workspace, markerless.fid) is None
    assert suppkeys(markerless) == frozenset()


@pytest.mark.parametrize("atoms", [
    [["supp", "chan"]],
    [["supp", "chan", "general", 1]],
])
def test_malformed_suppression_atoms_are_rejected_at_the_door(atoms):
    fact = Fact("sample", 1, atoms, {})
    with pytest.raises(ValueError, match="fact shape"):
        from_json(fact.to_json())


@pytest.mark.parametrize("atoms", [
    [],
    [None],
    [["supp", "chan", 1, "target"]],
    [["supp", "other", "general", "target"]],
    [["supp", "chan", "general", "other"]],
    [atom("general", deletion=True), atom("other", deletion=True)],
])
def test_noncanonical_or_ambiguous_markers_do_not_index(atoms):
    fact = EnvelopeOnly(atoms)
    assert suppkeys(fact) == frozenset()
    assert deathkey(fact) is None
    assert not is_deletion(fact)


def test_target_markers_are_a_membership_set():
    """Many TARGET markers declare many groups (REMOVALS.md §2) — the old
    0-or-2+ collapse to None was the one-group assumption, not a rule."""
    fact = EnvelopeOnly(
        [atom("general"), atom("author/alice"), atom("general")])
    assert suppkeys(fact) == {'["chan","general"]', '["chan","author/alice"]'}
    assert deathkey(fact) is None
    assert not is_deletion(fact)
