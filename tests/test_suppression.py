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
from core.suppression import (
    SELF,
    action,
    deathkey,
    is_deletion,
    self_selector,
    suppkeys,
)
from facts._policy import CONTENT_DELETE


class EnvelopeOnly:
    def __init__(self, atoms):
        self.atoms = atoms

    @property
    def body(self):
        raise AssertionError("suppression extraction read the body")


def test_type_owned_selectors_are_envelope_visible_and_exact():
    member = "cd" * 32
    msg = message("pk", "general", "hello", 1)
    attachment = file(
        "pk", "general", "a.txt", 3, "ab" * 32, 1, 2, member)

    assert suppkeys(msg) == {"fact:" + msg.fid}
    assert suppkeys(attachment) == {
        "fact:" + attachment.fid,
        "fact:" + member,
    }
    assert deathkey(msg) is None
    assert not is_deletion(msg)
    assert msg.atoms == [self_selector()]


def test_deathkey_is_body_free():
    target = message("pk", "general", "hello", 1)
    deletion = EnvelopeOnly([
        action(CONTENT_DELETE, SELF, target.key)])

    assert deathkey(deletion) == "fact:" + target.fid
    assert is_deletion(deletion)
    assert suppkeys(deletion) == frozenset()


def test_suppression_marker_survives_the_wire_codec():
    target = message("pk", "general", "hello", 2)
    deletion = Fact(
        "sample_delete", 3,
        [action(CONTENT_DELETE, SELF, target.key)], {})
    decoded, _ = decode_pile(encode_pile([deletion]))

    assert decoded == [deletion]
    assert is_deletion(decoded[0])
    assert deathkey(decoded[0]) == "fact:" + target.fid


@pytest.mark.parametrize("fact", [
    Fact("msg", 1, [],
         {"pk": "pk", "chan": "general", "text": "markerless"}),
    Fact("file_bao", 1, [],
         {"pk": "pk", "chan": "general", "name": "markerless",
          "size": 0, "root": "0" * 64, "width": 1, "n": 0,
          "enc": "clear-v1"}),
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
    [["action", CONTENT_DELETE, SELF, "not-a-key"]],
])
def test_noncanonical_or_ambiguous_markers_do_not_index(atoms):
    fact = EnvelopeOnly(atoms)
    assert suppkeys(fact) == frozenset()
    assert deathkey(fact) is None
    assert not is_deletion(fact)
