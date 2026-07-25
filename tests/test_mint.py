"""PLAN SKELETON — mint = evaluate ∘ close({request}) (SIMPLIFY.md §4, bead
poc-16-808.4, stage S3)."""
import pytest

pytestmark = pytest.mark.skip(
    reason="skeleton — poc-16-808.4 (SIMPLIFY.md §4)")


def test_mint_accepts_exactly_one_ephemeral_fact():
    """A mint pile with zero or two DURABLE=False facts is refused; the
    daemon's arity check now lives in the family."""
    raise NotImplementedError


def test_family_owns_expiry_and_tag():
    """Expired request / wrong tag is refused by request.evaluate under
    globals ∪ {("now", ms)} — daemon.mint contains no body parsing."""
    raise NotImplementedError


def test_grant_sealed_to_requester_pk():
    """The grant unseals only with the requester's sk; replaying the
    challenge yields nothing to anyone else."""
    raise NotImplementedError


def test_mint_writes_nothing():
    """Evaluate mode: no drain, no ingress writes, no idx/app rows — the
    challenge is judged and forgotten."""
    raise NotImplementedError


def test_stateless_mint_from_root_only():
    """The λ path: mint from (root bytes, pile) alone — anchor + globals via
    mint.root_globals (they ride the root node after jbg.1); no app.db is
    ever built."""
    raise NotImplementedError


def test_gate_mask_screens_whole_closure():
    """gxz seam: a pile whose CLOSURE contains an evicted signer's fact is
    refused at the gate even when the requester is in good standing — enable
    once poc-16-yez.9 confirms the seam."""
    raise NotImplementedError
