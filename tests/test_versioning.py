"""Acceptance tests for the versioning epic (poc-16-9fc).

Plan: docs/VERSIONING.md.  Model: DESIGN.md §Versioning.  Every test here is
skip-marked with its bead; implementing a bead means writing its bodies and
removing its skips.  Names and docstrings are the contract — the properties
were chosen before the code, and the suite stays green until each lands.
"""
import pytest

# ---- poc-16-9fc.1 — version in the tag (docs/VERSIONING.md §2) --------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.1")
def test_every_family_declares_family_and_version():
    """FAMILY and VERSION sit beside TAG in every routed module."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.1")
def test_family_version_pairs_are_unique_and_one_is_current():
    """(FAMILY, VERSION) is unique, and exactly one version per family authors."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.1")
def test_persisted_tags_are_never_recomputed_from_family_and_version():
    """TAG stays the exact stored wire string; old facts still reconstruct."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.1")
def test_core_names_no_anchor_family_tag():
    """core/tree.py stops hard-coding ('workspace', 'genesis') in the merge path."""
    raise NotImplementedError


# ---- poc-16-9fc.2 — the offer seam (docs/VERSIONING.md §3) ------------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.2")
def test_offer_table_is_filled_from_handler_output_not_envelope_atoms():
    """The kernel admits handler offers; Fact.offers() stays the envelope view."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.2")
def test_identity_offers_leave_every_root_byte_identical():
    """With identity offers() the whole corpus republishes unchanged."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.2")
def test_handler_only_offerer_keeps_a_persistent_proof_rank():
    """proof_sources ranks by emitted offers, so ranks survive rebuild."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.2")
def test_globals_are_stable_identities_not_decoded_schema_values():
    """Root-borne global rows carry keys/fids, so a bump rewrites no root bytes."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.2")
def test_non_scalar_offer_atom_is_litter_not_poison():
    """_admit moves inside the guard: a validating family with odd atoms rejects."""
    raise NotImplementedError


# ---- poc-16-9fc.3 — the proof (docs/VERSIONING.md §9) -----------------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.3")
def test_cross_release_replay_yields_an_identical_valid_set():
    """Tier 1, unconditional: releases N and N+1 admit the same fids."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.3")
def test_cross_release_replay_yields_identical_fingerprints():
    """fp is the diff identity, so a cross-version walk still prunes."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.3")
def test_undeclared_arrangement_change_fails():
    """Root bytes may move only when the release declares an arrangement bump."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.3")
def test_replay_moves_no_fact_byte():
    """Every obj/ the corpus shipped stays reachable and hash-consistent."""
    raise NotImplementedError


# ---- poc-16-9fc.4 — the vocabulary law (docs/VERSIONING.md §5) --------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.4")
def test_offer_addresses_are_append_only_against_the_snapshot():
    """No address is removed or redefined since the checked-in registry."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.4")
def test_a_changed_meaning_must_mint_a_new_address():
    """Redefining an address in place is the failure this law names."""
    raise NotImplementedError


# ---- poc-16-9fc.5 — the third outcome (docs/VERSIONING.md §6) ---------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.5")
def test_unknown_family_version_is_unreadable_not_invalid():
    """The unit does not enter the set and the pusher accrues no blame."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.5")
def test_unreadable_pile_is_retained_and_drains_after_upgrade():
    """Keep, do not delete; the same bytes judge cleanly once the handler exists."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.5")
def test_unreadable_range_stalls_instead_of_being_re_pulled_every_walk():
    """The live bug: today those facts never land, so the leaf re-pulls forever."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.5")
def test_invalid_pile_still_deletes_and_still_blames():
    """The two outcomes stay opposite; unreadable must not soften rejection."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.5")
def test_own_store_failing_its_own_kernel_still_asserts():
    """unreadable is about foreign piles; core/node.py's rebuild assert stands."""
    raise NotImplementedError


# ---- poc-16-9fc.6 — one release constant (docs/VERSIONING.md §8) ------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.6")
def test_release_bump_forces_both_stamps():
    """One constant drives the kernel replay and the projector refold together."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.6")
def test_new_idx_table_is_migrated_and_wiped_by_a_release_bump():
    """CREATE TABLE IF NOT EXISTS plus a hardcoded wipe list is the gap."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.6")
def test_version_driven_wipe_keeps_the_root_stamp_invariant():
    """Deleting derived state must also invalidate meta['root'], or cursors go stale."""
    raise NotImplementedError


# ---- poc-16-9fc.7 — the authoring floor (docs/VERSIONING.md §7) -------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.7")
def test_commands_refuse_to_author_above_the_member_floor():
    """The floor is the minimum implemented version over non-removed members."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.7")
def test_no_validation_or_closure_path_reads_the_floor():
    """Activation is authoring policy; a validator reading it would be time-dependent."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.7")
def test_a_fact_authored_above_the_floor_is_still_valid_forever():
    """Jumping the gun strands facts at old peers; it never makes them invalid."""
    raise NotImplementedError


# ---- poc-16-9fc.8 — the litmus (docs/VERSIONING.md §9.3) -------------------


@pytest.mark.skip(reason="skeleton — poc-16-9fc.8")
def test_v1_and_v2_facts_share_a_pile_without_reading_each_others_schemas():
    """The interlingua's actual claim, on a real second version."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.8")
def test_a_consumer_matches_v1_and_v2_providers_identically():
    """Normalized offers make provider version invisible to the consumer."""
    raise NotImplementedError


@pytest.mark.skip(reason="skeleton — poc-16-9fc.8")
def test_the_valid_set_is_unchanged_across_the_v2_bump():
    """Tier 1 again, this time against a genuine schema change."""
    raise NotImplementedError
