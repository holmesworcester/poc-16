"""core/vocabulary.py — the offer-address vocabulary, append-only by law.

Skeleton for bead poc-16-9fc.4; plan: docs/VERSIONING.md §5.

Tier 1: a release may never move the valid set.  What makes that true is that
normalization is a *relabeling of a stable meaning space*, applied to offers
and needs alike, so matching is invariant under it.  Encoding the law means
pinning the vocabulary: every address is registered with the release that
introduced it, and removing or redefining one fails a test.  A genuine change
of meaning mints a NEW address, which each old handler then decides whether it
can honestly offer.

Bodies unwritten.  Signatures are the contract.
"""
from dataclasses import dataclass

SNAPSHOT = "tests/vocabulary.json"
"""Checked-in registry snapshot; the test diffs the live registry against it."""


@dataclass(frozen=True)
class Address:
    """One offer address in the interlingua.

    ``a0`` and ``a1`` name what those slots *mean*, not their values — the
    envelope-to-address map is not injective (core/fact.py:44) and ``a1``
    means three different things by position (docs/VERSIONING.md §4), so the
    meaning has to be written down beside the name.
    """

    name: str
    a0: str
    a1: str
    introduced_in: str
    families: tuple


def registry():
    """Every address the running release's families offer or need."""
    raise NotImplementedError("poc-16-9fc.4 — docs/VERSIONING.md §5")


def snapshot(addresses):
    """Serialize a registry for check-in, canonically ordered."""
    raise NotImplementedError("poc-16-9fc.4 — docs/VERSIONING.md §5")


def violations(current, pinned):
    """Addresses removed or redefined since ``pinned`` — the Tier 1 breaches."""
    raise NotImplementedError("poc-16-9fc.4 — docs/VERSIONING.md §5")
