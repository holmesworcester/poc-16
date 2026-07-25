"""core/release.py — the one release constant, and the stamps derived from it.

Skeleton for bead poc-16-9fc.6; plan: docs/VERSIONING.md §8.

Today `INDEX_VERSION` and `APP_VERSION` (core/node.py:57-58) are two
hand-maintained constants that mean different things and are tied to nothing.
`INDEX_VERSION` re-runs the KERNEL — validity, needs, `global_rows` — and is
what an offer-normalization change requires.  `APP_VERSION` re-runs only
MATERIALIZE, because pump's reproject branch rebuilds `Valid` tuples by hand
from the already-admitted `facts` table and never calls the kernel.  A release
must force both; a schema-only change may still force just one, which is what
the discriminators are for.

Bodies unwritten.  Signatures are the contract.
"""

RELEASE = None
"""The release this binary is. One constant; everything else derives from it."""

INDEX_DISCRIMINATOR = None
"""Bumped alone when idx.db's kernel-visible shape changes without a release."""

APP_DISCRIMINATOR = None
"""Bumped alone when app.db's projector shape changes without a release."""


def index_version():
    """The idx.db stamp: a mismatch replays the store through the kernel."""
    raise NotImplementedError("poc-16-9fc.6 — docs/VERSIONING.md §8")


def app_version():
    """The app.db stamp: a mismatch replaces the file and refolds every ws."""
    raise NotImplementedError("poc-16-9fc.6 — docs/VERSIONING.md §8")


def declares_arrangement_bump():
    """Whether this release admits it may change leaf closures, hence oids.

    Read by the cross-release replay proof (poc-16-9fc.3): root bytes must be
    equal across releases unless this says otherwise, so an *undeclared*
    arrangement change fails the test rather than passing silently.
    """
    raise NotImplementedError("poc-16-9fc.6 — docs/VERSIONING.md §9")


def wipe_tables():
    """Every idx.db table a version-driven rebuild must clear.

    `Node.rebuild` clears a hardcoded tuple today (core/node.py:597) while
    IDX_SCHEMA is applied with CREATE TABLE IF NOT EXISTS, so a new table is
    neither migrated nor wiped.  This is the single place that list may live.
    """
    raise NotImplementedError("poc-16-9fc.6 — docs/VERSIONING.md §8")
