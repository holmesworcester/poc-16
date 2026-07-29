# POC-16 design

This document describes the code on `main`. It distinguishes running behavior
from limits and future work; it is not a backlog.

## Goal and trust boundary

POC-16 asks whether peers can reconcile an authenticated workspace against a
counterpart that mostly serves immutable bytes. The active peer performs the
walk, verifies hashes, validates fact closures, and updates local projections.
The responder supplies a small authentication gate plus an object-store-shaped
HTTP surface.

The prototype provides integrity, deterministic reconciliation, logical
suppression, and bounded request-time authorization reads. It does not provide
body confidentiality, physical erasure, production-grade garbage collection,
or compatibility across format stamps.

Fact bodies are plaintext JSON. Signatures authenticate facts. Only invite
blobs are encrypted with a secret carried in the invite link. Attachment bytes
are content addressed and Bao verified, but the surrounding file facts are not
encrypted.

## Facts and the kernel

A fact is a canonical JSON value containing:

- a type tag;
- an integer timestamp;
- clear-envelope atoms for references, offers, and suppression policy; and
- a family-owned body.

Its `fid` is the SHA-256 hash of those canonical bytes. Its reconciliation key
is the fixed-width string `(timestamp, fid)`. Timestamps primarily provide
locality and deterministic ordering; the prospective admission rule described
under “Action timing” also compares that key.

A pile is a canonical, topologically ordered, dependency-closed collection of
facts plus optional blobs. The same pile codec is used for ingress, sync, and
resident leaf objects.

The family-neutral kernel processes a pile in one pass. A reference must name
an earlier fact. Each family declares needs such as `member`, `admin`, or
`author`; the kernel selects the canonical provider by shortest proof rank and
then fid. Families validate their own shapes and values. `facts/_policy.py`
independently verifies the cross-family contract: named edge roles, exact
suppression selectors, direct target modes, admission guards, and continuing
authority liveness.

Persistent validity is immutable and does not read wall-clock or removal
globals. An ephemeral `req` additionally checks its verb and expiry against the
service’s trusted current time.

## Store and publication

Each workspace store exposes:

```text
root                         one mutable, CAS-written composite root
obj/<sha256>                 immutable pages, piles, facts, and blobs
pile/<member>/<sha256>       idempotent ingress
invite/<unguessable-id>      encrypted invite blob
failed/...                   node-local quarantine diagnostics
```

SQLite files are derived indexes and read models. Deleting them and reopening
the node rebuilds them from the objects named by `root`.

The root uses layout stamp `composite-btreap-v3` and atomically binds:

```text
anchor          workspace genesis fid
globals         non-suppression kernel globals
manifest        range-sync manifest root
layout_seed     deterministic authenticated-tree seed
trees           FactTree, SuppTree, AuthorityTree descriptors
actions         count and digest of the admitted action set
stamp           exact format identity
```

One compare-and-swap publishes the range manifest and all three authenticated
trees. There is no second mutable removal root and therefore no two-root
transaction.

The range manifest partitions sorted fact keys with the shared stable boundary
rule. A leaf is a closed pile; a closure sibling lists transitive dependencies
whose home is outside the leaf. Equal subtrees have equal object ids, so sync
prunes them by oid. On append, unchanged ranges are reused without decoding
their facts.

## The three authenticated trees

All logical indexes use one persistent Merkle treap codec. The priority of a
row is `H(layout_seed, key)`, which gives a unique Cartesian tree independent
of insertion history. Each immutable page stores one row and its child object
ids. An update path-copies only search and rotation paths. A Worker read is
bounded by the published depth and the hard depth cap; it never enumerates a
tree.

The schemas are:

- **FactTree** — `fact:<fid>` maps to a bounded `FactRecord` containing the
  raw-object id, named edges, offers, selectors, continuing liveness scopes,
  and optional action evidence. `action:<sid>` is a reserved CLEAR/ACTIVE
  action slot.
- **SuppTree** — a suppression id maps directly to CLEAR or to ACTIVE with its
  canonical action fid.
- **AuthorityTree** — a canonical `NeedKey` maps to the selected provider or
  authenticates absence.

This answers two different lookup directions without duplicating authority.
The authoritative read path is keyed by suppression id. The immutable action
fid and evidence are reachable from its ACTIVE slot and FactRecord. Local
SQLite keeps `actions(sid, fid, evidence)` and `supp(fid, sid)` as rebuildable
reverse projections so a node can retract already-resident victims. Those
tables are not a second published index and Workers never read them.

An action, its `action:<sid>` slot, its `sid` suppression slot, the fact and
authority updates, and the range manifest all become visible under the same
root CAS.

## Explicit suppression

Suppression is offered by the target fact, not guessed from arbitrary
dependencies. A registered family declares either no suppression policy or an
exact list composed from:

```text
SELF
PARENT(named_role, parent_fid)
ANCESTOR(named/path, ancestor_fid)
```

`SELF` is serialized as a non-circular marker and expands to the fact’s fid
after hash integrity succeeds. All selectors resolve into one typed namespace:

```text
SELF(f)                 -> fact:<fid(f)>
PARENT(_, p)            -> fact:<p>
ANCESTOR(_, a)          -> fact:<a>
member principal        -> member:<public-key>
device principal        -> device:<public-key>
```

A fact may offer several selectors. A family with no policy offers none and
cannot be a direct suppression target. This is separate from authorization:
an untargetable action fact can still require live admin authority.

Current content policies are explicit:

- messages and file descriptors offer `SELF`;
- Bao files additionally carry their member parent;
- chunks offer `SELF`, their file parent, and their file/member ancestor;
- deleting a file descriptor therefore suppresses its chunks without the
  deleter enumerating descendants;
- deletion and eviction facts offer no selector and cannot themselves be
  deleted.

The selector count is capped and checked both when authored and independently
at admission.

## Deletion, eviction, and authority

An exact content deletion contains an exact target key, a hard target ref, and
the `SELF` selector token. The target family’s `DIRECT_TARGETS` entry must allow
that action and mode. Supplying a bare suppression id is not a capability.

The ordinary fact graph authorizes the action:

- `OWNER` requires an author signature and a member provider whose durable
  principal equals the target’s owner principal;
- all devices belonging to one user resolve to that user principal, so sibling
  devices can remove the user’s content;
- `ADMIN` requires an author signature and a live admin provider and can remove
  every directly deletable family;
- an unrelated ordinary member satisfies neither path.

These checks live in the content-delete handler and the exhaustive policy
registry. The core does not special-case message or file ownership.

Member eviction is an admin-authored fact offering `removed(target_pk)`. It
activates `member:<target_pk>`, a terminal key-wide tombstone that covers
existing and future membership providers. A Worker checks that exact key when
minting a grant, so it does not load the fact set or rebuild a database.

Authorization has two intentionally distinct concepts:

- an `authorization_guard` must be live when admitting a new irreversible
  effect;
- an `authority_liveness_guard` continues to mask an already-published
  authority provider.

A delegated admin grant uses the grantor admin as a one-time admission guard
and the grantee membership as its continuing liveness guard. Evicting the
grantee disables the grant. Later loss of the grantor does not retroactively
undo a grant that was validly committed.

## Action timing

The admitted action set is monotone. Workers enforce current state strictly:
an ACTIVE principal or selector always refuses the request.

Replica admission must also converge when an old fact and an action arrive in
opposite orders. Without a linearizable receipt service, the running rule uses
the canonical fact key: an action blocks a candidate ordered after it, while a
candidate ordered before it remains admissible as history. This avoids an
arrival-order graph walk and is deterministic, but timestamps are
author-controlled. A colluding live relay can therefore present a newly signed,
backdated durable effect as historical. Remote minting still refuses the
removed principal itself. Closing the stronger “authored before, not merely
ordered before” distinction requires a service-issued admission frontier or
receipt; it cannot be inferred from an asynchronous signed fact alone.

## Worker authorization

`WorkerView` opens the composite root and performs exact authenticated reads:

1. decode and kernel-validate the submitted closure (maximum 64 facts);
2. require exactly one ephemeral request with an allowed verb and unexpired
   service-time deadline;
3. check committed authority winners and family-required co-offers;
4. read only the request/provider FactRecords and their declared liveness
   scopes;
5. read the corresponding SuppTree slots; and
6. return `(public_key, verb)` for sealing by the daemon.

`core/mint.py` contains only this path. There is no compatibility projection,
SQLite reconstruction, or full-tree fallback. A cached view is reusable only
while its root ETag matches.

The daemon seals a short-lived bearer grant to the requester’s public key.
The grant TTL is a deliberate revocation leakage window. After expiry, an
evicted member cannot mint another remote grant. The trusted local `ctl/*`
surface is not an authentication boundary: an evicted replica that missed its
own action may continue writing isolated local state, but authorized peers
refuse delivery.

## Sync and recovery

A dial reads the remote root conditionally. A 304 against an unchanged local
root is O(1) after blob completeness has been stamped for that ETag.

When roots differ, sync reconciles admitted actions first. Each ACTIVE slot and
its evidence closure are hash-checked and kernel-validated independently; one
missing or poisoned witness is skipped without blocking honest actions. The
ordinary range manifest is then diffed by oid, local-only facts are pushed as
one closed pile, remote ranges are assembled, and missing live blobs are
fetched. Push happens before draining the pull so canonical pruning cannot
remove a precomputed difference before delivery.

Ingress failures and sync failures are quarantined and visible through
`status`. Malformed roots, pages, facts, selectors, action evidence, or
authority rows fail closed. A root format mismatch forces a wholesale rebuild
from the current derived index; there is no ongoing dual decoder.

Application tables are insert-only source rows plus a projection cursor.
Suppression appends retractions to the delivery log. Rebuild replays the
authenticated resident facts, reconstructs action and selector reverse maps,
and then reproduces the application view.

## Performance

`bench/bench_latency.py` measures the running paths. On the development host on
2026-07-28, five hot posts at each scale produced:

| Seed facts | Post p50 | Post p95 | sorted-key scan p50 | immutable KiB/post |
|---:|---:|---:|---:|---:|
| 1,000 | 20.55 ms | 21.20 ms | 0.98 ms | 58.6 |
| 5,000 | 36.34 ms | 37.30 ms | 5.07 ms | 74.6 |
| 10,000 | 50.42 ms | 58.11 ms | 10.60 ms | 69.5 |

The authenticated trees and changed manifest ranges update in logarithmic
paths. One index-only sorted-key scan remains to derive the canonical range
partition, so post time is not perfectly flat; the benchmark makes that slope
visible. A primed same-root idle dial measured about 0.007 ms p50/p95 locally
and performed no fact, tree, object, or blob-demand scan. These numbers are
diagnostic, not cross-machine service guarantees.

## Limits and future decisions

- Ordinary bodies are plaintext. End-to-end body encryption needs a separate
  design and implementation.
- Logical deletion stops projection, authorization, and future blob demand; it
  does not erase immutable objects already stored. Physical GC is unbuilt.
- The canonical range manifest still performs an O(n) index-only key scan per
  commit.
- Strong authorship-time revocation needs serialized admission receipts, as
  described under “Action timing.”
- A removed node may not learn its own terminal action if it has no inbound
  peer and its cached grant expires first. The remote door is still closed;
  explicit tombstone delivery is a separate availability feature.
- The current prototype assumes one workspace per store directory. Shared
  multi-workspace buckets, lifecycle policy, and production cloud deployment
  are out of scope.
