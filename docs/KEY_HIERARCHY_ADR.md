# Recipient key hierarchy and purge guarantees

Status: accepted ADR for `poc-16-x1o.3`. It refines the threat model and
transition contract in
[`PUNCTURABLE_ENCRYPTION_SOURCE.md`](PUNCTURABLE_ENCRYPTION_SOURCE.md).
It is a provider contract and executable decision model, not a claim that a
production hardware provider has landed.

## Decision

**Decision: independent, non-exportable recipient-generation handles are the
primary hierarchy.** The portable fallback uses the same independently random
generation shape in software and makes a weaker guarantee. Poc-16 v1 has no
permanent content root and no deterministic generation schedule.

For one device recipient lineage:

- `dev_sign` is a stable signing/attestation identity. It cannot unwrap content,
  derive recipient generations, or authorize a retired schedule position.
- Every recipient generation is independently random. P private material
  cannot derive S or T.
- The provider keeps two handles at steady state: active P and P's staged
  successor S.
- A P-to-S transition creates and durably validates S's staged successor T
  before destroying P. The irreversible peak is therefore three handles:
  P, S, and T.
- After P destruction, promotion performs no key creation and returns to
  steady state S/T.
- A generation id is permanently bound to the provider suite and public key
  created for it. Recreating a handle under the same label does not change that
  commitment and makes every open, wrap, writer, and transition operation fail
  closed.
- Schedule position is separate from generation id. Before P's claim CAS, an
  unclaimed orphan at next position `n+1` may be destroyed, but its id is never
  reused; retry supplies a fresh generation fact id for the same position.
  P's accepted claim permanently binds the chosen id, suite, and public key.
- The recipient lineage is bound to one protected provider epoch. Restore
  compares that epoch and every restored suite-qualified generation commitment
  with the live provider; state from a fresh or reprovisioned provider fails
  closed and must enter as a new lineage.
- FrontierRoot and HistoryNode cover secrets are encrypted data, not hardware
  handles. Their count may grow with the canonical puncture cover while
  hardware handle count remains constant per recipient lineage.

The v1 first-F-only mode is rejected. Standard cover records are either
share-wrappable or generation-sealed, so purging F or any retained HistoryNode
is recovery-eligible and rotates the recipient generation exactly once for the
committed purge batch.

The portable software provider generates the same independent P/S/T keys and
implements the same state machine. It does not claim that filesystem backup,
clone, or snapshot restore cannot resurrect a deleted key or one-time claim.

## Why a stable root is not the answer

A root reduces visible handles only by retaining a recovery operation. If a
permanent `dev_box`, hardware root, seed, or parent can unwrap an archived P
blob or derive P again, destroying the P alias does not purge P. If P derives S
or T, compromise of P also crosses the intended rotation boundary.

Poc-16 therefore rejects:

1. a stable device-box key that wraps every recipient private key;
2. a forward KDF in which P or a retained seed derives S or T;
3. a permanent root that accepts an old generation number supplied by
   rollbackable software;
4. a saved root operation that reopens an archived cover ciphertext; and
5. a software-only “used” bit that a disk snapshot can roll back.

A future provider may retain a hardware root only if hardware enforces the
*exact live schedule position*: after monotonic advancement, the root must be
unable to operate at any earlier position even when given an archived keyblob
and an old database. TPM `PolicyNV` is one possible construction. It is a
provider extension, not the selected v1 hierarchy, and it must pass the same
snapshot, claim-fork, and purge tests before claiming a lower handle peak.

## Key and envelope layout

The shared recipient fact carries a provider suite and public key. The suite is
part of every key-wrap fact and its authenticated context; a P-256 key cannot
be relabeled as X25519 or vice versa.

- The frozen poc-10 compatibility suite remains
  X25519 + HKDF-SHA256 + XChaCha20-Poly1305.
- A hardware provider may advertise a different reviewed suite, such as P-256
  ECDH where that is the platform's non-exportable key-agreement primitive.
- Cross-suite migration decrypts with P through the provider and reseals to S
  under S's suite. It never exports P.

A local cover envelope contains:

```text
version
provider_suite
recipient_lineage_id
recipient_generation_fact_id
content_scope_id
frontier_id
secret_kind                  # FrontierRoot or HistoryNode
exact time/trie coordinate
source_secret_ref
tombstone_context
recovery_policy_ref
local_secret_commitment       # generation-independent canonical record id
nonce / sender public material
ciphertext
```

`local_secret_commitment` is the source contract's canonical local-secret
identity (`wrapped_secret_id`) or an equivalently versioned hash. The ADR
fixture computes it over a domain separator plus cover id, lineage, content
scope, frontier, secret kind, exact coordinate, source-secret ref, tombstone
context, recovery policy, and plaintext. It deliberately excludes recipient
generation, provider suite, nonce, and ciphertext so correct P-to-S resealing
preserves it.

Every field above is authenticated. On open, the caller supplies the exact
authoritative context and expected local-secret commitment from the named
canonical cover record. The provider compares them with the authenticated
envelope fields, verifies that the handle still matches the generation's
immutable suite-qualified public commitment, then decrypts and recomputes the
commitment from plaintext. An envelope cannot authorize itself by asking the
provider to trust its own suite, scope, frontier, coordinate, source, policy,
generation label, or secret identity. Implementations may use randomized
encryption and store the ciphertext in ordinary database/object storage. They
must not place plaintext F, HistoryNode secrets, leaf keys, or recipient private
material in facts, sync piles, logs, crash reports, or backup exports.

## Provider boundary

The production boundary must expose operations equivalent to:

| Operation | Required behavior |
|---|---|
| `generate_generation(id, position, suite)` | Create an independent key; return public material and an opaque handle, and retain the id's immutable position and suite-qualified public commitment. Track or destroy orphan allocation after failure; a replacement handle under the same id is ineligible. Before P's claim, a discarded orphan may be replaced only by a fresh id at that same next position. |
| `open(handle, envelope, expected_context, expected_secret_commitment)` | Before decrypting, require the handle to match the exact immutable generation suite and public key. Then authenticate the caller-supplied context and canonical local-secret commitment and recompute the commitment from plaintext. Private material never leaves a non-exportable provider. |
| `seal(public, plaintext, aad, secret_commitment)` | Seal F or one retained-cover node to a named generation, exact context, and generation-independent canonical local-secret commitment. |
| `claim(P, S, T, batch)` | Reject an empty canonical purge-operation set before authority changes. Otherwise atomically accept one exact transition tuple, including positions, successor suites and public-key bytes, together with the purge-target manifest derived from the canonical set of causally referenced operation ids. On the rollback-resistant tier, P must be the exact protected live position and a non-genesis P must have exact protected parent completion; then commit the whole protected claim/manifest record before writing rollbackable mirrors. Duplicate refs do not create another batch, identical saved-input retries coalesce, and every semantic mismatch conflicts. |
| `acquire_writer_lease(P)` | Admit a caller-requested generation-bound write only while that exact P is active, finalized, unfenced, and the live active/staged handles still match their immutable public commitments. Every commit rechecks the same conditions. Never replace a saved P request with the current generation. |
| `close_and_drain(P)` | Require P's accepted claim and immutable suite/public commitment, persist a provider-protected closing phase before returning, reject new P leases and commits against both protected and application state, and drain or abort all existing leases before survivor enumeration. |
| `migrate(P, S, manifest)` | Require the authoritative fence (the protected fence on the strong tier), P and S's immutable suite/public commitments, and the manifest from P's accepted claim; then reseal every live cover record except exact purge targets with restartable per-record progress. Freeze the exact `(cover id, local-secret commitment, authoritative context)` map on the first attempt; retries must match rather than replace it. The rollback-resistant tier commits this proof in protected state before replacing rollbackable cover storage. |
| `destroy(P)` | In one serialized retirement operation, snapshot the exact frozen survivor records, cryptographically reopen them as S, then prove the records are unchanged and recheck exact P/S/T handles immediately before retirement. On the rollback-resistant tier, atomically bind the exact claim and migration proof into the protected successor retirement position, which makes P unusable, before physical cleanup. Other tiers durably persist the same exact destruction intent before invoking non-transactional key deletion. Cleanup and evidence completion are idempotent. |
| `promote(P, S, T, claim)` | Require exact provider retirement evidence and P-handle absence, then project active/staged state to S/T without allocation or dependence on a clock or lookup-selected key. Every field is replayable from the exact claim/retirement record: a retry accepts only source/target values and repairs any prefix of a partial projection. |
| `finalize(P, S, T, claim)` | Recheck exact retirement evidence, P absence, S/T commitments, and the causal parent ref. The strong tier commits exact protected completion first; finalized and wrap-eligible fields are replayable mirrors, so a crash between them cannot strand or falsely authorize S. |
| `restore(metadata)` | Compare the restored provider epoch, positions, and suite-qualified generation commitments with live protected state, then revalidate the provider's current protected active/staged handles—not archived handles from the snapshot. A foreign/reprovisioned provider, missing/replaced live handle, or stale protected position fails closed; it is never rebound to an existing lineage by matching labels. |
| `capabilities()` | Report suite, non-exportability, deletion, rollback, attestation, capacity, backup, and clone guarantees without exaggeration. |

The stable identity provider may sign a provider attestation or shared
completion fact. It cannot call `open` and is not the schedule authority.

## Recursive one-time claim

Before any destructive step, the provider commits:

```text
TransitionClaimV1(
    content_scope_id,
    recipient_lineage_id,
    predecessor_recipient_fact_id = P,
    predecessor_schedule_position = n,
    successor_generation_fact_id,
    successor_schedule_position = n + 1,
    successor_provider_suite,
    successor_public_key_bytes = S,
    successor_next_generation_fact_id,
    successor_next_schedule_position = n + 2,
    successor_next_provider_suite,
    successor_next_public_key_bytes = T,
    retirement_batch_commitment,
)
```

The batch commitment is over the canonical set of exact causally referenced
purge-operation fact ids. Repeating the same ref does not add a causal
relationship and therefore does not change the commitment; an implementation
may equivalently reject duplicate refs at fact validation. There is no
timestamp in the claim. Fact authoring still captures “now” as required by the
source contract, but refs, needs, the claim, and the closed pile establish every
relationship. `S` and `T` mean the actual suite-qualified public commitments,
never aliases or generation labels. A retry supplies the originally saved
prepared tuple; the provider does not reconstruct it by looking up whichever
handles currently occupy those labels. Schedule positions are monotonic
provider state, not names inferred from `P`, `S`, or `T`: an unclaimed failed
allocation can be destroyed and a fresh opaque id prepared at the same next
position, while an id already present in a claim can never be reused.

On the rollback-resistant tier, acceptance is a protected compare-and-set of
the claim and its derived exact purge manifest, followed by rollbackable mirror
writes. An empty canonical operation set is rejected before this CAS, so a
no-op cannot consume P's one-time authority and block a later real purge.
Disk-only claim or manifest values are never authoritative. If power
fails after the protected CAS but before either mirror, the exact prepared retry
rehydrates both from protected state; a sibling conflicts. Later migration and
destruction consume that protected record, so tampered mirrors cannot redirect
the purge. The reverse order is forbidden because a disk-only “accepted” value
could be rolled back and forked.

For a predecessor P:

- the first valid whole tuple is accepted;
- an identical retry returns the same claim;
- different S, same S with different T, or the same P/S/T with a different
  batch is a permanent conflict;
- a reservation is not wrap-eligible; and
- finalized S must causally close over the claim, exact batch, fence/drain,
  migration, P destruction, provider completion evidence, and reader proof.

Finalized S and the provider's promoted state persist an explicit ref to the
exact P claim id/digest. At the next transition, the already committed S/T pair
advances to S/T/U. The provider follows that ref—not generation-list order, a
latest key, or a time lookup—and verifies that the live S and T public keys
still equal the referenced claim before allocating U and again before accepting
S/T/U. On the strong tier it also requires the protected live position to be S
and the exact protected P-to-S retirement/completion record to match that ref.
Forged or restored `active`, `finalized`, and `wrap_eligible` mirrors cannot
advance the protected schedule. S must itself be finalized and wrap-eligible
before its claim can begin. Replacing the handle currently stored under the
label `T` cannot silently create a new schedule. A rollback-resistant provider
retains enough one-time claim state outside rollbackable application storage to
reject a second P claim after restoration of an older snapshot.

## Rotation and migration protocol

Key purge is the trigger. Suppression visibility, deletion timestamp, observed
wrap inventory, and local absence are not triggers or proofs.

1. Identify the exact causally committed purge batch and recovery-eligible
   secret set.
2. Verify that P is the exact caller-requested active, finalized predecessor
   whose live handle matches its immutable suite-qualified public commitment,
   and that active/staged P/S match P's explicit causal parent claim when P has
   one. Generate and durably validate T at the next monotonic position.
   Capacity failure here leaves P live. Before claim, destroy an abandoned
   allocation and retry that position with a fresh id; never recreate T's id.
3. Atomically claim `(P, S, T, batch)` and its derived exact purge manifest. On
   the rollback-resistant tier, commit the protected claim/manifest CAS before
   its rollbackable mirrors.
4. Author the non-wrap reservation and its complete dependency-first closed
   pile.
5. Close the P writer fence in provider-protected state before reporting it
   closed, after revalidating P's suite and public key. Abort or drain every P
   lease. On the rollback-resistant tier, an old application snapshot cannot
   remove that closing phase or re-enable a saved P lease.
6. Load the purge-target manifest frozen by the claim. A different or omitted
   manifest fails; exact purge targets are not copied to S.
7. Open each live P envelope through the provider using the authoritative cover
   record context and generation-independent local-secret commitment stored
   separately from the envelope, including the expected generation and provider
   suite. Before decrypting, verify the handle against that generation's
   immutable suite-qualified public commitment. Recompute the local-secret
   commitment from plaintext. Immediately reseal to S without changing it and
   atomically persist the new authoritative context with the envelope. On
   restart, cryptographically reopen and recheck even a record already labeled
   S before counting it complete; an envelope cannot choose the handle, suite,
   or secret identity by self-description. Clear plaintext buffers.
8. Freeze the first exact `(survivor id, local-secret commitment,
   authoritative context)` map. A migration retry must reproduce that map and
   may never bless a reduced, relabeled, version-changed, or otherwise changed
   set. On the rollback-resistant tier the freeze is a protected CAS committed
   before rollbackable cover replacement.
9. In one lock/transaction/serialized provider retirement operation, snapshot
   the exact survivor records, require their map to equal the frozen proof,
   cryptographically reopen every snapshot record as S and recompute its
   commitment, then require the live records to be byte-for-byte unchanged and
   revalidate exact P/S/T handles immediately before the irreversible call.
   Also verify that no record can still be written under P. Loss or replacement
   of S, T, or P during validation, a missing or changed record,
   attacker-generated valid S ciphertext, metadata labels, or an earlier
   completion bit leaves P unretired.
10. Revalidate P's immutable suite-qualified public commitment. On the
    rollback-resistant tier, atomically record the exact accepted
    claim/manifest and migration proof while advancing protected retirement to
    the successor, making P unusable, before physical P-handle/keyblob cleanup.
    A floor or rollbackable `destroyed` bit without that exact record is not
    completion evidence. On lower tiers, durably write the equivalent exact
    destruction intent before calling the non-transactional deletion API. A
    retry with that exact intent distinguishes “not yet deleted” from “deleted
    before evidence commit”; any mismatch fails closed.
11. Promote the already existing S/T pair. No allocation is permitted after P
    destruction.
12. Revalidate that protected retirement names the exact transition, P is
    physically absent, and the live S and staged T handles, immutable public
    commitments, and S's persisted parent claim ref still match the accepted
    claim. On the strong tier, commit protected completion before projecting
    rollbackable finalized and wrap-eligible mirrors; an exact retry repairs
    either missing mirror. Only then can S satisfy key-wrap, request,
    proactive-share, or healing needs.
13. Garbage-collect superseded P metadata and ciphertext opportunistically.
    Archived P ciphertext is assumed to survive.

Multiple recovery-eligible secrets in one batch cause one transition. An
excluded purge operation never joins the batch by arrival order; it carries an
explicit rebase ref to finalized S and, when eligible, drives a later S-to-T
transition.

## Crash windows

| Crash point | Durable state and restart rule |
|---|---|
| Before T is durable | P/S remain steady. Delete or track any orphan; do not claim or fence. |
| After T, before claim | Retry with the same prepared T. If the unclaimed allocation must be discarded, destroy it and prepare a fresh id at the same next position; T's id remains permanently unusable. A rollbackable disk-only claim is not acceptance. |
| After protected claim/manifest CAS, before its disk mirrors | Retry the exact saved P/S/T/batch to rehydrate both mirrors. A sibling conflicts against protected state; migration always consumes the protected manifest. |
| After claim, before fence | Resume only the identical P/S/T/batch claim. A sibling is a conflict. |
| After fence, during migration | Keep P fenced and live. On the strong tier the provider-protected fence survives application-state rollback, so restored leases still fail their commit CAS. Resume the immutable manifest idempotently; do not rescan a moving set. |
| After protected survivor-map CAS, during cover replacement | Resume resealing from P or revalidate already-S records. The exact id, secret-commitment, and authoritative-context map cannot shrink or change. |
| After migration, before P retirement | Compare the live record/commitment map with the frozen proof and cryptographically reopen every authoritative S survivor again. Deletion, insertion, corruption, relabeling, or valid public-key encryption of different plaintext fails with P intact. |
| After protected retirement, before physical P cleanup | P already fails policy even if its handle bytes remain. Retry cleanup and reconstruct rollbackable destruction evidence from the exact protected claim, survivor proof, and retirement position. |
| Lower tier after destruction intent, before P deletion | P remains fenced. Retry the exact intent, revalidate P's suite/public commitment, and invoke deletion. |
| Lower tier after P deletion, before destruction evidence | Provider absence plus the exact precommitted intent permits forward reconstruction and promotion. Missing or mismatched intent fails closed. |
| After P cleanup, before promotion | Retry destruction idempotently. The strong tier reconstructs from the exact protected claim/proof and advanced floor; a lower tier requires its exact durable pre-delete intent plus provider absence. If the required evidence is missing, fail closed. Never allocate a replacement S or T or restore P. |
| During promotion projection | Retry promotion from the exact retirement record. Each active/staged/prepared/eligibility/parent-ref/promoted field must still be either its source or exact target value; repair every partial prefix or reject a conflicting value. No allocation occurs. |
| After promotion, before finalization | S/T are durable but S remains ineligible for shared wraps until completion evidence closes. |
| After protected completion, between finalized/eligibility mirrors | Retry exact finalization. Protected completion is authoritative and reprojects both mirrors; a disk-only mirror cannot authorize the next claim. |
| After finalization | Duplicate completion/finalization coalesces. Late P mismatch remains a conflict. |

An error before P destruction must leave P usable or report a precisely
recoverable fenced state. An error after P destruction may delay availability,
but cannot require P, allocate a new S/T pair, or report an ambiguous active
generation.

## Purging cover and recipient material

For an exact or range puncture:

- delete the target leaf, descend path, canonical bytes, caches, WAL/temp
  copies covered by the selected guarantee, and any target cover envelope;
- materialize only the canonical survivor siblings;
- migrate each survivor to S;
- destroy P after migration; and
- retain only the S-encrypted canonical cover plus S/T provider state.

The target is deliberately unavailable after completion. A retained sibling
continues to derive the same leaf for every surviving coordinate. Healing can
wrap the retained sibling but must never recreate F or a punctured path.

Under the selected standard provider, a retained HistoryNode is
generation-sealed and can also be a shared wrap source. Its purge therefore
rotates even when no wrap is visible locally. The first-F-only mode is rejected
because a delayed wrap or archived generation envelope would otherwise recover
the supposedly retired node.

## Guarantee tiers

Every provider reports one of these; product language must name the tier.

| Tier | Required property | What purge establishes | What it does not establish |
|---|---|---|---|
| `normal-disk` | Independently random software generations; best-effort overwrite/delete and cache cleanup. | Current ordinary storage no longer contains intentionally retained P plaintext/private state. | It does not establish that a backup, clone, forensic remanence, or restored filesystem cannot revive P or fork a claim. |
| `hardware-isolated` | Private key is non-exportable and current live provider state no longer exposes P. | A post-purge application/storage attacker cannot call P through the current handle set; extracting S/T private material is harder. | It does not establish that replaying an archived hardware keyblob or provider database is impossible. StrongBox/Secure Enclave branding alone is not rollback proof. |
| `rollback-resistant` | Hardware or an equally strong non-clonable witness irreversibly rejects deleted keyblobs and a second claim for each retired P. | Restoring old sealed state cannot open P material or authorize a sibling P claim; it fails closed. | It cannot make an authorized reader forget plaintext copied before purge or guarantee availability under malicious rollback. |

The rollback-resistant tier is both a key-erasure and schedule-uniqueness
claim. Supplying only one half is insufficient.

## Platform mapping

These are conservative ceilings, not automatic capability detection.

### Apple Security framework / Secure Enclave

Apple's [Secure Enclave key guide](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave)
documents device-bound, non-plaintext private keys and P-256 signing/key
agreement. That supports a P-256 recipient suite and the `hardware-isolated`
tier.

Apple also documents that a
[`ThisDeviceOnly` keychain item](https://developer.apple.com/documentation/Security/restricting-keychain-item-accessibility)
does not migrate to another device but can participate in same-device restore.
The cited public application API does not establish a monotonic transition
claim or rollback-resistant deletion guarantee. Therefore poc-16 does not claim
the rollback-resistant tier on Apple from Secure Enclave + `SecItemDelete`
alone. A future implementation needs a separately reviewed non-rollback
primitive or witness.

The stable Secure Enclave `dev_sign` key remains separate from rotating P/S/T
P-256 key-agreement handles.

### Android Keystore / StrongBox / KeyMint

The [Android Keystore guide](https://developer.android.com/privacy-and-security/keystore)
documents non-exportable keys and optional TEE/StrongBox protection. That
supports `hardware-isolated` when the actual key's security level and
authorizations are checked.

The lower-level
[KeyMint contract](https://source.android.com/docs/security/features/keystore/implementer-ref)
defines `ROLLBACK_RESISTANCE`: after deletion, secure hardware prevents a
previously captured keyblob from becoming usable again, commonly using replay
protected memory. It can also fail creation when trusted storage is full.

StrongBox alone is not treated as proof that this tag was requested, honored,
and available to the application provider. Ordinary Android Keystore adapters
claim at most `hardware-isolated`. A platform-specific adapter may claim
`rollback-resistant` only after it verifies deletion replay resistance,
one-time claim storage, attestation/security level, quota behavior, and the
three-handle transition on each supported device class.

### TPM 2.0

A direct TPM provider can bind sealed generation state to an exact monotonic NV
retirement position. The TPM specification defines
[`TPM2_PolicyNV`](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf)
as a policy assertion over NV contents, and an NV index with
[`TPMA_NV_COUNTER`](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.99.pdf)
can only be modified with `TPM2_NV_Increment`.

A retirement counter alone is insufficient for the strong tier. If it remains
at `n` while P is needed for migration, two callers can authorize different
claims before either completion increments it. The provider must therefore
also perform a protected claim-digest CAS: while P is at position `n`, atomically
change a hardware-protected per-position claim slot from empty to
`H(suite-qualified P/S/T/batch)`, or return the already matching digest, before
`claim` reports acceptance. A different digest conflicts. The generic
`TPM2_NV_Write`, `TPM2_NV_Increment`, and
[`TPM2_NV_Extend`](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf)
primitives are building blocks, not by themselves a reviewed CAS construction.

Only a platform adapter that proves that protected claim-digest CAS, prevents
claim-slot and counter deletion/redefinition, and binds P operations to both
the matching digest and position `n` may claim `rollback-resistant`. Completion
then advances the retirement position to `n+1`, making archived position-`n`
objects fail policy. The generic TPM mapping remains `hardware-isolated`;
rollback resistance is a conditional, separately reviewed provider extension.
TPM clear may destroy the root and data availability, but must not restore an
old position. NV endurance, ownership, multi-process coordination, and
provisioning are release gates.

### Software-only

Generate independent X25519 generations and encrypt their local storage using
the operating system's best available data protection. Never derive them from
`dev_sign`, a password, P, or a stable application root. This preserves
protocol interoperability, explicit P/S/T claims, and current-disk cleanup, but
the provider reports `normal-disk`: a pre-purge clone or backup can contain P
and can fork the one-time schedule.

## Backup, restore, and device recovery

Shared facts, content ciphertext, non-secret coordinates, and current cover
ciphertext may be backed up. Recipient private handles, plaintext cover,
plaintext leaf keys, and one-time schedule authority are not portable backup
material.

A new device is readmitted with a new stable device identity/recipient lineage.
An authorized surviving reader heals still-live F or retained cover to the new
recipient. It cannot heal a punctured secret. If no authorized reader retains
the live cover, confidentiality wins over availability and the content is
lost.

On same-device restore:

- `normal-disk` may resurrect P and fork its claim;
- `hardware-isolated` depends on provider behavior and makes no rollback claim;
  and
- `rollback-resistant` compares restored metadata with monotonic hardware
  state, the protected provider epoch, and the canonical suite/public
  commitments, then proves the provider's current protected active/staged
  handles still realize those commitments. Archived handles carried by the
  snapshot are never evidence about the live provider. It rejects stale P
  state, a snapshot from a fresh or reprovisioned provider, missing/replaced
  live handles, and forged schedule mirrors, then reconciles forward from exact
  protected retirement/completion and shared evidence. A maliciously old
  snapshot may lose availability, but cannot regain P.

Every private operation checks its addressed generation's protected provider
epoch and exact suite-qualified public commitment. Schedule operations—lease,
commit, wrap eligibility, claim, promotion, and finalization—also check the
protected live position and exact active/staged pair. Rolled-back metadata that
still calls P active or finalized, a context relabeled to another provider
suite, a foreign provider snapshot, or a new handle generated under an old
label is fail-closed before private-key use; it cannot admit a writer or open
replacement-key ciphertext. Opening a valid S cover does not by itself require
unrelated T to remain present, but S cannot become or remain wrap-eligible
without the exact live S/T schedule.

No restore path asks which key or timestamp is “latest.” It uses explicit
generation refs and the provider's exact monotonic position.

## Deferred retry-surface simplification

The executable decision model keeps `claim`, `migrate`, `destroy`, `promote`,
and `finalize` separate so this ADR can expose each required check. It proves
idempotent retries in the active transition and the documented
post-destruction/pre-promotion recovery window. It does not claim that an
arbitrarily late call to an old step returns the same success result after
later generations have retired that transition's S or T handles.

`poc-16-x1o.22` tracks the runtime simplification: issue one immutable,
suite-qualified transition token and drive it through a reconcile/advance
state machine. Its exhaustive contract matrix will retry every operation after
each later lifecycle state and generation. Until that lands, a historical
retry must fail closed without mutating current state; it must never reconstruct
arguments from a current-key or timestamp lookup.

## Rejected and deferred alternatives

| Alternative | Decision |
|---|---|
| One enclave handle per retained HistoryNode | Rejected: handle use scales with cover size and platform quotas. |
| Stable `dev_box` wrapping all generation keys | Rejected: an archived P blob plus the surviving box revives P. |
| P-derived forward ratchet | Rejected: P compromise derives successors; a retained seed/root can recreate retired material. |
| Precomputed reverse chain | Rejected for v1: either precompute/storage is unbounded or a retained root remains a recovery path. |
| Permanent root gated only by rollbackable generation metadata | Rejected: restoring metadata re-enables old operations. |
| TPM/external root gated by non-rollback exact position | Deferred provider extension; a counter alone is insufficient, so it must additionally prove protected claim-digest CAS, the complete contract, and any lower handle peak. |
| Independent per-node keys with no generation binding | Rejected for v1 first-F-only mode; it changes healing/wrap policy and needs separate proof that no old recipient/root path exists. |
| Remote serialization witness | Possible future rollback/clone tier, but it changes offline guarantees and is not part of the local v1 provider. |

## Executable decision evidence

The versioned fixture is
[`tests/fixtures/key_hierarchy_v1.json`](../tests/fixtures/key_hierarchy_v1.json).
`tests/test_key_hierarchy_adr.py` exercises a provider-shaped reference model:

- three recursive transitions P/S/T, S/T/U, and T/U/V;
- exact-claim retry and successor, next, and batch conflicts;
- rejection of an empty operation batch before claim, plus safe destruction of
  an unclaimed next-key orphan and rebinding of its monotonic position to a
  fresh opaque id;
- protected-first claim ordering, including repair of a disk-only partial write
  before rejecting a sibling retry, and immunity to tampered claim/manifest
  mirrors;
- exact protected-head enforcement, including rejection of forged
  active/finalized mirrors before a parent transition has protected completion;
- binding of those claims to actual suite-qualified public-key bytes, including
  rejection when an initial, active, or staged handle is regenerated under the
  same label, rejection of a recreated predecessor even with an empty survivor
  set, rejection of a foreign/reprovisioned provider epoch on restore, and
  revalidation on every writer commit and provider open;
- exact purge-manifest binding plus rejection of mismatched migration,
  destruction, promotion, and finalization state;
- authenticated binding of every cover-envelope context field and rejection of
  field mutation, suite relabeling, record transplant, ciphertext tamper,
  replacement-handle ciphertext, and public-key encryption of attacker-chosen
  survivor plaintext;
- generation-independent canonical local-secret commitments, immutable
  survivor id/commitment/authoritative-context proofs across migration retries,
  rejection of valid public-key context substitution, and protected proof
  recovery after rollback;
- independent real X25519 keys, including failure of known P material to open S
  or T ciphertext and different keys for equal public labels across providers;
- two steady handles, the three-handle peak, and capacity failure before
  destruction;
- protected writer-fence authority, survivor migration, target purge,
  allocation-free promotion with replay after every partial projection write,
  rejection of forged destruction evidence, and finalization;
- stale-snapshot writer rejection, protected retirement before physical handle
  cleanup, exact protected retirement records, exact lower-tier destruction
  intent before non-transactional deletion, and forward reconstruction of
  destruction evidence after every crash boundary;
- serialized post-open revalidation under loss/replacement of P, S, or T and
  concurrent survivor-record replacement or deletion;
- pre-finalization revalidation of both committed S/T handles after loss or
  replacement, plus replay of finalized/eligibility mirrors after a crash
  following protected completion;
- strong snapshot restore failing to revive P, accept a missing/replaced live
  active or staged handle, or fork its claim;
- software snapshot restore honestly demonstrating resurrection and a sibling
  claim;
- rejected root/first-F candidates; and
- conservative Apple, Android, TPM, and software capability ceilings.

This model does not prove a platform implementation. `poc-16-x1o.7` must run
the provider contract against the in-memory fault provider and each production
adapter. `poc-16-x1o.13` owns the full copy audit, including plaintext buffers,
caches, WAL, temp files, crash reports, backups, and provider-specific keyblob
residue.
