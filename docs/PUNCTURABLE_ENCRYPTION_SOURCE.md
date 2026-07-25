# Puncturable encryption source contract

Status: source contract for `poc-16-x1o`; this is a design model, not an
implementation or a proof of running poc-16 encryption code. The executable
work starts in the dependent `poc-16-x1o.*` beads.

The purpose of this record is to say exactly which poc-10 behavior is being
ported, which historical behavior is deliberately not being ported, and which
poc-16 invariants every implementation and cross-implementation vector must
preserve.

## Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` describe the poc-16 target. Statements
under “poc-10 source” describe source behavior and are not automatically
normative.

The versioned fixture is
[`tests/fixtures/puncturable_encryption_v1.json`](../tests/fixtures/puncturable_encryption_v1.json).
`tests/test_puncturable_encryption_source.py` independently recomputes its KDF
and wrap bytes and evaluates its lifecycle cases. That test module is a
test-only reference model. It does not claim that future runtime code is
verified until the runtime calls a proof-facing/executable core in the later
implementation beads.

## Source lineage

The source is poc-10. The commits below are the frozen evidence for this port.
They are intentionally historical references: this bead was explicitly asked
to audit prior designs.

| Commit | Source contribution | poc-16 disposition |
|---|---|---|
| `ad380cb4` | Per-content ciphertext uses a distinct history-tree leaf and deletion retires that leaf. This was an early single-axis/per-message implementation line. | Keep the per-content encryption and puncture intent; do not keep its obsolete coordinate geometry. |
| `7f60936f` | Replaces the flat history table with a power-of-two time tree plus a 256-bit within-bucket trie. It fixes the BLAKE3 keyed-hash domains and split encodings, but permits path-dependent Patricia KDF jumps. | Keep the two-axis geometry, domains, and adjacent split encoding. Poc-16 authors a fresh content coordinate and requires one KDF step per trie bit so retained-prefix recovery reproduces the original leaf. |
| `536b13c3` | Makes derivation resume from `Root`, `TimeInternal`, or `InMinute` retained ancestors and materialize only the path needed by the caller. | Keep lazy derivation and deepest-covering-ancestor behavior. |
| `9b40f352` | On retirement, materializes survivor siblings and wipes the complete descend path, including F, canonical secret bytes, and the leaf. | Keep exact/range puncture and durable secret erasure. |
| `bdaa60f6` | After F is gone, derivation falls back to the deepest retained sibling that covers the requested coordinate. | Keep retained-sibling recovery; treat every recoverable retained sibling as recovery-eligible for recipient rotation. |
| `178f198b` | Identifies the reconstruction path `old key_wrap + old recipient private key -> F` and requires recipient-key rotation when F is wiped. | Keep the threat and the purge-triggered rotation requirement. |
| `341b8c37` | Refines “every deletion rotates” to “the key wipe rotates”; the first F wipe on a peer was the source trigger. | Generalize from the first F wipe to every committed purge batch that retires any recovery-eligible secret. |
| `ed04d84f` | Publishes one successor `recipient_key` carrying `previous_recipient_key_id`, and purges predecessor material after supersession. | Keep explicit predecessor linkage and the reserve/finalize split; add recursive schedule and anti-fork claims. |
| `122cc471` | Deletes the old local private key, old public event bytes, and wraps addressed to the old recipient. | Keep complete retired-material cleanup. Reject its local wrap-inventory lookup as the source of eligibility. |
| `72756900` | Key requests and proactive healing wrap F while present, otherwise wrap retained `HistoryNode` secrets without recreating F. | Keep `FrontierRoot` and `HistoryNode` wrap kinds and the no-root-resurrection rule. |
| `fc111ad5` | Re-expresses targeted healing as fact/context matches and preserves recipient supersession cleanup. | Keep explicit fact relationships and desired-edge convergence. Reject its timestamp comparison between a recipient key and a frontier. |

poc-13 contributes only the connection-secret lifecycle represented by
`e61fd61`: a durable close suppresses a connection cluster and a purge deletes
suppressed handshake ephemeral private keys from disk and memory. It is useful
evidence that suppression and physical key purge are separate phases. poc-13
does not provide content recipient generations, a KDF history tree, retained
cover healing, or the recipient rotation protocol.

## Vocabulary and ownership mapping

| poc-10 | poc-16 target | Scope and owner |
|---|---|---|
| `removal_frontier` | `content_frontier` | Shared fact for the scope selected by `poc-16-t9f.4`; it explicitly refs its predecessor and authority. Membership-removal frontier rotation is separate from recipient rotation. |
| `local_key_secret` / F | `FrontierRoot` secret | Random 32-byte local secret owned by the encrypted-cover provider. Shared facts never contain it in plaintext. |
| `local_history_node_secret` | `HistoryNode` secret | Local retained-cover secret. Its coordinate and tombstone may be public facts; its secret is provider-encrypted local data. |
| per-event leaf | content leaf | Lazily derived 32-byte AEAD key for one explicit content coordinate. |
| `recipient_key` | finalized recipient generation | Shared, self-signed public key with full-reader authority and predecessor/schedule refs. Only finalized generations are wrap-eligible. |
| `local_recipient_key` | recipient private handle | Non-exportable provider handle where available; never a stable device-box key. |
| `key_wrap(FrontierRoot)` | root wrap | Shared ciphertext naming the exact frontier, recipient generation, source, policy, and authority refs. |
| `key_wrap(HistoryNode)` | retained-cover wrap | Shared ciphertext naming the exact node coordinate, source/tombstone context, recipient generation, policy, and authority refs. |
| `key_request` | targeted healing request | Shared request that carries a full-reader proof and exact frontier/recipient refs. |
| recipient successor | reservation then finalized successor | A non-wrap reservation fixes `P/S/T/batch`; finalized S becomes eligible only after fencing, migration, P destruction, and completion evidence. |

## Frozen KDF contract

### Root and coordinates

F is 32 random bytes generated by a cryptographically secure RNG for a
content frontier. An injected deterministic RNG may supply the fixture F for
tests; production MUST NOT derive F from a timestamp, identity, predecessor, or
database lookup.

The outer tree root is `(start=0, width=2^63)`. It is a binary
power-of-two range tree. A leaf at width one is the bucket bridge into the
inner trie.

The first-axis address is
`time_bucket = floor(authored_at_ms / 60_000)`, preserving poc-10’s unsigned
Unix-minute conversion exactly. Facts capture `authored_at_ms` as “now” when
first prepared. The value and its bucket are addresses only. They have no
causal, authorization, supersession, eligibility, assignment,
winner-selection, or retry-ordering meaning.

The second-axis address is a fresh 256-bit content coordinate prepared with the
fact. Retry reuses the saved coordinate and authored-at value. It MUST NOT
query a latest timestamp, latest key, current frontier, or logical row to
manufacture retry safety. A derived local artifact has no timestamp or copies
its basis timestamp as inert metadata.

This is an intentional deviation from the poc-10 message/reaction coordinate,
which hashed canonical identifying fields including `created_at_ms`. The
two-axis tree and split KDF are preserved; timestamp-derived retry identity is
not.

### Primitive

For a 32-byte parent secret `K`, domain byte string `D`, and canonical info
bytes `I`:

```text
child = BLAKE3-keyed-hash(key=K, input=D || 0x00 || I)
```

The domains are frozen:

```text
time: b"topo time split v1"
trie: b"topo trie split v1"
```

A time split encodes:

```text
u64_be(parent_start)
|| u64_be(parent_width)
|| u8(child_side)              # 0 left, 1 right
|| u64_be(child_start)
|| u64_be(child_width)
```

A trie split encodes:

```text
u16_be(parent_bit_depth)
|| mask_256(parent_prefix, parent_bit_depth)
|| u8(child_side)              # bit at parent_bit_depth
|| u16_be(child_bit_depth)
|| mask_256(child_prefix, child_bit_depth)
```

Bits are numbered most-significant first. Trie depth 0 is the bucket node;
depth 256 is a content leaf. Every cryptographic trie edge is exactly
`depth d -> d + 1`. An implementation may omit intermediate nodes from
storage, but it MUST execute every omitted bit step in memory.

This restriction repairs a path-dependence bug in the poc-10 Patricia fast
path. Because both parent and child depths occur in the KDF input,
`KDF(K, 0 -> 256)` differs from
`KDF(...KDF(K, 0 -> 12)..., 12 -> 256)`. Arbitrary jump derivation would make
an existing ciphertext’s leaf key change after F is purged and recovery
resumes from a retained prefix. With fixed bitwise derivation, splitting the
same 256-step path at any retained depth produces the identical leaf key.

### Lazy derivation and canonical cover

The provider derives from the deepest retained ancestor that covers the target:

- F covers the complete time tree while present.
- A time node covers its aligned half-open range.
- An in-bucket trie node covers coordinates matching its masked prefix.
- A leaf covers exactly one coordinate.

Fresh authoring computes the fixed path but materializes only what the running
path needs. Puncture materializes every survivor sibling required to cover the
complement, then
deletes the target leaf and every descend-path secret that could rederive it.
The retained set MUST be prefix-free and canonical for the same surviving
coordinate set.

When F has been purged, unrelated coordinates derive from retained siblings.
Failure to find a retained covering ancestor is a terminal “no cover” result,
not permission to restore F or consult another local snapshot.

## Wrap source contract

The poc-10 fixture preserves the source cryptography:

- X25519 sender/recipient Diffie-Hellman;
- HKDF-SHA256 with salt `b"topo key wrap v1"` and info
  `b"topo x25519 xchacha20poly1305 key"`;
- XChaCha20-Poly1305 over a 32-byte F or HistoryNode secret;
- all source kind, coordinate, recipient, frontier, and sender fields in AEAD
  associated data.

The poc-10 source derived a deterministic sender secret and nonce from the
wrapped secret plus the desired edge. The fixture pins that behavior so another
implementation can reproduce the source bytes. A poc-16 wire version MAY omit
the inert authored-at value or reuse the initially prepared value; it MUST
never obtain a value from lookup during retry.

`FrontierRoot` and `HistoryNode` are distinct wrapped-secret kinds.
`HistoryNode` always carries its exact time/trie coordinate, source-secret ref,
and tombstone context. Healing after F purge wraps only retained nodes and
never recreates F.

The v1 wrap vectors also pin valid poc-10 local-secret commitments. A
FrontierRoot `wrapped_secret_id` hashes the canonical local-root record. The
HistoryNode vector derives and materializes the complete root-to-bucket chain,
derives a depth-12 retained node, and hashes that node’s canonical local record.
The receiver can therefore reconstruct each named local secret id after open;
the ids are not arbitrary wrap labels.

Every wrap, request, proactive share, recipient publication, and healing fact
MUST carry a causal full-reader authority proof for the same content scope.
Authentication or sync authority alone is insufficient. Infrastructure that
can mint auth tokens but lacks the reader proof cannot obtain content keys.

## Purge-triggered recipient rotation

Recipient ephemeral rotation is triggered by **key purge**. A deletion fact,
suppression match, authored-at value, observed wrap, or local absence query is
not the trigger.

A retired secret is recovery-eligible when any immutable causal property says
the current recipient generation could recover it:

| Property | Recovery-eligible? | Reason |
|---|---:|---|
| Protocol permits a shared wrap for this secret kind | Yes | A valid wrap may be delayed, archived, or present only on another peer. |
| A wrap is already observed locally | Yes, but not because it was observed | The immutable wrap policy/source refs already made it eligible. |
| Secret ciphertext is sealed to the current recipient generation | Yes | The old private handle can open an archived sealed blob. |
| Secret is derivable from a retained generation root | Yes | The retained root is a recovery path even without a shared wrap. |
| Secret is independently encrypted, non-wrappable, non-generation-bound, and not root-derived | No | This is the optional weaker first-F-only provider tier. |
| Transient leaf with a causal no-wrap/no-seal/no-root policy | No | It may be purged without recipient rotation. |

Under the standard provider, both F and retained HistoryNodes are wrappable or
generation-sealed. Purging either therefore rotates. The poc-10 “first F wipe
only” result is valid only for a provider that proves every later retained node
has no shared, sealed, or retained-root recovery path.

One committed purge batch that contains one or more recovery-eligible secrets
causes exactly one recipient transition. Multiple eligible secrets in the same
batch do not cause multiple rotations.

## Recipient transition protocol

Let P be the active predecessor, S the staged successor, and T the successor
that S commits for its own next transition.

1. Prepare a now-authored, non-wrap-eligible reservation.
2. The provider’s one-time predecessor claim binds the complete tuple
   `(P, S, T, retirement_batch_commitment)`.
3. The reservation explicitly refs the exact purge-operation facts in the
   batch, plus P, reader authority, and provider claim.
4. Its fetchable unit is a dependency-first closed pile to the workspace
   anchor. Missing any ref or need rejects and retires the whole ingress unit.
   Nothing parks and no pending/wake state is created.
5. Fence P-bound writers. Stop new leases and commits, then drain or abort
   every in-flight lease before enumerating survivors.
6. Migrate every surviving cover ciphertext and durable provider record to S.
7. Before P destruction, validate S and prepare T. For independent
   non-exportable handles this is the three-handle peak P/S/T.
8. Destroy P’s private handle and all retired P-bound material.
9. Promote S without further capacity-dependent allocation.
10. Publish finalized S with predecessor P, next commitment T, reader proof,
    exact batch refs, and durable completion evidence. Only now may S receive
    wraps.

At the next transition the schedule advances from `P/S/T` to `S/T/U`.

Only identical `P/S/T/batch` retries coalesce. Different S, same S with
different T, or identical P/S/T with a different batch are conflicts and never
become wrap-eligible. This remains true after P finalizes: a late identical P
claim coalesces with the retained claim, while a late mismatch remains a
permanent conflict. Neither timestamps nor fact-id ranking selects a winner.

An independently valid purge operation outside the committed batch never
joins P retroactively, even if observed earlier. It remains explicit queued
work. A rebase artifact explicitly refs both that operation and finalized S;
the artifact, rather than a current-recipient lookup, assigns the operation to
a later provider-authorized batch. If it is recovery-eligible under S it
triggers the S-to-T transition.

## State and secret ownership

| State or secret | Durable? | Owner | Shared? | Destruction rule |
|---|---:|---|---:|---|
| Content ciphertext fact | Yes | Fact tree/object store | Yes | Suppression hides it; storage GC is separate from key purge. |
| F / FrontierRoot plaintext | Yes, provider-protected | Encrypted-cover provider | No | Purge exact provider record and all recoverable copies in the committed batch. |
| HistoryNode plaintext | Yes, provider-protected | Encrypted-cover provider | No | Purge exact node/path records; retain only canonical survivor cover. |
| Leaf plaintext key | At most provider cache lifetime | Encryption operation/provider | No | Zero/drop after use; puncture deletes durable/cache copies. |
| Recipient public generation | Yes | Fact graph | Yes | Successor refs P; old public facts may remain semantic evidence but cannot authorize wraps. |
| Recipient private handle | Yes, preferably non-exportable | Hardware/software key provider | No | Provider destruction after fence/migration/preparation succeeds. |
| Stable device identity key | Yes | Identity provider | Public half only | May survive content rotation; MUST NOT derive recipient generations or old cover. |
| Schedule/batch one-time state | Yes, rollback-resistant on strong tier | Recipient key provider | Claim evidence may be shared | Advance monotonically; old state cannot authorize another P claim. |
| Wrap ciphertext | Yes | Fact tree/object store | Yes | Old wraps may remain archived; old recipient private destruction makes them useless. |
| Reservation | Yes | Fact graph | Yes | Never wrap-eligible; rejected partial ingress creates no state. |
| Writer lease/fence state | Resumable local state | Encrypted-cover provider | No | No P-bound commit is legal after the fence closes. |
| Plaintext projection/cache/WAL/temp | Implementation-dependent | Application/storage layer | No | Audit and purge in `x1o.13`; a strong deletion claim includes these copies. |

Retained cover is encrypted as data. It does not consume one Secure Enclave or
KeyStore handle per node. A normal independently generated hierarchy uses two
recipient handles at steady state (active plus staged next) and three at the
irreversible transition peak (P, S, and T). A permanent hardware root is not
automatically safe: any root that can derive an old generation or open an
archived cover defeats purge. `poc-16-x1o.3` must choose the provider mechanism
and document platform-specific guarantees.

## Adversary matrix

| Adversary after completion | Standard software tier | Hardware deletion tier | Rollback-resistant tier |
|---|---|---|---|
| Reads current database/object store | Deleted leaf/F/path and old private material unavailable; survivor cover remains. | Same. | Same. |
| Finds an archived or delayed old wrap | Cannot open if old private material was actually deleted; software backup/clone caveat applies. | Cannot open with destroyed non-exportable handle. | Same. |
| Finds an archived generation-sealed cover blob | Software backup may retain the sealing key; guarantee must say so. | Destroyed generation handle cannot open it. | Same. |
| Restores a pre-purge filesystem snapshot | May restore software private/schedule state; no strong snapshot claim. | May restore sealed blobs, but not a destroyed hardware key; provider specifics apply. | Monotonic state also rejects a second P claim. |
| Clones device state before purge | Both clones may retain software keys and fork schedule claims. | Non-exportability limits extraction but two live hardware devices remain two principals. | Only a provider/device identity with non-clonable monotonic state can claim anti-fork behavior. |
| Compromised authorized reader before purge | Already learned plaintext/keys cannot be made forgotten. | Same. | Same. |
| Auth-only infrastructure peer | Has no reader proof, so cannot receive recipient keys, requests, proactive shares, or healing wraps. | Same. | Same. |
| Active writer racing purge | Fence drains or aborts the P lease before survivor enumeration; no post-fence P commit. | Same. | Same. |
| Replica delivers facts in another order | Closed-pile validation plus exact refs yields the same accepted graph and batch assignment. | Same. | Same. |

The guarantee never erases an adversary’s pre-purge plaintext copy. “Deletion”
must be qualified as storage deletion, hardware-key deletion, or
rollback-resistant erasure.

## Availability and recovery tradeoffs

- A puncture can intentionally make old ciphertext permanently undecryptable.
- A peer missing all retained cover for a coordinate cannot reconstruct it by
  restoring F.
- Offline readers heal from F while F lives, otherwise from the retained cover.
- Conservative recovery eligibility rotates more often but is safe under
  delayed/remote wraps. Local negative knowledge would rotate less often but is
  unsound.
- A provider capped below the three-handle transition peak fails before P
  destruction. It retains availability of current P and reports retryable
  capacity failure.
- A writer that crosses the fence is aborted or retried from its saved prepared
  basis against S. It does not ask “what is latest?” to create a new identity.
- Membership removal creates a new content frontier and F for remaining
  readers. It does not substitute for local purge-triggered recipient rotation.

## Intentional poc-16 deviations

These are required changes, not accidental incompatibilities:

1. Fresh explicit 256-bit content coordinates replace timestamp-derived
   coordinate identity.
2. Trie KDF derivation is fixed one bit at a time. Patricia compression may
   compress storage, never the cryptographic path; this corrects poc-10’s
   path-dependent jump derivation.
3. Authored-at is now-only, first-axis addressing/inert metadata; it is never a
   causal clock.
4. Retry uses saved prepared state, never a latest-row/timestamp/key/frontier
   lookup.
5. Recovery eligibility is causal policy/source/sealing data, never observed
   wrap inventory or local absence.
6. Purging any recovery-eligible HistoryNode rotates under the standard
   provider; rotation is not limited to the first F wipe.
7. Recipient publication requires a full-reader proof; auth-only/sync-only
   infrastructure cannot satisfy content-key needs.
8. Successor publication is two-phase: reservations cannot receive wraps.
9. The provider fixes a recursive `P/S/T`, then `S/T/U`, schedule before
   predecessor destruction.
10. The exact retirement batch is an immutable causal claim. Arrival order,
   timestamps, and fact-id sorting do not choose membership.
11. Excluded operations rebase explicitly to S and, when eligible, cause a
    later S-to-T rotation.
12. P-bound writers are fenced and drained before survivor enumeration.
13. Every transition unit is an already closed pile. Missing dependencies
    reject with no parking or side effects.
14. Independent non-exportable handles use two steady handles and a
    three-handle transition peak unless a provider proves a stronger
    alternative.
15. Global suppression determines visibility and can enqueue puncture work,
    but suppression is not added to stable validity.

## Fixture coverage

The v1 fixture freezes:

- injected F generation and both KDF domains;
- exact `floor(authored_at_ms / 60_000)` addressing, standalone adjacent
  time/trie split encodings, fixed bitwise root-to-leaf derivations, and
  identical leaf recovery from retained depths;
- source-compatible FrontierRoot and HistoryNode wrap/open bytes;
- first-F, later-cover, delayed-remote-wrap, generation-sealed, retained-root,
  and explicit no-recovery purge cases;
- writer fencing and survivor migration ordering;
- identical and conflicting P/S/T/batch claims through S/T/U;
- rejection of premature successor finalization and finalized-S closure over
  fence/drain, survivor migration, P-handle destruction, and durable completion
  evidence;
- two steady versus three transition handles;
- included-operation closure, multi-root pile closure, and duplicate delivery;
- truncated predecessor, authority, claim, and operation piles rejecting
  without parking;
- excluded operation evidence arriving before a reservation and rebasing to S;
- explicit operation-to-finalized-S rebase refs;
- topology-preserving timestamp/fid/ref rewrites producing the same assignment;
- late identical and mismatched predecessor retries after finalization.

Any implementation that changes a frozen KDF or source-wrap byte must introduce
a new fixture version and explicitly classify the change. Lifecycle fixture
cases are normative semantic examples; their symbolic ids are not a proposed
wire encoding.
