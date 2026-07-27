# Simplification plan — one engine, one kernel, mint = evaluate, cursored pump

**Status (2026-07-26): historical.** The one tree engine this plan built was
itself deleted in the one-store cutover (docs/CUTOVER.md; bead poc-16-oyd.5
removed `core/tree.py`, `hoist.py`, `layout.py`, `treap.py`,
`kernel.Scratchpad`, and `tests/test_engine.py`). This document is the record
of that engine and of the simplification method.

**Status (2026-07-25):** stages S1–S7 and production settle-node placement
landed on the integration line: one parameterized tree engine, one kernel
judge, pure mint, cursored pump, source-keyed projectors, the confluence suite,
and design foldback. Companion to
`TREAP_PROTOTYPE.md` (cost model),
`MULTILEVEL_PILE.md` (hoisting), `DELETION_CLOSURE.md` (suppression treap),
`DESIGN.md` §Concurrency & FaaS (fat nodes, non-serialized roots).

**Historical skeleton:** branch `simplify-skeleton` preserves the original stub
modules
(`core/shape.py`, `tree.py`, `sync.py`, `mint.py`, `pump.py`, plus
`kernel.Scratchpad` and `store.RemoteStore` stubs) and skip-marked acceptance
tests (`tests/test_engine.py`, `test_eset.py`, `test_mint.py`,
`test_pump.py`). The integration line replaces those bodies. The sole
skip-marked gate-mask test belongs to the pending `poc-16-yez.9` decision, not
the simplification suite.

The thesis: the codebase already contains ONE recursion written five times, and
two more copies are scheduled (fat-node fold, T_supp walk). Extract the engine
once, *as* the fat-node rewrite, and every planned epic gets smaller.

---

## 0. The one recursion

Every tree operation in the system is the same simultaneous recursion over two
tree views — a local one and a remote/hypothetical one — that prunes where
identities agree and recurses where they differ:

| operation | left view | right view | prune on | emits |
|---|---|---|---|---|
| full build | ∅ | key set | — | all nodes |
| fold / update (`treap.update`) | current tree | tree ∪ delta | subtree untouched by delta | path-copied nodes |
| sync walk (`sync.py`) | my tree | their tree | fp equal | one closed selected-path union → ingress |
| push (reactive) | their tree | my tree | fp equal | closed pile → their ingress |
| two-root merge (jbg.4) | root A | root B | hash equal | root(A ∪ B) |
| verify-once (`hoist.verify_once`) | judged baseline | new tree | hash in baseline | verdicts |
| surfacing walk (yez.3) | my T_supp | store T_supp | fp equal | out-of-range victims |
| rebuild / catchup | ∅ | store tree | — | replayed stream |

Two identities, never conflated: **fp** (the diff identity — in-range keys only,
what the walk prunes on) and **oid** (the storage identity — `h(pile bytes)`,
closure included, what you fetch by). Keeping them distinct is what keeps
closure copies out of the diff algebra.

Two accumulators, one down, one up:

- **down**: the separator interval plus the *path scratchpad* — the verified
  ancestor context (`sqlite :memory:`, push on descend, pop on backtrack). This
  is `verify_once`'s scratchpad, and it is the same capability the hoisted sync
  walk carries so consecutive ranges share a verified path (the known catchup
  tax; production wiring lands with hoisting in `808.9`).
- **up**: rebuilt node hashes / pull-push sets / verdicts, committed at the top
  by ONE commit discipline (CAS root, or append into `roots/` + amortized merge
  — jbg.3; the engine takes it as a callback).

Laws the engine must satisfy (these are the property tests):

```
fold(t, ∅) = t
fold(fold(t, a), b) = build(set(t) ∪ a ∪ b)          (byte-identical, any batching)
diff(T(A), T(B))   = A Δ B, partitioned by leaves
merge(A, B)        = root(A ∪ B)                      (validate untrusted placement;
                                                       O(diff) for prevalidated
                                                       roots when deps fixed;
                                                       rebuild when rewired)
reads              ≥ A(B, P) + spine                  (the TREAP_PROTOTYPE floor)
```

Push is not a sixth thing: **push = a fold executed by someone else** — I ship
the delta as a closed pile into their ingress; their next `turn()` (or the next
drainer over the shared store) folds it. Two scratchpads stay distinct on
purpose: the *path context* is ephemeral; the *ingress pile* is the durable
write-ahead log (TREAP_PROTOTYPE §5). Fusing them would trade crash safety for
nothing.

**Sans-io**: the engine takes `fetch(oid)` / `emit(obj)` callbacks and never
does I/O itself. Async-ness, HTTP, S3/R2, retries are driver properties. Test
drivers are dicts with counters asserting the read floor.

## 1. Module map

```
shape.py    key fn, boundary(fid), priority, cut tiers (CUT/COLD_CUT/GUARD), fp
tree.py     View {fp, oid, sep, n, children} + build / fold / diff / merge
            packing parameter: fanout F + spine placement
              F=2, chunked            = today's binary treap (treap.py)
              F=∞, inlined            = today's flat manifest (layout.py)
              F≈32–256, fat nodes     = jbg.1 (MST/prolly; the target)
            optional settle hook      = hoisting (hoist.py's _spans/_settle)
codec       close.py stays as-is (one codec, one predicate — untouched)
kernel.py   ONE judge loop + the path scratchpad (push/pop) as a kernel
            capability; hoist._judge/_insert/_pop deleted (they are a copy)
store.py    trait as today + RemoteStore(Peer) so remote trees are fetched
            through the same interface the engine sees
sync.py     thin: engine.diff(mine, theirs) with pull/push emitters
daemon.py   gate only: grant check, ingress PUT, mint (below)
```

Copies deleted by this: `hoist._judge` (kernel), `treap.build` vs `layout`
(one build, two packings), `walk`'s fence compare (engine diff), `node.rebuild`
replay (engine walk from ∅), and — prospectively — the fat-node fold and
T_supp walk that jbg/yez would otherwise write fresh.

## 2. Coordination with the FaaS epic (poc-16-jbg)

`jbg.1` (fat nodes, drop the flat manifest) rewrites the tree layer anyway.
**Execute jbg.1 as the engine extraction** — one rewrite, not two: land
`shape.py`/`tree.py` with the binary and flat packings reproducing today's
bytes (golden gates), then add the fat packing as the third instantiation.
Then jbg.2 (pruned GET-only walk) is `diff` with a range-reading fetch driver,
and jbg.4 (two-root merge) is `merge` — neither is new recursion code.

Consequence of dropping the manifest to flag now: `layout()`'s manifest carries
`{anchor, fences, tail, globals}`. In the fat-node world **anchor + globals ride
the root node** (or each `roots/` entry). The stateless mint (§4) reads them
from there; nothing else may assume a flat fence list exists.

Golden gates for the extraction: byte-identical roots *within* a packing across
insert orders and fold batchings (the existing treap byte-identity check,
generalized); identical leaf sets *across* packings.

The engine packings use the monotone fine-cut policy: adding a key can split a
leaf but never erase an existing boundary, which is what makes a blind
path-copying fold possible. The compatibility-only flat facade retains the old
moving warm/cold cuts for byte reproduction. Fat spine nodes replace the flat
manifest's scaling role; closure-copy reduction moves to the hoisting stage
(`808.9`) instead of relying on boundary deletion at a moving watermark.

## 3. Coordination with the deletion epic (poc-16-yez)

`T_supp` is the engine's second instantiation: same `tree.py`, key
`suppkey ‖ tag ‖ ts:fid` from `shape.py`. The proof bead (yez.6) deliberately
runs on the current binary prototype — fine, don't block it. The *production*
synced T_supp (yez.10) should instantiate the engine, not the prototype that
jbg.1 replaces. Sequencing hazard if ignored: two epics fork the tree layer in
opposite directions the same week.

The required adapter landed in `poc-16-yez.15`. `T_supp` may omit authority
facts that have no suppression key: each primary settle payload carries a
canonical annex of the no-key body refs it needs. Those duplicated refs are
structural index bytes; the named fact bodies remain one-copy CAS shared with
`T_fact`. Key-capable closure facts retain normal settle placement before and
after their key becomes explicit. Narrow reads and folds therefore pay only
their selected closure, and batched body fetches preserve path-bounded network
round trips. `yez.10` can now instantiate the same engine directly.

`resolve_supp` (yez.11) is the closure edge that flags a fact suppressed
without touching validity. The pump (§5) is its consumer on the read-model
side; nothing in any `materialize` handler ever sees suppression directly.

## 4. Mint = evaluate ∘ close({request})

The two-predicate frame, stated once (it feeds yez.9's matrix and the gxz
seam decision):

```
valid(f)  = pred(f, closure(f))     immutable, globals-blind, per-fact
S(D)      = targets of valid suppression/removal facts    monotone semilattice
E(D)      = V(D) ∖ S(D)             a pure difference of monotone sets
                                    ⇒ order-independent, no linearization
```

Verdicts never read S — suppression **masks after judgment**, at exactly three
places: the gate (mint/transport), the surfacing/closure edge (yez.11), the
pump (§5). Never the kernel, never the tree. This is why the DESIGN.md
"set-valued verdicts" open question dissolves (DELETION_CLOSURE §4 says the
same thing from the other end).

The mint itself reduces to the kernel:

```
mint(pile) = decode → evaluate(pile, anchor, globals ∪ {("now", now_ms())})
           → seal(token(grant_of(pile)))
```

- The family owns the policy: `request.grant(f) → (pk, verb)`; the daemon's
  hand-rolled checks (tag filter, arity, expiry) move into the family's
  `evaluate`. Rule: a mint pile contains exactly one `DURABLE=False` fact.
- The challenge is already ephemeral (never persisted); replay is harmless
  because the grant is sealed to the requester's pk.
- A peer passes its root-stamped canonical offer/proof view into `evaluate`, so
  omitted incompatible authority winners cannot revive quarantined chains.
  A Worker/λ uses `mint.Authority.from_root` to derive the equivalent read-only
  view from a durable-only tree whose drained globals exactly match its root
  metadata; `mint.stateless` reuses it only for the same root ETag. The peer
  synchronizes its root-stamped index before minting. **Neither path reads
  app.db**; §5 remains a leaf-client concern.
- gxz (evicted-signer relay by an active member): the candidate seam is the
  gate mask — screen the *whole submitted closure* against S at mint/ingress,
  not just the requester — plus suppression of post-removal authority via the
  T_supp path (a revoked signer is a suppression predicate over authority
  edges). Decision belongs to yez.9; this plan only supplies the frame and
  keeps validity globals-blind in every option.

## 5. Read models: a cursored pure fold, retraction generic

With suppression settled at the validity/closure layer, projectors become
trivial consumers. Target invariant:

```
app.db = fold(step, ∅, log)          exactly-once, resumable, order-robust
fold±(delivery order over D) = fold(canonical order over E)      (the theorem)
```

- **Log**: `log(seq, ±fid)` in idx.db. `merge()` appends `+fid` for newly
  admitted durable facts and `−target` for each target of a newly admitted
  deletion (single-target now; 1:N victims stream in as yez.3's surfacing pass
  hands them over). Because a deletion refs its target, `−t` follows `+t` in
  every legal stream.
- **Cursor**: `cursors(ws, projector, seq)` in app.db; the pump applies rows
  and advances the cursor in ONE transaction. Exactly-once replaces
  idempotence as the handler obligation (INSERT OR IGNORE stops being
  load-bearing).
- **Projector contract** (AST-enforced in `test_fact_contract.py`): every row
  carries its producing `src` fid; handlers contain zero suppression logic;
  retraction is ONE generic pump operation, `DELETE … WHERE src = ?` across
  the family's tables. Blessed discipline shrinks to: insert-only rows keyed
  by src, views for anything aggregate-shaped. (Abelian aggregates later; LWW
  cells never — deleting the winner needs the runner-up.)
- **Known bug this fixes**: `removal.materialize`'s `UPDATE members SET
  evicted=1` is delivery-order-dependent (removal's closure excludes the
  target's join). Fix inside the contract: insert-only removals row + a view
  for the `evicted` display flag. That flag is member display data, not fact
  suppression — S never lives in app.db.
- **Rebuild** is the clean side of the theorem: today it scans valid
  single-target deletion facts to compute S first, folds over E in canonical
  order, and fires zero retractions. Synced T_supp replaces that scan later.
  Live nodes fold over D with occasional `−` events. The equivalence is the
  headline property test.

## 6. Tests

1. Engine golden gates: byte-identity within packings, leaf-set equality
   across packings, fold laws (§0), read-floor counters on dict drivers.
2. E order-independence: random pile partitions × orders × batchings ⇒ same
   E (extends the history-independence test).
3. Rebuild equivalence: `fold± ≡ fold over E` (§5).
4. Contract extensions: `src` column everywhere; deletion refs its target;
   suppression facts are not themselves suppressible (S stays monotone);
   pump-twice = no change; pump crash/resume.
5. Kernel unification: `verify_once` via the shared kernel loop reproduces
   `hoist` judge counts (judge-ops = |V| on cold catchup, unchanged).

## 7. Staging

S1  shape.py + tree.py extraction under golden gates, absorbing jbg.1
    (binary + flat packings reproduce today's bytes; fat packing added third).
S2  kernel unification: path scratchpad into kernel.py, delete hoist._judge;
    tree verification carries it across ranges. `808.9` then landed production
    settle payloads and path-union sync; ingress piles remain independent.
S3  mint reduction (§4); daemon.mint thins to decode→evaluate→seal.
S4  log + cursor + pump (§5), single-target retraction.
S5  projector contract + removal/join confluence fix; AST tests.
S6  property tests (§6) green as a suite.
S7  docs foldback: DESIGN.md engine/mint/node-state sections updated;
    TREAP_PROTOTYPE.md + MULTILEVEL_PILE.md marked absorbed-by-engine.

S1–S2 unblock jbg.2/.4 and yez.10 structurally; S3 is independent; S4–S6 are
leaf-client work the λ path never touches.
