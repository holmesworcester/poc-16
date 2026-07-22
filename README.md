# POC-16

One-sided range reconciliation over a passive object store. See
[DESIGN.md](DESIGN.md); the two claims to prove are P1 (efficient sync from
the published treap) and P2 (efficient engine: validate piles into the
treap's tail range on request; promotion rides the same commit). [MODEL.md](MODEL.md) holds the performance/cost model and
the send/receive/compaction loop math.
