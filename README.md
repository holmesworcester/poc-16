# POC-16

One-sided range reconciliation over a passive object store. See
[DESIGN.md](DESIGN.md); the two claims to prove are P1 (efficient sync from
the published treap) and P2 (efficient compaction: raw pile + valid treap ⇒
valid new treap). [MODEL.md](MODEL.md) holds the performance/cost model and
the send/receive/compaction loop math.
