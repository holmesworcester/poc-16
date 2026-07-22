# POC-16

One-sided range reconciliation over a passive object store. See
[DESIGN.md](DESIGN.md); the two claims to prove are P1 (efficient sync from
the published treap) and P2 (efficient engine: validate piles into the
treap's tail range on request; promotion rides the same commit). [MODEL.md](MODEL.md) holds the performance/cost model and
the send/receive/compaction loop math.

**tinyp2p** (`tinyp2p/`) is the working build: ~1,400 lines of Python
implementing the whole semantic stack — kernel, closed piles, pure treap
layout with annexes, one-sided walk, seven-verb daemon, invite links,
eviction — with black-box multi-daemon tests. [IMPLEMENTATION.md](IMPLEMENTATION.md)
maps design to code, records the deviations, and carries the
treap-leaves-are-piles argument. `pytest tests/` runs it all.
