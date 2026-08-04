"""peerlog: the hybrid sync model (beads poc-16-6j4.30/.31, decided on .29).

Canonical storage is one dense append-only log per writer, everywhere.
Two protocols consume it:

  peer <-> peer    closed-range RBSR over a peer-local (ts, fid) treap
                   (walk.py) — completeness among live peers.
  client -> store  seq-diff plus demand-driven chase against the passive
                   GET/PUT interface (phase 2, bead .31).

Every peer also serves the passive interface, so a peer is synced from
exactly like the cloud store. Facts are authenticated by residence: a
writer's head signs its log's tree root, and any single fact is provable
with (bytes, signed head, inclusion path) — proof.py. RBSR is discovery
and transfer, never a storage model: received runs are filed back into
per-writer log copies (ingest.py).
"""
