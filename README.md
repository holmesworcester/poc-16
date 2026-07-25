# POC-16

One-sided range reconciliation over a passive object store. See
[DESIGN.md](DESIGN.md); the two claims to prove are P1 (efficient sync from
the published treap) and P2 (efficient engine: validate piles into the
treap's tail range on request; promotion rides the same commit).
[MODEL.md](docs/MODEL.md) holds the performance/cost model and
the send/receive/compaction loop math.

**tinyp2p** is the working build: ~2,000 lines of Python split between the
family-neutral `core/` runtime and routed `facts/` policy
implementing the whole semantic stack — kernel, closed piles (each leaf a
topo-sorted closed set), pure treap layout, one-sided walk, seven-verb daemon, invite links,
eviction, and routed `facts/auth` + `facts/content` families — with black-box
multi-daemon tests. [IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
maps design to code, records the deviations, and carries the
treap-leaves-are-piles argument. `pytest tests/` runs it all.

## Setup

The Python runtime needs PyNaCl:

```sh
python3 -m pip install pynacl
```

Bao attachments additionally use the vendored Rust extension. From the
project root (with a Rust toolchain installed), build and install it with:

```sh
python3 -m pip install ./native/bao_py
```

The extension is loaded only when attachment I/O needs it; auth, messages,
sync, and `import facts` work without this optional build.
