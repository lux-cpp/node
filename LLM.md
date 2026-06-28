# node2 — a running consensus2 node (ZAP votes over real TCP)

`node2` hosts the **consensus2** engine and disseminates its votes over a **full
mesh of real TCP sockets**, framed by the canonical **ZAP** wire codec. It is the
live-mesh step beyond `consensus2-seed`'s socketpair test: N validators, each on a
real loopback listener, dial each other and independently reach BLS quorum-cert
finality over the wire.

## Layer decomposition (decomplected — each layer is independently testable)

```
  node-host    Node2Host         NEW  src/node2_host.cpp   — listen/accept/dial the
                                       full mesh; own one Node; drive submit/poll/pump.
  mesh         MeshVoteTransport  NEW  include/.../mesh_vote_transport.hpp (header-only)
                                       VoteTransport over N peer fds; broadcast→all,
                                       pump→drain all. Holds a vote SINK, not a Node —
                                       zero consensus knowledge.
  reassembler  FrameReader        NEW  include/.../frame_reader.hpp (header-only)
                                       the ONE place that knows non-blocking framing:
                                       reassembles ZAP frames from recv(MSG_DONTWAIT).
  codec/wire   encode/decode_vote REUSE consensus2-seed/.../zap/vote_codec.hpp
               Writer/Reader/           zap-cpp-core/.../zap/wire.hpp
               write_frame_locked
  consensus    Node / Wave /      REUSE consensus2-seed (the gate, unmodified)
               QuorumCertEngine
  crypto       cevm::crypto::bls  REUSE crypto/bls/cpp + blst
```

Why a new `FrameReader` instead of `lux::zap::read_frame`: `read_frame` blocks and
treats `EAGAIN` as fatal, so it cannot serve a single-threaded pump over N peers
(a partial frame on one peer would stall the rest). `FrameReader` accumulates
ready bytes and yields a frame only once complete — fragmentation is invisible
above it. The fds stay **blocking** (writes never drop) while reads go through
`MSG_DONTWAIT` (pump never blocks).

Why `MeshVoteTransport` carries a sink, not a `Node*` (unlike the single-peer
`zap::ZapVoteTransport`): it makes the transport pure sockets+framing+codec, with
no consensus type in it. The host wires the sink to `Node::onVote`.

## Mesh formation

Per pair, the lower index dials and the higher index accepts → exactly one
connection per pair, `N-1` peers each. A dialer writes a 4-byte BE index
handshake on connect; the acceptor consumes it so the ZAP stream starts clean.
Dials retry to a deadline (staggered process start); accepts block on the listen
backlog. The wait-for relation (`i` waits on inbound from `j<i`) is a DAG rooted
at index 0 (which only dials) → no deadlock, in any start order.

## Concurrency model

Share-nothing. Each `Node` is touched by exactly one thread (its host driver).
Mesh setup is the only concurrent phase; the consensus phase is single-threaded
round-robin → deterministic. No application mutex except the per-peer write mutex
required by `write_frame_locked` (uncontended here).

## Build & test (on spark; links the reused checkout, no vendoring)

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release   # auto-finds ../{consensus2-seed,zap-cpp-core,blst,crypto}
cmake --build build -j
ctest --test-dir build --output-on-failure       # frame_reader + node2_cluster (+ reused suite)
./scripts/cluster_5.sh build/node2d 19310         # 5 real PROCESSES over loopback TCP
```

- `frame_reader_test` — reassembler in isolation (split-byte fragmentation, batching, oversize reject).
- `node2_cluster_test` — 5 hosts, ephemeral loopback ports, full TCP mesh; asserts **no node final before `pump()`**, then all 5 finalize with a verifying >2/3-stake cert.
- Verified clean under ThreadSanitizer (no races) and ASan+UBSan+Leak (run TSan with `setarch -R` on this arm64 kernel).

## Scope (honest)

Does: real listen/accept/connect mesh, ZAP framing with non-blocking reassembly,
real BLS quorum-cert finality across threads and processes.

Does NOT yet: peer discovery, reconnection/backoff after a drop, persistence,
peer authentication (the index handshake is unauthenticated but not
security-load-bearing — votes self-identify by pubkey and the gate verifies BLS +
set membership), continuous multi-block operation, or the dispatcher integration.
Those are later phases; the layers above are built to receive them without change.
