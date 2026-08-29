# node2 — a running consensus2 node (ZAP votes over real TCP)

`node2` hosts the **consensus2** engine and disseminates its votes over a **mesh
of real TCP sockets**, framed by the canonical **ZAP** wire codec. N validators,
each on a real listener, dial each other and independently reach BLS quorum-cert
finality over the wire — as threads in one binary and as separate OS processes.

## Layer decomposition (decomplected — each layer is independently testable)

```
  node-host    Node2Host         NEW  src/node2_host.cpp   — listen/accept/dial the
                                       mesh; own one Node; drive submit/round/pump.
  mesh         MeshVoteTransport  NEW  include/.../mesh_vote_transport.hpp (header-only)
                                       VoteTransport over N peer fds; broadcast→all,
                                       pump→drain all, one eviction rule. Holds a vote
                                       SINK, not a Node — zero consensus knowledge.
  reassembler  FrameReader        NEW  include/.../frame_reader.hpp (header-only)
                                       the ONE place that knows non-blocking framing:
                                       reassembles ZAP frames from recv(MSG_DONTWAIT),
                                       bounded by the frame size its link carries.
  codec/wire   encode/decode_vote REUSE consensus2/.../zap/vote_codec.hpp
               Writer/Reader/           zap-cpp-core/.../zap/wire.hpp
               write_frame_locked
  consensus    Node / Wave /      REUSE consensus2 (the gate, unmodified)
               QuorumCertEngine
  crypto       consensus2::bls    REUSE consensus2 (consensus DST) + blst
```

Why a new `FrameReader` instead of `lux::zap::read_frame`: `read_frame` blocks
and treats `EAGAIN` as fatal, so it cannot serve a single-threaded pump over N
peers (a partial frame on one peer would stall the rest). `FrameReader`
accumulates ready bytes and yields a frame only once complete — fragmentation is
invisible above it. The fds stay **blocking** (writes never drop) while reads go
through `MSG_DONTWAIT` (pump never blocks).

Why `MeshVoteTransport` carries a sink, not a `Node*`: it makes the transport
pure sockets+framing+codec, with no consensus type in it. The host wires the sink
to `Node::onVote`.

## The mesh is not the quorum

`connect_mesh` reaches as many configured peers as it can within ONE deadline and
returns how many. It does not demand all of them: the finality rule already says
how many votes are enough, and "every peer must connect" is that rule said a
second time and disagreeing with it — four validators holding 80 of 100 stake,
over the ⅔ floor of 66, would all refuse to start because the fifth was down.
`node2d` reads the returned count against `two_thirds_stake_floor`.

Per pair, the lower index dials and the higher index accepts → exactly one
connection per pair. A dialer writes a 4-byte BE index handshake (ZAP `Writer`,
the same encoder the frames use); the acceptor consumes it so the frame stream
starts clean, and matches the claimed index against the slots it is waiting on —
so one connection fills at most the slot it names. Accepts and dials are swept
together each round, so an absent low-indexed peer starves nothing, and the retry
policy lives in the sweep rather than inside the dial. A node with an absent validator waits out the mesh window
before starting consensus: it cannot tell "not started yet" from "not coming".

## What one hostile socket can do (and what it costs)

One eviction rule, in `MeshVoteTransport::dead`: a peer whose stream closed, whose
framing was violated, or whose socket will not take a write is dropped. Frames
already reassembled are delivered first, so a validator that votes and then hangs
up still counts. Under it:

- the reader states the frame size its link carries (a vote is 188 bytes; the cap
  is one page) and a **rejected stream accepts no further bytes** — 8 MiB fed
  after a rejection is 0 bytes held;
- every peer socket carries a send and receive timeout, so a peer that stops
  reading makes `broadcast` fail rather than hang;
- `SIGPIPE` is disarmed once, in the one place node2 writes to a socket — a peer
  that hangs up mid-broadcast used to kill the validator.

## Concurrency model

Share-nothing. Each `Node` is touched by exactly one thread (its host driver).
Mesh setup is the only concurrent phase; the consensus phase is single-threaded
round-robin → deterministic. No application mutex except the per-peer write mutex
required by `write_frame_locked` (uncontended here).

## Build & test (links the reused checkouts, no vendoring)

`consensus2` (sibling) and the `luxcpp` root (blst, `crypto/bls`, `zap-cpp-core`)
are found automatically; `-DCONSENSUS2_DIR` / `-DLUXCPP_ROOT` override.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure       # node2's five + the reused consensus2 suite
./scripts/cluster.sh build/node2d 19310 5        # 5 real PROCESSES over loopback TCP
./scripts/cluster.sh build/node2d 19310 5 4      # ...with validator 4 held down
```

- `frame_reader_test` — the reassembler alone: fragmentation, batching, the
  rejection latch, and the per-link frame cap.
- `wire_vector_test` — the two formats node2 owns end to end, written as literal
  bytes from the spec and compared against a socket the real transport wrote: the
  4-byte BE index handshake and the 193-byte vote frame.
- `mesh_transport_test` — what one hostile or dead socket can do: oversize
  announce + flood, an over-cap frame, vote-then-hang-up, an unwritable peer, and
  that eviction is per-peer.
- `mesh_formation_test` — setup is bounded (an absent peer, and a stranger that
  connects and says nothing, each cost a deadline), partial (2 of 3 report 1), and
  slot-checked (claims {0,0,9} against slots {0,1} admit exactly one peer).
- `node2_cluster_test` — 5 hosts, ephemeral ports, full TCP mesh; asserts **no
  node final before `pump()`**, then all 5 finalize with a verifying cert.
- `node2_liveness_test` — a DOWN validator (in every host's configured set, and
  dialled) and a WEDGED-but-present one are both routed around on the wire.

Verified clean under ThreadSanitizer and ASan+UBSan+Leak (run TSan under
`setarch -R`; instrumentation covers node2 + consensus2, never blst/bls).

## Conformance to Go

Go is the network; node2 conforms to it, and the conformance is tested, not
asserted in a comment.

- **The frame** is `[4-byte BE length][1-byte msg_type][payload]`, `HeaderSize=5`,
  `MaxMessageSize=16 MiB` — byte-identical to `github.com/luxfi/api/zap`. A frame
  captured off a live `node2d` socket parses with Go's `zap.ReadMessage` with no
  error and three fields of exactly 32/48/96 bytes, zero trailing.
- **The signed message and the floors** are consensus2's, checked against the
  Go-generated corpus by `conformance_test`, which runs in this suite.

## Scope (honest)

Does: real listen/accept/connect mesh, bounded and partial; ZAP framing with
non-blocking reassembly and per-peer eviction; real BLS quorum-cert finality
across threads and processes, at 5, 11, 21 and 33 real processes.

Does NOT yet, in the order it matters:

- **Peer authentication.** The index handshake is 4 plaintext bytes. A stranger
  that connects first takes a validator's inbound slot, which is a liveness DoS
  even though safety holds (votes self-identify by pubkey and the gate verifies
  BLS + set membership). Go ZAP has an X25519 + ML-KEM-768 hybrid handshake with
  AEAD; node2 uses only the frame layer — no reqID, no multiplexing, no ZAP RPC.
- **Sampling.** `Node2Host::round` drives the wave from the committee this node
  can *reach* — a connectivity measure, not a poll of anyone's opinion. It is one
  expression, in one place, and photon sampling replaces exactly it.
- **Reconnection.** The peer set is one-shot: no discovery, no backoff, no
  re-dial after an eviction. An evicted peer is gone for the run.
- **Multi-block operation and persistence.** `node2d` finalizes one block and
  exits. `Node::mark_finalized_through` is now called (via `Node2Host::accept`)
  when a height certifies, but the frontier is in memory: an embedder that
  restarts must re-seed it from a persisted decided height before signing.
